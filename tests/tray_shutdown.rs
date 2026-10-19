#![cfg(all(target_os = "linux", feature = "tray"))]

use antiban::control::{send, Message};
use std::{
    fs,
    io::{BufRead, BufReader},
    os::unix::{fs::PermissionsExt, net::UnixListener},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

struct Monitor(Child);

impl Monitor {
    fn wait(&mut self) -> std::process::ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "Monitor did not exit after shutdown"
            );
            thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        if self.0.try_wait().unwrap().is_none() {
            self.0.kill().unwrap();
            self.0.wait().unwrap();
        }
    }
}

#[test]
#[ignore = "requires fresh rootless user, mount and network namespaces; see README"]
fn tray_quit_and_disconnect_in_private_namespace() {
    let mapping = fs::read_to_string("/proc/self/uid_map").unwrap();
    let fields: Vec<_> = mapping.split_whitespace().collect();
    assert_eq!(fields.len(), 3);
    assert_eq!(fields[0], "0");
    assert_ne!(fields[1], "0", "Never run in the host namespace");
    assert_eq!(fields[2], "1");
    assert_ne!(
        fs::read_link("/proc/self/ns/net").unwrap(),
        std::path::PathBuf::from(std::env::var("ANTIBAN_TEST_HOST_NETNS").unwrap())
    );
    assert_ne!(
        fs::read_link("/proc/self/ns/mnt").unwrap(),
        std::path::PathBuf::from(std::env::var("ANTIBAN_TEST_HOST_MNTNS").unwrap())
    );
    assert!(Command::new("/usr/bin/mount")
        .args(["-t", "tmpfs", "tmpfs", "/var/run"])
        .status()
        .unwrap()
        .success());
    let executable = env!("CARGO_BIN_EXE_antiban");
    let directory = tempfile::tempdir().unwrap();
    let baseline = directory.path().join("baseline.txt");
    let original = "antiban-v1\n198.51.100.9\n-\n";
    fs::write(&baseline, original).unwrap();
    fs::set_permissions(&baseline, fs::Permissions::from_mode(0o600)).unwrap();

    for (index, (explicit_quit, saved)) in [(true, true), (false, true), (true, false)]
        .into_iter()
        .enumerate()
    {
        let socket = directory.path().join(format!("control-{index}.sock"));
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut command = Command::new(executable);
        command.arg("run");
        if saved {
            command.arg("--state").arg(&baseline);
        }
        let mut monitor = Monitor(
            command
                .arg("--control")
                .arg(&socket)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(connection) => break connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("Cannot accept monitor: {error}"),
            }
            assert!(monitor.0.try_wait().unwrap().is_none());
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(20));
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert_eq!(
            serde_json::from_str::<Message>(&line).unwrap(),
            Message::Status {
                allow4: false,
                allow6: false,
                addresses: 0,
                network: Default::default()
            }
        );
        let uninstall = Command::new(executable)
            .args(["uninstall", "--if-present"])
            .output()
            .unwrap();
        assert!(
            !uninstall.status.success(),
            "Uninstall must not bypass the live guardian lock"
        );
        if !saved {
            loop {
                line.clear();
                assert_ne!(reader.read_line(&mut line).unwrap(), 0);
                match serde_json::from_str::<Message>(&line).unwrap() {
                    Message::Status {
                        allow4,
                        allow6,
                        network,
                        ..
                    } if network.error.is_some() => {
                        assert!(!allow4 && !allow6);
                        assert!(network.ipv4.original.is_none());
                        assert!(network.ipv6.original.is_none());
                        assert!(network.error.unwrap().contains("Original IP unknown"));
                        break;
                    }
                    Message::Status { .. } => {}
                    message => panic!("Unexpected automatic-mode response: {message:?}"),
                }
            }
        }
        if explicit_quit {
            send(&mut stream, &Message::Quit).unwrap();
            loop {
                line.clear();
                assert_ne!(
                    reader.read_line(&mut line).unwrap(),
                    0,
                    "Missing cleanup acknowledgement"
                );
                match serde_json::from_str::<Message>(&line).unwrap() {
                    Message::Stopped => break,
                    Message::Status { .. } => {}
                    message => panic!("Unexpected monitor response: {message:?}"),
                }
            }
        }
        drop(reader);
        drop(stream);
        let status = monitor.wait();
        if explicit_quit {
            assert!(
                status.success(),
                "Monitor failed to complete Quit: {status}"
            );
        } else {
            assert!(
                status.code().is_some(),
                "Monitor must finish cleanup, not be killed"
            );
        }
        assert_eq!(
            fs::read_to_string(&baseline).unwrap(),
            original,
            "Startup must not overwrite the original IP"
        );
        let table = Command::new("/usr/sbin/nft")
            .args(["list", "table", "inet", "antiban"])
            .output()
            .unwrap();
        assert_eq!(table.status.success(), !explicit_quit);
        if !explicit_quit {
            assert!(Command::new(executable)
                .arg("uninstall")
                .status()
                .unwrap()
                .success());
        }
        assert!(
            Command::new(executable)
                .args(["uninstall", "--if-present"])
                .status()
                .unwrap()
                .success(),
            "Removal must also work after tray Quit already deleted the table"
        );
    }
}
