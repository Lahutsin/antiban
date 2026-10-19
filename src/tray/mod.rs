#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

use crate::control::{self, Message};
use crate::network::NetworkOptions;
use anyhow::{bail, Context, Result};
use clap::Parser;
use std::{
    io::{BufRead, BufReader},
    os::unix::{fs::PermissionsExt, net::UnixListener},
    path::Path,
    process::{Command, Stdio},
    sync::mpsc::{self, Receiver, Sender, TryRecvError},
    thread,
    time::{Duration, Instant},
};

#[derive(Parser, Debug)]
#[command(
    version,
    about = "Claude/Anthropic external-IP gate in the system tray"
)]
pub struct Options {
    /// Use the restricted passwordless helper installed by install-autostart.sh.
    #[arg(long, conflicts_with_all = ["state", "direct_interface", "interval", "domain"])]
    installed_helper: bool,
    #[command(flatten)]
    network: NetworkOptions,
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u64).range(1..=10))]
    interval: u64,
    #[arg(long)]
    domain: Vec<String>,
}

#[derive(Debug)]
enum Event {
    Status(Message),
    Finished,
    Failed(String),
    Quit,
    #[cfg(target_os = "macos")]
    Refresh,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Color {
    Waiting,
    Blocked,
    Allowed,
    Partial,
}

struct View {
    label: String,
    details: [String; 3],
    color: Color,
    quitting: bool,
    failed: bool,
}

impl Default for View {
    fn default() -> Self {
        Self {
            label: "Starting; waiting for administrator authorization...".into(),
            details: [
                "IPv4: checking...".into(),
                "IPv6: checking...".into(),
                "Direct interface: detecting...".into(),
            ],
            color: Color::Waiting,
            quitting: false,
            failed: false,
        }
    }
}

impl View {
    fn event(&mut self, event: Event, worker: &Worker) -> Result<bool> {
        match event {
            Event::Status(Message::Status {
                allow4,
                allow6,
                addresses,
                network,
            }) if !self.quitting => {
                let allow4 = allow4 && network.ipv4.changed();
                let allow6 = allow6 && network.ipv6.changed();
                self.label = if allow4 || allow6 {
                    let family = match (allow4, allow6) { (true, true) => "IPv4 + IPv6", (true, false) => "IPv4", _ => "IPv6" };
                    format!("IP changed - OK to use ({family}; {addresses} known IPs)")
                } else if network.error.is_some() {
                    if network.ipv4.original.is_none() && network.ipv6.original.is_none() {
                        "Original IP unknown - BLOCKED".into()
                    } else {
                        "Network check failed - BLOCKED".into()
                    }
                } else if [&network.ipv4, &network.ipv6].iter().any(|family| {
                    matches!((family.original, family.current), (Some(a), Some(b)) if a == b)
                }) {
                    "IP unchanged - BLOCKED".into()
                } else if network.ipv4.original.is_none() || network.ipv6.original.is_none() {
                    "Original IP unknown - BLOCKED".into()
                } else if network.ipv4.current.is_none() || network.ipv6.current.is_none() {
                    "Current IP unknown - BLOCKED".into()
                } else {
                    "IP unchanged - BLOCKED".into()
                };
                let detail = |family: &crate::network::FamilyStatus, name, allowed| {
                    let text = format!(
                        "{} - {}",
                        family.label(name),
                        if allowed { "ALLOWED" } else { "BLOCKED" }
                    );
                    family
                        .error
                        .as_ref()
                        .map_or(text.clone(), |error| format!("{text}; {error}"))
                };
                self.details = [
                    detail(&network.ipv4, "IPv4", allow4),
                    detail(&network.ipv6, "IPv6", allow6),
                    network.error.clone().unwrap_or_else(|| {
                        network.interface.as_ref().map_or_else(
                            || {
                                if network.ipv4.original.is_some()
                                    || network.ipv6.original.is_some()
                                {
                                    "Original source: saved baseline".into()
                                } else {
                                    "Direct interface: detecting...".into()
                                }
                            },
                            |name| format!("Direct interface: {name}"),
                        )
                    }),
                ];
                self.color = match (allow4, allow6) {
                    (true, true) => Color::Allowed,
                    (false, false) => Color::Blocked,
                    _ => Color::Partial,
                };
            }
            Event::Status(Message::Failure { message }) | Event::Failed(message) => {
                eprintln!("ERROR: {message}");
                self.label = format!(
                    "Error: {}. Rules may remain; see README.",
                    message.chars().take(180).collect::<String>()
                );
                self.color = Color::Blocked;
                self.failed = true;
                self.quitting = false;
            }
            Event::Quit if self.failed => return Ok(true),
            Event::Quit if !self.quitting => {
                worker.quit()?;
                self.label = "Stopping and removing firewall rules...".into();
                self.quitting = true;
            }
            Event::Finished => return Ok(true),
            _ => {}
        }
        Ok(false)
    }
}

const ICON_SIZE: u32 = 32;
const ICON_PNG: &[u8] = include_bytes!("../../icon/icon.png");

fn icon_pixels() -> Result<Vec<u8>> {
    let source = image::load_from_memory_with_format(ICON_PNG, image::ImageFormat::Png)
        .context("Cannot decode embedded tray icon")?;
    let resized = source
        .resize(ICON_SIZE, ICON_SIZE, image::imageops::FilterType::Lanczos3)
        .to_rgba8();
    let mut canvas = image::RgbaImage::new(ICON_SIZE, ICON_SIZE);
    image::imageops::overlay(
        &mut canvas,
        &resized,
        i64::from((ICON_SIZE - resized.width()) / 2),
        i64::from((ICON_SIZE - resized.height()) / 2),
    );
    Ok(canvas.into_raw())
}

fn pixels(base: &[u8], color: Color) -> Vec<u8> {
    let rgb = match color {
        Color::Waiting => [130, 140, 150],
        Color::Blocked => [220, 55, 55],
        Color::Allowed => [45, 190, 90],
        Color::Partial => [235, 170, 35],
    };
    let mut rgba = base.to_vec();
    for y in 23i32..32 {
        for x in 23i32..32 {
            let radius = (x - 27).pow(2) + (y - 27).pow(2);
            if radius <= 16 {
                let offset = ((y as usize * ICON_SIZE as usize) + x as usize) * 4;
                let color = if radius <= 9 { rgb } else { [255, 255, 255] };
                rgba[offset..offset + 4].copy_from_slice(&[color[0], color[1], color[2], 255]);
            }
        }
    }
    rgba
}

pub fn run(options: Options) -> Result<()> {
    let uid = Command::new("/usr/bin/id").arg("-u").output()?;
    if !uid.status.success() || uid.stdout == b"0\n" {
        bail!("Run antiban-tray as your desktop user, NOT with sudo");
    }
    #[cfg(target_os = "linux")]
    return linux::run(options);
    #[cfg(target_os = "macos")]
    return macos::run(options);
}

struct Worker {
    commands: Sender<()>,
}

impl Worker {
    fn start(options: Options, notify: impl Fn(Event) + Send + 'static) -> Result<Self> {
        let (commands, receiver) = mpsc::channel();
        thread::Builder::new()
            .name("antiban-monitor".into())
            .spawn(move || {
                if let Err(error) = work(options, receiver, &notify) {
                    notify(Event::Failed(format!("{error:#}")));
                }
            })?;
        Ok(Self { commands })
    }

    fn quit(&self) -> Result<()> {
        self.commands
            .send(())
            .context("Monitor worker already stopped")
    }
}

fn monitor_arguments(options: &Options, socket: &Path) -> Vec<String> {
    if options.installed_helper {
        return vec![
            "desktop-helper".into(),
            "--control".into(),
            socket.to_string_lossy().into_owned(),
        ];
    }
    let mut arguments = vec![
        "run".into(),
        "--interval".into(),
        options.interval.to_string(),
        "--control".into(),
        socket.to_string_lossy().into_owned(),
    ];
    if let Some(state) = &options.network.state {
        arguments.extend(["--state".into(), state.to_string_lossy().into_owned()]);
    }
    if let Some(interface) = &options.network.direct_interface {
        arguments.extend(["--direct-interface".into(), interface.clone()]);
    }
    for domain in &options.domain {
        arguments.extend(["--domain".into(), domain.clone()]);
    }
    arguments
}

#[cfg(any(target_os = "macos", test))]
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn elevation(program: &Path, arguments: &[String], installed: bool) -> Result<Command> {
    if installed {
        let mut command = Command::new("/usr/bin/sudo");
        command.arg("-n").arg("--").arg(program).args(arguments);
        return Ok(command);
    }
    #[cfg(target_os = "linux")]
    {
        if !Path::new("/usr/bin/pkexec").is_file() {
            bail!("pkexec is required. Install polkit and run a desktop authentication agent");
        }
        let mut command = Command::new("/usr/bin/pkexec");
        command
            .arg("--disable-internal-agent")
            .arg(program)
            .args(arguments);
        Ok(command)
    }
    #[cfg(target_os = "macos")]
    {
        let shell_command = std::iter::once(program.to_string_lossy().into_owned())
            .chain(arguments.iter().cloned())
            .map(|value| shell_quote(&value))
            .collect::<Vec<_>>()
            .join(" ");
        let mut command = Command::new("/usr/bin/osascript");
        command.args([
            "-e",
            "on run argv\n do shell script (item 1 of argv) with administrator privileges\nend run",
            &shell_command,
        ]);
        Ok(command)
    }
}

fn work(options: Options, commands: Receiver<()>, notify: &impl Fn(Event)) -> Result<()> {
    let program = std::env::current_exe()?
        .parent()
        .context("Cannot locate executable directory")?
        .join("antiban")
        .canonicalize()
        .context("Keep antiban and antiban-tray in the same directory")?;
    let mut options = options;
    if let Some(state) = &options.network.state {
        options.network.state = Some(
            state
                .canonicalize()
                .context("Saved-baseline mode requires an existing baseline file")?,
        );
    }
    let temporary_root = std::env::temp_dir()
        .canonicalize()
        .context("Cannot resolve temporary directory")?;
    let directory = tempfile::Builder::new()
        .prefix("antiban-tray-")
        .tempdir_in(temporary_root)?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    let path = directory.path().join("control.sock");
    let listener = UnixListener::bind(&path)?;
    listener.set_nonblocking(true)?;
    let mut child = elevation(
        &program,
        &monitor_arguments(&options, &path),
        options.installed_helper,
    )?
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::inherit())
    .spawn()
    .context("Cannot start administrator authorization")?;
    let started = Instant::now();
    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.into()),
        }
        if let Some(status) = child.try_wait()? {
            bail!("Administrator helper exited before connecting: {status}. Check authorization and terminal output");
        }
        if commands.try_recv() != Err(TryRecvError::Empty) {
            child
                .kill()
                .context("Cannot cancel administrator authorization")?;
            child.wait()?;
            notify(Event::Finished);
            return Ok(());
        }
        if started.elapsed() > Duration::from_secs(120) {
            child.kill()?;
            child.wait()?;
            bail!("Administrator authorization timed out");
        }
        thread::sleep(Duration::from_millis(100));
    };
    let reader = stream.try_clone()?;
    let (messages, incoming) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(reader).lines() {
            let message = line
                .map_err(anyhow::Error::from)
                .and_then(|line| Ok(serde_json::from_str::<Message>(&line)?));
            if messages.send(message).is_err() {
                return;
            }
        }
    });
    let mut quit_sent = false;
    let mut stopped = false;
    loop {
        if !quit_sent && commands.try_recv() != Err(TryRecvError::Empty) {
            control::send(&mut stream, &Message::Quit)?;
            quit_sent = true;
        }
        for message in incoming.try_iter() {
            match message? {
                Message::Stopped => stopped = true,
                message => notify(Event::Status(message)),
            }
        }
        if let Some(status) = child.try_wait()? {
            // Drain the reader after process exit before checking the final acknowledgement.
            for message in incoming.iter() {
                match message? {
                    Message::Stopped => stopped = true,
                    message => notify(Event::Status(message)),
                }
            }
            if stopped && status.success() {
                notify(Event::Finished);
                return Ok(());
            }
            bail!("Monitor exited without confirmed firewall cleanup ({status}); protection may remain blocked");
        }
        thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_arguments_cannot_become_commands() {
        assert_eq!(shell_quote("a'b; $HOME"), "'a'\\''b; $HOME'");
    }

    #[test]
    fn indicators_reflect_both_address_families() {
        let (sender, _receiver) = mpsc::channel();
        let worker = Worker { commands: sender };
        let mut view = View::default();
        for (v4, v6, color) in [
            (false, false, Color::Blocked),
            (true, false, Color::Partial),
            (false, true, Color::Partial),
            (true, true, Color::Allowed),
        ] {
            assert!(!view
                .event(
                    Event::Status(Message::Status {
                        allow4: v4,
                        allow6: v6,
                        addresses: 2,
                        network: crate::network::NetworkStatus {
                            ipv4: crate::network::FamilyStatus {
                                original: Some("8.8.8.8".parse().unwrap()),
                                current: Some(
                                    if v4 { "1.1.1.1" } else { "8.8.8.8" }.parse().unwrap()
                                ),
                                error: None,
                            },
                            ipv6: crate::network::FamilyStatus {
                                original: Some("2001:4860:4860::8888".parse().unwrap()),
                                current: Some(
                                    if v6 {
                                        "2606:4700:4700::1111"
                                    } else {
                                        "2001:4860:4860::8888"
                                    }
                                    .parse()
                                    .unwrap()
                                ),
                                error: None,
                            },
                            ..Default::default()
                        }
                    }),
                    &worker
                )
                .unwrap());
            assert_eq!(view.color, color);
            assert_eq!(view.label.contains("OK to use"), v4 || v6);
            assert!(view.details[0].contains("original 8.8.8.8 -> current"));
        }
        assert!(!view.event(Event::Quit, &worker).unwrap());
        assert!(view.quitting);
        assert!(view.event(Event::Finished, &worker).unwrap());
        assert_eq!(
            pixels(&icon_pixels().unwrap(), Color::Blocked).len(),
            32 * 32 * 4
        );
    }

    #[test]
    fn embedded_artwork_is_visible_and_preserved_outside_status_badge() {
        let base = icon_pixels().unwrap();
        assert_eq!(base.len(), (ICON_SIZE * ICON_SIZE * 4) as usize);
        assert!(base
            .as_chunks::<4>()
            .0
            .iter()
            .any(|pixel| pixel[3] > 0 && pixel[0] > 100));
        let offset = ((27 * ICON_SIZE + 27) * 4) as usize;
        for (color, rgb) in [
            (Color::Waiting, [130, 140, 150]),
            (Color::Blocked, [220, 55, 55]),
            (Color::Allowed, [45, 190, 90]),
            (Color::Partial, [235, 170, 35]),
        ] {
            let rendered = pixels(&base, color);
            assert_eq!(
                &rendered[..23 * ICON_SIZE as usize * 4],
                &base[..23 * ICON_SIZE as usize * 4]
            );
            assert_eq!(
                &rendered[offset..offset + 4],
                &[rgb[0], rgb[1], rgb[2], 255]
            );
        }
    }

    #[test]
    fn unknown_original_cannot_show_ok_even_if_permissions_are_reported() {
        let (commands, _receiver) = mpsc::channel();
        let worker = Worker { commands };
        let mut view = View::default();
        view.event(
            Event::Status(Message::Status {
                allow4: true,
                allow6: false,
                addresses: 4,
                network: Default::default(),
            }),
            &worker,
        )
        .unwrap();
        assert_eq!(view.color, Color::Blocked);
        assert_eq!(view.label, "Original IP unknown - BLOCKED");
        assert!(!view.label.contains("OK to use"));
    }

    #[test]
    fn automatic_launch_needs_no_saved_baseline() {
        let options = Options::try_parse_from(["antiban-tray"]).unwrap();
        let arguments = monitor_arguments(&options, Path::new("/tmp/control.sock"));
        assert!(!arguments.iter().any(|arg| arg == "--state"));
        let options =
            Options::try_parse_from(["antiban-tray", "--direct-interface", "en0"]).unwrap();
        assert!(monitor_arguments(&options, Path::new("/tmp/control.sock"))
            .windows(2)
            .any(|args| args == ["--direct-interface", "en0"]));
        assert!(Options::try_parse_from([
            "antiban-tray",
            "--direct-interface",
            "en0",
            "--state",
            "/tmp/baseline"
        ])
        .is_err());
    }

    #[test]
    fn installed_mode_uses_only_the_restricted_helper() {
        let options = Options::try_parse_from(["antiban-tray", "--installed-helper"]).unwrap();
        assert_eq!(
            monitor_arguments(&options, Path::new("/tmp/control.sock")),
            ["desktop-helper", "--control", "/tmp/control.sock"]
        );
        for flag in ["--state", "--direct-interface", "--interval", "--domain"] {
            assert!(
                Options::try_parse_from(["antiban-tray", "--installed-helper", flag, "x"]).is_err()
            );
        }
        let command = elevation(
            Path::new("/opt/antiban/antiban"),
            &monitor_arguments(&options, Path::new("/tmp/control.sock")),
            true,
        )
        .unwrap();
        assert_eq!(command.get_program(), "/usr/bin/sudo");
        assert_eq!(command.get_args().take(2).collect::<Vec<_>>(), ["-n", "--"]);
    }
}
