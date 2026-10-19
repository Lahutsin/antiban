#[cfg(any(target_os = "linux", test))]
use crate::LEASE_SECONDS;
use crate::{executable, Policy};
use anyhow::{bail, Context, Result};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    process::{Command, Stdio},
};

pub(crate) fn lock() -> Result<File> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options.open("/var/run/antiban.lock")?;
    file.try_lock()
        .context("Another antiban guardian/uninstall is running; stop it first")?;
    Ok(file)
}

fn execute(program: &std::path::Path, args: &[&str], input: &str) -> Result<String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("Cannot start {}", program.display()))?;
    let write_result = child
        .stdin
        .take()
        .context("No firewall stdin")?
        .write_all(input.as_bytes());
    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!(
            "{} failed: {}",
            program.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    write_result?;
    Ok(String::from_utf8(output.stdout)?)
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn nft_rules(policy: &Policy) -> String {
    let mut rules = String::from("delete table inet antiban\ntable inet antiban {\n");
    for (family, ipv6, allowed) in [("4", false, policy.allow4), ("6", true, policy.allow6)] {
        let addresses: Vec<_> = policy
            .addresses
            .iter()
            .filter(|ip| ip.is_ipv6() == ipv6)
            .map(ToString::to_string)
            .collect();
        let kind = if ipv6 { "ipv6_addr" } else { "ipv4_addr" };
        rules.push_str(&format!("set protected{family} {{ type {kind};"));
        if !addresses.is_empty() {
            rules.push_str(&format!(" elements = {{ {} }};", addresses.join(", ")));
        }
        rules.push_str(" }\n");
        rules.push_str(&format!(
            "set allowed{family} {{ type {kind}; flags timeout;"
        ));
        if allowed && !addresses.is_empty() {
            let elements: Vec<_> = addresses
                .iter()
                .map(|ip| format!("{ip} timeout {LEASE_SECONDS}s"))
                .collect();
            rules.push_str(&format!(" elements = {{ {} }};", elements.join(", ")));
        }
        rules.push_str(" }\n");
    }
    rules.push_str(
        "chain output {\n type filter hook output priority -10; policy accept;\n\
         ip daddr @protected4 ip daddr != @allowed4 counter drop\n\
         ip6 daddr @protected6 ip6 daddr != @allowed6 counter drop\n}\n}\n",
    );
    rules
}

#[cfg(any(target_os = "macos", test))]
pub(crate) fn pf_rules(policy: &Policy) -> String {
    let mut rules = String::new();
    for (family, ipv6) in [("4", false), ("6", true)] {
        let addresses: Vec<_> = policy
            .addresses
            .iter()
            .filter(|ip| ip.is_ipv6() == ipv6)
            .map(ToString::to_string)
            .collect();
        rules.push_str(&format!(
            "table <antiban{family}> persist {{ {} }}\n",
            addresses.join(", ")
        ));
    }
    for (family, ipv6, allowed) in [("4", false, policy.allow4), ("6", true, policy.allow6)] {
        if !allowed {
            let inet = if ipv6 { "inet6" } else { "inet" };
            rules.push_str(&format!(
                "block drop out quick {inet} from any to <antiban{family}>\n"
            ));
        }
    }
    rules
}

#[cfg(target_os = "linux")]
pub(crate) fn prepare() -> Result<()> {
    let nft = executable(&["/usr/sbin/nft", "/sbin/nft"])?;
    execute(&nft, &["-f", "-"], "add table inet antiban\n")?;
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn apply(policy: &Policy) -> Result<()> {
    let nft = executable(&["/usr/sbin/nft", "/sbin/nft"])?;
    execute(&nft, &["-f", "-"], &nft_rules(policy))?;
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn uninstall() -> Result<()> {
    let nft = executable(&["/usr/sbin/nft", "/sbin/nft"])?;
    execute(&nft, &["-f", "-"], "delete table inet antiban\n")?;
    Ok(())
}

pub(crate) fn uninstall_if_present() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let nft = executable(&["/usr/sbin/nft", "/sbin/nft"])?;
        let tables = execute(&nft, &["list", "tables"], "")?;
        if !tables
            .lines()
            .any(|line| line.trim() == "table inet antiban")
        {
            eprintln!("Antiban firewall table is already absent");
            return Ok(());
        }
    }
    uninstall()
}

#[cfg(target_os = "macos")]
pub(crate) fn prepare() -> Result<()> {
    let pf = executable(&["/sbin/pfctl"])?;
    let status = execute(&pf, &["-s", "info"], "")?;
    if !status
        .lines()
        .any(|line| line.starts_with("Status: Enabled"))
    {
        bail!("PF is disabled; configure /etc/pf.conf and enable PF first (see README)");
    }
    let rules = execute(&pf, &["-sr"], "")?;
    let first = rules
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("");
    if first != "anchor \"antiban\" all" && first != "anchor \"antiban\"" {
        bail!("The FIRST active PF filter rule must be anchor \"antiban\" (see README)");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn apply(policy: &Policy) -> Result<()> {
    let pf = executable(&["/sbin/pfctl"])?;
    execute(&pf, &["-a", "antiban", "-f", "-"], &pf_rules(policy))?;
    // PF checks existing states before rules. Kill only states for blocked addresses.
    for ip in &policy.addresses {
        if if ip.is_ipv4() {
            !policy.allow4
        } else {
            !policy.allow6
        } {
            let any = if ip.is_ipv4() { "0.0.0.0/0" } else { "::/0" };
            execute(&pf, &["-k", any, "-k", &ip.to_string()], "")?;
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn uninstall() -> Result<()> {
    let pf = executable(&["/sbin/pfctl"])?;
    execute(&pf, &["-a", "antiban", "-F", "all"], "")?;
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn prepare() -> Result<()> {
    bail!("Only Linux and macOS are supported")
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn apply(_: &Policy) -> Result<()> {
    bail!("Only Linux and macOS are supported")
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn uninstall() -> Result<()> {
    bail!("Only Linux and macOS are supported")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Policy {
        Policy {
            addresses: [
                "198.51.100.8".parse().unwrap(),
                "2001:db8::8".parse().unwrap(),
            ]
            .into(),
            allow4: true,
            allow6: false,
        }
    }

    #[test]
    fn nft_has_family_specific_expiring_permissions_and_output_drops() {
        let rules = nft_rules(&sample());
        assert!(rules.contains("198.51.100.8 timeout 30s"));
        assert!(!rules.contains("2001:db8::8 timeout"));
        assert!(rules.contains("ip daddr @protected4 ip daddr != @allowed4 counter drop"));
        assert!(rules.contains("ip6 daddr @protected6 ip6 daddr != @allowed6 counter drop"));
        assert!(rules.starts_with("delete table inet antiban\n"));
    }

    #[test]
    fn pf_blocks_only_disabled_family() {
        let rules = pf_rules(&sample());
        assert!(!rules.contains("block drop out quick inet from"));
        assert!(rules.contains("block drop out quick inet6 from any to <antiban6>"));
        assert!(rules.contains("table <antiban4> persist { 198.51.100.8 }"));
        assert!(rules.contains("table <antiban6> persist { 2001:db8::8 }"));
    }

    #[test]
    fn blocked_rules_have_no_permissions() {
        let mut policy = sample();
        policy.block();
        assert!(!nft_rules(&policy).contains("timeout 30s"));
        assert_eq!(pf_rules(&policy).matches("block drop out quick").count(), 2);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires a fresh rootless user/network namespace; see README"]
    fn linux_kernel_gate_and_lease_in_private_namespace() {
        use std::{
            io::Read,
            net::{TcpListener, TcpStream},
            time::Duration,
        };

        let mapping = std::fs::read_to_string("/proc/self/uid_map").unwrap();
        let fields: Vec<_> = mapping.split_whitespace().collect();
        assert_eq!(fields.len(), 3, "Use a fresh rootless user namespace");
        assert_eq!(fields[0], "0");
        assert_ne!(fields[1], "0", "Never run this test in the host namespace");
        assert_eq!(fields[2], "1");
        assert_ne!(
            std::fs::read_link("/proc/self/ns/net").unwrap(),
            std::path::PathBuf::from(
                std::env::var("ANTIBAN_TEST_HOST_NETNS")
                    .expect("Set ANTIBAN_TEST_HOST_NETNS before unshare; see README")
            ),
            "Use a private network namespace"
        );
        let nft = executable(&["/usr/sbin/nft", "/sbin/nft"]).unwrap();
        assert!(execute(&nft, &["list", "tables"], "").unwrap().is_empty());
        let ip = executable(&["/usr/sbin/ip", "/sbin/ip"]).unwrap();
        execute(&ip, &["link", "set", "lo", "up"], "").unwrap();

        let v4 = TcpListener::bind("127.0.0.3:0").unwrap();
        let v6 = TcpListener::bind("[::1]:0").unwrap();
        let unrelated = TcpListener::bind("127.0.0.2:0").unwrap();
        let connect = |listener: &TcpListener| {
            TcpStream::connect_timeout(&listener.local_addr().unwrap(), Duration::from_millis(200))
        };
        let mut policy = Policy {
            addresses: ["127.0.0.3".parse().unwrap(), "::1".parse().unwrap()].into(),
            ..Policy::default()
        };
        prepare().unwrap();
        apply(&policy).unwrap();
        assert!(connect(&v4).is_err());
        assert!(connect(&v6).is_err());
        assert!(connect(&unrelated).is_ok());

        policy.allow4 = true;
        apply(&policy).unwrap();
        let mut client = connect(&v4).unwrap();
        let (mut server, _) = v4.accept().unwrap();
        assert!(connect(&v6).is_err());
        policy.block();
        apply(&policy).unwrap();
        server
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        client.write_all(b"x").unwrap();
        assert!(
            server.read_exact(&mut [0u8; 1]).is_err(),
            "Established traffic must also be blocked"
        );
        drop(client);
        drop(server);

        policy.allow4 = true;
        policy.allow6 = true;
        apply(&policy).unwrap();
        assert!(connect(&v4).is_ok());
        assert!(connect(&v6).is_ok());
        assert!(connect(&unrelated).is_ok());
        std::thread::sleep(Duration::from_secs(LEASE_SECONDS + 1));
        assert!(
            connect(&v4).is_err(),
            "IPv4 permission must expire in the kernel"
        );
        assert!(
            connect(&v6).is_err(),
            "IPv6 permission must expire in the kernel"
        );
        assert!(connect(&unrelated).is_ok());
        uninstall().unwrap();
        assert!(connect(&v4).is_ok());
        assert!(connect(&v6).is_ok());
    }
}
