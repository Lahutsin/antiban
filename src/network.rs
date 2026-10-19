use anyhow::{bail, Context, Result};
use clap::Args;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet, io::Read, net::IpAddr, path::PathBuf, process::Command, time::Duration,
};

#[derive(Args, Debug, Clone, Default)]
pub struct NetworkOptions {
    /// Use a saved baseline instead of automatically probing the physical interface.
    #[arg(long, conflicts_with = "direct_interface")]
    pub state: Option<PathBuf>,
    /// Physical interface for the direct original-IP probe (otherwise autodetect).
    #[arg(long, value_parser = interface_name)]
    pub direct_interface: Option<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FamilyStatus {
    pub original: Option<IpAddr>,
    pub current: Option<IpAddr>,
    pub error: Option<String>,
}

impl FamilyStatus {
    pub fn changed(&self) -> bool {
        self.error.is_none()
            && matches!((self.original, self.current), (Some(a), Some(b))
                if a.is_ipv4() == b.is_ipv4() && a != b)
    }

    pub fn from_checks(original: Result<IpAddr>, current: Result<IpAddr>) -> Self {
        let mut errors = Vec::new();
        let mut value = |check: Result<IpAddr>, name| match check {
            Ok(ip) => Some(ip),
            Err(error) => {
                errors.push(format!("{name}: {error:#}"));
                None
            }
        };
        let original = value(original, "Original IP unknown");
        let current = value(current, "Current IP unknown");
        Self {
            original,
            current,
            error: (!errors.is_empty()).then(|| errors.join("; ")),
        }
    }

    pub fn label(&self, family: &str) -> String {
        let address = |ip: Option<IpAddr>| ip.map_or_else(|| "unknown".into(), |ip| ip.to_string());
        let state = if self.error.is_some() || self.original.is_none() || self.current.is_none() {
            "unknown"
        } else if self.changed() {
            "changed"
        } else {
            "unchanged"
        };
        format!(
            "{family}: original {} -> current {} ({state})",
            address(self.original),
            address(self.current)
        )
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkStatus {
    pub interface: Option<String>,
    pub ipv4: FamilyStatus,
    pub ipv6: FamilyStatus,
    pub error: Option<String>,
}

pub fn interface_name(value: &str) -> std::result::Result<String, String> {
    if !value.is_empty()
        && value.len() < 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
        && !value.starts_with('-')
    {
        Ok(value.into())
    } else {
        Err("Expected an interface name such as enp2s0 or en0".into())
    }
}

fn output(programs: &[&str], args: &[&str]) -> Result<String> {
    let program = crate::executable(programs)?;
    let output = Command::new(&program)
        .args(args)
        .env("LC_ALL", "C")
        .output()?;
    if !output.status.success() {
        bail!(
            "{} failed: {}",
            program.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8(output.stdout)?)
}

#[cfg(target_os = "linux")]
fn physical(interface: &str) -> Result<()> {
    let path = PathBuf::from("/sys/class/net").join(interface);
    if !path.join("device").exists() {
        bail!("{interface} is not a hardware-backed interface");
    }
    let state = std::fs::read_to_string(path.join("operstate"))?;
    if state.trim() != "up" {
        bail!("Physical interface {interface} is not up");
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
#[derive(Deserialize)]
struct Route {
    dev: Option<String>,
    #[serde(default)]
    metric: u32,
}

#[cfg(any(target_os = "linux", test))]
fn linux_candidate(routes: &str, mut usable: impl FnMut(&str) -> bool) -> Result<Option<String>> {
    let routes: Vec<Route> = serde_json::from_str(routes)?;
    let candidates: Vec<_> = routes
        .into_iter()
        .filter_map(|route| route.dev.map(|dev| (route.metric, dev)))
        .filter(|(_, dev)| usable(dev))
        .collect();
    let Some(metric) = candidates.iter().map(|(metric, _)| *metric).min() else {
        return Ok(None);
    };
    let names: BTreeSet<_> = candidates
        .into_iter()
        .filter(|(cost, _)| *cost == metric)
        .map(|(_, dev)| dev)
        .collect();
    if names.len() != 1 {
        bail!("Multiple physical default routes; select --direct-interface explicitly");
    }
    Ok(names.into_iter().next())
}

#[cfg(target_os = "linux")]
pub fn direct_interface(requested: Option<&str>) -> Result<String> {
    if let Some(name) = requested {
        interface_name(name).map_err(anyhow::Error::msg)?;
        physical(name)?;
        return Ok(name.into());
    }
    let v4 = output(
        &["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip"],
        &["-j", "-4", "route", "show", "table", "main", "default"],
    )?;
    if let Some(name) = linux_candidate(&v4, |name| physical(name).is_ok())? {
        return Ok(name);
    }
    let v6 = output(
        &["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip"],
        &["-j", "-6", "route", "show", "table", "main", "default"],
    )?;
    linux_candidate(&v6, |name| physical(name).is_ok())?
        .context("Cannot identify the original connection; specify --direct-interface")
}

#[cfg(any(target_os = "macos", test))]
fn hardware_ports(text: &str) -> BTreeSet<String> {
    text.lines()
        .filter_map(|line| line.trim().strip_prefix("Device: "))
        .filter(|name| {
            name.strip_prefix("en").is_some_and(|suffix| {
                !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
            })
        })
        .map(str::to_owned)
        .collect()
}

#[cfg(any(target_os = "macos", test))]
fn mac_candidate(routes: &str, mut usable: impl FnMut(&str) -> bool) -> Result<Option<String>> {
    let mut column = None;
    let mut names = BTreeSet::new();
    let mut unscoped = BTreeSet::new();
    for line in routes.lines() {
        let words: Vec<_> = line.split_whitespace().collect();
        if words.first() == Some(&"Destination") {
            column = words.iter().position(|word| *word == "Netif");
        } else if words.first() == Some(&"default") {
            let name = words
                .get(column.context("Missing Netif route column")?)
                .context("Invalid default-route row")?;
            if usable(name) {
                names.insert((*name).to_string());
                if !words.get(2).context("Missing route flags")?.contains('I') {
                    unscoped.insert((*name).to_string());
                }
            }
        }
    }
    let names = if unscoped.is_empty() { names } else { unscoped };
    if names.len() > 1 {
        bail!("Cannot uniquely identify the physical default route; specify --direct-interface");
    }
    Ok(names.into_iter().next())
}

#[cfg(target_os = "macos")]
pub fn direct_interface(requested: Option<&str>) -> Result<String> {
    let ports = hardware_ports(&output(
        &["/usr/sbin/networksetup"],
        &["-listallhardwareports"],
    )?);
    let usable = |name: &str| -> bool {
        ports.contains(name)
            && output(&["/sbin/ifconfig"], &[name])
                .is_ok_and(|text| text.lines().any(|line| line.trim() == "status: active"))
    };
    if let Some(name) = requested {
        interface_name(name).map_err(anyhow::Error::msg)?;
        if !usable(name) {
            bail!("{name} is not an active hardware Ethernet/Wi-Fi interface");
        }
        return Ok(name.into());
    }
    let v4 = output(&["/usr/sbin/netstat"], &["-rn", "-f", "inet"])?;
    if let Some(name) = mac_candidate(&v4, usable)? {
        return Ok(name);
    }
    let v6 = output(&["/usr/sbin/netstat"], &["-rn", "-f", "inet6"])?;
    mac_candidate(&v6, usable)?.context("No active physical default-route interface found")
}

fn probe_client(interface: Option<&str>) -> Result<Client> {
    let mut builder = Client::builder()
        .no_proxy()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(5))
        .pool_max_idle_per_host(0);
    if let Some(name) = interface {
        builder = builder.interface(name);
    }
    Ok(builder.build()?)
}

pub fn public_ip(ipv6: bool, interface: Option<&str>) -> Result<IpAddr> {
    let client = probe_client(interface)?;
    let urls = if ipv6 {
        ["https://api6.ipify.org", "https://ipv6.icanhazip.com"]
    } else {
        ["https://api4.ipify.org", "https://ipv4.icanhazip.com"]
    };
    let mut observed = Vec::new();
    for url in urls {
        let response = client
            .get(url)
            .send()
            .with_context(|| format!("IP probe failed ({url}, interface {interface:?})"))?
            .error_for_status()?;
        let mut body = String::new();
        response.take(257).read_to_string(&mut body)?;
        if body.len() > 256 {
            bail!("Oversized response from {url}");
        }
        let ip: IpAddr = body
            .trim()
            .parse()
            .with_context(|| format!("Invalid IP from {url}"))?;
        if ip.is_ipv6() != ipv6 || ip.is_unspecified() || ip.is_loopback() {
            bail!("Invalid IP family or address from {url}");
        }
        observed.push(ip);
    }
    if observed[0] != observed[1] {
        bail!("Independent public-IP services disagree");
    }
    Ok(observed[0])
}

pub fn live_check(ipv6: bool, interface: Result<&str>) -> FamilyStatus {
    std::thread::scope(|scope| {
        let original = scope.spawn(|| interface.and_then(|name| public_ip(ipv6, Some(name))));
        let current = public_ip(ipv6, None);
        let original = original
            .join()
            .unwrap_or_else(|_| Err(anyhow::anyhow!("Direct IP probe thread panicked")));
        FamilyStatus::from_checks(original, current)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comparisons_fail_closed_and_do_not_mix_families() {
        let ip = "8.8.8.8".parse().unwrap();
        assert!(!FamilyStatus::from_checks(Ok(ip), Ok(ip)).changed());
        assert!(FamilyStatus::from_checks(Ok(ip), Ok("1.1.1.1".parse().unwrap())).changed());
        assert!(
            !FamilyStatus::from_checks(Ok(ip), Ok("2001:4860:4860::8888".parse().unwrap()))
                .changed()
        );
        let unknown =
            FamilyStatus::from_checks(Err(anyhow::anyhow!("VPN blocks direct exit")), Ok(ip));
        assert!(!unknown.changed());
        assert!(unknown.original.is_none());
        assert_eq!(unknown.current, Some(ip));
        assert!(unknown.error.unwrap().contains("Original IP unknown"));
        assert!(!FamilyStatus::from_checks(Ok(ip), Err(anyhow::anyhow!("timeout"))).changed());
    }

    #[test]
    fn linux_chooses_lowest_metric_physical_route_and_rejects_ties() {
        let routes =
            r#"[{"dev":"wg0"},{"dev":"enp2s0","metric":100},{"dev":"wlan0","metric":200}]"#;
        assert_eq!(
            linux_candidate(routes, |name| name != "wg0")
                .unwrap()
                .unwrap(),
            "enp2s0"
        );
        assert!(linux_candidate(r#"[{"dev":"en0"},{"dev":"en1"}]"#, |_| true).is_err());
        assert_eq!(linux_candidate("[]", |_| true).unwrap(), None);
        assert!(linux_candidate("invalid", |_| true).is_err());
    }

    #[test]
    fn mac_uses_hardware_ports_and_physical_scoped_routes() {
        let ports = hardware_ports(
            "Hardware Port: Wi-Fi\nDevice: en0\nDevice: utun3\nDevice: bridge0\nDevice: en3\n",
        );
        assert_eq!(ports, ["en0".into(), "en3".into()].into());
        let routes = "Destination Gateway Flags Netif Expire\ndefault link#2 UCSg utun3\ndefault 192.168.1.1 UGScIg en0\n";
        assert_eq!(
            mac_candidate(routes, |name| ports.contains(name))
                .unwrap()
                .unwrap(),
            "en0"
        );
        let routes = format!("{routes}default 10.0.0.1 UGScIg en3\n");
        assert!(mac_candidate(&routes, |name| ports.contains(name)).is_err());
        assert_eq!(
            mac_candidate(&format!("{routes}default 10.0.0.1 UGScg en3\n"), |name| {
                ports.contains(name)
            })
            .unwrap()
            .unwrap(),
            "en3"
        );
    }

    #[test]
    fn interface_names_cannot_be_paths_or_flags() {
        assert!(interface_name("enp2s0").is_ok());
        for bad in ["", "../en0", "-en0", "en0\n", "en0;id"] {
            assert!(interface_name(bad).is_err());
        }
    }

    #[test]
    fn failed_interface_binding_never_falls_back_to_default_route() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let client = probe_client(Some("ab-missing0")).unwrap();
        let error = client
            .get(format!("https://{}", listener.local_addr().unwrap()))
            .send()
            .unwrap_err();
        let error = anyhow::Error::from(error);
        assert!(format!("{error:#}").contains("bind interface"), "{error:#}");
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}
