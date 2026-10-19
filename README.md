# Antiban

A Rust IP gate for Linux and macOS, with a command-line monitor and a system tray
app. Known Claude/Anthropic destination IPs are allowed only when the public
address differs from the original address measured directly through the physical
network interface. A VPN is optional: any public-IP change counts.

**This is a best-effort IP filter, not a leak-proof kill switch or ban protection.**
Read [Limitations](#limitations) before relying on it.

## Build

Install the current stable Rust toolchain, then run:

```sh
cd /path/to/antiban
cargo build --release --features tray
```

This produces two binaries:

- `target/release/antiban`: baseline capture and privileged firewall monitor.
- `target/release/antiban-tray`: unprivileged tray app.

Keep both binaries in the same directory. Build on each OS separately; a Linux
binary does not run on macOS. For a CLI-only build, omit `--features tray`.

### Linux requirements

- `nft` (nftables), `ip` (iproute2), and root access.
- OpenSSL development headers and `pkg-config` when building on Linux; the
  resulting binary uses the system OpenSSL libraries and trusted certificates.
- A desktop session with D-Bus and a StatusNotifierItem/AppIndicator tray host.
  GNOME generally needs the AppIndicator/KStatusNotifierItem extension.
- `pkexec` (polkit) and a running desktop authentication agent for manual tray
  mode, or `sudo`/`visudo` for the optional passwordless login installation.
  The tray uses D-Bus directly; GTK development libraries are not required.

### macOS requirements

- The built-in `pfctl`, `osascript`, `networksetup`, `netstat`, and `ifconfig`,
  plus administrator access. HTTPS uses the native system TLS implementation.
- A configured, enabled PF firewall; see [macOS PF setup](#macos-pf-setup).

## Automatic original-IP detection

No saved baseline or VPN-off setup is required in the default mode.
On each check, Antiban compares:

1. **Original IP:** an HTTPS probe with the socket bound to the physical
   Ethernet/Wi-Fi interface, intentionally attempting a direct exit outside VPN.
2. **Current IP:** an HTTPS probe using the normal system route.

Both paths must independently receive matching answers from two IP services.
IPv4 and IPv6 are checked separately. An unknown original/current address,
a failed direct exit, or an unchanged address never authorizes that family.
There is no automatic fallback to a saved baseline or an unbound socket.

Linux uses `SO_BINDTODEVICE`; macOS uses `IP_BOUND_IF`/`IPV6_BOUND_IF`.
Antiban does not change global routes or disable your VPN. These direct probes
are intentional traffic outside the VPN, including while the VPN is enabled.

The physical interface is selected from active hardware interfaces with default
routes (Linux prefers the lowest route metric; macOS prefers an unscoped route).
Ambiguous routes are blocked until you select the interface explicitly:

```sh
# Linux example:
./target/release/antiban-tray --direct-interface enp2s0
# macOS example:
./target/release/antiban-tray --direct-interface en0
```

Hardware-backed Ethernet/Wi-Fi interfaces are supported; tunnel, loopback,
bridge, and other purely virtual interfaces are not accepted as direct exits.

### Can I start the app with my VPN already enabled?

**Yes.** The default mode tries to measure the direct original address even if
the VPN was enabled before startup. If the VPN kill switch or routing policy
forbids the direct connection, the original IP cannot be discovered this way.
The tray shows **Original IP unknown - BLOCKED**, rather than guessing.

## Run in the tray

Start this as your **normal desktop user, without sudo**:

```sh
./target/release/antiban-tray
```

Authorize the firewall helper when prompted:

- Linux uses the desktop polkit authentication dialog.
- macOS uses the native administrator authorization dialog.

The tray itself does not run as root. It communicates with the helper through
a Unix socket in a private, permission-restricted temporary directory.

### Tray indicator and menu

The artwork from `icon/icon.png` is embedded in the tray binary on both Linux
and macOS, so no external image file is needed at runtime. Its aspect ratio
is preserved. A small colored badge in the bottom-right corner shows the
connection state without replacing the artwork. Rebuild after changing the PNG.

| Color | Meaning |
|-------|---------|
| Gray | Starting / waiting for authorization |
| Red | Both families blocked, or an error; read the menu status |
| Amber | One family allowed, the other blocked |
| Green | Both IPv4 and IPv6 allowed |

The menu explicitly shows:

- **IP changed - OK to use** when at least one verified family is allowed.
- **IP unchanged - BLOCKED** when the original and current address match.
- **Original IP unknown - BLOCKED** when the direct original cannot be measured.
- **Current IP unknown - BLOCKED** or **Network check failed - BLOCKED** for
  other failed checks.

Separate menu rows show the original and current IPv4/IPv6 addresses, whether
each family changed, its actual permission, and the direct interface/errors.
Amber is normal when IPv4 changed but IPv6 is unavailable or unchanged:
IPv6 stays blocked. "OK to use" only refers to the verified allowed families
and known destination IPs, not a no-leak guarantee.
A blocked state with zero known IPs does not cover undiscovered IPs.

Choose **Quit (remove protection)** to:

1. Stop the monitor and its guardian.
2. Remove Antiban's firewall rules.
3. Close the tray app after cleanup is acknowledged and the helper exits.

This intentionally leaves Claude/Anthropic **unprotected after Quit**, as
requested. Your baseline file is preserved. Cleanup may wait for an ongoing
network probe. If authorization or cleanup fails, the tray displays an error;
rules may remain. Stop remaining monitors and use the manual uninstall command
below. An unexpected tray crash/disconnection is not treated as an authorized
request to remove the firewall rules.

An optional login installer is provided below. There is no macOS `.app` bundle.

## Start automatically at desktop login (Linux and macOS)

Build the binaries **on the target OS**, then run the installer as the desktop
user, **not with sudo**:

```sh
cargo build --release --features tray
bash scripts/install-autostart.sh
```

The installer requests administrator authorization once. It copies both
binaries into a root-owned, non-user-writable directory and adds:

| OS | Installed binaries | Login entry |
|----|--------------------|-------------|
| Linux | `/opt/antiban/` | `~/.config/autostart/antiban.desktop` |
| macOS | `/Library/PrivilegedHelperTools/dev.antiban/` | `~/Library/LaunchAgents/dev.antiban.tray.plist` |

Log out and back in. The tray starts in the graphical desktop as your normal
user; it launches the restricted root helper automatically via `sudo -n`,
without another password prompt. Linux waits up to 60 seconds for the tray host
to become available. A desktop with no StatusNotifier/AppIndicator support
still needs that support installed/enabled.

To start immediately instead of logging out:

```sh
# Linux:
/opt/antiban/antiban-tray --installed-helper
# macOS:
/Library/PrivilegedHelperTools/dev.antiban/antiban-tray --installed-helper
```

Do not start another tray if one is already running. macOS still requires the
manual [PF setup](#macos-pf-setup); the installer does not change or enable PF.

**Privilege scope:** `/etc/sudoers.d/antiban-desktop` grants only this desktop
UID passwordless execution of the installed binary's `desktop-helper`
subcommand. It does not grant a root shell or arbitrary commands. That
subcommand accepts only a control socket owned by the invoking UID in its
private 0700 directory. It runs automatic original-IP detection with default
domains/interval; arbitrary baseline paths and custom monitor options are not
accepted in installed mode. Anyone controlling this desktop account can start
or stop this limited firewall gate, but cannot use this grant for other root
operations. Root-owned binaries must never be replaced with user-writable ones.
The installer validates sudoers with `visudo` and checks that the permission
is effective. Installations for multiple desktop accounts are not supported.

This is **login autostart, not boot-time protection**. Before graphical login,
no Antiban monitor or new firewall policy is installed. There is no restart
loop: **Quit (remove protection)** closes the application for the rest of that
login session; the next login starts it again. A crash leaves known destinations
blocked as described under Limitations.

To install binaries from another build directory:

```sh
bash scripts/install-autostart.sh /absolute/path/to/release
```

To remove login autostart, the passwordless grant, installed binaries, and
Antiban's firewall rules:

1. Choose **Quit (remove protection)** in the tray first.
2. As the same desktop account, run:

   ```sh
   bash scripts/uninstall-autostart.sh
   ```

The uninstaller requests administrator authorization and refuses to remove a
running guardian or another account's installation. It does not remove the
baseline file, disable PF, or edit the main PF configuration. To update an
installation, uninstall, rebuild, and install again. These scripts are opt-in;
building the project does not modify system startup or sudoers.

## Run from the terminal instead

```sh
sudo ./target/release/antiban run
```

The original public IP blocks known protected destinations. A different public
IP allows that address family. DNS/IP-check failures or disagreement between
the two independent IP services block the affected known destinations.

Add exact hostnames, or change the pause between checks:

```sh
sudo ./target/release/antiban run --direct-interface enp2s0 \
  --interval 2 --domain additional.example.com
```

The tray accepts the same `--direct-interface`, `--interval`, and repeatable `--domain` options.
Wildcards are not supported.

Unlike tray Quit, **Ctrl+C in CLI monitor mode leaves known destinations
blocked**. To remove protection, stop the monitor, wait for its guardian to
exit, and run:

```sh
sudo ./target/release/antiban uninstall
```

Concurrent guardians and uninstall are prevented by a file lock at
`/var/run/antiban.lock`. Do not manually delete this lock file.

## Optional saved-baseline mode

The earlier manual workflow is still available explicitly. Passing `--state`
opts out of automatic direct probing and compares against that saved file
instead; do not pass it if you want live original-IP discovery.
`--state` and `--direct-interface` cannot be combined.

First, with the VPN **OFF**, record the original address:

```sh
sudo ./target/release/antiban baseline --state /etc/antiban-baseline.txt
# Add --ipv6 only if the original connection has working IPv6.
```

Then use that file explicitly:

```sh
./target/release/antiban-tray --state /etc/antiban-baseline.txt
# Or:
sudo ./target/release/antiban run --state /etc/antiban-baseline.txt
```

The file is never overwritten automatically. It must remain a root-owned
regular file not writable by other users. Without `baseline --ipv6`, protected
IPv6 stays blocked in saved-baseline mode. Never capture a manual baseline
while the VPN is enabled. Failed automatic checks never fall back to this mode.

## macOS PF setup

Antiban does not overwrite the main PF configuration or enable/disable PF.
Configure it once before running the monitor or tray:

1. Back up `/etc/pf.conf`.
2. Add `anchor "antiban"` as the **first filter rule**, before other
   `anchor`/`pass`/`block` rules. Keep options, normalization, and translation
   sections before filter rules, as required by PF.
3. Validate and load your configuration:

   ```sh
   sudo pfctl -nf /etc/pf.conf
   sudo pfctl -f /etc/pf.conf
   ```

4. If PF is disabled, enable it:

   ```sh
   sudo pfctl -E
   ```

Reloading PF affects the system firewall. Coordinate with existing network
tools; do not blindly use `pfctl -d`, which disables system-wide protection.
Interfaces excluded with `set skip` are not filtered.

Antiban only updates its own `antiban` anchor. It removes states for blocked
destinations because PF checks established states before evaluating rules.
Tray Quit empties this anchor; it does not disable PF or edit `/etc/pf.conf`.

On Linux, Antiban owns only `table inet antiban`, uses transactional updates,
and filters local outgoing packets, including established connections.
Container/forwarded traffic is not covered.

## Limitations

- This is destination-IP filtering, not application identity filtering.
  Shared CDN IPs may also block unrelated sites. Other destinations are not
  deliberately filtered.
- Only addresses returned by system DNS for listed exact hostnames are covered.
  Subdomains are not discovered automatically. Application DNS/DoH, cached or
  undiscovered addresses, proxies, AWS Bedrock, Google Vertex, third-party
  gateways, and new domains can bypass this filter.
- There is an exposure window between an IP/route change and the next check.
  `--interval` is the pause **after** checks, not a maximum detection time.
  Allowed connections are not deliberately interrupted between successful checks.
- IPv4 and IPv6 are evaluated separately. HTTP proxies are bypassed when
  measuring public IP. Split tunneling and policy routing can make the route
  to Anthropic differ from the route to the IP-check services.
- Interface binding attempts a direct exit but cannot recover an address
  hidden by the upstream router, a remote tunnel, an enforced VPN kill switch,
  or transparent network interception. If the direct path is intercepted and
  returns the same VPN IP, access is blocked as unchanged. Automatic mode
  compares the current physical exit, not a historical ISP address.
- Public addresses are checked over HTTPS with `api4.ipify.org` /
  `api6.ipify.org` and `ipv4.icanhazip.com` / `ipv6.icanhazip.com`.
  Those services see both your direct and normal-route public addresses.
  HTTPS probes use fresh interface-bound sockets and the system TLS trust store;
  curl configuration is not used.
- In saved-baseline mode only, an ISP address change also counts as a change.
  An incorrectly captured baseline makes that mode's decision incorrect.
  To replace it, separately remove the old file and capture again with
  substitution off.
- The guardian blocks known destinations after a 30-second heartbeat timeout.
  Linux also expires permissions in the kernel after 30 seconds without
  renewal. On macOS, forcibly killing **both** privileged processes while
  access is allowed can leave an allowed state behind.
- Root processes, firewall resets, reboot, and starting applications before
  destination discovery can bypass protection. Known addresses accumulate only
  during the current monitoring session. This is not a persistent boot policy.
- The names `inet antiban` and PF anchor `antiban` are reserved for this app.

A strict no-leak guarantee requires an isolated application network with a
single verified exit, not periodically comparing public IP addresses.

## Development checks

```sh
cargo fmt --check
cargo test --features tray
cargo clippy --features tray --all-targets -- -D warnings
bash -n scripts/install-autostart.sh scripts/uninstall-autostart.sh
shellcheck scripts/install-autostart.sh scripts/uninstall-autostart.sh
```

The ignored Linux kernel test requires `unshare`, `ip`, `nft`, and enabled
unprivileged user namespaces. It uses a private network namespace, not the
host firewall, and verifies IPv4/IPv6 blocking, established TCP, unrelated
traffic, uninstall, and the actual 30-second kernel permission expiry:

```sh
ANTIBAN_TEST_HOST_NETNS="$(readlink /proc/self/ns/net)" \
  unshare --user --map-root-user --net \
  cargo test linux_kernel_gate_and_lease_in_private_namespace -- --ignored
```

The tray shutdown integration test additionally mounts a private `/var/run`.
It checks that explicit Quit removes rules, an unexpected control disconnect
keeps the block, both privileged processes exit, and startup preserves the
recorded baseline. It also checks that automatic mode starts without a baseline
and keeps both families blocked when no physical exit is available, removal is
idempotent with `--if-present`, and the live-guardian lock cannot be bypassed:

```sh
ANTIBAN_TEST_HOST_NETNS="$(readlink /proc/self/ns/net)" \
ANTIBAN_TEST_HOST_MNTNS="$(readlink /proc/self/ns/mnt)" \
  unshare --user --map-root-user --net --mount --propagation private \
  cargo test --features tray --test tray_shutdown -- --ignored
```

Real external-network switching and PF still require dedicated Linux/macOS
test machines. Do not modify a shared machine's firewall just to run tests.
