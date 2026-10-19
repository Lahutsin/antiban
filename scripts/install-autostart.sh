#!/bin/bash
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
umask 077

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
[[ $(id -u) != 0 ]] || fail "Run as your desktop user, without sudo. The script requests sudo when needed."
[[ $# -le 1 ]] || fail "Usage: bash scripts/install-autostart.sh [release-binary-directory]"

script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
binary_dir=${1:-"$script_dir/../target/release"}
binary_dir=$(cd -- "$binary_dir" && pwd -P)
for binary in antiban antiban-tray; do
    [[ -f "$binary_dir/$binary" && -x "$binary_dir/$binary" ]] ||
        fail "Missing $binary_dir/$binary. Build first: cargo build --release --features tray"
done
"$binary_dir/antiban-tray" --help | grep -q -- --installed-helper ||
    fail "These binaries are too old. Rebuild with --features tray."

uid=$(id -u)
home=$(cd -- "$HOME" && pwd -P)
[[ "$home" != *$'\n'* ]] || fail "Home directories containing newlines are not supported."
case $(uname -s) in
    Linux)
        platform=linux
        destination=/opt/antiban
        autostart="$home/.config/autostart/antiban.desktop"
        command -v nft >/dev/null || fail "Install nftables first."
        command -v ip >/dev/null || fail "Install iproute2 first."
        ;;
    Darwin)
        platform=macos
        destination=/Library/PrivilegedHelperTools/dev.antiban
        autostart="$home/Library/LaunchAgents/dev.antiban.tray.plist"
        ;;
    *) fail "Only Linux and macOS are supported." ;;
esac
command -v sudo >/dev/null || fail "sudo is required."
command -v visudo >/dev/null || fail "visudo is required."
[[ ! -e "$autostart" && ! -L "$autostart" ]] ||
    fail "Autostart already exists at $autostart. Remove it with uninstall-autostart.sh first."

printf '%s\n' \
    "Installing login autostart for UID $uid ($platform)." \
    "The tray runs as you; only the restricted firewall helper runs as root." \
    "Quit existing Antiban monitors before continuing." \
    "This grants this account passwordless access to the restricted desktop-helper only."

sudo /bin/bash -s -- "$binary_dir" "$destination" "$uid" <<'ROOT'
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
umask 077
source_dir=$1
destination=$2
uid=$3
[[ "$uid" =~ ^[0-9]+$ && "$uid" != 0 ]] || exit 1
account=$(id -nu "$uid")
[[ $(id -u "$account") == "$uid" ]] || {
    echo "Cannot resolve the desktop UID to a local account." >&2; exit 1;
}
case "$destination" in
    /opt/antiban) parent=/opt ;;
    /Library/PrivilegedHelperTools/dev.antiban) parent=/Library/PrivilegedHelperTools ;;
    *) echo "Unexpected installation path" >&2; exit 1 ;;
esac
secure_directory() {
    local path=$1 owner mode
    [[ -d "$path" && ! -L "$path" ]] || {
        echo "Not a regular directory: $path" >&2; exit 1;
    }
    if [[ $(uname -s) == Darwin ]]; then
        owner=$(stat -f %u "$path")
        mode=$(stat -f %Lp "$path")
    else
        owner=$(stat -c %u "$path")
        mode=$(stat -c %a "$path")
    fi
    [[ "$owner" == 0 ]] && (( (8#$mode & 0022) == 0 )) || {
        echo "Directory must be root-owned and not group/other writable: $path" >&2; exit 1;
    }
}
if [[ "$destination" == /opt/antiban ]]; then
    [[ -e /opt || -L /opt ]] || install -d -m 0755 /opt
else
    secure_directory /Library
    [[ -e "$parent" || -L "$parent" ]] || install -d -m 0755 "$parent"
fi
secure_directory "$parent"
[[ ! -e "$destination" && ! -L "$destination" ]] || {
    echo "Installation directory already exists; uninstall first: $destination" >&2; exit 1;
}
[[ -d /etc/sudoers.d && ! -L /etc/sudoers.d ]] || {
    echo "/etc/sudoers.d must exist and not be a symlink" >&2; exit 1;
}
secure_directory /etc/sudoers.d
policy=/etc/sudoers.d/antiban-desktop
[[ ! -e "$policy" && ! -L "$policy" ]] || {
    echo "Sudoers policy already exists; uninstall first: $policy" >&2; exit 1;
}
staged=$(mktemp /etc/sudoers.d/antiban-check.XXXXXX)
complete=false
cleanup() {
    rm -f -- "$staged"
    if [[ "$complete" != true ]]; then
        rm -f -- "$policy" "$destination/antiban" "$destination/antiban-tray" "$destination/.managed"
        rmdir -- "$destination"
    fi
}
trap cleanup EXIT
install -d -m 0755 "$destination"
printf 'antiban-login-v1\n%s\n' "$uid" > "$destination/.managed"
install -m 0755 "$source_dir/antiban" "$destination/antiban"
install -m 0755 "$source_dir/antiban-tray" "$destination/antiban-tray"
printf '# Managed by Antiban login installer; desktop UID %s\n' "$uid" > "$staged"
printf '#%s ALL=(root) NOPASSWD: NOSETENV: %s/antiban desktop-helper --control *\n' \
    "$uid" "$destination" >> "$staged"
chmod 0440 "$staged"
visudo -cf "$staged"
mv -- "$staged" "$policy"
if ! visudo -c; then
    rm -f -- "$policy"
    echo "Invalid sudoers configuration; the new permission was removed." >&2
    exit 1
fi
if ! sudo -l -U "$account" -- "$destination/antiban" desktop-helper --control /tmp/control.sock >/dev/null; then
    rm -f -- "$policy"
    echo "Cannot verify the helper permission for $account; removed only $policy." >&2
    exit 1
fi
complete=true
ROOT

if [[ "$platform" == linux ]]; then
    mkdir -p -- "$home/.config/autostart"
    cat > "$autostart" <<EOF
[Desktop Entry]
Type=Application
Name=Antiban
Comment=Claude/Anthropic external-IP gate
Exec=$destination/antiban-tray --installed-helper
Terminal=false
StartupNotify=false
X-GNOME-Autostart-enabled=true
EOF
else
    mkdir -p -- "$home/Library/LaunchAgents"
    cat > "$autostart" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>dev.antiban.tray</string>
    <key>ProgramArguments</key>
    <array>
        <string>$destination/antiban-tray</string>
        <string>--installed-helper</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>LimitLoadToSessionType</key><string>Aqua</string>
</dict>
</plist>
EOF
    /usr/bin/plutil -lint "$autostart"
fi
chmod 0600 "$autostart"
printf '\nInstalled. Log out and log in to start automatically.\n'
printf 'Start now (as your user, without sudo):\n  %s/antiban-tray --installed-helper\n' "$destination"
if [[ "$platform" == macos ]]; then
    printf 'Configure and enable PF first; see the macOS PF setup section in README.md.\n'
fi
