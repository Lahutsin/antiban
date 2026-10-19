#!/bin/bash
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
umask 077

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
[[ $(id -u) != 0 ]] || fail "Run as the desktop user who installed Antiban, without sudo."
[[ $# == 0 ]] || fail "Usage: bash scripts/uninstall-autostart.sh"
uid=$(id -u)
home=$(cd -- "$HOME" && pwd -P)
case $(uname -s) in
    Linux)
        destination=/opt/antiban
        autostart="$home/.config/autostart/antiban.desktop"
        ;;
    Darwin)
        destination=/Library/PrivilegedHelperTools/dev.antiban
        autostart="$home/Library/LaunchAgents/dev.antiban.tray.plist"
        ;;
    *) fail "Only Linux and macOS are supported." ;;
esac

printf 'Choose Quit (remove protection) in the Antiban tray before uninstalling.\n'
sudo /bin/bash -s -- "$destination" "$uid" <<'ROOT'
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
destination=$1
uid=$2
case "$destination" in
    /opt/antiban|/Library/PrivilegedHelperTools/dev.antiban) ;;
    *) exit 1 ;;
esac
[[ -d "$destination" && ! -L "$destination" && -f "$destination/.managed" &&
   ! -L "$destination/.managed" ]] || {
    echo "Not a managed Antiban installation; refusing deletion." >&2; exit 1;
}
expected=$(printf 'antiban-login-v1\n%s' "$uid")
[[ $(cat "$destination/.managed") == "$expected" ]] || {
    echo "This installation belongs to another desktop account." >&2; exit 1;
}
policy=/etc/sudoers.d/antiban-desktop
[[ -f "$policy" && ! -L "$policy" ]] &&
    grep -qxF "# Managed by Antiban login installer; desktop UID $uid" "$policy" || {
        echo "Sudoers policy is not managed by this installation; refusing removal." >&2; exit 1;
    }
# The lock prevents removal while a guardian is running; no host rules are flushed.
if ! "$destination/antiban" uninstall --if-present; then
    echo "Could not remove Antiban rules. Quit the running monitor first." >&2
    exit 1
fi
rm -- "$policy"
visudo -c
rm -- "$destination/antiban" "$destination/antiban-tray" "$destination/.managed"
rmdir -- "$destination"
ROOT
if [[ $(uname -s) == Darwin ]]; then
    if /bin/launchctl print "gui/$uid/dev.antiban.tray" >/dev/null 2>&1; then
        /bin/launchctl bootout "gui/$uid/dev.antiban.tray"
    fi
fi
if [[ -e "$autostart" || -L "$autostart" ]]; then
    rm -- "$autostart"
fi
printf 'Antiban login autostart and passwordless permission removed.\n'
