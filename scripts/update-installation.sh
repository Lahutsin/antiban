#!/bin/bash
set -euo pipefail
umask 077

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
[[ $(id -u) != 0 ]] || fail "Run as your desktop user, without sudo."
[[ $# == 0 ]] || fail "Usage: bash scripts/update-installation.sh"
[[ $(uname -s) == Linux ]] || fail "This updater currently supports Linux only."

destination=/opt/antiban
uid=$(id -u)
home=$(cd -- "$HOME" && pwd -P)
script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
repo_dir=$(cd -- "$script_dir/.." && pwd -P)
binary_dir="$repo_dir/target/release"

cargo_bin="${CARGO_HOME:-$HOME/.cargo}/bin"
[[ ! -x "$cargo_bin/cargo" ]] || PATH="$cargo_bin:$PATH"
command -v cargo >/dev/null || fail "Cargo is not installed or is missing from PATH. Install Rust stable and retry."

printf 'Building Antiban release binaries...\n'
cargo build --locked --release --features tray
for binary in antiban antiban-tray; do
    [[ -f "$binary_dir/$binary" && -x "$binary_dir/$binary" ]] ||
        fail "Build did not produce $binary_dir/$binary"
done
"$binary_dir/antiban-tray" --help | grep -q -- --installed-helper ||
    fail "The tray binary does not support installed-helper mode."

export PATH=/usr/bin:/bin:/usr/sbin:/sbin
command -v sudo >/dev/null || fail "sudo is required."
sudo -v

tray_pids() {
    local process pid process_uid executable
    for process in /proc/[0-9]*; do
        [[ -r "$process/status" && -e "$process/exe" ]] || continue
        pid=${process##*/}
        process_uid=$(awk '$1 == "Uid:" { print $2; exit }' "$process/status" 2>/dev/null) || continue
        [[ "$process_uid" == "$uid" ]] || continue
        executable=$(readlink -- "$process/exe" 2>/dev/null) || continue
        if [[ "$executable" == "$destination/antiban-tray" ]]; then
            printf '%s\n' "$pid"
        fi
    done
}

mapfile -t pids < <(tray_pids)
for pid in "${pids[@]}"; do
    if [[ $(readlink -- "/proc/$pid/exe" 2>/dev/null || true) == "$destination/antiban-tray" ]]; then
        kill -TERM "$pid" 2>/dev/null || true
    fi
done
for _ in {1..150}; do
    mapfile -t pids < <(tray_pids)
    ((${#pids[@]} == 0)) && break
    sleep 0.2
done
mapfile -t pids < <(tray_pids)
((${#pids[@]} == 0)) ||
    fail "Antiban did not stop cleanly. No binaries were replaced; check the tray and retry."

printf 'Updating root-owned binaries in %s...\n' "$destination"
sudo /bin/bash -s -- "$uid" "$binary_dir" <<'ROOT'
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
umask 077

uid=$1
source_dir=$2
destination=/opt/antiban
[[ "$uid" =~ ^[0-9]+$ && "$uid" != 0 ]] || {
    echo "Invalid desktop UID." >&2; exit 1;
}
[[ -d "$destination" && ! -L "$destination" &&
   -f "$destination/.managed" && ! -L "$destination/.managed" ]] || {
    echo "Not a managed installation: $destination" >&2; exit 1;
}
expected=$(printf 'antiban-login-v1\n%s' "$uid")
[[ $(cat "$destination/.managed") == "$expected" ]] || {
    echo "This installation belongs to another account or is not managed." >&2; exit 1;
}
[[ $(stat -c %u "$destination") == 0 ]] || {
    echo "Installation directory must be root-owned." >&2; exit 1;
}
for binary in antiban antiban-tray; do
    [[ -f "$destination/$binary" && ! -L "$destination/$binary" &&
       -f "$source_dir/$binary" && ! -L "$source_dir/$binary" ]] || {
        echo "Missing or unsafe binary: $binary" >&2; exit 1;
    }
done

"$destination/antiban" uninstall --if-present
staging=$(mktemp -d "$destination/.update.XXXXXX")
replacing=false
complete=false
cleanup() {
    status=$?
    trap - EXIT
    if [[ "$replacing" == true && "$complete" != true ]]; then
        mv -f -- "$staging/antiban.old" "$destination/antiban" ||
            echo "ERROR: failed to restore the previous antiban binary" >&2
        mv -f -- "$staging/antiban-tray.old" "$destination/antiban-tray" ||
            echo "ERROR: failed to restore the previous antiban-tray binary" >&2
    fi
    rm -rf -- "$staging"
    exit "$status"
}
trap cleanup EXIT

install -o root -g root -m 0755 "$source_dir/antiban" "$staging/antiban.new"
install -o root -g root -m 0755 "$source_dir/antiban-tray" "$staging/antiban-tray.new"
install -o root -g root -m 0755 "$destination/antiban" "$staging/antiban.old"
install -o root -g root -m 0755 "$destination/antiban-tray" "$staging/antiban-tray.old"
replacing=true
mv -f -- "$staging/antiban.new" "$destination/antiban"
mv -f -- "$staging/antiban-tray.new" "$destination/antiban-tray"
complete=true
ROOT

log_dir="$home/.local/state/antiban"
mkdir -p -- "$log_dir"
chmod 0700 "$log_dir"
log_file="$log_dir/update.log"
nohup "$destination/antiban-tray" --installed-helper >>"$log_file" 2>&1 </dev/null &
tray_pid=$!
sleep 1
if ! kill -0 "$tray_pid" 2>/dev/null; then
    wait "$tray_pid" || true
    fail "Updated binaries were installed, but the tray did not stay running. See $log_file"
fi
printf 'Antiban updated and started. Startup output: %s\n' "$log_file"
