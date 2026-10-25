#!/usr/bin/env bash
# Validate only a freshly created, private 64 MiB ext4 image; never a host device.
set -euo pipefail
[[ "$(uname -s)" == Linux ]] || { echo 'This fixture requires Linux.' >&2; exit 1; }
sudo -n true
fixture=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/loggate-ext4.XXXXXX")
image="$fixture/disk.img"
mounted="$fixture/mount"
cleanup() {
    if mountpoint -q "$mounted"; then sudo umount "$mounted" || return; fi
    rm -rf -- "$fixture"
}
trap cleanup EXIT
mkdir "$mounted"
fallocate -l 64M "$image"
mkfs.ext4 -q -F -m 0 "$image"
sudo mount -o loop,data=ordered,barrier=1 "$image" "$mounted"
sudo chown "$(id -u):$(id -g)" "$mounted"
printf 'loggate-private-ext4-64MiB\n' > "$mounted/.loggate-ext4-fixture"
[[ "$(findmnt -n -o FSTYPE --target "$mounted")" == ext4 ]]
uname -srv
findmnt -n -o FSTYPE,OPTIONS --target "$mounted"
mkfs.ext4 -V
export LOGGATE_STORAGE_TEST_DIR="$mounted"
cargo test -p gateway-runtime --locked --test storage filesystem_full -- --ignored --nocapture --test-threads=1
cargo test -p gateway-runtime --locked --test crash -- --nocapture --test-threads=1
sudo mount -o remount,ro "$mounted"
findmnt -n -o FSTYPE,OPTIONS --target "$mounted"
cargo test -p gateway-runtime --locked --test storage filesystem_read_only -- --ignored --nocapture --test-threads=1
