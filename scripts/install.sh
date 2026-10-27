#!/usr/bin/env bash
# Build this checkout with its pinned toolchain and install without root.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
prefix=${HOME}/.local
if [[ ${1:-} == --help ]]; then
    echo 'Usage: bash scripts/install.sh [--prefix DIRECTORY]'
    echo 'Installs loggate, loggate-retain (requires Python 3), and the MIT license.'
    exit 0
fi
if [[ $# -gt 0 ]]; then
    [[ $# == 2 && $1 == --prefix && -n $2 ]] || { echo 'usage: install.sh [--prefix DIRECTORY]' >&2; exit 2; }
    prefix=$2
fi
# Make relative prefixes relative to the caller, not the source checkout.
[[ $prefix == /* ]] || prefix="$PWD/$prefix"
cd "$repo"
cargo build --release --locked --bin loggate
metadata=$(cargo metadata --locked --no-deps --format-version 1)
# Cargo may have a custom target directory. Python is also used by loggate-retain.
target_dir=$(printf '%s' "$metadata" | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
install -d "$prefix/bin" "$prefix/share/licenses/loggate"
work=$(mktemp -d "$prefix/bin/.loggate-install.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
install -m 755 "$target_dir/release/loggate" "$work/loggate"
install -m 755 "$repo/scripts/loggate-retain" "$work/loggate-retain"
"$work/loggate" --version
mv -f "$work/loggate" "$prefix/bin/loggate"
mv -f "$work/loggate-retain" "$prefix/bin/loggate-retain"
install -m 644 "$repo/LICENSE" "$prefix/share/licenses/loggate/LICENSE"
printf 'Installed to %s/bin; add that directory to PATH.\n' "$prefix"
