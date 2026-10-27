#!/usr/bin/env bash
# Build this checkout with its pinned toolchain and install without root.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
prefix=${HOME}/.local
if [[ ${1:-} == --help ]]; then
    echo 'Usage: bash scripts/install.sh [--prefix DIRECTORY]'
    echo 'Installs hypgate, hypgate-retain (requires Python 3), and the MIT license.'
    exit 0
fi
if [[ $# -gt 0 ]]; then
    [[ $# == 2 && $1 == --prefix && -n $2 ]] || { echo 'usage: install.sh [--prefix DIRECTORY]' >&2; exit 2; }
    prefix=$2
fi
# Make relative prefixes relative to the caller, not the source checkout.
[[ $prefix == /* ]] || prefix="$PWD/$prefix"
cd "$repo"
cargo build --release --locked --bin hypgate
metadata=$(cargo metadata --locked --no-deps --format-version 1)
# Cargo may have a custom target directory. Python is also used by hypgate-retain.
target_dir=$(printf '%s' "$metadata" | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
install -d "$prefix/bin" "$prefix/share/licenses/hypgate"
work=$(mktemp -d "$prefix/bin/.hypgate-install.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
install -m 755 "$target_dir/release/hypgate" "$work/hypgate"
install -m 755 "$repo/scripts/hypgate-retain" "$work/hypgate-retain"
"$work/hypgate" --version
mv -f "$work/hypgate" "$prefix/bin/hypgate"
mv -f "$work/hypgate-retain" "$prefix/bin/hypgate-retain"
install -m 644 "$repo/LICENSE" "$prefix/share/licenses/hypgate/LICENSE"
printf 'Installed to %s/bin; add that directory to PATH.\n' "$prefix"
