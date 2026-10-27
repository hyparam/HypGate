#!/usr/bin/env bash
# Compare executable bytes from two uncached builds of the runtime build stage.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
containers=()
images=()
cleanup() {
    for container in ${containers[@]+"${containers[@]}"}; do docker rm -f "$container" >/dev/null 2>&1 || true; done
    for image in ${images[@]+"${images[@]}"}; do docker image rm "$image" >/dev/null 2>&1 || true; done
    rm -rf "$work"
}
trap cleanup EXIT

docker info >/dev/null
for run in 1 2; do
    echo "Building independent linux/amd64 executable $run of 2"
    # No layer reuse: the second build must actually compile again. The pinned
    # base, toolchain, lockfile, architecture, and /src path match deployment.
    docker build --no-cache --platform linux/amd64 --target build \
        --file "$repo/deploy/Dockerfile.runtime" --iidfile "$work/image-$run" "$repo"
    image=$(cat "$work/image-$run")
    images+=("$image")
    container=$(docker create --platform linux/amd64 "$image" /bin/true)
    containers+=("$container")
    docker cp "$container:/src/target/release/hypgate" "$work/hypgate-$run"
done

if ! cmp -s "$work/hypgate-1" "$work/hypgate-2"; then
    echo 'FAIL: independent builds produced different executable bytes' >&2
    shasum -a 256 "$work/hypgate-1" "$work/hypgate-2" >&2
    exit 1
fi
echo 'PASS: independent builds produced identical executable bytes'
shasum -a 256 "$work/hypgate-1"
