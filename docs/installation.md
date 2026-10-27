# Installation

## From a checkout

Requires Unix, Rust through rustup, a C linker, and Python 3 for the installer and
retention tool. The repository pins the Rust toolchain and dependencies.

```sh
git clone https://github.com/hyparam/HypGate.git
cd HypGate
bash scripts/install.sh
export PATH="$HOME/.local/bin:$PATH"
hypgate --version
```

The installer builds a release executable and installs it, `hypgate-retain`, and
the MIT license under `~/.local`. No root access is needed. Use
`bash scripts/install.sh --prefix /some/directory` to choose another location.
Run the installer from the version or commit you intend to deploy; it does not
fetch updates or execute a downloaded installer.

Follow [running the gateway](running.md) to create policy and route files, supply
provider credentials, and choose a fresh audit filename. For an upgrade, drain
the running process, install the new version, and start with a new log file.
Replacing the executable does not restart an existing process.

## Runtime container

The runtime recipe is separate from `deploy/Dockerfile`, which runs validation
and deployment tests. Build your own image from the reviewed checkout:

```sh
docker build --file deploy/Dockerfile.runtime --tag hypgate .
docker run --rm hypgate --version
```

The image runs as UID/GID 10001. Mount configuration read-only and readable by
that UID, provide credentials
through your deployment's secret mechanism, and mount a private writable log
directory owned by that UID. Each start needs a new log filename. The image
contains the binary and license; retention runs on the host against closed logs.

HypGate binds loopback inside the container. Publishing a Docker port does not
make that listener accessible through the container's network interface. On
Linux, use host networking with a TLS proxy on the same host:

```sh
# Provision ./logs as UID/GID 10001, mode 700, before starting.
docker run --rm --network host \
  --mount type=bind,src="$PWD/config.json",dst=/etc/hypgate/config.json,readonly \
  --mount type=bind,src="$PWD/logs",dst=/var/lib/hypgate \
  --env PROVIDER_KEY \
  hypgate /etc/hypgate/config.json /var/lib/hypgate/session-001.log
```

A proxy in the same container network namespace (for example a Kubernetes pod)
can also reach loopback. See [deployment](deployment.md) for TLS and no-replay
proxy settings. Docker Desktop networking differs; the local installer is the
simpler development path on macOS. Use your deployment's image digest when
pinning a built runtime image; this repository does not yet publish images.
