# Clean-environment reproduction of the build, tests, proofs, and deployment check.
# Build context is the repository root:
#   docker build --file deploy/Dockerfile --tag loggate-deploy .
#   docker run --rm loggate-deploy
# The base is the official Rust 1.99.1 image on Debian trixie, pinned by digest and
# matching rust-toolchain.toml so no toolchain download occurs. The pinned Verus
# release needs glibc 2.39 or newer and ships only an x86 Linux binary, so proofs
# run on x86_64 and are skipped elsewhere.
FROM rust:1.99.1-slim-trixie@sha256:aab42391a986424e22d6a3ec14f37bc6dd3dacff4d457ca7cccd781e02297cc6
ENV VERUS_RELEASE=0.2026.10.18.7d82994 \
    VERUS_ARCHIVE_SHA256=e9af03732d4bdd32b93a8fcf471706739c24c1473fa5086618d96c47237845dd \
    PATH=/opt/verus/verus-x86-linux:/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl openssl haproxy procps unzip \
    && rm -rf /var/lib/apt/lists/*
RUN if [ "$(uname -m)" = x86_64 ]; then \
        curl --fail --location --retry 3 --output /tmp/verus.zip \
            "https://github.com/verus-lang/verus/releases/download/release/${VERUS_RELEASE}/verus-${VERUS_RELEASE}-x86-linux.zip" \
        && echo "${VERUS_ARCHIVE_SHA256}  /tmp/verus.zip" | sha256sum --check --strict \
        && unzip -q /tmp/verus.zip -d /opt/verus && rm /tmp/verus.zip \
        && /opt/verus/verus-x86-linux/verus --version; \
    else echo "skipping Verus on $(uname -m): no pinned Linux binary for this architecture"; fi
WORKDIR /src
COPY . .
RUN cargo build --release --locked --bin loggate
RUN cargo test --workspace --locked
RUN if command -v verus >/dev/null; then verus crates/gateway-core/src/lib.rs --crate-type lib --triggers-mode silent; fi
CMD ["bash", "scripts/check_deployment.sh"]
