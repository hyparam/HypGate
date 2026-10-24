# Clean-environment reproduction of the build, tests, proofs, and deployment check.
# Build context is the repository root:
#   docker build --file deploy/Dockerfile --tag soundgate-deploy .
#   docker run --rm soundgate-deploy
# The base is the official Rust 1.99.1 image, pinned by digest, matching
# rust-toolchain.toml so no toolchain download occurs. Verus proofs run on x86_64
# because the pinned Verus release ships only an x86 Linux binary.
FROM rust:1.99.1-slim-bookworm@sha256:86234e857a413004348b471d11a4ebe1aa92d2eae2b6b143cac68fd1ac3c48be
ENV VERUS_RELEASE=0.2026.10.18.7d82994 \
    VERUS_ARCHIVE_SHA256=e9af03732d4bdd32b93a8fcf471706739c24c1473fa5086618d96c47237845dd
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl openssl haproxy procps unzip \
    && rm -rf /var/lib/apt/lists/*
RUN if [ "$(uname -m)" = x86_64 ]; then \
        curl --fail --location --retry 3 --output /tmp/verus.zip \
            "https://github.com/verus-lang/verus/releases/download/release/${VERUS_RELEASE}/verus-${VERUS_RELEASE}-x86-linux.zip" \
        && echo "${VERUS_ARCHIVE_SHA256}  /tmp/verus.zip" | sha256sum --check --strict \
        && unzip -q /tmp/verus.zip -d /opt/verus && rm /tmp/verus.zip \
        && ln -s /opt/verus/verus-x86-linux/verus /opt/verus/verus-x86-linux/cargo-verus /usr/local/bin/ \
        && verus --version; \
    else echo "skipping Verus on $(uname -m): no pinned Linux binary for this architecture"; fi
WORKDIR /src
COPY . .
RUN cargo build --release --locked --bin soundgate
RUN cargo test --workspace --locked
RUN if command -v verus >/dev/null; then cargo verus verify -p gateway-core --locked -- --triggers-mode silent; fi
CMD ["bash", "scripts/check_deployment.sh"]
