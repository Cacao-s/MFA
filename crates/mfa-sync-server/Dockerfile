# Build:  docker build -f crates/mfa-sync-server/Dockerfile -t mfa-sync-server .
# Run:    docker run -p 8787:8787 -v mfa-sync:/data \
#           -e MFA_SYNC_TOKEN="$(openssl rand -hex 32)" mfa-sync-server
#
# Context is the repository root, because the server shares the workspace.

FROM rust:1-slim-bookworm AS build
WORKDIR /src

# Dependencies first, so a code change does not rebuild the world. Every
# workspace member's manifest has to be here, including the ones this image
# does not build: cargo refuses to load a workspace with a missing member.
COPY Cargo.toml Cargo.lock ./
COPY crates/mfa-core/Cargo.toml crates/mfa-core/
COPY crates/mfa-ffi/Cargo.toml crates/mfa-ffi/
COPY crates/mfa-sync-server/Cargo.toml crates/mfa-sync-server/
RUN mkdir -p crates/mfa-core/src crates/mfa-ffi/src/bin crates/mfa-sync-server/src \
 && echo '' > crates/mfa-core/src/lib.rs \
 && echo '' > crates/mfa-ffi/src/lib.rs \
 && echo 'fn main() {}' > crates/mfa-ffi/src/bin/uniffi-bindgen.rs \
 && echo 'fn main() {}' > crates/mfa-sync-server/src/main.rs \
 && cargo build --release -p mfa-sync-server \
 && rm -r crates/mfa-core/src crates/mfa-ffi/src crates/mfa-sync-server/src

COPY crates/ crates/
# Cargo skips a rebuild when mtimes look unchanged; touch the real sources.
RUN touch crates/mfa-core/src/lib.rs crates/mfa-sync-server/src/main.rs \
 && cargo build --release -p mfa-sync-server

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home /data mfa \
 && mkdir -p /data && chown mfa:mfa /data

COPY --from=build /src/target/release/mfa-sync-server /usr/local/bin/

USER mfa
WORKDIR /data
VOLUME ["/data"]

ENV MFA_SYNC_DATA=/data \
    MFA_SYNC_ADDR=0.0.0.0:8787
EXPOSE 8787

# MFA_SYNC_TOKEN has no default on purpose: the server refuses to start
# without one, which is better than running with a guessable token.
ENTRYPOINT ["mfa-sync-server"]
