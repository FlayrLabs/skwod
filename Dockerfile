# skwod — ONE image: the server (single Rust binary, ADR-005) + a pinned LiveKit SFU
# the server supervises on loopback (server/src/livekit.rs). Voice/video work through the p2p
# tunnel with nothing to configure and nothing extra exposed.
#
# Migrations are embedded at compile time via sqlx::migrate!. The server stores only ciphertext +
# public keys on its /data volume. Both bases are pinned by digest (resolved from the Docker Hub
# registry API; re-pin by re-resolving, never by editing the hash). LiveKit is pinned by version
# AND per-architecture SHA-256 in deploy/livekit.lock.

# The compiler version is pinned by server/rust-toolchain.toml (1.93.1 — libsignal's MSRV); the
# image's rustup fetches exactly that toolchain on first use, whatever 1.x this digest carries.
# rust:1-trixie
FROM rust:1-trixie@sha256:6ff07edce8775d0f64be7aba9197229407301bddf2054d62c27b541a6238a181 AS builder
# libsignal-protocol compiles its protobuf definitions at build time and needs `protoc`.
# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
# Copy the whole workspace: server/ depends on core/skwod-crypto via a path dependency.
COPY core ./core
COPY server ./server
# init.rs embeds the deploy bundle via include_str!("../../deploy/docker-compose.yml").
COPY deploy ./deploy
# --locked: build exactly what Cargo.lock pins; fail rather than re-resolve a dependency.
# The publisher's push-gateway host, baked in as the default allowlist (server/src/gateway.rs):
#   docker build --build-arg SKWOD_DEFAULT_PUSH_GATEWAY=push.example.org .
# Empty = no built-in list (the operator sets SKWOD_PUSH_GATEWAYS, or the owner's app decides).
ARG SKWOD_DEFAULT_PUSH_GATEWAY=""
ENV SKWOD_DEFAULT_PUSH_GATEWAY=${SKWOD_DEFAULT_PUSH_GATEWAY}
RUN cargo build --release --locked --manifest-path server/Cargo.toml

# LiveKit: download the pinned release for this architecture and verify it before use.
FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f AS livekit
# BuildKit sets TARGETARCH; the classic builder (`docker build` without buildx — still what
# several NAS boxes ship) leaves it empty, so fall back to the stage's own architecture.
ARG TARGETARCH
# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY deploy/livekit.lock deploy/fetch-livekit.sh /lk/
RUN case "${TARGETARCH:-$(dpkg --print-architecture)}" in \
      amd64) p=linux_amd64 ;; \
      arm64) p=linux_arm64 ;; \
      arm|armhf) p=linux_armv7 ;; \
      *) echo "no pinned LiveKit build for ${TARGETARCH:-$(dpkg --print-architecture)}" >&2; exit 1 ;; \
    esac \
    && /lk/fetch-livekit.sh "$p" /out

# debian:trixie-slim
FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
# ca-certificates only: nothing shells out at runtime (a hardened image is not a toolbox — the
# healthcheck and the volume-ownership fix are subcommands of the binary). Numeric non-root
# user so the kubelet can verify runAsNonRoot.
# hadolint ignore=DL3008,DL3005
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 1000 --create-home skwod \
    && mkdir -p /data && chown skwod:skwod /data
COPY --from=builder /build/server/target/release/skwod /usr/local/bin/skwod
# Found by the server next to its own binary; bound to 127.0.0.1 only, never published.
COPY --from=livekit /out/livekit-server /usr/local/bin/livekit-server
# Who the server runs as when a platform has to start the container as root (see below).
ENV SKWOD_RUN_AS=1000:1000 \
    SKWOD_DATA=/data \
    SKWOD_LISTEN=0.0.0.0:3000
USER 1000
VOLUME /data
# 3000  the API (plain HTTP — publish it only behind a TLS reverse proxy; p2p hosts never do)
# 3477  the host admin page, when SKWOD_ADMIN_LISTEN=0.0.0.0:3477 (LAN only, one-time token)
EXPOSE 3000 3477
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD ["skwod", "healthcheck"]
# Run it hardened: --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges.
# Writable paths: /data (SQLite + encrypted blobs + keys + generated livekit.yaml) and /tmp.
#
# VOLUME OWNERSHIP. The server is uid 1000. A volume written by an older (root) image, or a
# host folder Docker created (root:root — the norm on Unraid/Synology), cannot be opened by it.
# Either run once:  docker run --rm --user 0 --cap-drop ALL --cap-add CHOWN -v <vol>:/data
#                   <image> skwod fix-ownership --data /data
# (deploy/docker-compose.yml does this in an init service), or start the container itself as
# root with exactly CHOWN+SETUID+SETGID: the binary then fixes the volume and switches to
# SKWOD_RUN_AS before it opens a socket (deploy/unraid/skwod.xml). See server/src/privs.rs.
#
# `run` applies embedded migrations on boot. For a home/NAS host set
#   SKWOD_ADMIN_LISTEN=0.0.0.0:3477  SKWOD_WAIT_FOR_START=true
# and open http://<host>:3477: the one-time admin token is printed in this container's log.
# Without those, a FRESH volume is initialized at boot and the one-time join code (+ p2p invite)
# is printed to stdout, as before. The p2p endpoint (docs/P2P.md) needs outbound UDP;
# SKWOD_NO_P2P=true turns it off.
CMD ["skwod", "run"]
