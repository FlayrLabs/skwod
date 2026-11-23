#!/usr/bin/env bash
# Populate the macOS app's bundled host tools: the skwod server and a pinned LiveKit SFU.
# The Mac app runs both as child processes behind its one "Start server" button
# (Sources/HostManager.swift). The server finds `livekit-server` beside itself and supervises it
# on loopback only (server/src/livekit.rs) — nothing else is bundled, and nothing is fetched at
# run time.
#
# LiveKit publishes no macOS binaries on its GitHub releases, so the pinned artifact is the
# Homebrew bottle for the exact version below: a content-addressed blob (the URL *is* its
# SHA-256), verified again here before anything is unpacked. To bump: change the version and
# both digests together (https://formulae.brew.sh/api/formula/livekit.json → bottle.stable.files,
# urls.stable.checksum). Never point this at a "latest" URL.
#
#   SKWOD_LIVEKIT_FROM_SOURCE=1   build the same pinned tag with the local Go toolchain instead
#                                 (source tarball SHA-256 verified).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/Resources/host-tools"

LIVEKIT_VERSION="1.13.11"
# Homebrew bottle, arm64 macOS 15 build (":any_skip_relocation": a self-contained Go binary).
LIVEKIT_BOTTLE_SHA256="1268330c7264fcc1626f673f5abb8cb1a1691344ac171f1941014c45fe4da214"
LIVEKIT_BOTTLE_URL="https://ghcr.io/v2/homebrew/core/livekit/blobs/sha256:${LIVEKIT_BOTTLE_SHA256}"
# Upstream source tarball for the same tag (used with SKWOD_LIVEKIT_FROM_SOURCE=1).
LIVEKIT_SOURCE_SHA256="c8d9b7ba9d66c8b5f314a438c0c2493815e7e70085e37706b888cab3c4ab8f8d"
LIVEKIT_SOURCE_URL="https://github.com/livekit/livekit/archive/refs/tags/v${LIVEKIT_VERSION}.tar.gz"

if [ "$(uname -m)" != "arm64" ]; then
  echo "error: host tools are bundled for Apple Silicon only (this is $(uname -m))" >&2
  exit 1
fi

sha256_of() { shasum -a 256 "$1" | awk '{print $1}'; }

verify_sha256() { # <file> <expected>
  local got; got="$(sha256_of "$1")"
  if [ "$got" != "$2" ]; then
    echo "error: SHA-256 mismatch for $(basename "$1")" >&2
    echo "  expected $2" >&2
    echo "  got      $got" >&2
    exit 1
  fi
}

mkdir -p "$OUT"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/skwod-host-tools.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# 1) skwod server binary (release)
echo "==> building skwod server (release)"
# The server's default push-gateway allowlist is the host it is BUILT with (server/src/gateway.rs).
# Derive it from the gateway the apps are built for, so a Mac-hosted skwod calls that gateway
# and no other out of the box.
# (SKWOD_PUSH_GATEWAY comes from the environment or the gitignored signing.env, as in upload-ios.sh.)
if [ -z "${SKWOD_PUSH_GATEWAY:-}" ] && [ -z "${SKWOD_DEFAULT_PUSH_GATEWAY:-}" ] && [ -f "$HERE/../../signing.env" ]; then
  SKWOD_PUSH_GATEWAY="$(set +u; . "$HERE/../../signing.env" >/dev/null 2>&1; printf %s "${SKWOD_PUSH_GATEWAY:-}")"
fi
if [ -z "${SKWOD_DEFAULT_PUSH_GATEWAY:-}" ] && [ -n "${SKWOD_PUSH_GATEWAY:-}" ]; then
  SKWOD_DEFAULT_PUSH_GATEWAY="${SKWOD_PUSH_GATEWAY#https://}"; SKWOD_DEFAULT_PUSH_GATEWAY="${SKWOD_DEFAULT_PUSH_GATEWAY%%/*}"
fi
if [ -z "${SKWOD_DEFAULT_PUSH_GATEWAY:-}" ]; then
  # A release must not ship a server that accepts no push registrations by accident; a
  # development build may. (package-release.sh sets SKWOD_RELEASE=1.)
  if [ "${SKWOD_RELEASE:-0}" = 1 ] && [ "${SKWOD_NO_DEFAULT_PUSH_GATEWAY:-0}" != 1 ]; then
    echo "✗ SKWOD_DEFAULT_PUSH_GATEWAY / SKWOD_PUSH_GATEWAY is not set (environment or signing.env): the bundled server would have no push gateway." >&2
    echo "  Set one, or SKWOD_NO_DEFAULT_PUSH_GATEWAY=1 to bundle a server with no built-in gateway on purpose." >&2
    exit 1
  fi
  echo "note: the bundled server has no built-in push-gateway allowlist (the owner's app will choose the host)" >&2
fi
export SKWOD_DEFAULT_PUSH_GATEWAY="${SKWOD_DEFAULT_PUSH_GATEWAY:-}"
( cd "$HERE/../../server" && cargo build --locked --release --bin skwod )
cp "$HERE/../../server/target/release/skwod" "$OUT/skwod-server"

# 2) livekit-server, pinned + verified. Re-fetched only when the stamp doesn't match the pin.
STAMP="$HERE/.host-tools-livekit.stamp"   # outside $OUT: everything in there ships in the app
WANT="${LIVEKIT_VERSION} ${LIVEKIT_BOTTLE_SHA256} ${SKWOD_LIVEKIT_FROM_SOURCE:-0}"
if [ ! -x "$OUT/livekit-server" ] || [ "$(cat "$STAMP" 2>/dev/null || true)" != "$WANT" ]; then
  rm -f "$OUT/livekit-server" "$STAMP"
  if [ "${SKWOD_LIVEKIT_FROM_SOURCE:-0}" = "1" ]; then
    echo "==> building livekit-server v${LIVEKIT_VERSION} from source"
    command -v go >/dev/null || { echo "error: SKWOD_LIVEKIT_FROM_SOURCE=1 needs Go on PATH" >&2; exit 1; }
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
      -o "$WORK/livekit-src.tar.gz" "$LIVEKIT_SOURCE_URL"
    verify_sha256 "$WORK/livekit-src.tar.gz" "$LIVEKIT_SOURCE_SHA256"
    mkdir "$WORK/src"
    tar xzf "$WORK/livekit-src.tar.gz" -C "$WORK/src" --strip-components 1
    ( cd "$WORK/src" && GOFLAGS=-mod=readonly CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" \
        -o "$WORK/livekit-server" ./cmd/server )
  else
    echo "==> fetching livekit-server v${LIVEKIT_VERSION} (pinned bottle, sha256 ${LIVEKIT_BOTTLE_SHA256:0:12}…)"
    # ghcr.io serves public blobs to the anonymous bearer below; the blob is addressed by digest.
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
      -H "Authorization: Bearer QQ==" -o "$WORK/livekit-bottle.tar.gz" "$LIVEKIT_BOTTLE_URL"
    verify_sha256 "$WORK/livekit-bottle.tar.gz" "$LIVEKIT_BOTTLE_SHA256"
    mkdir "$WORK/bottle"
    # Extract exactly one member — never trust the archive's layout beyond that path.
    tar xzf "$WORK/livekit-bottle.tar.gz" -C "$WORK/bottle" "livekit/${LIVEKIT_VERSION}/bin/livekit-server"
    cp "$WORK/bottle/livekit/${LIVEKIT_VERSION}/bin/livekit-server" "$WORK/livekit-server"
  fi
  # The binary must be a plain arm64 Mach-O and report the pinned version.
  file "$WORK/livekit-server" | grep -q "Mach-O 64-bit executable arm64" \
    || { echo "error: livekit-server is not an arm64 Mach-O executable" >&2; exit 1; }
  chmod +x "$WORK/livekit-server"
  "$WORK/livekit-server" --version | grep -q "$LIVEKIT_VERSION" \
    || { echo "error: livekit-server does not report version $LIVEKIT_VERSION" >&2; exit 1; }
  cp "$WORK/livekit-server" "$OUT/livekit-server"
  echo "$WANT" > "$STAMP"
fi

# Anything from an older bundle layout (the Cloudflare tunnel client) must not ship.
rm -f "$OUT/cloudflared"
chmod +x "$OUT/skwod-server" "$OUT/livekit-server"
echo "==> host tools ready: $OUT"
echo "    skwod-server    $(sha256_of "$OUT/skwod-server")"
echo "    livekit-server  $(sha256_of "$OUT/livekit-server")  (v${LIVEKIT_VERSION})"
