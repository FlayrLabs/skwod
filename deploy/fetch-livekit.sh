#!/usr/bin/env bash
# Download the pinned LiveKit server for one platform, verify its SHA-256, and unpack the
# binary. The version and hashes live in deploy/livekit.lock — nothing is ever "latest".
#
#   deploy/fetch-livekit.sh <linux_amd64|linux_arm64|linux_armv7|windows_amd64|windows_arm64> <out dir>
#
# Used by the Dockerfile and by the host/ packaging scripts. Upstream publishes no macOS
# archive (macOS hosts get LiveKit from the Mac app's own bundle).
set -euo pipefail

PLATFORM="${1:?platform, e.g. linux_amd64}"
OUT="${2:?output directory}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCK="$HERE/livekit.lock"

VERSION="$(sed -n 's/^LIVEKIT_VERSION=//p' "$LOCK")"
EXPECTED="$(sed -n "s/^SHA256_${PLATFORM}=//p" "$LOCK")"
[ -n "$VERSION" ] || { echo "no LIVEKIT_VERSION in $LOCK" >&2; exit 1; }
[ -n "$EXPECTED" ] || { echo "no pinned hash for platform '$PLATFORM' in $LOCK" >&2; exit 1; }

case "$PLATFORM" in
  windows_*) EXT=zip; BIN=livekit-server.exe ;;
  *)         EXT=tar.gz; BIN=livekit-server ;;
esac
ARCHIVE="livekit_${VERSION}_${PLATFORM}.${EXT}"
URL="https://github.com/livekit/livekit/releases/download/v${VERSION}/${ARCHIVE}"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
curl -fsSL --proto '=https' --tlsv1.2 -o "$TMP/$ARCHIVE" "$URL"

if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL="$(sha256sum "$TMP/$ARCHIVE" | awk '{print $1}')"
else
  ACTUAL="$(shasum -a 256 "$TMP/$ARCHIVE" | awk '{print $1}')"
fi
if [ "$ACTUAL" != "$EXPECTED" ]; then
  echo "SHA-256 mismatch for $ARCHIVE" >&2
  echo "  expected $EXPECTED" >&2
  echo "  got      $ACTUAL" >&2
  exit 1
fi

mkdir -p "$OUT"
if [ "$EXT" = zip ]; then
  unzip -q -o "$TMP/$ARCHIVE" "$BIN" -d "$OUT"
else
  tar -xzf "$TMP/$ARCHIVE" -C "$OUT" "$BIN"
fi
chmod 0755 "$OUT/$BIN"
echo "livekit-server $VERSION ($PLATFORM) verified -> $OUT/$BIN"
