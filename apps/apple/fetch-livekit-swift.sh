#!/usr/bin/env bash
# The LiveKit Swift SDK, at one pinned commit, with Skwod's own small patch on it:
# apps/apple/Vendor/client-sdk-swift (not committed). `xcodegen generate` runs this first
# (project.yml, preGenCommand); it does nothing when the folder is already right.
#
# Why a patch: a p2p call's media server is on this device's 127.0.0.1 (docs/P2P.md). WebRTC
# ignores the loopback interface unless told otherwise, and binds one socket per other interface;
# on a point-to-point one (cellular, some VPNs) that socket can send to 127.0.0.1 and is never
# answered (docs/APPLE.md, "A call on cellular"). WebRTC has a public option for it; the SDK
# exposes none, so the patch adds one (`LiveKitSDK.setGathersLoopback`). It also drops the SDK's test
# targets and their two dependencies, so what is resolved stays what Package.resolved pins.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

URL=https://github.com/livekit/client-sdk-swift.git
COMMIT=43c1c0870e51eedbfd95b20b1b5c43a767886786   # v2.19.0
PATCH="$PWD/livekit-swift.patch"
DEST=Vendor/client-sdk-swift

want="$COMMIT $(shasum -a 256 "$PATCH" | awk '{print $1}')"
if [ "$(cat "$DEST/.skwod-patched" 2>/dev/null || true)" = "$want" ]; then exit 0; fi

rm -rf "$DEST"
mkdir -p "$DEST"
git -C "$DEST" init -q
git -C "$DEST" fetch -q --depth 1 "${SKWOD_LIVEKIT_SWIFT_GIT:-$URL}" "$COMMIT"
# The commit id is the checksum: git verifies every object against it.
git -C "$DEST" -c advice.detachedHead=false checkout -q FETCH_HEAD
[ "$(git -C "$DEST" rev-parse HEAD)" = "$COMMIT" ] || { echo "client-sdk-swift: not the pinned commit" >&2; exit 1; }
git -C "$DEST" apply --whitespace=nowarn "$PATCH"
rm -rf "$DEST/.git"
printf '%s\n' "$want" >"$DEST/.skwod-patched"
echo "client-sdk-swift: $COMMIT + $(basename "$PATCH")"
