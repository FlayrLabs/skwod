#!/usr/bin/env bash
# Build the desktop host packages. Runs on Debian/Ubuntu (or in the container docker-build.sh
# starts) with a Rust toolchain installed; needs network access for crates and for the pinned
# LiveKit download (deploy/fetch-livekit.sh verifies its SHA-256).
#
#   host/packaging/build.sh linux   [out dir]   ->  skwod-host_<ver>_<arch>.deb + .tar.gz
#   host/packaging/build.sh windows [out dir]   ->  skwod-host-setup-<ver>-x64.exe (+ .zip)
#
# STATUS: the app itself is compiled, linted and tested (see docs/SELF-HOSTING.md); THIS SCRIPT
# has not been run end to end yet. Treat the first run as its test.
#
# linux:   build on the OLDEST distro you want to support (a binary runs on the glibc it was
#          built against and newer). Debian 12 "bookworm" (glibc 2.36) covers Debian 12+ and
#          Ubuntu 24.04+; build on Ubuntu 22.04 to cover that too.
# windows: cross-compiled with mingw-w64 (x86_64-pc-windows-gnu); the installer is NSIS.
set -euo pipefail

WHAT="${1:?linux|windows}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NATIVE="$(cd "$HERE/../.." && pwd)"
OUT="$(mkdir -p "${2:-$NATIVE/host/dist}" && cd "${2:-$NATIVE/host/dist}" && pwd)"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$NATIVE/host/Cargo.toml" | head -1)"
# Build outside the source tree when asked (a read-only or slow bind mount).
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$NATIVE/host/target/package}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

apt_install() {
  if [ "$(id -u)" = 0 ]; then
    apt-get update -q
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends "$@"
  else
    echo "missing build dependencies; install: $*" >&2
    exit 1
  fi
}

need() { # need <command> <apt packages…>
  command -v "$1" >/dev/null 2>&1 || apt_install "${@:2}"
}

# The server only calls push gateways on its allowlist, and its default allowlist is the host it
# is BUILT with (server/src/gateway.rs, RELEASE-SIGNING.md). A package built without one accepts
# no member's push registration until the owner's own app picks a host — never ship that by
# accident: name the host, or say explicitly that this build has none.
if [ -z "${SKWOD_DEFAULT_PUSH_GATEWAY:-}" ] && [ -n "${SKWOD_PUSH_GATEWAY:-}" ]; then
  SKWOD_DEFAULT_PUSH_GATEWAY="${SKWOD_PUSH_GATEWAY#https://}"
  SKWOD_DEFAULT_PUSH_GATEWAY="${SKWOD_DEFAULT_PUSH_GATEWAY%%/*}"
fi
if [ -z "${SKWOD_DEFAULT_PUSH_GATEWAY:-}" ] && [ "${SKWOD_NO_DEFAULT_PUSH_GATEWAY:-0}" != 1 ]; then
  echo "✗ SKWOD_DEFAULT_PUSH_GATEWAY is not set (the publisher's push-gateway host, e.g. push.example.org)." >&2
  echo "  Set it, or SKWOD_NO_DEFAULT_PUSH_GATEWAY=1 to build a server with no built-in gateway on purpose." >&2
  exit 1
fi
export SKWOD_DEFAULT_PUSH_GATEWAY="${SKWOD_DEFAULT_PUSH_GATEWAY:-}"

build() { # build <manifest dir> [cargo args…]
  (cd "$NATIVE/$1" && cargo build --release --locked "${@:2}")
}

case "$WHAT" in
  linux)
    need protoc protobuf-compiler
    pkg-config --exists gtk+-3.0 ayatana-appindicator3-0.1 2>/dev/null \
      || apt_install pkg-config libgtk-3-dev libayatana-appindicator3-dev
    need curl curl ca-certificates
    need dpkg-deb dpkg-dev
    ARCH="$(dpkg --print-architecture)"
    case "$ARCH" in
      amd64) LK=linux_amd64 ;;
      arm64) LK=linux_arm64 ;;
      armhf) LK=linux_armv7 ;;
      *) echo "no pinned LiveKit build for $ARCH" >&2; exit 1 ;;
    esac
    build server
    build host

    ROOT="$STAGE/root"
    APP="$ROOT/opt/skwod-host"
    install -d "$APP" "$ROOT/usr/bin" "$ROOT/usr/share/applications" \
      "$ROOT/usr/share/icons/hicolor/256x256/apps" "$ROOT/usr/share/doc/skwod-host" "$ROOT/DEBIAN"
    install -m 0755 "$CARGO_TARGET_DIR/release/skwod-host" "$CARGO_TARGET_DIR/release/skwod" "$APP/"
    "$NATIVE/deploy/fetch-livekit.sh" "$LK" "$APP"
    ln -s /opt/skwod-host/skwod-host "$ROOT/usr/bin/skwod-host"
    install -m 0644 "$HERE/linux/skwod-host.desktop" "$ROOT/usr/share/applications/"
    install -m 0644 "$NATIVE/host/assets/icon-256.png" "$ROOT/usr/share/icons/hicolor/256x256/apps/skwod-host.png"
    install -m 0644 "$NATIVE/LICENSE" "$ROOT/usr/share/doc/skwod-host/copyright"
    install -m 0644 "$NATIVE/THIRD-PARTY-NOTICES.md" "$ROOT/usr/share/doc/skwod-host/"
    cat > "$ROOT/DEBIAN/control" <<CONTROL
Package: skwod-host
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: skwod <noreply@skwod.invalid>
Section: net
Priority: optional
Depends: libc6, libgtk-3-0 | libgtk-3-0t64, libayatana-appindicator3-1 | libappindicator3-1, xdg-utils, ca-certificates
Homepage: https://github.com/FlayrLabs/skwod
Description: Host your own skwod server from the system tray
 Private, end-to-end-encrypted group chat with voice and video for you and
 your friends. This package runs the server on your PC: a tray icon with
 Start, Stop and Quit, and a page with the invite to send to your friends.
 Includes the skwod server and a pinned LiveKit server (voice/video, bound
 to this computer only).
CONTROL
    DEB="$OUT/skwod-host_${VERSION}_${ARCH}.deb"
    dpkg-deb --build --root-owner-group "$ROOT" "$DEB"
    # The same three programs for distros without dpkg: unpack anywhere, run ./skwod-host.
    tar -C "$ROOT/opt" -czf "$OUT/skwod-host_${VERSION}_linux_${ARCH}.tar.gz" skwod-host
    echo "built: $DEB"
    ;;

  windows)
    TARGET=x86_64-pc-windows-gnu
    need protoc protobuf-compiler
    need x86_64-w64-mingw32-gcc gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64
    need makensis nsis
    need unzip unzip
    need zip zip
    need curl curl ca-certificates
    # In the crate directory, so the target is added to the toolchain rust-toolchain.toml pins.
    (cd "$NATIVE/host" && rustup target add "$TARGET")
    build server --target "$TARGET"
    build host --target "$TARGET"

    APP="$STAGE/skwod-host"
    install -d "$APP"
    install -m 0755 "$CARGO_TARGET_DIR/$TARGET/release/skwod-host.exe" "$CARGO_TARGET_DIR/$TARGET/release/skwod.exe" "$APP/"
    "$NATIVE/deploy/fetch-livekit.sh" windows_amd64 "$APP"
    install -m 0644 "$NATIVE/host/assets/skwod-host.ico" "$APP/"
    install -m 0644 "$NATIVE/LICENSE" "$APP/LICENSE.txt"
    install -m 0644 "$NATIVE/THIRD-PARTY-NOTICES.md" "$APP/"
    makensis -V2 -DVERSION="$VERSION" -DSRC="$APP" -DOUTFILE="$OUT/skwod-host-setup-${VERSION}-x64.exe" "$HERE/windows/installer.nsi"
    (cd "$STAGE" && zip -q -r "$OUT/skwod-host-${VERSION}-windows-x64.zip" skwod-host)
    echo "built: $OUT/skwod-host-setup-${VERSION}-x64.exe (unsigned)"
    ;;

  *)
    echo "usage: build.sh linux|windows [out dir]" >&2
    exit 2
    ;;
esac
