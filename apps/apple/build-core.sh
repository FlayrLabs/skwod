#!/usr/bin/env bash
# Build the Rust core into SkwodCore.xcframework + copy the generated Swift bindings.
# Usage: ./build-core.sh [macos|ios-sim|all]   (default: all)
#   macos    macOS slice only
#   ios-sim  macOS + iOS Simulator slices (local simulator work; no device slice)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CORE="$(cd "$HERE/../../core" && pwd)"
OUT="$HERE/Generated"
MODE="${1:-all}"

case "$MODE" in
  macos) TARGETS=(aarch64-apple-darwin) ;;
  # The macOS slice is always built: the Swift bindings are generated from its dylib.
  ios-sim) TARGETS=(aarch64-apple-darwin aarch64-apple-ios-sim) ;;
  all) TARGETS=(aarch64-apple-darwin aarch64-apple-ios aarch64-apple-ios-sim) ;;
  *) echo "usage: $0 [macos|ios-sim|all]" >&2; exit 2 ;;
esac

cd "$CORE"
for t in "${TARGETS[@]}"; do
  echo "==> building skwod-core for $t"
  if [[ "$t" == *"-apple-ios"* ]]; then
    # iOS: build ONLY the staticlib. The cdylib link fails on iOS (a vendored-OpenSSL
    # symbol resolves at app-link time from the .a archive, but not when linking a dylib).
    cargo rustc --locked -p skwod-core --lib --release --target "$t" --crate-type staticlib
  else
    # macOS: full build — the cdylib is needed to generate the Swift bindings below.
    cargo build --locked --release -p skwod-core --target "$t"
  fi
done

echo "==> generating Swift bindings"
rm -rf "$OUT"; mkdir -p "$OUT/bindings" "$OUT/headers"
DYLIB="$CORE/target/aarch64-apple-darwin/release/libskwod_core.dylib"
cargo run --locked --release -p skwod-core --bin uniffi-bindgen -- generate --library "$DYLIB" --language swift --out-dir "$OUT/bindings"
cp "$OUT/bindings/skwod_core.swift" "$OUT/SkwodCore.swift"
cp "$OUT/bindings/skwod_coreFFI.h" "$OUT/headers/skwod_coreFFI.h"
# uniffi names the modulemap <name>FFI.modulemap; an xcframework headers dir needs module.modulemap
cp "$OUT/bindings/skwod_coreFFI.modulemap" "$OUT/headers/module.modulemap"

echo "==> assembling xcframework"
rm -rf "$OUT/SkwodCore.xcframework"
ARGS=()
for t in "${TARGETS[@]}"; do
  ARGS+=(-library "$CORE/target/$t/release/libskwod_core.a" -headers "$OUT/headers")
done
xcodebuild -create-xcframework "${ARGS[@]}" -output "$OUT/SkwodCore.xcframework"

echo "==> done: $OUT/SkwodCore.xcframework"

# Keep the macOS app's bundled server binary in sync with the latest server code, so a stale
# server never ships in the app (a past footgun). A failure here is a failure of this script:
# a Mac app without (or with stale) host tools has a dead "Start server" button.
# SKWOD_SKIP_HOST_TOOLS=1 skips it explicitly (iOS-only work, CI lanes that don't ship the Mac app).
if [ "${SKWOD_SKIP_HOST_TOOLS:-0}" = "1" ]; then
  echo "==> skipping bundled host tools (SKWOD_SKIP_HOST_TOOLS=1)"
else
  echo "==> refreshing bundled host tools (server + livekit-server)"
  "$HERE/bundle-host-tools.sh"
fi
