#!/usr/bin/env bash
# Build the Rust core into Android JNILibs + generate the UniFFI Kotlin bindings.
# Produces apps/android/core/src/main/jniLibs/<abi>/libskwod_core.so + skwod_core.kt.
# bash 3.2 compatible (macOS default).
# Usage: ./build-core.sh            all release ABIs (arm64-v8a + armeabi-v7a)
#        ./build-core.sh arm64      arm64-v8a only (emulators on Apple Silicon, quick local builds)
#        ./build-core.sh x86_64     x86_64 only (Intel emulators)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CORE="$(cd "$HERE/../../core" && pwd)"
OUT="$HERE/core"

# short-abi|cargo-triple|android-abi
# arm64 (all modern devices + Apple-Silicon emulators) + armv7 (older devices).
# x86/i686 omitted: vendored OpenSSL's x86 asm fails to cross-build, and arm64
# emulators cover testing on Apple Silicon.
ABIS="aarch64|aarch64-linux-android|arm64-v8a
armv7|armv7-linux-androideabi|armeabi-v7a"
case "${1:-all}" in
  all) ;;
  arm64) ABIS="aarch64|aarch64-linux-android|arm64-v8a" ;;
  x86_64) ABIS="x86_64|x86_64-linux-android|x86_64" ;;
  *) echo "usage: $0 [all|arm64|x86_64]" >&2; exit 2 ;;
esac
FIRST_TRIPLE="$(echo "$ABIS" | head -1 | cut -d'|' -f2)"

cd "$CORE"

echo "==> building skwod-core for android (cdylib per ABI)"
echo "$ABIS" | while IFS='|' read -r short triple android_abi; do
  echo "  $short -> $triple"
  cargo ndk -t "$triple" build --locked --release -p skwod-core
done

echo "==> generating Kotlin bindings"
BINDIR="$OUT/src/main/java/io/skwod/core"
rm -rf "$BINDIR"; mkdir -p "$BINDIR"
cargo run --locked --release -p skwod-core --bin uniffi-bindgen -- generate \
  --library "$CORE/target/$FIRST_TRIPLE/release/libskwod_core.so" \
  --language kotlin --out-dir "$BINDIR"

echo "==> assembling jniLibs"
JNIDIR="$OUT/src/main/jniLibs"
rm -rf "$JNIDIR"; mkdir -p "$JNIDIR"
echo "$ABIS" | while IFS='|' read -r short triple android_abi; do
  mkdir -p "$JNIDIR/$android_abi"
  cp "$CORE/target/$triple/release/libskwod_core.so" "$JNIDIR/$android_abi/"
done

echo "==> done: $OUT (jniLibs + kotlin bindings)"
