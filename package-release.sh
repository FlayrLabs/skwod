#!/usr/bin/env bash
# Build one skwod release: every artifact and feed that gets published to the public release repo
# https://github.com/FlayrLabs/skwod-releases (binaries + feeds only; the source is https://github.com/FlayrLabs/skwod).
#
#   ./package-release.sh            # → ./releases/<build>/
#   ./publish-release.sh <build>    # → GitHub release v<build>   (separate, deliberate step)
#
# skwod is decentralized and mostly p2p, so apps do NOT update from the skwod they are connected to.
# Every install reads the same two feeds, served from the newest GitHub release:
#   macOS    https://github.com/FlayrLabs/skwod-releases/releases/latest/download/appcast.xml
#   Android  https://github.com/FlayrLabs/skwod-releases/releases/latest/download/manifest.json
# GitHub only carries the files. Authenticity comes from signatures made HERE, with keys GitHub
# never sees: Sparkle's EdDSA signature over the Mac archive AND over the appcast itself
# (SURequireSignedFeed), and the publisher Ed25519 key that Updater.kt and UpdateManifest.swift
# pin, which signs the apk (build number + SHA256) and the manifest's statement — build numbers,
# notes, the apk URL, the iOS TestFlight link, an expiry and the source commit
# (tools/release/sign-manifest.sh).
#
# A release is made from a CLEAN checkout at a TAGGED commit (skwod-v<build>) that passes
# ./check-deps.sh; the script refuses otherwise. That commit id is written into the signed
# statement and into releases/<build>/SOURCE.
#
# What lands in releases/<build>/ (everything in it is uploaded by publish-release.sh, except
# release-notes.md, which becomes the release text):
#   Skwod-<build>-macos.zip  the update archive Sparkle installs — Developer ID signed, notarized, stapled
#   Skwod-<build>.dmg        the same app as a first-install download — signed, notarized, stapled
#   appcast.xml              Sparkle feed; enclosure → …/releases/download/v<build>/Skwod-<build>-macos.zip
#   skwod-<build>.apk        release-keystore signed, both ABIs of the Rust core inside
#   manifest.json            Android entry (url → …/releases/download/v<build>/skwod-<build>.apk,
#                            sha256, publisher sig) + the iOS TestFlight hand-off
#
# Order matters and is enforced:
#   1. Rust core for Android, BOTH ABIs (apps/android/build-core.sh) — an apk without it installs
#      and then crashes at launch, so the apk is checked for both .so files before it is accepted.
#   2. Rust core for Apple + the Mac app's bundled host tools (apps/apple/build-core.sh).
#   3. Mac app → sign inside-out (entitlements on the app) → notarize → staple → zip → DMG → appcast.
#   4. Android apk → publisher signature → manifest.json.
#   5. Verify what was produced with the same checks the apps run.
#
# Environment:
#   SKWOD_RELEASE_NOTES   one or two plain sentences; goes in the manifest, the appcast and the release text
#   SKWOD_TESTFLIGHT_URL  public TestFlight link for the manifest's ios entry
#   SKWOD_SKIP_CORE=1     don't rebuild the Rust core / host tools (they must already be built; still checked)
#   SKWOD_SKIP_NOTARIZE=1 dry run: sign but don't notarize. The output is NOT shippable and is marked so.
#   SKWOD_UNVERIFIED_SOURCE=1  dry run: package from a dirty or untagged tree and/or without a
#                         passing ./check-deps.sh. The output is NOT shippable and is marked so
#                         (publish-release.sh refuses it).
#   SKWOD_MANIFEST_VALID_DAYS  how long the signed manifest statement counts as fresh (default 120).
#                         Publish a release — or re-sign and re-publish the manifest — before it runs out.
#   SKWOD_MAC_PROFILE     a Developer ID provisioning profile for io.skwod.mac (see "keychain" below)
#   SKWOD_UPDATE_KEY      path to the Android update publisher key (default apps/android/update_publisher_key.pem)
#
# Signing keys (never committed; restore with ./fetch-signing-keys.sh — see RELEASE-SIGNING.md):
#   apps/apple/sparkle_private_key.pem      Sparkle EdDSA (public half: SUPublicEDKey in Info-macOS.plist)
#   apps/android/skwod-release.keystore     Android apk signing (+ keystore.properties)
#   apps/android/update_publisher_key.pem   Ed25519 over build number + SHA256(apk) (public half: Updater.kt)
#   login keychain                          "Developer ID Application: Flayr Labs LLC" + notary profile skwod-notary
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
YML="$HERE/apps/apple/project.yml"
GRADLE="$HERE/apps/android/app/build.gradle.kts"

REPO="FlayrLabs/skwod-releases"
DEVID_NAME="Developer ID Application: Flayr Labs LLC"
DEVID_TEAM="NRNU83UJ68"
NOTARY_PROFILE="skwod-notary"
# Notary credentials: an App Store Connect API key from the environment (no keychain needed, works
# from non-interactive shells), else the stored keychain profile.
if [ -n "${SKWOD_NOTARY_KEY:-}" ] && [ -n "${SKWOD_NOTARY_KEY_ID:-}" ] && [ -n "${SKWOD_NOTARY_ISSUER:-}" ]; then
  NOTARY_AUTH=(--key "$SKWOD_NOTARY_KEY" --key-id "$SKWOD_NOTARY_KEY_ID" --issuer "$SKWOD_NOTARY_ISSUER")
else
  NOTARY_AUTH=(--keychain-profile "$NOTARY_PROFILE")
fi
MAC_BUNDLE_ID="io.skwod.mac"

BUILD=$(grep -E 'CURRENT_PROJECT_VERSION: "[0-9]+"' "$YML" | grep -oE '[0-9]+')
VERSION=$(grep -E 'MARKETING_VERSION: "[^"]+"' "$YML" | sed -E 's/.*"([^"]+)".*/\1/')
ANDROID_BUILD=$(grep -oE 'versionCode = [0-9]+' "$GRADLE" | grep -oE '[0-9]+')
NOTES="${SKWOD_RELEASE_NOTES:-}"
TAG="v$BUILD"
DOWNLOAD_BASE="https://github.com/$REPO/releases/download/$TAG"

OUT="$HERE/releases/$BUILD"
MAC_ZIP="Skwod-$BUILD-macos.zip"
MAC_DMG="Skwod-$BUILD.dmg"
APK="skwod-$BUILD.apk"

die() { echo "✗ $*" >&2; exit 1; }
sha256() { shasum -a 256 "$1" | awk '{print $1}'; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/skwod-release.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# ---- preflight: fail in the first second, not after twenty minutes of building ----
# What is being built must be something that can be named afterwards: a committed, tagged state
# of this tree with nothing else in it, whose dependencies pass the gate. Otherwise a properly
# signed release could contain a local edit or an unreviewed dependency and nobody could tell.
UNVERIFIED_SOURCE=0
SOURCE_PROBLEMS=()
GIT_ROOT="$(git -C "$HERE" rev-parse --show-toplevel 2>/dev/null)" || die "not a git checkout: a release is built from a tagged commit"
SOURCE_COMMIT="$(git -C "$HERE" rev-parse HEAD)"
# Tracked changes and untracked files under this product (ignored files — keys, build output — don't count).
[ -z "$(git -C "$GIT_ROOT" status --porcelain --untracked-files=all -- "$HERE")" ] \
  || SOURCE_PROBLEMS+=("the working tree has uncommitted or untracked files (git status)")
SOURCE_TAG="skwod-v$BUILD"
[ "$(git -C "$GIT_ROOT" rev-parse -q --verify "refs/tags/$SOURCE_TAG^{commit}" 2>/dev/null)" = "$SOURCE_COMMIT" ] \
  || SOURCE_PROBLEMS+=("HEAD is not tagged $SOURCE_TAG (git tag -s $SOURCE_TAG, after ./bump-build.sh is committed)")
if [ "${SKWOD_UNVERIFIED_SOURCE:-0}" != "1" ]; then
  echo "▸ dependency gate (./check-deps.sh)…"
  "$HERE/check-deps.sh" >"$WORK/check-deps.log" 2>&1 \
    || { grep -E "^(✗|⚠)" "$WORK/check-deps.log" >&2 || tail -20 "$WORK/check-deps.log" >&2; SOURCE_PROBLEMS+=("./check-deps.sh failed"); }
else
  SOURCE_PROBLEMS+=("./check-deps.sh was not run")
fi
if [ "${#SOURCE_PROBLEMS[@]}" -gt 0 ]; then
  for p in "${SOURCE_PROBLEMS[@]}"; do echo "✗ $p" >&2; done
  [ "${SKWOD_UNVERIFIED_SOURCE:-0}" = "1" ] || die "refusing to package (SKWOD_UNVERIFIED_SOURCE=1 makes an unpublishable dry run)"
  UNVERIFIED_SOURCE=1
  echo "⚠️⚠️⚠️  SKWOD_UNVERIFIED_SOURCE=1: packaging anyway. THIS OUTPUT MUST NOT BE PUBLISHED. ⚠️⚠️⚠️" >&2
fi
[ "$BUILD" = "$ANDROID_BUILD" ] || die "build numbers differ (Apple $BUILD, Android $ANDROID_BUILD) — run ./bump-build.sh"
for t in cargo xcodegen xcodebuild openssl xxd; do
  command -v "$t" >/dev/null || die "$t not found on PATH"
done
openssl version | grep -q "^OpenSSL [3-9]" || die "need OpenSSL 3+ on PATH for Ed25519 (brew install openssl); found: $(openssl version)"
SPARKLE_KEY="$HERE/apps/apple/sparkle_private_key.pem"
[ -s "$SPARKLE_KEY" ] || die "missing apps/apple/sparkle_private_key.pem — run ./fetch-signing-keys.sh"
[ -f "$HERE/apps/android/keystore.properties" ] && [ -f "$HERE/apps/android/skwod-release.keystore" ] \
  || die "missing the Android release keystore — run ./fetch-signing-keys.sh (an apk signed with any other key can't update an installed app)"
UPDATE_KEY="${SKWOD_UPDATE_KEY:-$HERE/apps/android/update_publisher_key.pem}"
[ -s "$UPDATE_KEY" ] || die "missing the Android update publisher key ($UPDATE_KEY) — run ./fetch-signing-keys.sh"
# The key on disk must be the one the app pins, or every phone would refuse the update.
PINNED_UPDATE_PUB=$(grep -oE 'UPDATE_PUBLIC_KEY_B64 = "[^"]+"' "$HERE/apps/android/app/src/main/java/io/skwod/app/Updater.kt" | sed -E 's/.*"([^"]+)"/\1/')
LOCAL_UPDATE_PUB=$(openssl pkey -in "$UPDATE_KEY" -pubout -outform DER 2>/dev/null | tail -c 32 | base64)
[ -n "$PINNED_UPDATE_PUB" ] && [ "$PINNED_UPDATE_PUB" = "$LOCAL_UPDATE_PUB" ] \
  || die "the update publisher key on disk is not the one pinned in Updater.kt (UPDATE_PUBLIC_KEY_B64)"
# …and the one the iOS app pins for the manifest statement (the TestFlight link).
PINNED_IOS_PUB=$(grep -oE 'publisherKeyB64 = "[^"]+"' "$HERE/apps/apple/Sources/UpdateManifest.swift" | sed -E 's/.*"([^"]+)"/\1/')
[ "$PINNED_IOS_PUB" = "$LOCAL_UPDATE_PUB" ] \
  || die "the update publisher key on disk is not the one pinned in UpdateManifest.swift (publisherKeyB64)"

NOTARIZE=1
if [ "${SKWOD_SKIP_NOTARIZE:-0}" = "1" ]; then
  NOTARIZE=0
else
  security find-identity -v -p codesigning 2>/dev/null | grep -q "\"$DEVID_NAME ($DEVID_TEAM)\"" \
    || die "no \"$DEVID_NAME ($DEVID_TEAM)\" certificate in the keychain (RELEASE-SIGNING.md), or SKWOD_SKIP_NOTARIZE=1 for a dry run"
  xcrun notarytool history "${NOTARY_AUTH[@]}" >/dev/null 2>&1 \
    || die "notary credentials missing or rejected: set SKWOD_NOTARY_KEY/_KEY_ID/_ISSUER or store profile '$NOTARY_PROFILE' (RELEASE-SIGNING.md); SKWOD_SKIP_NOTARIZE=1 for a dry run"
fi
# Sign with Developer ID whenever the certificate is there (a dry run then exercises the real
# signing path); otherwise ad-hoc, which only ever happens in a dry run.
if security find-identity -v -p codesigning 2>/dev/null | grep -q "\"$DEVID_NAME ($DEVID_TEAM)\""; then
  SIGN_ID="$DEVID_NAME ($DEVID_TEAM)"; TIMESTAMP="--timestamp"
else
  SIGN_ID="-"; TIMESTAMP="--timestamp=none"
fi

# The bundled server's default push-gateway allowlist is the host it is BUILT with
# (server/src/gateway.rs). A release without one would accept no member's push registration
# until the owner's own app picked a host — refuse to make that by accident.
if [ -z "${SKWOD_DEFAULT_PUSH_GATEWAY:-}" ] && [ -z "${SKWOD_PUSH_GATEWAY:-}" ] && [ -f "$HERE/signing.env" ]; then
  SKWOD_PUSH_GATEWAY="$(set +u; . "$HERE/signing.env" >/dev/null 2>&1; printf %s "${SKWOD_PUSH_GATEWAY:-}")"
fi
if [ -z "${SKWOD_DEFAULT_PUSH_GATEWAY:-}" ] && [ -n "${SKWOD_PUSH_GATEWAY:-}" ]; then
  SKWOD_DEFAULT_PUSH_GATEWAY="${SKWOD_PUSH_GATEWAY#https://}"; SKWOD_DEFAULT_PUSH_GATEWAY="${SKWOD_DEFAULT_PUSH_GATEWAY%%/*}"
fi
if [ -z "${SKWOD_DEFAULT_PUSH_GATEWAY:-}" ] && [ "${SKWOD_NO_DEFAULT_PUSH_GATEWAY:-0}" != 1 ]; then
  die "SKWOD_DEFAULT_PUSH_GATEWAY / SKWOD_PUSH_GATEWAY is not set (environment or signing.env): the bundled server would have no push gateway. Set one, or SKWOD_NO_DEFAULT_PUSH_GATEWAY=1 to ship without on purpose (RELEASE-SIGNING.md)"
fi
export SKWOD_DEFAULT_PUSH_GATEWAY="${SKWOD_DEFAULT_PUSH_GATEWAY:-}" SKWOD_RELEASE=1

echo "▸ packaging skwod $VERSION ($BUILD)  →  $OUT"
rm -rf "$OUT"; mkdir -p "$OUT"
if [ "$UNVERIFIED_SOURCE" = "1" ]; then
  printf '%s\n' "${SOURCE_PROBLEMS[@]}" > "$OUT/UNVERIFIED-SOURCE-DO-NOT-PUBLISH"
else
  printf 'commit %s\ntag %s\n' "$SOURCE_COMMIT" "$SOURCE_TAG" > "$OUT/SOURCE"
fi

# ---- 1+2. Rust core: Android (both ABIs) first, then Apple + host tools ----
JNI="$HERE/apps/android/core/src/main/jniLibs"
HOST_TOOLS="$HERE/apps/apple/Resources/host-tools"
if [ "${SKWOD_SKIP_CORE:-0}" = "1" ]; then
  echo "▸ SKWOD_SKIP_CORE=1 — using the Rust core + host tools already built in this tree"
else
  echo "▸ building the Rust core for Android (arm64-v8a + armeabi-v7a)…"
  "$HERE/apps/android/build-core.sh" all >"$WORK/android-core.log" 2>&1 \
    || { tail -30 "$WORK/android-core.log" >&2; die "apps/android/build-core.sh failed"; }
  echo "▸ building the Rust core for Apple + the Mac host tools…"
  "$HERE/apps/apple/build-core.sh" all >"$WORK/apple-core.log" 2>&1 \
    || { tail -30 "$WORK/apple-core.log" >&2; die "apps/apple/build-core.sh failed"; }
fi
for abi in arm64-v8a armeabi-v7a; do
  [ -s "$JNI/$abi/libskwod_core.so" ] || die "the Rust core for Android $abi is not built (apps/android/build-core.sh) — refusing to package an apk that can't start"
done
[ -d "$HERE/apps/apple/Generated/SkwodCore.xcframework/macos-arm64" ] || die "the Rust core for macOS is not built (apps/apple/build-core.sh)"
for tool in skwod-server livekit-server; do
  [ -x "$HOST_TOOLS/$tool" ] || die "bundled host tool $tool is missing (apps/apple/bundle-host-tools.sh)"
done
# The server that is actually in the tree (SKWOD_SKIP_CORE=1 reuses an earlier build) must carry
# the gateway host this release names: the host is a string compiled into the binary.
if [ -n "$SKWOD_DEFAULT_PUSH_GATEWAY" ]; then
  LC_ALL=C grep -a -q -F -- "$SKWOD_DEFAULT_PUSH_GATEWAY" "$HOST_TOOLS/skwod-server" \
    || die "the bundled skwod-server was not built with SKWOD_DEFAULT_PUSH_GATEWAY=$SKWOD_DEFAULT_PUSH_GATEWAY — rebuild it (apps/apple/bundle-host-tools.sh)"
fi

# ---- 3. macOS: Release build → sign inside-out → notarize → staple → zip + DMG → appcast ----
echo "▸ building macOS (Release)…"
MAC_DD="$HERE/apps/apple/build-release"
# Built UNSIGNED: every signature that ships is made below, in one place, in the right order.
# (With signing on, Xcode demands a provisioning profile for the keychain entitlement.)
( cd "$HERE/apps/apple" && xcodegen generate >/dev/null \
  && xcodebuild -project Skwod.xcodeproj -scheme Skwod-macOS -configuration Release \
       -derivedDataPath "$MAC_DD" -destination 'platform=macOS,arch=arm64' \
       CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY="" \
       build >"$WORK/xcodebuild.log" 2>&1 ) \
  || { grep -E "error:|\*\* BUILD FAILED" "$WORK/xcodebuild.log" | head -30 >&2; die "xcodebuild failed"; }
MAC_APP="$MAC_DD/Build/Products/Release/Skwod.app"
[ -d "$MAC_APP" ] || die "no Skwod.app at $MAC_APP"
plist() { /usr/libexec/PlistBuddy -c "Print :$1" "$MAC_APP/Contents/Info.plist"; }
[ "$(plist CFBundleVersion)" = "$BUILD" ] || die "built app is build $(plist CFBundleVersion), expected $BUILD"
[ "$(plist CFBundleIdentifier)" = "$MAC_BUNDLE_ID" ] || die "unexpected bundle id $(plist CFBundleIdentifier)"
[ "$(plist SUFeedURL)" = "https://github.com/$REPO/releases/latest/download/appcast.xml" ] \
  || die "the app's SUFeedURL is '$(plist SUFeedURL)' — it must be the fixed release feed"
# The app refuses an unsigned feed, with no fallback; generate_appcast signs the feed because of it.
[ "$(plist SURequireSignedFeed)" = "true" ] && [ "$(plist SUVerifyUpdateBeforeExtraction)" = "true" ] \
  || die "the app does not require a signed feed (SURequireSignedFeed / SUVerifyUpdateBeforeExtraction in Info-macOS.plist)"
SPARKLE_PUB="$(plist SUPublicEDKey)"

SPARKLE_BIN="$MAC_DD/SourcePackages/artifacts/sparkle/Sparkle/bin"
[ -x "$SPARKLE_BIN/generate_appcast" ] && [ -x "$SPARKLE_BIN/sign_update" ] || die "Sparkle's tools not found at $SPARKLE_BIN"

# Entitlements for the outer app. `codesign --force` REPLACES the signature, and with it the
# entitlements, so they are passed explicitly — without them the hardened runtime denies the
# microphone and camera and calls are silent.
#
# keychain: Skwod-macOS.entitlements also asks for `keychain-access-groups` (the data-protection
# keychain). On macOS that is a restricted entitlement: a Developer ID app that claims it without an
# embedded provisioning profile authorizing it is killed at launch. Profiles for Developer ID can't
# be created from the command line, so by default the entitlement is DROPPED for this build and the
# app uses its login-keychain fallback (Sources/Keychain.swift probes for it at run time). To ship
# with it, create a Developer ID profile for io.skwod.mac (Keychain Sharing) in the developer
# portal and pass its path as SKWOD_MAC_PROFILE.
ENT="$WORK/Skwod.entitlements"
cp "$HERE/apps/apple/Skwod-macOS.entitlements" "$ENT"
if [ -n "${SKWOD_MAC_PROFILE:-}" ]; then
  [ -f "$SKWOD_MAC_PROFILE" ] || die "SKWOD_MAC_PROFILE=$SKWOD_MAC_PROFILE does not exist"
  grep -q "$DEVID_TEAM.$MAC_BUNDLE_ID" <<<"$(security cms -D -i "$SKWOD_MAC_PROFILE" 2>/dev/null)" \
    || die "SKWOD_MAC_PROFILE is not a profile for $DEVID_TEAM.$MAC_BUNDLE_ID"
  cp "$SKWOD_MAC_PROFILE" "$MAC_APP/Contents/embedded.provisionprofile"
  /usr/libexec/PlistBuddy -c "Set :keychain-access-groups:0 $DEVID_TEAM.$MAC_BUNDLE_ID" \
    -c "Add :com.apple.application-identifier string $DEVID_TEAM.$MAC_BUNDLE_ID" \
    -c "Add :com.apple.developer.team-identifier string $DEVID_TEAM" "$ENT"
  echo "  keychain: data-protection keychain (embedded profile $(basename "$SKWOD_MAC_PROFILE"))"
else
  /usr/libexec/PlistBuddy -c "Delete :keychain-access-groups" "$ENT"
  echo "  keychain: login-keychain fallback (no SKWOD_MAC_PROFILE; keychain-access-groups dropped)"
fi

echo "▸ signing ($SIGN_ID)…"
sign() { # codesign narrates every replaced signature on stderr; keep only real complaints
  codesign --force $TIMESTAMP --options runtime -s "$SIGN_ID" "$@" 2>&1 | { grep -v "replacing existing signature" >&2 || true; }
}
# Inside-out. First the loose Mach-O files that no bundle seals as code: the host tools the app
# runs as child processes, and Sparkle's Autoupdate helper.
sign "$MAC_APP/Contents/Resources/host-tools/skwod-server" "$MAC_APP/Contents/Resources/host-tools/livekit-server"
find "$MAC_APP/Contents/Frameworks" -type f -name Autoupdate -not -path "*/Versions/Current/*" -print0 |
  while IFS= read -r -d '' f; do sign "$f"; done
# Then every nested bundle and dylib, deepest first (find -depth), so a container is always signed
# after what it contains: Sparkle's XPC services + Updater.app, then the frameworks themselves.
find "$MAC_APP/Contents/Frameworks" -depth \( -name "*.xpc" -o -name "*.app" -o -name "*.dylib" -o -name "*.framework" \) \
  -not -type l -not -path "*/Versions/Current/*" -print0 |
  while IFS= read -r -d '' item; do
    case "$item" in
      *.xpc) sign --preserve-metadata=entitlements "$item" ;;   # Sparkle's Downloader keeps its own
      *)     sign "$item" ;;
    esac
  done
# Last, the app itself — with its entitlements.
sign --entitlements "$ENT" "$MAC_APP"
codesign --verify --deep --strict "$MAC_APP" || die "codesign verification failed"
GOT_ENT="$(codesign -d --entitlements - --xml "$MAC_APP" 2>/dev/null)"
for e in com.apple.security.device.audio-input com.apple.security.device.camera; do
  grep -q "$e" <<<"$GOT_ENT" || die "the signed app lost its $e entitlement"
done
if [ -z "${SKWOD_MAC_PROFILE:-}" ] && grep -q "keychain-access-groups" <<<"$GOT_ENT"; then
  die "the signed app claims keychain-access-groups without a provisioning profile — it would not launch"
fi
echo "  ✓ signed; entitlements: microphone, camera$( [ -n "${SKWOD_MAC_PROFILE:-}" ] && echo ", keychain group" )"

notarize() { # <file> — submit, wait, and insist on "Accepted"
  # notarytool exits 0 as long as it TALKED to Apple, even when the verdict is "Invalid".
  local out id
  out=$(xcrun notarytool submit "$1" "${NOTARY_AUTH[@]}" --wait 2>&1) || true
  echo "$out" | grep -E "^ *(id|status):" | tail -2
  if ! grep -q "status: Accepted" <<<"$out"; then
    id=$(echo "$out" | awk '/id:/{print $2; exit}')
    echo "✗ notarization of $(basename "$1") NOT accepted — Apple's log:" >&2
    [ -n "$id" ] && xcrun notarytool log "$id" "${NOTARY_AUTH[@]}" >&2
    exit 1
  fi
}

if [ "$NOTARIZE" = "1" ]; then
  echo "▸ notarizing the app (Apple usually answers in a few minutes)…"
  /usr/bin/ditto -c -k --keepParent "$MAC_APP" "$WORK/submit.zip"
  notarize "$WORK/submit.zip"
  # Staple the ticket into the .app so it validates offline; only then make the archives.
  xcrun stapler staple -q "$MAC_APP" || die "stapling the app failed"
  spctl --assess --type execute "$MAC_APP" || die "Gatekeeper rejects the notarized app"
  echo "  ✓ notarized + stapled; Gatekeeper accepts the app"
fi
/usr/bin/ditto -c -k --keepParent "$MAC_APP" "$OUT/$MAC_ZIP"

echo "▸ building the DMG…"
mkdir "$WORK/dmg"
/usr/bin/ditto "$MAC_APP" "$WORK/dmg/Skwod.app"
ln -s /Applications "$WORK/dmg/Applications"
hdiutil create -quiet -volname "skwod" -srcfolder "$WORK/dmg" -fs HFS+ -format UDZO -ov "$OUT/$MAC_DMG"
rm -rf "$WORK/dmg"
codesign --force $TIMESTAMP -s "$SIGN_ID" "$OUT/$MAC_DMG"
if [ "$NOTARIZE" = "1" ]; then
  echo "▸ notarizing the DMG…"
  notarize "$OUT/$MAC_DMG"
  xcrun stapler staple -q "$OUT/$MAC_DMG" || die "stapling the DMG failed"
  spctl --assess --type open --context context:primary-signature "$OUT/$MAC_DMG" || die "Gatekeeper rejects the DMG"
  echo "  ✓ $MAC_ZIP + $MAC_DMG  (Developer ID signed, notarized, stapled)"
else
  echo "  ⚠️  NOT NOTARIZED — Gatekeeper blocks this build on every other Mac. Dry run only."
  touch "$OUT/NOT-NOTARIZED-DO-NOT-PUBLISH"
fi

echo "▸ generating the EdDSA-signed appcast…"
# Only the zip goes in the feed (the DMG is for people, not for Sparkle), so the feed is generated
# from a directory that holds nothing else. Absolute enclosure URLs → this release's tag.
mkdir "$WORK/feed"
cp "$OUT/$MAC_ZIP" "$WORK/feed/"
[ -n "$NOTES" ] && printf '%s\n' "$NOTES" > "$WORK/feed/${MAC_ZIP%.zip}.txt"
"$SPARKLE_BIN/generate_appcast" --ed-key-file "$SPARKLE_KEY" \
  --download-url-prefix "$DOWNLOAD_BASE/" --embed-release-notes --maximum-deltas 0 \
  -o "$OUT/appcast.xml" "$WORK/feed" >"$WORK/appcast.log" 2>&1 \
  || { cat "$WORK/appcast.log" >&2; die "generate_appcast failed"; }
rm -rf "$WORK/feed"

# ---- 4. Android: release apk → publisher signature → manifest.json ----
echo "▸ building Android (Release, release-keystore signed)…"
( cd "$HERE/apps/android" && ./gradlew --quiet assembleRelease >"$WORK/gradle.log" 2>&1 ) \
  || { tail -40 "$WORK/gradle.log" >&2; die "gradle assembleRelease failed"; }
APK_SRC="$HERE/apps/android/app/build/outputs/apk/release/app-release.apk"
[ -f "$APK_SRC" ] || die "no signed release apk at $APK_SRC (an -unsigned.apk means the keystore wasn't used)"
APK_LIST="$(unzip -l "$APK_SRC")"   # captured first: `unzip | grep -q` trips pipefail when grep exits early
for abi in arm64-v8a armeabi-v7a; do
  grep -q "lib/$abi/libskwod_core.so" <<<"$APK_LIST" || die "the apk has no Rust core for $abi"
done
AAPT="$(find "${ANDROID_HOME:-$HOME/Library/Android/sdk}/build-tools" -name aapt2 2>/dev/null | sort | tail -1)"
if [ -n "$AAPT" ]; then
  BADGING="$("$AAPT" dump badging "$APK_SRC")"
  grep -q "versionCode='$BUILD'" <<<"$BADGING" || die "the apk's versionCode is not $BUILD"
  grep -q "package: name='com.skwod.app'" <<<"$BADGING" || die "unexpected apk package name"
fi
cp "$APK_SRC" "$OUT/$APK"
APK_SHA=$(sha256 "$OUT/$APK")
# The manifest (tools/release/sign-manifest.sh). Signed with the publisher key:
#   android.sig   over the 32 RAW digest bytes — what build 45 and older verify.
#   android.sig2  over "skwod-android-update-v2\n<build>\n" + the digest — build 46.
#   signed + signed_sig   the statement: build, version, notes, apk url + digest, the iOS link,
#                 issued/expires and the source commit. Later builds read NOTHING else.
echo "  ✓ $APK  ($(du -h "$OUT/$APK" | awk '{print $1}'), both ABIs)"
MANIFEST_ARGS=(--key "$UPDATE_KEY" --build "$BUILD" --version "$VERSION" --apk-file "$APK"
  --apk-url "$DOWNLOAD_BASE/$APK" --apk-sha256 "$APK_SHA" --notes "$NOTES"
  --valid-days "${SKWOD_MANIFEST_VALID_DAYS:-120}")
[ -z "${SKWOD_TESTFLIGHT_URL:-}" ] || MANIFEST_ARGS+=(--testflight "$SKWOD_TESTFLIGHT_URL")
[ "$UNVERIFIED_SOURCE" = "1" ] || MANIFEST_ARGS+=(--commit "$SOURCE_COMMIT")
"$HERE/tools/release/sign-manifest.sh" "${MANIFEST_ARGS[@]}" > "$OUT/manifest.json" || die "signing the manifest failed"
printf '%s\n' "${NOTES:-skwod $VERSION ($BUILD)}" > "$OUT/release-notes.md"

# ---- 5. verify, the way the apps will ----
echo "▸ verifying…"
# appcast: one item, this build, the tagged URL, and an EdDSA signature that verifies.
read -r FEED_URL FEED_SIG FEED_LEN FEED_VER < <(/usr/bin/python3 - "$OUT/appcast.xml" <<'PY'
import sys, xml.etree.ElementTree as ET   # parses the feed generate_appcast just wrote locally
ns = "{http://www.andymatuschak.org/xml-namespaces/sparkle}"
items = ET.parse(sys.argv[1]).getroot().findall("./channel/item")
assert len(items) == 1, f"expected exactly one item in the appcast, found {len(items)}"
enc = items[0].find("enclosure")
ver = enc.get(ns + "version") or items[0].findtext(ns + "version")
print(enc.get("url"), enc.get(ns + "edSignature"), enc.get("length"), ver)
PY
) || die "appcast.xml is not a one-item Sparkle feed"
[ "$FEED_URL" = "$DOWNLOAD_BASE/$MAC_ZIP" ] || die "appcast enclosure is $FEED_URL, expected $DOWNLOAD_BASE/$MAC_ZIP"
[ "$FEED_VER" = "$BUILD" ] || die "appcast advertises build $FEED_VER, expected $BUILD"
[ "$FEED_LEN" = "$(stat -f %z "$OUT/$MAC_ZIP")" ] || die "appcast length does not match the zip"
# (a) Sparkle's own tool, (b) independently against the PUBLIC key inside the app that was built —
# the key every installed copy will check with.
"$SPARKLE_BIN/sign_update" --verify --ed-key-file "$SPARKLE_KEY" "$OUT/$MAC_ZIP" "$FEED_SIG" >/dev/null \
  || die "Sparkle's sign_update rejects the appcast signature"
ed25519_pub_der() { { printf '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00'; printf '%s' "$1" | base64 -d; } > "$2"; }
ed25519_pub_der "$SPARKLE_PUB" "$WORK/sparkle.pub.der"
printf '%s' "$FEED_SIG" | base64 -d > "$WORK/feed.sig"
openssl pkeyutl -verify -pubin -inkey "$WORK/sparkle.pub.der" -keyform DER -rawin -in "$OUT/$MAC_ZIP" -sigfile "$WORK/feed.sig" >/dev/null \
  || die "the appcast signature does not verify against the app's SUPublicEDKey"
echo "  ✓ appcast.xml: build $BUILD → $FEED_URL, EdDSA signature verifies against SUPublicEDKey"
# The feed itself: everything before the trailing "<!-- sparkle-signatures:" block must verify
# against the same key, with the length the block states (what SUAppcastDriver checks).
read -r APPCAST_SIG APPCAST_LEN < <(/usr/bin/python3 - "$OUT/appcast.xml" "$WORK/appcast.content" <<'PY'
import re, sys
data = open(sys.argv[1], "rb").read()
at = data.rfind(b"<!-- sparkle-signatures:\n")
assert at >= 0, "the appcast has no sparkle-signatures block"
block = data[at:].decode()
sig = re.search(r"^edSignature:\s*(\S+)\s*$", block, re.M).group(1)
length = int(re.search(r"^length:\s*(\d+)\s*$", block, re.M).group(1))
assert length == at, f"signed length {length} is not the content length {at}"
open(sys.argv[2], "wb").write(data[:at])
print(sig, length)
PY
) || die "appcast.xml is not a signed feed (generate_appcast signs it when the app has SURequireSignedFeed)"
printf '%s' "$APPCAST_SIG" | base64 -d > "$WORK/appcast.sig"
openssl pkeyutl -verify -pubin -inkey "$WORK/sparkle.pub.der" -keyform DER -rawin -in "$WORK/appcast.content" -sigfile "$WORK/appcast.sig" >/dev/null \
  || die "the appcast's feed signature does not verify against the app's SUPublicEDKey"
echo "  ✓ appcast.xml: the feed itself is EdDSA-signed ($APPCAST_LEN bytes covered)"
# manifest: the signed statement, with openssl alone and the key pinned in the apps…
"$HERE/tools/release/verify-manifest.sh" --pub "$PINNED_UPDATE_PUB" "$OUT/manifest.json" --build "$BUILD" \
  --apk-sha256 "$APK_SHA" --apk-url "$DOWNLOAD_BASE/$APK" ${SKWOD_TESTFLIGHT_URL:+--testflight "$SKWOD_TESTFLIGHT_URL"} >/dev/null \
  || die "manifest.json's signed statement does not verify against the pinned publisher key"
echo "  ✓ manifest.json: the statement (build, apk, iOS link, expiry) verifies against the pinned publisher key"
# …and through the Android updater's own code:
# manifest: through the Android verifier itself (UpdaterTest.packagedReleaseVerifiesWithThePinnedKey).
( cd "$HERE/apps/android" && SKWOD_RELEASE_DIR="$OUT" ./gradlew --quiet :app:testReleaseUnitTest \
    --tests 'io.skwod.app.UpdaterTest' >"$WORK/gradle-test.log" 2>&1 ) \
  || { tail -40 "$WORK/gradle-test.log" >&2; die "the Android updater rejects this release (UpdaterTest)"; }
TEST_XML="$HERE/apps/android/app/build/test-results/testReleaseUnitTest/TEST-io.skwod.app.UpdaterTest.xml"
# The test skips itself when SKWOD_RELEASE_DIR is unset; make sure it really ran, and passed.
/usr/bin/python3 - "$TEST_XML" <<'PY' || die "the Android release check did not run"
import sys, xml.etree.ElementTree as ET   # a report gradle just wrote on this machine
case = [c for c in ET.parse(sys.argv[1]).getroot().iter("testcase") if c.get("name") == "packagedReleaseVerifiesWithThePinnedKey"]
sys.exit(0 if len(case) == 1 and len(case[0]) == 0 else 1)
PY
echo "  ✓ manifest.json: statement, apk url, sha256 and apk signature accepted by the Android updater"

echo
echo "✓ skwod $VERSION ($BUILD) packaged in $OUT"
find "$OUT" -type f -exec du -h {} + | awk '{printf "    %6s  %s\n", $1, $2}' | sort -k2
if [ "$UNVERIFIED_SOURCE" = "1" ]; then
  echo "  ⚠️  DRY RUN (SKWOD_UNVERIFIED_SOURCE=1): not built from a clean, tagged, dependency-checked tree. Do not publish."
elif [ "$NOTARIZE" = "1" ]; then
  echo "  Next: ./publish-release.sh $BUILD   (then TestFlight: apps/apple/upload-ios.sh)"
else
  echo "  ⚠️  DRY RUN (SKWOD_SKIP_NOTARIZE=1): the Mac artifacts are not notarized. Do not publish."
fi
