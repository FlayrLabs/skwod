#!/usr/bin/env bash
# Publish a packaged skwod release to the public release repo, where every Mac and Android install
# looks for updates:
#
#   ./package-release.sh          # builds, signs, notarizes → releases/<build>/
#   ./publish-release.sh <build>  # this script
#
# It creates the GitHub release v<build> in FlayrLabs/skwod-releases with the files from
# releases/<build>/ and marks it "latest", which is what makes
#   https://github.com/FlayrLabs/skwod-releases/releases/latest/download/appcast.xml    (macOS, Sparkle)
#   https://github.com/FlayrLabs/skwod-releases/releases/latest/download/manifest.json  (Android)
# point at it. From that moment every install with automatic checks on picks the release up within
# a day — so this is the irreversible step. It refuses to publish anything that is not notarized,
# not signed, or not the build it was asked for, and it never overwrites an existing release.
#
# Needs: gh, signed in to an account that can write to FlayrLabs/skwod-releases (a PUBLIC repo that
# holds binaries + feeds only — never push source there).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="FlayrLabs/skwod-releases"

BUILD="${1:-}"
[[ "$BUILD" =~ ^[0-9]+$ ]] || { echo "usage: $0 <build>      e.g. $0 41" >&2; exit 2; }
TAG="v$BUILD"
DIR="$HERE/releases/$BUILD"
BASE="https://github.com/$REPO/releases"
MAC_ZIP="Skwod-$BUILD-macos.zip"; MAC_DMG="Skwod-$BUILD.dmg"; APK="skwod-$BUILD.apk"
FILES=("$MAC_ZIP" "$MAC_DMG" "$APK" appcast.xml manifest.json)

die() { echo "✗ $*" >&2; exit 1; }
WORK="$(mktemp -d "${TMPDIR:-/tmp}/skwod-publish.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# ---- what is about to go public ----
[ -d "$DIR" ] || die "no $DIR — run ./package-release.sh first"
[ ! -e "$DIR/NOT-NOTARIZED-DO-NOT-PUBLISH" ] || die "releases/$BUILD is a dry run (not notarized) — re-run ./package-release.sh without SKWOD_SKIP_NOTARIZE"
[ ! -e "$DIR/UNVERIFIED-SOURCE-DO-NOT-PUBLISH" ] || die "releases/$BUILD was packaged with SKWOD_UNVERIFIED_SOURCE=1 (dirty/untagged tree or no dependency check) — package again from the tagged commit"
[ -s "$DIR/SOURCE" ] || die "releases/$BUILD/SOURCE is missing — this release does not say which commit it was built from; package again"
for f in "${FILES[@]}"; do [ -s "$DIR/$f" ] || die "releases/$BUILD/$f is missing"; done
# Notarized + stapled, checked on the files themselves rather than taken on trust.
xcrun stapler validate -q "$DIR/$MAC_DMG" || die "$MAC_DMG has no notarization ticket"
/usr/bin/ditto -x -k "$DIR/$MAC_ZIP" "$WORK/app"
xcrun stapler validate -q "$WORK/app/Skwod.app" || die "the app in $MAC_ZIP has no notarization ticket"
spctl --assess --type execute "$WORK/app/Skwod.app" || die "Gatekeeper rejects the app in $MAC_ZIP"
[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$WORK/app/Skwod.app/Contents/Info.plist")" = "$BUILD" ] \
  || die "the app in $MAC_ZIP is not build $BUILD"
# Both feeds must point at THIS tag, or installs would be sent to files that don't exist.
grep -q "url=\"$BASE/download/$TAG/$MAC_ZIP\"" "$DIR/appcast.xml" || die "appcast.xml does not point at $TAG/$MAC_ZIP"
grep -q 'sparkle:edSignature="[A-Za-z0-9+/=]\{80,\}"' "$DIR/appcast.xml" || die "appcast.xml carries no EdDSA signature"
/usr/bin/python3 - "$DIR/manifest.json" "$BUILD" "$BASE/download/$TAG/$APK" "$(shasum -a 256 "$DIR/$APK" | awk '{print $1}')" <<'PY' \
  || die "manifest.json does not describe this build's apk (build, url, sha256, sig)"
import json, sys
a = json.load(open(sys.argv[1]))["android"]
ok = a["build"] == int(sys.argv[2]) and a["url"] == sys.argv[3] and a["sha256"] == sys.argv[4] and len(a["sig"]) >= 80
sys.exit(0 if ok else 1)
PY
# The feed and the manifest must be SIGNED: builds that require it stop updating otherwise.
grep -q '<!-- sparkle-signatures:$' "$DIR/appcast.xml" || die "appcast.xml is not a signed feed (no sparkle-signatures block)"
PINNED_UPDATE_PUB=$(grep -oE 'UPDATE_PUBLIC_KEY_B64 = "[^"]+"' "$HERE/apps/android/app/src/main/java/io/skwod/app/Updater.kt" | sed -E 's/.*"([^"]+)"/\1/')
"$HERE/tools/release/verify-manifest.sh" --pub "$PINNED_UPDATE_PUB" "$DIR/manifest.json" --build "$BUILD" \
  --apk-url "$BASE/download/$TAG/$APK" --apk-sha256 "$(shasum -a 256 "$DIR/$APK" | awk '{print $1}')" >/dev/null \
  || die "manifest.json's signed statement does not verify against the publisher key pinned in the apps"
VERSION=$(/usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["android"]["version"])' "$DIR/manifest.json")
NOTES_FILE="$DIR/release-notes.md"
[ -s "$NOTES_FILE" ] || { NOTES_FILE="$WORK/notes.md"; echo "skwod $VERSION ($BUILD)" > "$NOTES_FILE"; }

# ---- GitHub ----
command -v gh >/dev/null || die "gh (GitHub CLI) not found"
gh auth status >/dev/null 2>&1 || die "gh is not signed in (gh auth login)"
[ "$(gh repo view "$REPO" --json visibility -q .visibility 2>/dev/null)" = "PUBLIC" ] \
  || die "$REPO does not exist, is not public, or this account can't see it — create it (public, empty) first"
if gh release view "$TAG" --repo "$REPO" >/dev/null 2>&1; then
  die "release $TAG already exists in $REPO — a published build is never replaced; bump the build (./bump-build.sh) and package again"
fi

echo "▸ publishing skwod $VERSION ($BUILD) to $REPO as $TAG"
( cd "$DIR" && gh release create "$TAG" --repo "$REPO" --latest \
    --title "skwod $VERSION ($BUILD)" --notes-file "$NOTES_FILE" "${FILES[@]}" )

# ---- prove the feeds now serve this release ----
# The apps ask for .../releases/latest/download/<feed>; GitHub redirects to the tag and then to its
# asset host. Fetch both feeds the same way and compare them byte for byte with what was built.
# (GitHub can take a few seconds to move "latest".)
echo "▸ verifying the public feeds…"
ALLOWED_HOSTS="github.com release-assets.githubusercontent.com objects.githubusercontent.com"   # = Updater.kt REDIRECT_HOSTS
check() { # <path under releases/> <local file>
  local url="$BASE/$1" final host
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if final=$(curl -fsSL --proto '=https' --proto-redir '=https' --max-redirs 5 -o "$WORK/got" -w '%{url_effective}' "$url") \
       && cmp -s "$WORK/got" "$2"; then
      host=$(printf '%s' "$final" | sed -E 's#^https://([^/:]+).*#\1#')
      case " $ALLOWED_HOSTS " in
        *" $host "*) echo "  ✓ $1  (served by $host)" ;;
        *) echo "  ⚠️  $1 is served by $host, which the Android app does NOT allow redirects to." >&2
           echo "     Android installs can't update until Updater.kt's REDIRECT_HOSTS includes it." >&2; return 1 ;;
      esac
      return 0
    fi
    sleep 3
  done
  echo "✗ $url does not serve this release's $(basename "$2")" >&2; return 1
}
fail=0
check "latest/download/appcast.xml" "$DIR/appcast.xml" || fail=1
check "latest/download/manifest.json" "$DIR/manifest.json" || fail=1
check "download/$TAG/$APK" "$DIR/$APK" || fail=1
check "download/$TAG/$MAC_ZIP" "$DIR/$MAC_ZIP" || fail=1
[ "$fail" = "0" ] || die "the release is published but the feeds don't check out — look at $BASE/tag/$TAG now"

echo "✓ skwod $VERSION ($BUILD) is live: $BASE/tag/$TAG"
echo "  Mac and Android installs with automatic checks on will pick it up within a day."
echo "  Download page for new people: $BASE/latest  (the DMG and apk file names carry the build number)."
echo "  iOS: apps/apple/upload-ios.sh (TestFlight)."
