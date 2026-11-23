#!/bin/bash
# Archive the iOS app and upload it to App Store Connect (TestFlight).
#
# By default Xcode signs and uploads with the Apple ID signed in under Xcode → Settings → Accounts.
# An App Store Connect API key is optional and never in this repository; it is used only when all
# three of these are set:
#   ASC_KEY_PATH    the .p8 file
#   ASC_KEY_ID      the API key's 10-character Key ID
#   ASC_ISSUER_ID   the Issuer ID (a UUID) shown above the key list in App Store Connect
# The signing team comes from DEVELOPMENT_TEAM in project.yml and teamID in ExportOptions.plist.
#
# The push gateway is not in project.yml (its default is empty = no remote push). A release names
# its own, in the environment or in the gitignored ../../signing.env:
#   SKWOD_PUSH_GATEWAY   https://… base URL of your blind push gateway (docs/PUSH.md)
#   SKWOD_NO_PUSH=1      upload a build without remote push on purpose
set -euo pipefail
cd "$(dirname "$0")"

# shellcheck source=/dev/null
[ -f ../../signing.env ] && . ../../signing.env
GATEWAY="${SKWOD_PUSH_GATEWAY:-}"
if [ -z "$GATEWAY" ]; then
  [ "${SKWOD_NO_PUSH:-0}" = 1 ] || { echo "✗ SKWOD_PUSH_GATEWAY is not set (environment or signing.env). Set it, or SKWOD_NO_PUSH=1 to ship without remote push." >&2; exit 1; }
  echo "▸ no push gateway: this build only notifies while it is running"
else
  case "$GATEWAY" in https://?*) ;; *) echo "✗ SKWOD_PUSH_GATEWAY must be an https:// URL" >&2; exit 1 ;; esac
  echo "▸ push gateway: $GATEWAY"
fi

# Why the key is opt-in: an upload-only API key cannot see Certificates, Identifiers & Profiles, so
# -allowProvisioningUpdates fails with "Authentication failed" whenever a capability changes.
AUTH=()
if [ -n "${ASC_KEY_PATH:-}" ] && [ -n "${ASC_KEY_ID:-}" ] && [ -n "${ASC_ISSUER_ID:-}" ]; then
  [ -f "$ASC_KEY_PATH" ] || { echo "✗ no API key at $ASC_KEY_PATH" >&2; exit 1; }
  AUTH=(-authenticationKeyPath "$ASC_KEY_PATH" -authenticationKeyID "$ASC_KEY_ID" -authenticationKeyIssuerID "$ASC_ISSUER_ID")
  echo "▸ authenticating with App Store Connect API key $ASC_KEY_ID"
else
  echo "▸ authenticating with the Apple ID signed in to Xcode"
fi

ARCH=build-ios/Skwod.xcarchive
rm -rf build-ios; mkdir -p build-ios
echo "▸ archiving iOS (Release)…"
# ${AUTH[@]+…}: bash 3.2 (macOS) treats an empty array as unset under `set -u`.
xcodebuild -project Skwod.xcodeproj -scheme Skwod-iOS -configuration Release \
  -archivePath "$ARCH" -destination 'generic/platform=iOS' \
  -allowProvisioningUpdates ${AUTH[@]+"${AUTH[@]}"} \
  SKWOD_PUSH_GATEWAY="$GATEWAY" \
  archive 2>&1 | tail -4
# The archive must carry exactly the gateway asked for — a release without push is a silent failure.
BUILT="$(/usr/libexec/PlistBuddy -c 'Print :SkwodPushGateway' "$ARCH/Products/Applications/Skwod.app/Info.plist" 2>/dev/null || true)"
[ "$BUILT" = "$GATEWAY" ] || { echo "✗ the archive's SkwodPushGateway is '$BUILT', expected '$GATEWAY'" >&2; exit 1; }
# The build number as archived (CURRENT_PROJECT_VERSION → CFBundleVersion), for the closing line.
BUILD="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$ARCH/Products/Applications/Skwod.app/Info.plist" 2>/dev/null || true)"
VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$ARCH/Products/Applications/Skwod.app/Info.plist" 2>/dev/null || true)"
[ -n "$BUILD" ] || { echo "✗ the archive's Info.plist has no CFBundleVersion" >&2; exit 1; }
echo "▸ archived ${VERSION:-?} (build $BUILD)"
echo "▸ exporting + uploading to App Store Connect (TestFlight)…"
xcodebuild -exportArchive -archivePath "$ARCH" \
  -exportOptionsPlist ExportOptions.plist -exportPath build-ios/export \
  -allowProvisioningUpdates ${AUTH[@]+"${AUTH[@]}"} 2>&1 | tail -8
echo "✓ iOS ${VERSION:-} build $BUILD uploaded to TestFlight"
