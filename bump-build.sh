#!/usr/bin/env bash
# Bump the build number on all three platforms in lockstep, so a running app's visible version
# always identifies exactly which build it is. Run before each new build you want to distinguish.
#
#   ./bump-build.sh          # increment the current build number by 1
#   ./bump-build.sh 20       # set the build number to 20 explicitly
#
# Sources of truth:
#   Apple:   apps/apple/project.yml   -> CURRENT_PROJECT_VERSION  (Info.plist CFBundleVersion)
#   Android: apps/android/app/build.gradle.kts -> versionCode
# The marketing version (0.1.0 / versionName) is bumped by hand when you cut a real release.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
YML="$HERE/apps/apple/project.yml"
GRADLE="$HERE/apps/android/app/build.gradle.kts"

cur=$(grep -E 'CURRENT_PROJECT_VERSION: "[0-9]+"' "$YML" | grep -oE '[0-9]+')
next="${1:-$((cur + 1))}"

# Apple
sed -i '' -E "s/CURRENT_PROJECT_VERSION: \"[0-9]+\"/CURRENT_PROJECT_VERSION: \"$next\"/" "$YML"
# Android
sed -i '' -E "s/versionCode = [0-9]+/versionCode = $next/" "$GRADLE"

# Regenerate the Xcode project so the new build number lands in the pbxproj.
( cd "$HERE/apps/apple" && xcodegen generate >/dev/null 2>&1 )

echo "✓ build number: $cur → $next  (Apple CURRENT_PROJECT_VERSION + Android versionCode)"
echo "  rebuild each app to pick it up; the version shows in Profile (Apple) / Settings (Android)."
