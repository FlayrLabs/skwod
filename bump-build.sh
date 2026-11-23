#!/usr/bin/env bash
# Bump the build number on all three platforms in lockstep, so a running app's visible version
# always identifies exactly which build it is. Run before each new build you want to distinguish.
#
#   ./bump-build.sh          # increment the current build number by 1
#   ./bump-build.sh 20       # set the build number to 20 explicitly
#
# One number everywhere. Build N is shown as version "0.N" in every app and reported as
# "0.N.0" by the server, so what a user sees always matches the build they run.
#
# Sources of truth:
#   Apple:   apps/apple/project.yml   -> CURRENT_PROJECT_VERSION (CFBundleVersion) = N,
#                                        MARKETING_VERSION (CFBundleShortVersionString) = 0.N
#   Android: apps/android/app/build.gradle.kts -> versionCode = N, versionName = 0.N
#   Rust:    server/, host/ and the core workspace -> package version 0.N.0 (+ their Cargo.lock)
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

# The visible version, in step with the build number.
sed -i '' -E "s/MARKETING_VERSION: \"[0-9.]+\"/MARKETING_VERSION: \"0.$next\"/" "$YML"
sed -i '' -E "s/versionName = \"[0-9.]+\"/versionName = \"0.$next\"/" "$GRADLE"
python3 - "$next" "$HERE/server/Cargo.toml" "$HERE/host/Cargo.toml" "$HERE/core/Cargo.toml" "$HERE"/core/*/Cargo.toml <<'PY'
import re, sys
n = sys.argv[1]
for p in sys.argv[2:]:
    s = open(p).read()
    # our own crates depend on each other by path AND version; keep that version in step
    s = re.sub(r'(skwod-[a-z]+ = \{ path = "[^"]+", version = ")[0-9.]+(")', r'\g<1>0.%s.0\2' % n, s)
    if "version.workspace = true" in s:
        open(p, "w").write(s)
        continue
    if "[workspace.package]" in s:
        # the core workspace: its members take version.workspace
        s = re.sub(r'(\[workspace\.package\][^\[]*?\nversion = ")[0-9.]+(")', r'\g<1>0.%s.0\2' % n, s, count=1)
    else:
        # the [package] table's own version (the first `version =` line in the file)
        s = re.sub(r'(?m)^version = "[0-9.]+"', 'version = "0.%s.0"' % n, s, count=1)
    open(p, "w").write(s)
PY
# Keep each lockfile's own package entries in step (`--workspace` touches only our own packages,
# never a dependency). Release builds use --locked, so a mismatch would fail them.
for ws in core server host; do
  ( cd "$HERE/$ws" && cargo update --workspace --quiet ) || { echo "✗ cargo update --workspace failed in $ws" >&2; exit 1; }
done

# Regenerate the Xcode project so the new build number lands in the pbxproj.
( cd "$HERE/apps/apple" && xcodegen generate >/dev/null 2>&1 )

echo "✓ build $cur → $next, version 0.$next on Apple, Android and the Rust packages"
echo "  rebuild each app to pick it up; the version shows in Profile (Apple) / Settings (Android)."
