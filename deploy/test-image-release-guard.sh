#!/usr/bin/env bash
# Tests for image-release-guard.sh and for the signer identity verify-image.sh pins. No network.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
G="$HERE/image-release-guard.sh"
fails=0
ok() { if "$@" >/dev/null 2>&1; then echo "  ✓ $*"; else echo "  ✗ should pass: $*" >&2; fails=$((fails + 1)); fi; }
no() { if "$@" >/dev/null 2>&1; then echo "  ✗ should refuse: $*" >&2; fails=$((fails + 1)); else echo "  ✓ refused: $*"; fi; }

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
printf 'settings:\n  base:\n    CURRENT_PROJECT_VERSION: "45"\n' > "$T/project.yml"

echo "build-number"
ok "$G" build-number skwod-v45 "$T/project.yml"
if [ "$("$G" build-number skwod-v45 "$T/project.yml")" = 45 ]; then echo "  ✓ prints 45"; else echo "  ✗ does not print 45" >&2; fails=$((fails + 1)); fi
no "$G" build-number skwod-v46 "$T/project.yml"
no "$G" build-number main "$T/project.yml"
no "$G" build-number v45 "$T/project.yml"
no "$G" build-number skwod-v45x "$T/project.yml"
no "$G" build-number 'skwod-v45;id' "$T/project.yml"

echo "newer"
ok "$G" newer 45
ok "$G" newer 45 ""
ok "$G" newer 46 45
no "$G" newer 45 45
no "$G" newer 44 45
no "$G" newer 9 10
no "$G" newer 46 abc
no "$G" newer x 45

echo "on-main"
(
  cd "$T" && export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
  g() { git -c user.name=t -c user.email=t@t -c commit.gpgsign=false "$@"; }
  g init -q -b main r && cd r
  g commit -q --allow-empty -m one && g commit -q --allow-empty -m two
  g switch -q -c side HEAD~1 && g commit -q --allow-empty -m side
) >/dev/null
R="$T/r"
ok env GIT_DIR="$R/.git" "$G" on-main "$(git -C "$R" rev-parse main~1)" main
ok env GIT_DIR="$R/.git" "$G" on-main "$(git -C "$R" rev-parse main)" main
no env GIT_DIR="$R/.git" "$G" on-main "$(git -C "$R" rev-parse side)" main
no env GIT_DIR="$R/.git" "$G" on-main "$(git -C "$R" rev-parse side)" origin/main

echo "verify-image.sh signer identity"
re="$(sed -nE 's/^IDENTITY_REGEXP="\$\{SKWOD_IMAGE_IDENTITY_REGEXP:-(.*)\}"$/\1/p' "$HERE/verify-image.sh")"
[ -n "$re" ] || { echo "  ✗ IDENTITY_REGEXP not found" >&2; fails=$((fails + 1)); }
id_ok() { if printf '%s\n' "$1" | grep -Eq "$re"; then echo "  ✓ accepts $1"; else echo "  ✗ should accept $1" >&2; fails=$((fails + 1)); fi; }
id_no() { if printf '%s\n' "$1" | grep -Eq "$re"; then echo "  ✗ should refuse $1" >&2; fails=$((fails + 1)); else echo "  ✓ refuses $1"; fi; }
W="https://github.com/FlayrLabs/skwod/.github/workflows/image.yml"
id_ok "$W@refs/tags/skwod-v45"
id_no "$W@refs/heads/main"
id_no "$W@refs/tags/v45"
id_no "$W@refs/tags/skwod-v45-rc"
id_no "https://github.com/someone/skwod/.github/workflows/image.yml@refs/tags/skwod-v45"
id_no "https://github.com/FlayrLabs/skwod/.github/workflows/ci.yml@refs/tags/skwod-v45"
# shellcheck disable=SC2016  # the literal text of the script is matched
if grep -q -- '--certificate-github-workflow-repository "$REPOSITORY"' "$HERE/verify-image.sh"; then
  echo "  ✓ verify-image.sh pins the workflow repository"
else
  echo "  ✗ verify-image.sh does not pin the workflow repository" >&2; fails=$((fails + 1))
fi

if [ "$fails" != 0 ]; then echo "✗ $fails release-guard test(s) failed" >&2; exit 1; fi
echo "✓ release-guard tests passed"
