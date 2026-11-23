#!/usr/bin/env bash
# Tests for verify-image.sh's digest-pin rule and for the deploy files' own pins. No network.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
fails=0
D="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
yes() { if "$HERE/verify-image.sh" --format-only "$1" >/dev/null 2>&1; then echo "  ✓ accepted $1"; else echo "  ✗ should accept $1" >&2; fails=$((fails + 1)); fi; }
no() { if "$HERE/verify-image.sh" --format-only "$1" >/dev/null 2>&1; then echo "  ✗ should refuse $1" >&2; fails=$((fails + 1)); else echo "  ✓ refused  $1"; fi; }
yes "ghcr.io/flayrlabs/skwod-server@sha256:$D"
yes "ghcr.io/flayrlabs/skwod-server:v46@sha256:$D"
no "ghcr.io/flayrlabs/skwod-server:main"
no "ghcr.io/flayrlabs/skwod-server:latest"
no "ghcr.io/flayrlabs/skwod-server"
no "ghcr.io/flayrlabs/skwod-server@sha256:${D%?}"
no "ghcr.io/flayrlabs/skwod-server@sha256:${D}0"
no "ghcr.io/flayrlabs/skwod-server@sha256:REPLACE_WITH_THE_IMAGE_DIGEST"
no "ghcr.io/flayrlabs/skwod-server@md5:$D"

check() { if eval "$2"; then echo "  ✓ $1"; else echo "  ✗ $1" >&2; fails=$((fails + 1)); fi; }
# The files people copy: no mutable tag as a default, and the admin page on loopback.
check "docker-compose.yml has no default image" "! grep -Eq 'image: *\\\$\\{SKWOD_IMAGE:-' '$HERE/docker-compose.yml'"
check "docker-compose.yml requires SKWOD_IMAGE" "[ \"\$(grep -c 'image: \${SKWOD_IMAGE:?' '$HERE/docker-compose.yml')\" = 2 ]"
check "no :main / :latest image in the compose files" "! grep -REn 'image:.*:(main|latest)\\b' '$HERE' --include='*.yml'"
check "no :main tag anywhere in deploy/" "! grep -REn '(image:|<Repository>).*:main\\b' '$HERE' --include='*.yml' --include='*.xml'"
check "compose publishes the admin page on loopback by default" "grep -q '\"\${SKWOD_ADMIN_BIND:-127.0.0.1}:\${SKWOD_ADMIN_PORT:-3477}:3477\"' '$HERE/docker-compose.yml'"
check "the Unraid template publishes the admin page on loopback" "grep -q -- '-p 127.0.0.1:3477:3477' '$HERE/unraid/skwod.xml' && ! grep -q 'Target=\"3477\"' '$HERE/unraid/skwod.xml'"
# Unraid: the one place a tag is used, so "check for updates" works. Only the signed image
# workflow's `latest` (moved after smoke test + signature) — never another name or tag.
check "the Unraid template names the published image (:latest)" "grep -qx '  <Repository>ghcr.io/flayrlabs/skwod-server:latest</Repository>' '$HERE/unraid/skwod.xml'"
check "the Unraid template explains digest pinning" "grep -q '@sha256:<digest>' '$HERE/unraid/skwod.xml'"
check "the Unraid template keeps the privilege drop" "grep -q -- '--cap-drop=ALL --cap-add=CHOWN --cap-add=SETUID --cap-add=SETGID --security-opt no-new-privileges:true --read-only' '$HERE/unraid/skwod.xml'"
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  check "compose refuses to start without SKWOD_IMAGE" "! (cd '$HERE' && env -u SKWOD_IMAGE docker compose -f docker-compose.yml config >/dev/null 2>&1)"
  check "compose accepts a digest-pinned SKWOD_IMAGE" "(cd '$HERE' && SKWOD_IMAGE=ghcr.io/flayrlabs/skwod-server@sha256:$D docker compose -f docker-compose.yml config >/dev/null 2>&1)"
fi
if [ "$fails" != "0" ]; then echo "✗ $fails deploy pin test(s) failed" >&2; exit 1; fi
echo "✓ deploy pin tests passed"
