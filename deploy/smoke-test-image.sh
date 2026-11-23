#!/usr/bin/env bash
# Smoke-test a skwod server image before it is published (the image workflow runs this on each
# architecture), or before you run one you built yourself:
#
#   deploy/smoke-test-image.sh <image>          # e.g. skwod-server:smoke
#
# Two short-lived containers, each with a fresh throwaway data folder, nothing published on the
# host and nothing kept afterwards:
#
#   1. "unraid"  — exactly the flags of deploy/unraid/skwod.xml: started as root with only
#                  CHOWN+SETUID+SETGID, read-only root, waiting for the Start button. It must
#                  become healthy, print the one-time admin token, wait for Start, and run the
#                  server as 99:100 (Unraid's nobody:users), not as root.
#   2. "started" — the deploy/docker-compose.yml posture (uid 1000, no capabilities at all)
#                  without the Start button, so the server starts at once: it must become
#                  healthy, print the admin token and the owner's join code, and run the bundled
#                  livekit-server (voice and video).
#
# Needs docker. Exit 0 = every check passed. The p2p endpoint is left on (it needs outbound UDP
# only); it is not a check here, because CI runners' networks vary.
set -euo pipefail

IMAGE="${1:-${SKWOD_IMAGE:-}}"
[ -n "$IMAGE" ] || { echo "usage: $0 <image>" >&2; exit 2; }
TIMEOUT="${SKWOD_SMOKE_TIMEOUT:-120}"   # seconds per wait

WORK="$(mktemp -d)"
TAG="skwod-smoke-$$"
CONTAINERS=()
cleanup() {
  for c in "${CONTAINERS[@]}"; do docker rm -f "$c" >/dev/null 2>&1 || true; done
  docker volume rm -f "$TAG-started" >/dev/null 2>&1 || true
  # The "unraid" case re-owns its folder to 99:100; remove it through a container.
  docker run --rm --user 0:0 --network none -v "$WORK:/w" --entrypoint /bin/sh "$IMAGE" \
    -c 'rm -rf /w/*' >/dev/null 2>&1 || true
  rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

fails=0
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; fails=$((fails + 1)); }

# wait_for <seconds> <command...>: retry once a second until it succeeds.
wait_for() {
  local limit="$1"; shift
  local i=0
  until "$@" >/dev/null 2>&1; do
    i=$((i + 1)); [ "$i" -lt "$limit" ] || return 1
    sleep 1
  done
}
healthy() { docker exec "$1" skwod healthcheck; }
logs_have() { docker logs "$1" 2>&1 | grep -Eq "$2"; }
# Processes of the container, as "uid command" lines (docker top passes the options to ps).
procs() { docker top "$1" -o uid,comm | tail -n +2; }
runs() { procs "$1" | awk -v c="$2" '$2 == c { found = 1 } END { exit !found }'; }

show_logs() { echo "---- logs of $1 ----" >&2; docker logs "$1" 2>&1 | tail -n 40 >&2; echo "----" >&2; }

echo "smoke test: $IMAGE ($(docker image inspect -f '{{.Os}}/{{.Architecture}}' "$IMAGE" 2>/dev/null || echo 'not local yet'))"

# --- 1. the Unraid template's flags ------------------------------------------------------------
c="$TAG-unraid"; CONTAINERS+=("$c")
mkdir -p "$WORK/unraid"
echo "1. unraid template flags (root → 99:100, waits for Start)"
docker run -d --name "$c" \
  --user 0:0 --cap-drop=ALL --cap-add=CHOWN --cap-add=SETUID --cap-add=SETGID \
  --security-opt no-new-privileges:true --read-only --tmpfs /tmp:noexec,nosuid,size=64m \
  -e SKWOD_ADMIN_LISTEN=0.0.0.0:3477 -e SKWOD_WAIT_FOR_START=true -e SKWOD_P2P_PORT=47474 \
  -e SKWOD_RUN_AS=99:100 \
  -v "$WORK/unraid:/data" "$IMAGE" >/dev/null
if wait_for "$TIMEOUT" healthy "$c"; then pass "healthy"; else fail "not healthy after ${TIMEOUT}s"; fi
if logs_have "$c" 'One-time admin token: [A-Z0-9]+(-[A-Z0-9]+)+'; then pass "one-time admin token in the log"; else fail "no admin token in the log"; fi
if logs_have "$c" 'Not serving yet'; then pass "waits for Start server"; else fail "did not wait for Start server"; fi
if procs "$c" | awk '$2 == "skwod" && $1 == "99" { ok = 1 } END { exit !ok }'; then
  pass "server runs as uid 99, not root"
else
  fail "server is not running as uid 99:"; procs "$c" >&2 || true
fi
[ "$fails" = 0 ] || show_logs "$c"

# --- 2. compose posture, started at once: voice must run ---------------------------------------
c="$TAG-started"; CONTAINERS+=("$c")
before="$fails"
echo "2. compose posture (uid 1000, no capabilities), started: LiveKit must run"
docker volume create "$TAG-started" >/dev/null
docker run -d --name "$c" \
  --user 1000:1000 --cap-drop=ALL --security-opt no-new-privileges:true \
  --read-only --tmpfs /tmp:noexec,nosuid,size=64m \
  -e SKWOD_ADMIN_LISTEN=0.0.0.0:3477 -e SKWOD_P2P_PORT=47474 \
  -v "$TAG-started:/data" "$IMAGE" >/dev/null
if wait_for "$TIMEOUT" healthy "$c"; then pass "healthy"; else fail "not healthy after ${TIMEOUT}s"; fi
if logs_have "$c" 'One-time admin token: [A-Z0-9]+(-[A-Z0-9]+)+'; then pass "one-time admin token in the log"; else fail "no admin token in the log"; fi
if logs_have "$c" '^Join code: '; then pass "fresh instance printed the owner's join code"; else fail "no owner join code in the log"; fi
if wait_for "$TIMEOUT" runs "$c" livekit-server; then pass "livekit-server is running"; else fail "livekit-server is not running"; procs "$c" >&2 || true; fi
if logs_have "$c" 'voice disabled'; then fail "the log says voice is disabled"; fi
[ "$fails" = "$before" ] || show_logs "$c"

if [ "$fails" = 0 ]; then echo "smoke test: ok"; else echo "smoke test: $fails check(s) failed" >&2; exit 1; fi
