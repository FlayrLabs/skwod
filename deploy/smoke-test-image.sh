#!/usr/bin/env bash
# Smoke-test a skwod server image before it is published (the image workflow runs this on each
# architecture), or before you run one you built yourself:
#
#   deploy/smoke-test-image.sh <image>          # e.g. skwod-server:smoke
#
# Two short-lived containers, each with a fresh throwaway data folder, published on this
# machine's 127.0.0.1 only (the first one; random ports) and nothing kept afterwards:
#
#   1. "unraid"  — exactly the flags of deploy/unraid/skwod.xml: started as root with only
#                  CHOWN+SETUID+SETGID, read-only root, waiting for the Start button. Its data
#                  folder is root-owned with 0700 directories, the layout a root-run
#                  `skwod restore` leaves (moving a skwod from a Mac). It must become healthy,
#                  print the one-time admin token, wait for Start, and run the server as 99:100
#                  (Unraid's nobody:users), not as root. Then Start is pressed (the admin page's
#                  own request) under the template's 768 MB limit: voice must come on — the live
#                  status, not the one from the start — with livekit-server running as 99.
#      "call"    — in that same container, a real call: a p2p member (skwod-core's `p2p_member`
#                  example) joins by its owner invite over the published UDP port, its minted room
#                  token is accepted by LiveKit through the tunnel, and two participants exchange
#                  demo video — one through the member's loopback forwarder, one inside the
#                  container's own network namespace (one network stack can hold one p2p member).
#                  Both must receive the other's track, and the tunnel must carry it both ways.
#                  SKIPPED, with the reason printed, unless all of these hold:
#                    SKWOD_SMOKE_MEMBER  is the built example
#                                        (cargo build --release -p skwod-core --example p2p_member)
#                    SKWOD_SMOKE_LK      is LiveKit's `lk` CLI for this Linux machine, its checksum
#                                        checked by whoever fetched it
#                    this is Linux       (the container must be able to run that `lk`)
#                  SKWOD_SMOKE_CALL=required turns the skip into a failure.
#   2. "started" — the deploy/docker-compose.yml posture (uid 1000, no capabilities at all)
#                  without the Start button, so the server starts at once: it must become
#                  healthy, print the admin token and the owner's join code, and run the bundled
#                  livekit-server (voice and video).
#
# Needs docker, curl and python3. No secret is printed. Exit 0 = every check passed. The p2p endpoint is left on (it needs outbound UDP
# only); it is not a check here, because CI runners' networks vary.
set -euo pipefail
# shellcheck disable=SC1091  # smoke-values.sh, next to this file
. "$(cd "$(dirname "$0")" && pwd)/smoke-values.sh"

IMAGE="${1:-${SKWOD_IMAGE:-}}"
[ -n "$IMAGE" ] || { echo "usage: $0 <image>" >&2; exit 2; }
TIMEOUT="${SKWOD_SMOKE_TIMEOUT:-120}"   # seconds per wait

TAG="skwod-smoke-$$"
CONTAINERS=()
WORK="$(mktemp -d)"
PIDS=()
cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" >/dev/null 2>&1 || true; done
  rm -rf "$WORK"
  for c in "${CONTAINERS[@]}"; do docker rm -f "$c" >/dev/null 2>&1 || true; done
  docker volume rm -f "$TAG-started" "$TAG-unraid" >/dev/null 2>&1 || true
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
# Read the whole log first: `grep -q` quitting early would SIGPIPE `docker logs` under pipefail.
logs_have() { local l; l="$(docker logs "$1" 2>&1)"; grep -Eq "$2" <<<"$l"; }
# Processes of the container, as "uid command" lines (docker top passes the options to ps,
# and needs the pid column).
procs() { docker top "$1" -o pid,uid,comm | awk 'NR > 1 { print $2, $3 }'; }
runs() { local p; p="$(procs "$1")"; awk -v c="$2" '$2 == c { found = 1 } END { exit !found }' <<<"$p"; }

show_logs() { echo "---- logs of $1 ----" >&2; docker logs "$1" 2>&1 | tail -n 40 >&2; echo "----" >&2; }

echo "smoke test: $IMAGE ($(docker image inspect -f '{{.Os}}/{{.Architecture}}' "$IMAGE" 2>/dev/null || echo 'not local yet'))"

# --- 1. the Unraid template's flags ------------------------------------------------------------
c="$TAG-unraid"; CONTAINERS+=("$c")
echo "1. unraid template flags (root → 99:100, waits for Start), root-owned 0700 data folder"
docker volume create "$TAG-unraid" >/dev/null
docker run --rm --user 0:0 --network none -v "$TAG-unraid:/d" --entrypoint /bin/sh "$IMAGE" -c \
  'chown 0:0 /d && chmod 700 /d && mkdir -m 700 /d/blobs /d/snapshots && echo x > /d/blobs/b && chmod 600 /d/blobs/b'
docker run -d --name "$c" \
  --user 0:0 --cap-drop=ALL --cap-add=CHOWN --cap-add=SETUID --cap-add=SETGID \
  --security-opt no-new-privileges:true --read-only --tmpfs /tmp:noexec,nosuid,size=64m \
  -e SKWOD_ADMIN_LISTEN=0.0.0.0:3477 -e SKWOD_WAIT_FOR_START=true -e SKWOD_P2P_PORT=47474 \
  -e SKWOD_RUN_AS=99:100 \
  --memory=768m -p 127.0.0.1::3477 -p 127.0.0.1::47474/udp \
  -v "$TAG-unraid:/data" "$IMAGE" >/dev/null
if wait_for "$TIMEOUT" healthy "$c"; then pass "healthy"; else fail "not healthy after ${TIMEOUT}s"; fi
if logs_have "$c" 'One-time admin token: [A-Z0-9]+(-[A-Z0-9]+)+'; then pass "one-time admin token in the log"; else fail "no admin token in the log"; fi
if logs_have "$c" 'Not serving yet'; then pass "waits for Start server"; else fail "did not wait for Start server"; fi
if logs_have "$c" 'data volume ownership: [0-9]+ entries given to 99:100' && ! logs_have "$c" 'could not be changed'; then
  pass "the whole root-owned data folder was given to 99:100"
else
  fail "the data folder was not fully re-owned"
fi
if awk '$2 == "skwod" && $1 == "99" { ok = 1 } END { exit !ok }' <<<"$(procs "$c")"; then
  pass "server runs as uid 99, not root"
else
  fail "server is not running as uid 99:"; procs "$c" >&2 || true
fi

# Press Start, the way the page does: the one-time token for a session, then one POST.
admin="http://$(docker port "$c" 3477/tcp | head -n 1)"
token="$(docker logs "$c" 2>&1 | sed -n 's/.*One-time admin token: \([A-Z0-9-]*\).*/\1/p' | head -n 1)"
page() { # page <method> <path> [json] — the answer's body; non-zero on anything but 2xx
  local args=(-fsS --max-time 60 -X "$1" -b "$WORK/cookies" -c "$WORK/cookies" -H 'x-skwod-admin: 1')
  [ -z "${3:-}" ] || args+=(-H 'content-type: application/json' --data-binary "@$3")
  curl "${args[@]}" "$admin$2"
}
field() { python3 -I -c 'import json,sys; v=json.load(sys.stdin)
for k in sys.argv[1].split("."): v=(v or {}).get(k)
print("" if v is None else v)' "$1"; }
(umask 077; printf '{"token":"%s"}' "$token" >"$WORK/login.json")
if page POST /admin/api/login "$WORK/login.json" >/dev/null && page POST /admin/api/start >/dev/null; then
  pass "Start server pressed through the admin page"
else
  fail "the admin page did not accept the token or Start"
fi
voice_on() { [ "$(page GET /admin/api/status | field voice_status)" = on ]; }
if wait_for "$TIMEOUT" voice_on; then
  pass "voice is on (live status), under 768 MB"
else
  fail "voice is not on: $(page GET /admin/api/status | field voice_reason)"
fi
if awk '$2 == "livekit-server" && $1 == "99" { ok = 1 } END { exit !ok }' <<<"$(procs "$c")"; then
  pass "livekit-server runs as uid 99"
else
  fail "livekit-server is not running as uid 99:"; procs "$c" >&2 || true
fi
if logs_have "$c" 'voice disabled'; then fail "the log says voice is disabled"; fi
if [ "$(docker inspect -f '{{.State.OOMKilled}}' "$c")" = false ]; then pass "within the memory limit"; else fail "the memory limit was hit"; fi

# --- a call through that container --------------------------------------------------------------
call_skip=""
[ "$(uname -s)" = Linux ] || call_skip="not Linux (the container could not run this machine's lk)"
[ -x "${SKWOD_SMOKE_LK:-}" ] || call_skip="SKWOD_SMOKE_LK is not set to the lk CLI"
[ -x "${SKWOD_SMOKE_MEMBER:-}" ] || call_skip="SKWOD_SMOKE_MEMBER is not set to the p2p_member example"
[ "$fails" = 0 ] || call_skip="the checks above failed"

call_test() {
  local link udp room url jwt uid key secret signal member="$WORK/member.log" a="$WORK/a.log" b="$TAG-b"
  # The owner's invite, as the page shows it to this machine; in the app's own scheme.
  link="$(page GET /admin/api/status | field invite.link)"
  link="$(sed -E 's#^https://[^/]*/join\#([a-z0-9]+)\.([A-Za-z0-9-]+).*#skwod://join/\1\#\2#' <<<"$link")"
  case "$link" in skwod://join/*) ;; *) fail "no owner invite on the admin page"; return ;; esac
  udp="$(docker port "$c" 47474/udp | head -n 1)"
  "$SKWOD_SMOKE_MEMBER" "$link" --no-fallback --addr "$udp" --user smoke --password "smoke-$RANDOM-$RANDOM" \
    --messages 1 --voice --hold 120 >"$member" 2>"$WORK/member.err" &
  PIDS+=("$!")
  if wait_for 60 grep -q '^LIVEKIT_TOKEN=' "$member"; then pass "a p2p member joined and got a room token"; else fail "no room token over p2p"; return; fi
  # All of it is the tested host's word (smoke-values.sh): of the expected shape, or not used.
  room="$(first_after 'voice room       : ' "$member")"
  url="$(first_after LIVEKIT_URL= "$member")"
  jwt="$(first_after LIVEKIT_TOKEN= "$member")"
  uid="$(sed -n 's/^signed in .*(\(.*\))$/\1/p' "$member" | head -n 1)"
  if ! is_name "$room" || ! is_name "$uid"; then fail "the room or the user is not a plain name"; return; fi
  is_tunnel_url "$url" || { fail "the call's address is not this machine's tunnel"; return; }
  is_jwt "$jwt" || { fail "the room token is not a token"; return; }
  # Real token, real signaling: LiveKit accepts the WebSocket through the tunnel.
  (umask 077; printf 'url = "%s/rtc?access_token=%s&protocol=15&sdk=go&version=2.0.0"\n' "${url/#ws:/http:}" "$jwt" >"$WORK/rtc.curl")
  curl -sS --http1.1 -i -N --max-time 4 -K "$WORK/rtc.curl" -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
    -H 'Sec-WebSocket-Version: 13' -H "Sec-WebSocket-Key: $(head -c 16 /dev/urandom | base64)" -o "$WORK/rtc.out" 2>/dev/null || true
  if head -n 1 "$WORK/rtc.out" | grep -q ' 101 '; then pass "its token opened signaling through the tunnel"; else fail "signaling was refused through the tunnel"; return; fi
  # Throwaway keys of a throwaway volume; read as the server's own user (0600), never printed.
  docker exec --user 99:100 "$c" cat /data/livekit.yaml >"$WORK/livekit.yaml"
  signal="$(first_after 'port: ' "$WORK/livekit.yaml")"
  key="$(sed -n '/^keys:/{n;s/^ *\([^:]*\):.*/\1/p;}' "$WORK/livekit.yaml" | head -n 1)"
  secret="$(sed -n '/^keys:/{n;s/^ *[^:]*: *//p;}' "$WORK/livekit.yaml" | head -n 1)"
  if ! is_livekit_key "$key" || ! is_livekit_key "$secret"; then fail "the container's LiveKit keys are not plain"; return; fi
  is_port "$signal" || { fail "the container's LiveKit port is not a port"; return; }
  CONTAINERS+=("$b")
  LIVEKIT_API_KEY="$key" LIVEKIT_API_SECRET="$secret" \
    docker run -d --name "$b" --network "container:$c" --user 65534:65534 --cap-drop=ALL --security-opt no-new-privileges:true \
    --read-only --tmpfs /tmp -e LIVEKIT_API_KEY -e LIVEKIT_API_SECRET -e HOME=/tmp -v "$SKWOD_SMOKE_LK:/lk:ro" --entrypoint /lk "$IMAGE" \
    room join --url "ws://127.0.0.1:$signal" --identity smoke-b --publish-demo --auto-subscribe "$room" >/dev/null
  (LIVEKIT_API_KEY="$key" LIVEKIT_API_SECRET="$secret" HOME="$WORK" \
   exec "$SKWOD_SMOKE_LK" room join --url "$url" --identity "$uid" --publish-demo --auto-subscribe "$room") >"$a" 2>&1 &
  PIDS+=("$!")
  if wait_for 60 grep -q 'track subscribed' "$a"; then pass "media arrives at the member through its loopback forwarder"; else fail "the member received no track"; fi
  if wait_for 60 logs_have "$b" 'track subscribed'; then pass "the member's media arrives at the other participant"; else fail "the other participant received no track"; fi
  # Bytes, not just subscriptions: well over what ICE and DTLS alone would move.
  carried() {
    sed -n 's/.*voice tunnel: up [0-9]* pkts \/ \([0-9]*\) kB, down [0-9]* pkts \/ \([0-9]*\) kB.*/\1 \2/p' "$member" | tail -n 1 |
      awk '{ ok = ($1 > 200 && $2 > 200) } END { exit !ok }'
  }
  if wait_for 60 carried; then pass "the tunnel carried media both ways"; else fail "the tunnel did not carry media both ways"; tail -n 2 "$member" | grep 'voice tunnel' >&2 || true; fi
}
if [ -z "$call_skip" ]; then
  echo "   a call through it"
  call_test
elif [ "${SKWOD_SMOKE_CALL:-}" = required ]; then
  fail "the call test is required but was not run: $call_skip"
else
  echo "  - call test skipped: $call_skip"
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
