#!/usr/bin/env bash
# Tests for smoke-values.sh: what a hostile image could print where the smoke test reads. No network,
# no docker.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091  # smoke-values.sh, next to this file
. "$HERE/smoke-values.sh"
fails=0
ok() { if "$@"; then echo "  ✓ $*"; else printf '  ✗ should pass: %q\n' "$*" >&2; fails=$((fails + 1)); fi; }
no() { if "$@"; then printf '  ✗ should refuse: %q\n' "$*" >&2; fails=$((fails + 1)); else printf '  ✓ refused: %q\n' "$*"; fi; }
eq() { if [ "$1" = "$2" ]; then echo "  ✓ $1"; else printf '  ✗ %q is not %q\n' "$1" "$2" >&2; fails=$((fails + 1)); fi; }
NL=$'\n'
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

echo "key and secret"
ok is_livekit_key APIabc123; ok is_livekit_key 'a+b/c_d-e=='
# shellcheck disable=SC2016  # as it would be written
for v in '' '$(touch x)' '`id`' 'a;id' 'a b' "a'b" 'a"b' "a${NL}PATH=/tmp" 'a$IFS' 'é'; do no is_livekit_key "$v"; done

echo "signal port"
ok is_port 7880; ok is_port 65535
# shellcheck disable=SC2016
for v in '' 0 65536 99999 123456 '7880 -v' "7880${NL}1" 0x1 -1 08 7a '$x'; do no is_port "$v"; done

echo "room token"
ok is_jwt eyJh.eyJ2.s_-1
for v in '' a.b a.b.c.d 'a.b.c"' "a.b.c${NL}output = /tmp/x" 'a.b.c&x' 'a b.c.d' '..' 'a..c'; do no is_jwt "$v"; done

echo "tunnel address"
ok is_tunnel_url ws://127.0.0.1:50123/s3cret_-/livekit
for v in '' ws://127.0.0.1:1/ ws://127.0.0.1/x wss://127.0.0.1:1/x ws://127.0.0.1:1x/y ws://127a0b0c1:1/x ws://10.0.0.1:1/x \
         'ws://127.0.0.1:1/x"' 'ws://127.0.0.1:1/x?y' "ws://127.0.0.1:1/x${NL}output = /etc/x" 'ws://127.0.0.1:1/../x' 'ws://127.0.0.1:1@evil/x' \
         'file:///etc/passwd' 'ws://127.0.0.1:1/x y'; do no is_tunnel_url "$v"; done

echo "room and user"
ok is_name 5f3c-a_1; ok is_name 0198
for v in '' -x --url _a 'a b' "a${NL}b" 'a"' 'a/b' 'a;b'; do no is_name "$v"; done

echo "first line only"
printf 'noise\nxLIVEKIT_TOKEN=no\nLIVEKIT_TOKEN=a.b.c\nLIVEKIT_TOKEN=evil\nLIVEKIT_URL=\n' >"$T/member"
eq "$(first_after LIVEKIT_TOKEN= "$T/member")" a.b.c
eq "$(first_after LIVEKIT_URL= "$T/member")" ''
eq "$(first_after NOT_THERE= "$T/member")" ''

[ "$fails" = 0 ] || { echo "$fails failed" >&2; exit 1; }
echo "all passed"
