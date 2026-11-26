# shellcheck shell=bash
# What smoke-test-image.sh takes from the image it tests, and from the host inside it: data, never
# code. Each value is one line of the expected shape or it is not used at all.
# Sourced; tests: test-smoke-values.sh.

# first_after <prefix> <file>: the rest of the FIRST line that starts with <prefix>, as written.
first_after() { awk -v p="$1" 'index($0, p) == 1 { print substr($0, length(p) + 1); exit }' "$2"; }

# (A newline is in none of the classes below, and `$` is the end of the whole value.)
_is() { local LC_ALL=C; [[ "$1" =~ $2 ]]; }
is_livekit_key() { _is "$1" '^[A-Za-z0-9_+/=-]+$'; }
is_port() { _is "$1" '^[1-9][0-9]{0,4}$' && [ "$1" -le 65535 ]; }
is_jwt() { _is "$1" '^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$'; }
is_tunnel_url() { _is "$1" '^ws://127\.0\.0\.1:[0-9]+/[A-Za-z0-9/_-]+$'; }
# A room or a user id: never an option of a command it is passed to.
is_name() { _is "$1" '^[A-Za-z0-9][A-Za-z0-9_-]*$'; }
