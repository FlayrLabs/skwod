#!/usr/bin/env bash
# Tests for deny-expiry.py (the expiry gate on deny.toml's advisory ignores).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/skwod-deny-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
fails=0
run() { /usr/bin/python3 "$HERE/deny-expiry.py" "$@"; }
expect() { # <name> <want exit> <grep pattern or ''> <args…>
  local name="$1" want="$2" pat="$3" out got; shift 3
  out="$(run "$@" 2>&1)" && got=0 || got=$?
  if [ "$got" = "$want" ] && { [ -z "$pat" ] || grep -q "$pat" <<<"$out"; }; then echo "  ✓ $name"
  else echo "  ✗ $name (exit $got, wanted $want): $out" >&2; fails=$((fails + 1)); fi
}

cat > "$WORK/ok.toml" <<'EOF'
[advisories]
yanked = "deny"
ignore = [
    # --- a heading ---

    # Why it does not apply.
    # Expires 2027-02-28, or when the parent moves.
    { id = "RUSTSEC-2023-0071", reason = "only verifies signatures; no private key" },
    # Another. Expires 2027-01-31.
    { id = "RUSTSEC-2026-0459", reason = "directory is private to the server" },
]

[sources]
unknown-git = "deny"
EOF
expect "dated, reasoned ignores pass" 0 "2 advisory ignore" "$WORK/ok.toml" --today 2026-11-22
expect "the day an ignore expires it fails" 1 "RUSTSEC-2026-0459: ignore expired on 2027-01-31" "$WORK/ok.toml" --today 2027-01-31
expect "…and the other one is still fine that day" 1 "" "$WORK/ok.toml" --today 2027-02-01
expect "the day before, it passes with a warning" 0 "RUSTSEC-2026-0459: ignore expires on 2027-01-31 (1 days)" "$WORK/ok.toml" --today 2027-01-30

sed 's/# Another. Expires 2027-01-31./# Another, with no date./' "$WORK/ok.toml" > "$WORK/nodate.toml"
expect "an ignore with no expiry fails" 1 "RUSTSEC-2026-0459: no 'Expires" "$WORK/nodate.toml" --today 2026-11-22
# A date in ANOTHER entry's comment does not cover the next entry.
expect "…a neighbour's date does not count" 1 "RUSTSEC-2026-0459" "$WORK/nodate.toml" --today 2026-11-22

sed 's/, reason = "directory is private to the server"//' "$WORK/ok.toml" > "$WORK/noreason.toml"
expect "an ignore with no reason fails" 1 "no reason given" "$WORK/noreason.toml" --today 2026-11-22

sed 's/    { id = "RUSTSEC-2026-0459".*/    "RUSTSEC-2026-0459",/' "$WORK/ok.toml" > "$WORK/bare.toml"
expect "a bare id fails" 1 "bare id" "$WORK/bare.toml" --today 2026-11-22

printf '[advisories]\nignore = ["RUSTSEC-2026-0001"]\n' > "$WORK/oneline.toml"
expect "a one-line ignore list fails" 1 "one line" "$WORK/oneline.toml" --today 2026-11-22

printf '[advisories]\nignore = [\n]\n' > "$WORK/empty.toml"
expect "an empty ignore list passes" 0 "0 advisory ignore" "$WORK/empty.toml" --today 2026-11-22

# The real file: every entry dated (whether one has run out is today's business, not this test's).
expect "the repository's deny.toml is fully dated" 0 "advisory ignore" "$HERE/../../deny.toml" --today 2026-11-22

if [ "$fails" != "0" ]; then echo "✗ $fails deny-expiry test(s) failed" >&2; exit 1; fi
echo "✓ deny-expiry tests passed"
