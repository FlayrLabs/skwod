#!/usr/bin/env bash
# Tests for sign-manifest.sh / verify-manifest.sh. Uses a THROWAWAY key made here; needs
# OpenSSL 3+ and python3. `--write-fixture` also rewrites the fixture the Kotlin and Swift
# updater tests verify (tools/release/fixtures/), so all three implementations are held to
# the same bytes.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/skwod-manifest-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
fails=0
ok() { echo "  ✓ $1"; }
bad() { echo "  ✗ $1" >&2; fails=$((fails + 1)); }
expect_ok() { local name="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi; }
expect_fail() { local name="$1"; shift; if "$@" >/dev/null 2>&1; then bad "$name"; else ok "$name"; fi; }

openssl genpkey -algorithm ed25519 -out "$WORK/key.pem" 2>/dev/null
openssl genpkey -algorithm ed25519 -out "$WORK/other.pem" 2>/dev/null
pub() { openssl pkey -in "$1" -pubout -outform DER | tail -c 32 | base64; }
PUB="$(pub "$WORK/key.pem")"; OTHER="$(pub "$WORK/other.pem")"
SHA="$(printf 'apk bytes' | shasum -a 256 | awk '{print $1}')"
URL="https://github.com/FlayrLabs/skwod-releases/releases/download/v46/skwod-46.apk"
TF="https://testflight.apple.com/join/AbCd1234"
NOW=1800000000
# shellcheck disable=SC2120  # extra options are appended by some callers
sign() { "$HERE/sign-manifest.sh" --key "$WORK/key.pem" --build 46 --version 0.1.0 --apk-file skwod-46.apk \
  --apk-url "$URL" --apk-sha256 "$SHA" --notes 'Fixes "things" & more.' --testflight "$TF" \
  --commit 0123456789abcdef0123456789abcdef01234567 --now "$NOW" "$@"; }
verify() { "$HERE/verify-manifest.sh" --pub "$PUB" --now "$((NOW + 60))" "$@"; }

# shellcheck disable=SC2119
sign > "$WORK/manifest.json"
expect_ok "a signed manifest verifies" verify "$WORK/manifest.json" --build 46 --apk-sha256 "$SHA" --apk-url "$URL" --testflight "$TF"
expect_fail "…not against another key" "$HERE/verify-manifest.sh" --pub "$OTHER" --now "$NOW" "$WORK/manifest.json"
expect_fail "…not as another build" verify "$WORK/manifest.json" --build 47
expect_fail "…not with another iOS link" verify "$WORK/manifest.json" --testflight "https://testflight.apple.com/join/EVIL"
expect_fail "…not once it has expired" "$HERE/verify-manifest.sh" --pub "$PUB" --now "$((NOW + 121 * 86400))" "$WORK/manifest.json"

# Tampering with the statement breaks the signature; tampering with the unsigned copy is noticed.
/usr/bin/python3 - "$WORK/manifest.json" "$WORK" <<'PY'
import base64, json, sys
m = json.load(open(sys.argv[1])); d = sys.argv[2]
s = json.loads(base64.b64decode(m["signed"]))
s["ios"]["testflight"] = "https://testflight.apple.com/join/EVIL"
t = dict(m, signed=base64.b64encode(json.dumps(s, sort_keys=True, separators=(",", ":")).encode()).decode())
json.dump(t, open(d + "/tampered-statement.json", "w"))
u = json.loads(json.dumps(m)); u["ios"]["testflight"] = "https://testflight.apple.com/join/EVIL"
json.dump(u, open(d + "/tampered-legacy.json", "w"))
n = {k: v for k, v in m.items() if k not in ("signed", "signed_sig")}
json.dump(n, open(d + "/unsigned.json", "w"))
PY
expect_fail "a rewritten statement is refused" verify "$WORK/tampered-statement.json"
expect_fail "a rewritten unsigned iOS link is refused" verify "$WORK/tampered-legacy.json"
expect_fail "a manifest without a statement is refused" verify "$WORK/unsigned.json"

# What gets signed must be sane.
expect_fail "an iOS link outside Apple's hosts is never signed" sign --testflight "https://testflight.apple.com.evil.example/join/x"
expect_fail "an http iOS link is never signed" sign --testflight "http://testflight.apple.com/join/x"
expect_fail "an http apk url is never signed" sign --apk-url "http://github.com/x.apk"
expect_fail "a short commit id is never signed" sign --commit abc123

# The legacy fields older builds read are still there, and say the same.
expect_ok "legacy android/ios fields are kept for older builds" /usr/bin/python3 - "$WORK/manifest.json" "$SHA" "$TF" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
a = m["android"]
assert a["build"] == 46 and a["sha256"] == sys.argv[2] and len(a["sig"]) == 88 and len(a["sig2"]) == 88
assert m["ios"] == {"build": 46, "version": "0.1.0", "testflight": sys.argv[3]}
PY

if [ "${1:-}" = "--write-fixture" ]; then
  mkdir -p "$HERE/fixtures"
  cp "$WORK/manifest.json" "$HERE/fixtures/manifest-v1.json"
  printf '%s\n' "$PUB" > "$HERE/fixtures/manifest-v1.pub"
  echo "  ↻ wrote tools/release/fixtures/manifest-v1.{json,pub} (throwaway key; issued $NOW)"
elif [ -s "$HERE/fixtures/manifest-v1.json" ]; then
  # The committed fixture is what the Kotlin and Swift tests read: it must still verify.
  expect_ok "the committed fixture verifies with its own key" "$HERE/verify-manifest.sh" \
    --pub "$(cat "$HERE/fixtures/manifest-v1.pub")" --now "$((NOW + 60))" "$HERE/fixtures/manifest-v1.json" --build 46 --testflight "$TF"
fi

if [ "$fails" != "0" ]; then echo "✗ $fails sign-manifest test(s) failed" >&2; exit 1; fi
echo "✓ sign-manifest tests passed"
