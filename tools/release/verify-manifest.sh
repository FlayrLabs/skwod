#!/usr/bin/env bash
# Check a release manifest's signed statement the way the apps do, with nothing but openssl:
#
#   tools/release/verify-manifest.sh --pub <base64 raw Ed25519 public key> manifest.json \
#       [--build 46] [--apk-sha256 <hex>] [--apk-url <url>] [--testflight <url>] [--now <unix s>]
#
# Exit 0 only when the signature verifies against that key over
# "skwod-release-manifest-v1\n" + the statement bytes, the statement is not expired, the
# unsigned legacy fields say the same as the statement, and every expectation given matches.
# Prints the statement on success.
set -euo pipefail
PUB="" FILE="" BUILD="" SHA="" URL="" TESTFLIGHT="" NOW=""
while [ $# -gt 0 ]; do
  case "$1" in
    --pub) PUB="$2"; shift 2 ;; --build) BUILD="$2"; shift 2 ;; --apk-sha256) SHA="$2"; shift 2 ;;
    --apk-url) URL="$2"; shift 2 ;; --testflight) TESTFLIGHT="$2"; shift 2 ;; --now) NOW="$2"; shift 2 ;;
    -*) echo "verify-manifest.sh: unknown option $1" >&2; exit 2 ;;
    *) FILE="$1"; shift ;;
  esac
done
die() { echo "verify-manifest.sh: $*" >&2; exit 1; }
[ -n "$PUB" ] || die "--pub is required"
[ -s "$FILE" ] || die "no manifest file"
NOW="${NOW:-$(date +%s)}"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/skwod-manifest.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

/usr/bin/python3 - "$FILE" "$WORK" <<'PY' || die "the manifest has no signed statement"
import base64, json, sys
m = json.load(open(sys.argv[1]))
raw = base64.b64decode(m["signed"], validate=True)
sig = base64.b64decode(m["signed_sig"], validate=True)
assert len(sig) == 64
open(sys.argv[2] + "/statement", "wb").write(raw)
open(sys.argv[2] + "/msg", "wb").write(b"skwod-release-manifest-v1\n" + raw)
open(sys.argv[2] + "/sig", "wb").write(sig)
PY
{ printf '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00'; printf '%s' "$PUB" | base64 -d; } > "$WORK/pub.der"
[ "$(wc -c < "$WORK/pub.der" | tr -d ' ')" = "44" ] || die "--pub is not a 32-byte Ed25519 key in base64"
openssl pkeyutl -verify -pubin -inkey "$WORK/pub.der" -keyform DER -rawin -in "$WORK/msg" -sigfile "$WORK/sig" >/dev/null 2>&1 \
  || die "the statement's signature does NOT verify against the given key"

/usr/bin/python3 - "$FILE" "$WORK/statement" "$NOW" "$BUILD" "$SHA" "$URL" "$TESTFLIGHT" <<'PY' || die "the signed statement does not say what was expected"
import json, sys
m = json.load(open(sys.argv[1])); s = json.loads(open(sys.argv[2], "rb").read())
now, build, sha, url, testflight = sys.argv[3:8]
def need(ok, why):
    if not ok:
        print("verify-manifest.sh: " + why, file=sys.stderr); sys.exit(1)
need(s.get("v") == 1, "unknown statement version")
need(isinstance(s.get("issued"), int) and isinstance(s.get("expires"), int) and s["issued"] < s["expires"], "bad issued/expires")
need(int(now) < s["expires"], "the statement has expired")
a = s.get("android") or {}
if build: need(a.get("build") == int(build), "android build differs")
if sha: need(a.get("sha256") == sha, "apk sha256 differs")
if url: need(a.get("url") == url, "apk url differs")
if testflight:
    need((s.get("ios") or {}).get("testflight") == testflight, "ios link differs")
    need(s["ios"].get("build") == a.get("build"), "ios build differs from android build")
# The unsigned copies older builds read must not disagree with what was signed.
for k in ("build", "version", "file", "url", "sha256", "sig2", "notes"):
    need(m.get("android", {}).get(k) == a.get(k), f"unsigned android.{k} differs from the statement")
for k in ("build", "version", "testflight"):
    need((m.get("ios") or {}).get(k) == (s.get("ios") or {}).get(k), f"unsigned ios.{k} differs from the statement")
print(json.dumps(s, indent=2, sort_keys=True))
PY
