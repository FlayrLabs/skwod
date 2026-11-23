#!/usr/bin/env bash
# Write the release manifest (manifest.json) with a SIGNED STATEMENT of what the release is.
#
#   tools/release/sign-manifest.sh --key <ed25519.pem> --build 46 --version 0.1.0 \
#       --apk-file skwod-46.apk --apk-url https://…/skwod-46.apk --apk-sha256 <hex> \
#       [--notes "…"] [--testflight https://testflight.apple.com/join/…] [--commit <sha>] \
#       [--valid-days 120] [--now <unix seconds>]   > manifest.json
#
# The manifest has two layers:
#
#   "signed"      base64 of the statement: a small JSON document naming, for each platform, the
#                 build number, version, download (apk url + SHA-256), release notes and — for
#                 iOS — the TestFlight / App Store link, plus when it was issued, when it stops
#                 being fresh, and the source commit it was built from.
#   "signed_sig"  base64 Ed25519 signature by the update publisher key over
#                 "skwod-release-manifest-v1\n" followed by exactly those statement bytes.
#
#   "android", "ios"   the same facts once more, UNSIGNED, in the shape earlier builds read.
#                 Builds that know the statement never read these (apart from Android < 13,
#                 which cannot check Ed25519 and takes only the bare build number from them).
#
# The apps verify the signature over the bytes as they arrive and only then parse them, so
# there is no canonical-JSON question: what was signed is what is read.
set -euo pipefail

KEY="" BUILD="" VERSION="" APK_FILE="" APK_URL="" APK_SHA="" NOTES="" TESTFLIGHT="" COMMIT="" VALID_DAYS=120 NOW=""
while [ $# -gt 0 ]; do
  case "$1" in
    --key) KEY="$2" ;; --build) BUILD="$2" ;; --version) VERSION="$2" ;;
    --apk-file) APK_FILE="$2" ;; --apk-url) APK_URL="$2" ;; --apk-sha256) APK_SHA="$2" ;;
    --notes) NOTES="$2" ;; --testflight) TESTFLIGHT="$2" ;; --commit) COMMIT="$2" ;;
    --valid-days) VALID_DAYS="$2" ;; --now) NOW="$2" ;;
    *) echo "sign-manifest.sh: unknown option $1" >&2; exit 2 ;;
  esac
  shift 2
done
die() { echo "sign-manifest.sh: $*" >&2; exit 1; }
[ -s "$KEY" ] || die "--key: no such key file"
[[ "$BUILD" =~ ^[0-9]+$ ]] || die "--build must be a number"
[ -n "$VERSION" ] || die "--version is required"
[[ "$APK_SHA" =~ ^[0-9a-f]{64}$ ]] || die "--apk-sha256 must be 64 lowercase hex digits"
[[ "$APK_URL" == https://* ]] || die "--apk-url must be https"
[ -n "$APK_FILE" ] || die "--apk-file is required"
[[ "$VALID_DAYS" =~ ^[0-9]+$ ]] && [ "$VALID_DAYS" -ge 1 ] || die "--valid-days must be a positive number"
# The only places an iOS "update" may lead. The apps check this again; refusing here keeps a
# typo from being signed.
if [ -n "$TESTFLIGHT" ]; then
  [[ "$TESTFLIGHT" =~ ^https://(testflight\.apple\.com|apps\.apple\.com)/[A-Za-z0-9/._-]+$ ]] \
    || die "--testflight must be an https://testflight.apple.com/… or https://apps.apple.com/… link"
fi
[ -z "$COMMIT" ] || [[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]] || die "--commit must be a full 40-hex commit id"
NOW="${NOW:-$(date +%s)}"
[[ "$NOW" =~ ^[0-9]+$ ]] || die "--now must be unix seconds"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/skwod-manifest.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# The two apk signatures (see package-release.sh): `sig` over the raw digest for builds <= 45,
# `sig2` over "skwod-android-update-v2\n<build>\n" + digest for build 46+.
printf '%s' "$APK_SHA" | xxd -r -p > "$WORK/apk.digest"
openssl pkeyutl -sign -rawin -inkey "$KEY" -in "$WORK/apk.digest" -out "$WORK/apk.sig"
{ printf 'skwod-android-update-v2\n%s\n' "$BUILD"; cat "$WORK/apk.digest"; } > "$WORK/apk.msg2"
openssl pkeyutl -sign -rawin -inkey "$KEY" -in "$WORK/apk.msg2" -out "$WORK/apk.sig2"
SIG=$(base64 < "$WORK/apk.sig" | tr -d '\n')
SIG2=$(base64 < "$WORK/apk.sig2" | tr -d '\n')

/usr/bin/python3 - "$WORK/statement" "$BUILD" "$VERSION" "$APK_FILE" "$APK_URL" "$APK_SHA" "$SIG2" "$NOTES" "$TESTFLIGHT" "$COMMIT" "$NOW" "$VALID_DAYS" <<'PY'
import json, sys
out, build, version, apk, url, sha, sig2, notes, testflight, commit, now, days = sys.argv[1:13]
s = {"v": 1, "issued": int(now), "expires": int(now) + int(days) * 86400,
     "android": {"build": int(build), "version": version, "file": apk, "url": url,
                 "sha256": sha, "sig2": sig2, "notes": notes}}
if commit:
    s["commit"] = commit
if testflight:
    s["ios"] = {"build": int(build), "version": version, "testflight": testflight, "notes": notes}
open(out, "wb").write(json.dumps(s, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii"))
PY
{ printf 'skwod-release-manifest-v1\n'; cat "$WORK/statement"; } > "$WORK/statement.msg"
openssl pkeyutl -sign -rawin -inkey "$KEY" -in "$WORK/statement.msg" -out "$WORK/statement.sig"

/usr/bin/python3 - "$WORK/statement" "$WORK/statement.sig" "$SIG" <<'PY'
import base64, json, sys
raw = open(sys.argv[1], "rb").read()
s = json.loads(raw)
legacy_android = dict(s["android"], sig=sys.argv[3])
m = {"android": legacy_android}
if "ios" in s:
    m["ios"] = {k: s["ios"][k] for k in ("build", "version", "testflight")}
m["signed"] = base64.b64encode(raw).decode()
m["signed_sig"] = base64.b64encode(open(sys.argv[2], "rb").read()).decode()
print(json.dumps(m, indent=2))
PY
