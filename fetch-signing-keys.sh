#!/usr/bin/env bash
# Restore the gitignored release-signing keys from an Infisical project onto this machine. Run
# once on a new build box (or after a wipe) before ./package-release.sh.
#
#   ./fetch-signing-keys.sh           # write any key that is missing locally
#   ./fetch-signing-keys.sh --check   # compare local files against the secret store, write nothing
#   ./fetch-signing-keys.sh --force   # overwrite local files with the stored copy
#
# Nothing about where the keys live is in this file. Say where with the environment, or with a
# `signing.env` file next to this script (gitignored; plain KEY=value lines, sourced by bash):
#
#   SKWOD_SECRETS_URL         base URL of the Infisical instance, e.g. https://secrets.example.com
#   SKWOD_SECRETS_WORKSPACE   the Infisical project (workspace) id
#   SKWOD_SECRETS_PATH        the folder that holds the four secrets below
#   SKWOD_SECRETS_ENV         environment slug (default: prod)
#   INFISICAL_TOKEN           an access token, or
#   INFISICAL_TOKEN_FILE      a file that contains one
#
# Each secret is the base64 of the file's exact bytes. The keys never go in git — see
# RELEASE-SIGNING.md. If you build your own fork you need your OWN keys (and your own name and
# icons — TRADEMARKS.md); this script is only a convenience for restoring them.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
MODE="${1:-}"

# shellcheck source=/dev/null
[ -f "$HERE/signing.env" ] && . "$HERE/signing.env"

need() { [ -n "${!1:-}" ] || { echo "✗ $1 is not set (environment or signing.env — see the header of $0)" >&2; exit 1; }; }
need SKWOD_SECRETS_URL
need SKWOD_SECRETS_WORKSPACE
need SKWOD_SECRETS_PATH
# https only. The request carries the store's access token and the answer is every release
# key: a mistyped http:// (or a redirect to one) would put both on the wire in clear.
case "$SKWOD_SECRETS_URL" in
  https://*) ;;
  *) echo "✗ SKWOD_SECRETS_URL must start with https:// (refusing to send the access token anywhere else)" >&2; exit 1 ;;
esac
SECRETS_ENV="${SKWOD_SECRETS_ENV:-prod}"
TOKEN="${INFISICAL_TOKEN:-}"
if [ -z "$TOKEN" ] && [ -n "${INFISICAL_TOKEN_FILE:-}" ]; then TOKEN="$(cat "$INFISICAL_TOKEN_FILE")"; fi
[ -n "$TOKEN" ] || { echo "✗ no access token (set INFISICAL_TOKEN or INFISICAL_TOKEN_FILE)" >&2; exit 1; }

# secret name -> local path
KEYS="ANDROID_RELEASE_KEYSTORE_B64:apps/android/skwod-release.keystore
ANDROID_KEYSTORE_PROPERTIES_B64:apps/android/keystore.properties
UPDATE_PUBLISHER_KEY_PEM_B64:apps/android/update_publisher_key.pem
SPARKLE_PRIVATE_KEY_PEM_B64:apps/apple/sparkle_private_key.pem"

# The access token goes to curl in a 0600 header file, never on its command line (a process's
# arguments are visible to every user on the machine through `ps`). `printf` is a shell builtin.
AUTH=$(mktemp); chmod 600 "$AUTH"
printf 'Authorization: Bearer %s\n' "$TOKEN" > "$AUTH"

fetch() { # $1 = secret name, $2 = output file (bytes decoded from base64)
  curl -fsS --proto '=https' --proto-redir '=https' --max-redirs 0 -G -H @"$AUTH" \
    --data-urlencode "workspaceId=$SKWOD_SECRETS_WORKSPACE" \
    --data-urlencode "environment=$SECRETS_ENV" \
    --data-urlencode "secretPath=$SKWOD_SECRETS_PATH" \
    "${SKWOD_SECRETS_URL%/}/api/v3/secrets/raw/$1" |
    /usr/bin/python3 -c 'import json,sys,base64; sys.stdout.buffer.write(base64.b64decode(json.load(sys.stdin)["secret"]["secretValue"]))' > "$2"
}

TMP=$(mktemp); chmod 600 "$TMP"; trap 'rm -f "$TMP" "$AUTH"' EXIT
fail=0
while IFS=: read -r name rel; do
  dest="$HERE/$rel"
  fetch "$name" "$TMP" || { echo "✗ $rel: fetch of $name failed"; fail=1; continue; }
  if [ -f "$dest" ] && cmp -s "$TMP" "$dest"; then
    echo "✓ $rel matches the secret store"
  elif [ "$MODE" = "--check" ]; then
    if [ -f "$dest" ]; then echo "✗ $rel DIFFERS from the secret store"; else echo "✗ $rel missing locally"; fi
    fail=1
  elif [ -f "$dest" ] && [ "$MODE" != "--force" ]; then
    echo "✗ $rel differs from the secret store — left alone (re-run with --force to overwrite)"
    fail=1
  else
    install -m 600 "$TMP" "$dest"
    echo "↓ $rel written from the secret store"
  fi
done <<< "$KEYS"
exit $fail
