#!/usr/bin/env bash
# The vendored n0-mainline is the published 0.7.2 plus n0-mainline-0.7.2.patch, and nothing else.
#   verify.sh            # offline: the pinned hashes of the patch and of the vendored tree
#   verify.sh --online   # also: fetch the crate, check its pinned hash, apply the patch, compare; and the
#                        # release gate: no advisory for it, and no upstream version nobody has looked at
# (cargo-deny reads advisories for crates.io sources only, and so not for this one.)
set -euo pipefail
cd "$(dirname "$0")"
CRATE=n0-mainline VERSION=0.7.2 REVIEWED_UPSTREAM=0.8.0   # 0.8.0: the same receive loop, not fixed
CRATE_SHA=b46bd27a3729d0e94ca0ce610f72d0d71e5955d66e4f3d37241c56693fe41587
PATCH_SHA=bc5bc0041e307b4ce800bcc1db8ccec3b7338a2346d7dcff45b65acc85704870
TREE_SHA=49628e9460552a5e9e3ee4bc4d0eee34752bb7eec4dec5306b8412ae95d9f773
sha() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }
tree() { (cd "$1/" && find . -type f ! -path './target/*' ! -name Cargo.lock ! -name .cargo-ok | LC_ALL=C sort | while read -r f; do printf '%s  %s\n' "$(sha "$f" | cut -c1-64)" "$f"; done) | sha | cut -c1-64; }
fail() { echo "vendored $CRATE: $*" >&2; exit 1; }
[ "$(sha "$CRATE-$VERSION.patch" | cut -c1-64)" = "$PATCH_SHA" ] || fail "the patch is not the pinned one"
[ "$(tree "$CRATE")" = "$TREE_SHA" ] || fail "the vendored files are not the pinned ones"
[ "${1:-}" = --online ] || { echo "vendored $CRATE: pinned hashes match (offline)"; exit 0; }
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
curl -sfL -m 60 -o "$tmp/c" "https://static.crates.io/crates/$CRATE/$CRATE-$VERSION.crate"
[ "$(sha "$tmp/c" | cut -c1-64)" = "$CRATE_SHA" ] || fail "the published crate is not the pinned one"
tar xzf "$tmp/c" -C "$tmp"
(cd "$tmp/$CRATE-$VERSION" && patch -p1 -s) < "$CRATE-$VERSION.patch"
[ "$(tree "$tmp/$CRATE-$VERSION")" = "$TREE_SHA" ] || fail "published crate + patch is not what is vendored"
latest="$(curl -sf -m 60 -H 'User-Agent: release-check' "https://crates.io/api/v1/crates/$CRATE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["crate"]["max_version"])')"
[ "$latest" = "$REVIEWED_UPSTREAM" ] || fail "upstream is at $latest, last looked at: $REVIEWED_UPSTREAM (is the dead-socket loop fixed there? then drop this copy)"
body="$(printf '{"version":"%s","package":{"name":"%s","ecosystem":"crates.io"}}' "$VERSION" "$CRATE")"
[ "$(curl -sf -m 60 -d "$body" https://api.osv.dev/v1/query | tr -d '[:space:]')" = "{}" ] || fail "an advisory names $CRATE $VERSION"
echo "vendored $CRATE: published crate + patch, no advisory, upstream $latest looked at"
