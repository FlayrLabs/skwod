#!/usr/bin/env bash
# Check an image reference before you run it as your skwod server.
#
#   deploy/verify-image.sh ghcr.io/flayrlabs/skwod-server@sha256:<64 hex>
#   deploy/verify-image.sh --format-only <reference>     # no network, no cosign: the pin only
#
# 1. The reference must be pinned BY DIGEST. A tag (`:main`, `:latest`, `:v46`) is a name the
#    registry can point anywhere; a digest is the image's own hash, and Docker refuses content
#    that does not match it.
# 2. The digest must carry a cosign signature made by the release workflow of the source
#    repository (keyless: a short-lived certificate from Sigstore's Fulcio, bound to the GitHub
#    Actions identity below, recorded in the Rekor transparency log). Needs `cosign` >= 3 (the
#    workflow signs with cosign 3's bundle format).
#
# An image you built yourself (`docker build -t skwod-server .`) needs none of this: you are
# the publisher. See docs/SELF-HOSTING.md.
set -euo pipefail

# Who must have signed: the image workflow (.github/workflows/image.yml) of the source repository,
# run on a `skwod-v<n>` release tag. The certificate's identity (workflow path + repository + tag
# ref), its GitHub repository extension and its issuer are all checked.
IDENTITY_REGEXP="${SKWOD_IMAGE_IDENTITY_REGEXP:-^https://github\.com/FlayrLabs/skwod/\.github/workflows/image\.yml@refs/tags/skwod-v[0-9]+$}"
REPOSITORY="${SKWOD_IMAGE_REPOSITORY:-FlayrLabs/skwod}"
OIDC_ISSUER="https://token.actions.githubusercontent.com"

FORMAT_ONLY=0
if [ "${1:-}" = "--format-only" ]; then FORMAT_ONLY=1; shift; fi
REF="${1:-${SKWOD_IMAGE:-}}"
[ -n "$REF" ] || { echo "usage: $0 [--format-only] <image@sha256:digest>" >&2; exit 2; }

if ! [[ "$REF" =~ ^[a-z0-9]([a-z0-9._/:-]*[a-z0-9])?@sha256:[0-9a-f]{64}$ ]]; then
  echo "✗ $REF is not pinned by digest." >&2
  echo "  Use <name>@sha256:<64 hex digits>. A tag can be moved by whoever can push to the registry." >&2
  exit 1
fi
echo "✓ pinned by digest"
[ "$FORMAT_ONLY" = "1" ] && exit 0

command -v cosign >/dev/null 2>&1 || { echo "✗ cosign is not installed (https://docs.sigstore.dev/cosign/system_config/installation/)" >&2; exit 2; }
if cosign verify "$REF" --certificate-identity-regexp "$IDENTITY_REGEXP" --certificate-oidc-issuer "$OIDC_ISSUER" \
     --certificate-github-workflow-repository "$REPOSITORY" >/dev/null; then
  echo "✓ signed by the skwod release workflow ($IDENTITY_REGEXP)"
else
  echo "✗ no valid signature by the skwod release workflow on $REF — do not run it." >&2
  exit 1
fi
