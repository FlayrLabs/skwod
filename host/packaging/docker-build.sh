#!/usr/bin/env bash
# Run build.sh inside a container, so the host needs only Docker.
#
#   host/packaging/docker-build.sh linux|windows
#
# STATUS: not run yet (see build.sh). Packages land in host/dist/. The cargo registry and the
# build directory live in named volumes (skwod-host-cargo, skwod-host-target) so a second run is
# incremental; remove them with `docker volume rm` to get the disk back (a full build of the
# server needs roughly 3 GB there).
set -euo pipefail

WHAT="${1:?linux|windows}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NATIVE="$(cd "$HERE/../.." && pwd)"
# Debian 12: the oldest glibc the Linux package should run on. Pin by digest in CI.
IMAGE="${SKWOD_BUILD_IMAGE:-rust:1-bookworm}"

mkdir -p "$NATIVE/host/dist"
exec docker run --rm \
  -v "$NATIVE:/src:ro" \
  -v "$NATIVE/host/dist:/out" \
  -v skwod-host-cargo:/usr/local/cargo/registry \
  -v skwod-host-target:/target \
  -e CARGO_TARGET_DIR=/target \
  -w /src \
  "$IMAGE" /src/host/packaging/build.sh "$WHAT" /out
