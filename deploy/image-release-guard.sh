#!/usr/bin/env bash
# The release rules of .github/workflows/image.yml, as one testable script
# (deploy/test-image-release-guard.sh). Each subcommand exits non-zero, with a reason, when the
# rule is broken.
#
#   image-release-guard.sh build-number <ref name> <apps/apple/project.yml>
#       The ref must be a `skwod-v<n>` tag, and <n> must equal CURRENT_PROJECT_VERSION in the
#       project file at that commit. Prints <n>.
#   image-release-guard.sh on-main <commit> <main ref>
#       The commit must be on main (an ancestor of, or equal to, <main ref>). A tag pushed on a
#       commit that never went through a reviewed pull request is refused.
#   image-release-guard.sh newer <new build> [<build `latest` carries now>]
#       `latest` only moves forward: <new build> must be strictly greater than the current one.
#       An empty current build means nothing is published yet.
set -euo pipefail

die() { echo "image-release-guard: $*" >&2; exit 1; }
is_number() { [[ "$1" =~ ^[0-9]+$ ]]; }

cmd="${1:-}"; shift || true
case "$cmd" in
  build-number)
    [ $# = 2 ] || die "usage: build-number <ref name> <project.yml>"
    ref="$1"; project="$2"
    [[ "$ref" =~ ^skwod-v([0-9]+)$ ]] || die "'$ref' is not a release tag (skwod-v<n>); run the workflow on a tag"
    n="${BASH_REMATCH[1]}"
    [ -f "$project" ] || die "no $project"
    src="$(sed -nE 's/^ *CURRENT_PROJECT_VERSION: *"([0-9]+)".*/\1/p' "$project" | head -n 1)"
    is_number "$src" || die "no CURRENT_PROJECT_VERSION in $project"
    [ "$((10#$n))" = "$((10#$src))" ] || die "tag says build $n, but this commit is build $src ($project)"
    echo "$((10#$n))"
    ;;
  on-main)
    [ $# = 2 ] || die "usage: on-main <commit> <main ref>"
    git cat-file -e "$1^{commit}" 2>/dev/null || die "unknown commit $1"
    git cat-file -e "$2^{commit}" 2>/dev/null || die "unknown ref $2 (fetch main first)"
    git merge-base --is-ancestor "$1" "$2" || die "commit $1 is not on main ($2): release tags must point at merged commits"
    echo "on main: $1"
    ;;
  newer)
    [ $# -ge 1 ] && [ $# -le 2 ] || die "usage: newer <new build> [<current latest build>]"
    new="$1"; cur="${2:-}"
    is_number "$new" || die "new build '$new' is not a number"
    if [ -z "$cur" ]; then echo "latest: none yet → $new"; exit 0; fi
    is_number "$cur" || die "the current latest carries build '$cur', not a number; refusing to move it"
    [ "$((10#$new))" -gt "$((10#$cur))" ] || die "latest is build $cur; build $new is not newer, so latest stays where it is"
    echo "latest: $cur → $new"
    ;;
  *) die "usage: $0 build-number|on-main|newer …" ;;
esac
