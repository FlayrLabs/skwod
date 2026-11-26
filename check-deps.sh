#!/usr/bin/env bash
# Supply-chain gate for the Skwod native tree. `package-release.sh` runs it and refuses to
# package on a failure; CI runs the same command. Non-interactive; exit 0 = every check passed,
# 1 = at least one failed, 2 = a required tool is missing (also a failure for a gate).
#
#   ./check-deps.sh                # everything
#   ./check-deps.sh --static-only  # only the checks that need no cargo and no network (says so)
#
# Static (no network, no cargo):
#   1. every advisory ignore in deny.toml has a reason and an `Expires YYYY-MM-DD` that has not
#      passed (tools/release/deny-expiry.py — cargo-deny itself never expires an ignore);
#   2. every cargo invocation in a script that produces something we ship passes `--locked`;
#   3. every git dependency in a lockfile is one of the exact repository+commit pairs below
#      (cargo-deny can only allow a repository, not a commit);
#   4. the committed Gradle wrapper jar is a genuine Gradle release artifact, and the wrapper
#      pins the distribution it downloads by SHA-256;
#   5. npm lockfiles resolve to the npm registry only, with an integrity hash on every package;
#   6. container pins: every Dockerfile `FROM` is by digest, and the deploy bundle names no
#      mutable image tag (deploy/test-verify-image.sh).
# Needs cargo + network:
#   (6b also fetches the crate and asks for advisories and newer versions;)
#   6b. the vendored n0-mainline is the pinned patch on the pinned crate (core/vendor/verify.sh);
#   7. every Cargo.lock is in sync with its manifests (`cargo metadata --locked`);
#   8. `cargo deny check` (advisories, licences, sources, bans — policy in deny.toml) in each
#      Rust workspace;
#   9. `npm audit --audit-level=high` on the push gateway's lockfile.
#
# NOT covered by anything here (RELEASE-SIGNING.md, "Provenance and reproducible builds"):
# Gradle/Maven artifacts (no verification-metadata.xml; JitPack is enabled) and Swift packages
# beyond the exact versions in Package.resolved.
#
# Needs: python3, shasum; for the full run also cargo, cargo-deny
# (cargo install --locked cargo-deny) and npm.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
STATIC_ONLY=0
case "${1:-}" in
  "") ;;
  --static-only) STATIC_ONLY=1 ;;
  *) echo "usage: $0 [--static-only]" >&2; exit 2 ;;
esac
fail=0
bad() { echo "✗ $*"; fail=1; }

# The only git sources allowed, exactly as Cargo.lock records them (URL, requested ref, resolved
# commit). Bumping libsignal means changing these on purpose, in the same commit.
ALLOWED_GIT_SOURCES='git+https://github.com/signalapp/libsignal?rev=8be00c282001caa3585d18de0f044c6d500348ab#8be00c282001caa3585d18de0f044c6d500348ab
git+https://github.com/signalapp/SparsePostQuantumRatchet.git?tag=v1.7.0#3a69df8f01179fce970693f072b710a8ab8dc6c2'

echo "==> advisory ignores: reasons and expiry dates"
/usr/bin/env python3 "$HERE/tools/release/deny-expiry.py" "$HERE/deny.toml" || fail=1

echo "==> release builds use --locked"
# Every script (and the Dockerfile) whose output ships. A cargo build/run/rustc/ndk line
# without --locked would let cargo re-resolve and silently pick up a dependency version that
# no lockfile, and so no review and no cargo-deny run, ever saw.
LOCKED_FILES=(apps/apple/build-core.sh apps/apple/bundle-host-tools.sh apps/android/build-core.sh host/packaging/build.sh Dockerfile)
unlocked="$(cd "$HERE" && /usr/bin/env python3 - "${LOCKED_FILES[@]}" <<'PY'
import re, sys
for path in sys.argv[1:]:
    try:
        lines = open(path, encoding="utf-8").read().splitlines()
    except OSError:
        print(f"{path}: missing (update LOCKED_FILES in check-deps.sh)"); continue
    for n, line in enumerate(lines, 1):
        code = line.split("#", 1)[0]
        if re.search(r"\bcargo\s+(ndk\b.*\bbuild|build|run|rustc|install)\b", code) and "--locked" not in code:
            print(f"{path}:{n}: {line.strip()}")
PY
)"
if [ -n "$unlocked" ]; then
  bad "cargo is invoked without --locked in a release build:"
  while IFS= read -r line; do echo "    $line"; done <<<"$unlocked"
else
  echo "✓ every release cargo invocation passes --locked"
fi

for ws in core server host; do
  echo "==> $ws: git sources pinned to the allowed commits"
  unexpected="$(sed -n 's/^source = "\(git+.*\)"$/\1/p' "$HERE/$ws/Cargo.lock" | sort -u | grep -vxF "$ALLOWED_GIT_SOURCES" || true)"
  if [ -n "$unexpected" ]; then
    bad "$ws/Cargo.lock has a git source that is not an allowed repository+commit:"
    while IFS= read -r line; do echo "    $line"; done <<<"$unexpected"
  fi
done

echo "==> vendored n0-mainline"
# Hashes always; with the network also the published crate, advisories (cargo-deny reads none for a
# crate that is not from crates.io) and upstream versions nobody has looked at.
if [ "$STATIC_ONLY" = "1" ]; then "$HERE/core/vendor/verify.sh" || fail=1; else "$HERE/core/vendor/verify.sh" --online || fail=1; fi

echo "==> Gradle wrapper"
PROPS="$HERE/apps/android/gradle/wrapper/gradle-wrapper.properties"
JAR="$HERE/apps/android/gradle/wrapper/gradle-wrapper.jar"
grep -q '^distributionSha256Sum=[0-9a-f]\{64\}$' "$PROPS" || bad "gradle-wrapper.properties does not pin distributionSha256Sum"
grep -q '^validateDistributionUrl=true$' "$PROPS" || bad "gradle-wrapper.properties: validateDistributionUrl is not true"
# SHA-256 of the committed gradle-wrapper.jar, which must equal a checksum Gradle publishes at
# https://services.gradle.org/distributions/gradle-<version>-wrapper.jar.sha256 . This value was
# recorded for the jar that shipped with Gradle 8.7/8.8; the wrapper now DOWNLOADS 8.9 (pinned
# by distributionSha256Sum above), and whether 8.9 publishes the same wrapper jar hash has not
# been re-checked against gradle.org — do that when the wrapper is next regenerated.
WRAPPER_JAR_SHA256="cb0da6751c2b753a16ac168bb354870ebb1e162e9083f116729cec9c781156b8"
actual="$(shasum -a 256 "$JAR" | awk '{print $1}')"
if [ "$actual" != "$WRAPPER_JAR_SHA256" ]; then
  bad "gradle-wrapper.jar is not the expected Gradle release artifact (sha256 $actual)"
  echo "  If the wrapper was upgraded on purpose, update WRAPPER_JAR_SHA256 from"
  echo "  https://services.gradle.org/distributions/gradle-<version>-wrapper.jar.sha256"
else
  echo "✓ gradle-wrapper.jar matches the recorded Gradle checksum"
fi

echo "==> npm lockfiles: registry and integrity"
NPM_LOCKS=(push-gateway/package-lock.json)
for lock in "${NPM_LOCKS[@]}"; do
  /usr/bin/env python3 - "$HERE/$lock" <<'PY' || fail=1
import json, sys
path = sys.argv[1]
pk = json.load(open(path)).get("packages", {})
bad = []
for name, p in pk.items():
    if not name or p.get("link"):
        continue
    r = p.get("resolved", "")
    if not r.startswith("https://registry.npmjs.org/"):
        bad.append(f"{name}: resolved from {r or '(nothing)'}")
    elif not str(p.get("integrity", "")).startswith("sha512-"):
        bad.append(f"{name}: no sha512 integrity")
for b in bad[:20]:
    print(f"✗ {path}: {b}")
if not bad:
    print(f"✓ {len(pk) - 1} packages, all from registry.npmjs.org with an integrity hash")
sys.exit(1 if bad else 0)
PY
done

echo "==> container pins"
unpinned="$(grep -nE '^FROM ' "$HERE/Dockerfile" | grep -vE '@sha256:[0-9a-f]{64}' || true)"
if [ -n "$unpinned" ]; then bad "Dockerfile has a FROM that is not pinned by digest: $unpinned"; else echo "✓ every Dockerfile FROM is pinned by digest"; fi
if "$HERE/deploy/test-verify-image.sh" >/dev/null 2>&1; then
  echo "✓ deploy bundle: digest-pinned image, loopback admin page"
else
  bad "deploy bundle pins (run deploy/test-verify-image.sh)"
fi

if [ "$STATIC_ONLY" = "1" ]; then
  echo
  echo "⚠ --static-only: cargo metadata, cargo deny and npm audit were NOT run. This is not the release gate."
  exit $fail
fi

command -v cargo-deny >/dev/null 2>&1 || { echo "✗ cargo-deny is not installed (cargo install --locked cargo-deny)" >&2; exit 2; }
command -v npm >/dev/null 2>&1 || { echo "✗ npm is not installed (needed for npm audit of push-gateway)" >&2; exit 2; }
for ws in core server host; do
  echo "==> $ws: lockfile in sync"
  (cd "$HERE/$ws" && cargo metadata --locked --format-version 1 >/dev/null) || bad "$ws/Cargo.lock is out of date"
  echo "==> $ws: cargo deny check"
  (cd "$HERE/$ws" && cargo deny --locked --config "$HERE/deny.toml" check) || fail=1
done
echo "==> push-gateway: npm audit"
(cd "$HERE/push-gateway" && npm audit --package-lock-only --audit-level=high) || fail=1

if [ "$fail" = "0" ]; then echo "✓ check-deps: all checks passed"; else echo "✗ check-deps: FAILED" >&2; fi
exit $fail
