# Skwod — release signing & distribution

How Skwod ships signed, verifiable updates to every platform, and the exact procedure for cutting
a release.

## Where updates come from

Skwod is decentralized and mostly p2p: a Skwod usually has no https address, so the apps do **not**
update from the Skwod they are connected to. Every release is published to one public GitHub
repository, **`FlayrLabs/skwod-releases`** — binaries and feeds only; the source is `FlayrLabs/skwod` —
and every install reads the same feed from its newest release:

| Platform | Feed | Schedule |
|----------|------|----------|
| **macOS** | `https://github.com/FlayrLabs/skwod-releases/releases/latest/download/appcast.xml` (Sparkle; `SUFeedURL`, build setting `SKWOD_UPDATE_FEED`) | once a day; downloads by itself, installs when the app quits |
| **Android** | `https://github.com/FlayrLabs/skwod-releases/releases/latest/download/manifest.json` (`Updater.kt`) | once a day; "Update available" notification, then the user taps Update and confirms Android's installer |
| **iOS** | TestFlight / App Store | Apple's |

Both automatic checks can be switched off by the user ("Check for updates automatically"); what a
check reveals to GitHub is described in `docs/SECURITY.md` → *App updates*.

Each release is a git tag `v<build>` (e.g. `v41`) whose assets are the files in
`releases/<build>/`. The feeds name their downloads by tag
(`…/releases/download/v<build>/<file>`), and `latest/download/<feed>` always resolves to the
newest release — so publishing a release is what rolls it out.

## Trust model (why users can't be served a malicious update)

GitHub is a distribution channel, not a trust anchor. Signatures are made on the release machine
with keys GitHub never sees.

| Platform | Mechanism | Authenticity guarantee |
|----------|-----------|------------------------|
| **macOS** | Sparkle: EdDSA-signed archive **and** EdDSA-signed feed | The app verifies an Ed25519 signature (`SUPublicEDKey` in Info.plist) over the archive before unpacking, and — from the first build with this change — over the appcast itself (`SURequireSignedFeed`, no fallback), so version numbers, release notes and links in the update window are the publisher's. The feed URL is fixed in code (`feedURLString(for:)`). Whoever controls the repo, the CDN or the network **cannot** forge an update or its description without the private key. Plus Developer ID + notarization so Gatekeeper allows it. |
| **Android** | Publisher Ed25519 signature + stable release keystore | The app verifies a signature over **the build number and SHA-256(apk)** (`sig2` in the manifest) against the key pinned in `Updater.kt` before handing the apk to the installer, refuses a build that is not newer than the installed one, and checks that the downloaded apk really is that build; the OS then refuses an apk whose signing certificate differs from the installed app's or whose version code is lower. Requests go to GitHub's release hosts only, https only, every redirect hop re-checked. |
| **iOS** | TestFlight / App Store; the link is publisher-signed | Apple's signing for the binary. The "Update available" banner — build number, text and the TestFlight / App Store link it opens — is read only from the manifest's **signed statement** (`UpdateManifest.swift`, same publisher key as Android), and the link must be https on `testflight.apple.com` or `apps.apple.com`. Builds from before this change read the link unsigned. |

**The manifest's signed statement** (`tools/release/sign-manifest.sh`). `manifest.json` carries
`signed` — base64 of a small JSON document: per platform the build number, version, notes, the
apk's URL and SHA-256, the iOS link, plus `issued`, `expires` and the source `commit` — and
`signed_sig`, an Ed25519 signature by the update publisher key over
`"skwod-release-manifest-v1\n"` followed by exactly those bytes. Builds with this change (Android and
iOS) verify the signature over the bytes as received and read **nothing else** from the file.
The unsigned `android` / `ios` objects are still written so that earlier builds keep updating;
`verify-manifest.sh` refuses a manifest in which they disagree with the statement.

## Secrets (never in git)

The maintainers keep the release keys in a private secret store (an Infisical project); each secret
is the base64 of the file's exact bytes. Where that store is, and how to authenticate to it, is
configuration and is not in this repository.

| Secret | Name in the store | Local path |
|--------|-------------------|------------|
| Android release keystore | `ANDROID_RELEASE_KEYSTORE_B64` | `apps/android/skwod-release.keystore` |
| Android keystore passwords | `ANDROID_KEYSTORE_PROPERTIES_B64` | `apps/android/keystore.properties` |
| Android update Ed25519 key | `UPDATE_PUBLISHER_KEY_PEM_B64` | `apps/android/update_publisher_key.pem` |
| Sparkle EdDSA private key | `SPARKLE_PRIVATE_KEY_PEM_B64` | `apps/apple/sparkle_private_key.pem` |
| App Store Connect API key (notarization + TestFlight) | key id, issuer id, `.p8` | notary profile `skwod-notary` in the login Keychain |

All four local files are gitignored. **Losing the Android keystore = every user must uninstall +
reinstall to update again**, so treat it like production infrastructure: never delete the stored
copy.

These keys sign the official Skwod builds and are not available to anyone else. A fork ships under
its own name (see [`TRADEMARKS.md`](TRADEMARKS.md)) with its own keys, its own update feed
(`SKWOD_UPDATE_FEED`, `Updater.MANIFEST_URL`) and its own pinned public keys (`SUPublicEDKey`,
`Updater.kt`).

### Restore on a new build machine

```sh
# Where the store is: environment variables, or a gitignored ./signing.env (see the script header).
export SKWOD_SECRETS_URL=… SKWOD_SECRETS_WORKSPACE=… SKWOD_SECRETS_PATH=… INFISICAL_TOKEN=…
./fetch-signing-keys.sh           # writes any missing key
./fetch-signing-keys.sh --check   # verify local keys match the store

# Notary credential profile, from your App Store Connect API key (.p8, Key ID, Issuer ID)
xcrun notarytool store-credentials skwod-notary --key /path/to/AuthKey_XXXXXXXXXX.p8 \
  --key-id "$ASC_KEY_ID" --issuer "$ASC_ISSUER_ID"
```

## THE ONE MANUAL STEP — create a Developer ID Application certificate

macOS updates must be **notarized**, or Gatekeeper blocks the app on every user's Mac. Notarization
requires a *Developer ID Application* certificate, which only your Apple Developer **Account Holder**
can create — it can't be scripted:

1. Xcode → Settings → Accounts → your team → **Manage Certificates** → **+** → **Developer ID Application**.
   (Or Apple Developer portal → Certificates → **+** → Developer ID Application.)
2. It installs into your login Keychain. Verify: `security find-identity -v -p codesigning | grep "Developer ID Application"`.

`package-release.sh` requires it (and the `skwod-notary` profile) and signs + notarizes + staples
with it. Without it only a dry run is possible (`SKWOD_SKIP_NOTARIZE=1`), which is not shippable.
The official builds are signed `Developer ID Application: Flayr Labs LLC (NRNU83UJ68)`
(`DEVID_NAME` / `DEVID_TEAM` in `package-release.sh`).

## Cutting a release

Run from the repository root on a Mac with the keys restored (above), Xcode, the Android SDK +
NDK, `cargo-ndk`, `xcodegen`, OpenSSL 3 and `gh`. One-time: the public repo
`FlayrLabs/skwod-releases` must exist (empty is fine; **never push source to it**).

**0. Dependency check — a gate, not a habit.** `package-release.sh` runs it and refuses to
package on a failure; run it yourself first (and in CI — it is non-interactive and exits
non-zero on any failure):

```sh
./check-deps.sh                      # needs cargo-deny (cargo install --locked cargo-deny) and npm
./check-deps.sh --static-only        # the offline subset (says it is not the gate)
tools/release/test-deny-expiry.sh && tools/release/test-sign-manifest.sh && deploy/test-verify-image.sh
```

`check-deps.sh` must exit 0: no RustSec advisory or yanked crate in `core/`, `server/` or
`host/` beyond the justified, dated `ignore` entries in `deny.toml` — whose `Expires` dates are
now **parsed and enforced** (`tools/release/deny-expiry.py`); every lockfile in sync; every
release build invoking cargo with `--locked`; every git dependency at its allowed commit; the
Gradle wrapper genuine; the push gateway's npm lockfile registry-only, with integrity hashes,
and clean under `npm audit --audit-level=high`; every Dockerfile base and the deploy bundle's
image pinned by digest. **Do not release on a
failure**, and do not add an `ignore` to get past one: upgrade the dependency, or show the
affected code is unreachable and write that down next to the entry with an expiry date. An
entry past its expiry counts as a failure — remove it and deal with what comes back. The
advisory database moves, so a tree that passed last week can fail today; that is the point of
running it here.

**1. Bump** — one build number for all three platforms; commit it.

```sh
./bump-build.sh                      # Apple CURRENT_PROJECT_VERSION + Android versionCode
git commit -am "chore(skwod): build <n>"
```

Bump `MARKETING_VERSION` (project.yml) and `versionName` (app/build.gradle.kts) by hand when the
user-visible version changes.

**2. Build + package** — one command; it builds everything in the right order and refuses to
produce a release it can't verify.

```sh
SKWOD_RELEASE_NOTES="What changed, in a sentence or two." \
SKWOD_TESTFLIGHT_URL=https://testflight.apple.com/join/XXXX \
  ./package-release.sh               # → releases/<n>/   (15–30 min; two notarization round trips)
```

What it does, in order:

1. Rust core for Android, **both ABIs** (`apps/android/build-core.sh`), then the Rust core for
   Apple and the Mac app's bundled host tools (`apps/apple/build-core.sh`). An apk without the
   core lib installs and then crashes, so the apk is checked for both `.so` files.
2. Mac app (Release) → signed inside-out with `Developer ID Application: Flayr Labs LLC`, the app
   itself with its entitlements (microphone, camera) → notarized (keychain profile `skwod-notary`)
   → stapled → `Skwod-<n>-macos.zip`; then `Skwod-<n>.dmg`, signed, notarized and stapled too.
3. `appcast.xml`, EdDSA-signed, enclosure → `…/releases/download/v<n>/Skwod-<n>-macos.zip`.
4. Android release apk (release keystore) → `skwod-<n>.apk`, publisher-signed → `manifest.json`
   with the apk's url (`…/releases/download/v<n>/skwod-<n>.apk`), sha256 and signature, plus the
   iOS TestFlight link — all of it inside the signed statement (`tools/release/sign-manifest.sh`),
   together with an expiry and the source commit.
5. Verification: the archive signature with Sparkle's `sign_update --verify` and again against the
   `SUPublicEDKey` inside the built app; the **feed's own** signature (the trailing
   `sparkle-signatures` block) against that key with openssl; the manifest statement with
   `tools/release/verify-manifest.sh` against the key pinned in the apps, and through the Android
   updater's own code (`UpdaterTest.packagedReleaseVerifiesWithThePinnedKey`).

Before any of that it refuses to start unless the tree is **clean**, HEAD is **tagged
`skwod-v<n>`** and `./check-deps.sh` passes (it runs it itself). The commit id goes into the
signed statement and into `releases/<n>/SOURCE`.

`releases/<n>/` then holds `Skwod-<n>-macos.zip`, `Skwod-<n>.dmg`, `appcast.xml`, `skwod-<n>.apk`,
`manifest.json` and `release-notes.md` (the release text; not uploaded as a file).

Options: `SKWOD_SKIP_NOTARIZE=1` makes a dry run (signed, not notarized, marked
`NOT-NOTARIZED-DO-NOT-PUBLISH`; `publish-release.sh` refuses it). `SKWOD_UNVERIFIED_SOURCE=1`
packages from a dirty or untagged tree without the dependency gate, says so loudly, and marks
the output `UNVERIFIED-SOURCE-DO-NOT-PUBLISH` (also refused). `SKWOD_MANIFEST_VALID_DAYS`
(default 120) is how long the manifest statement counts as fresh — **publish a release, or
re-sign and re-publish `manifest.json`, before it runs out**, or Android and iOS installs start
saying they cannot confirm they are up to date. `SKWOD_SKIP_CORE=1` reuses a
Rust core already built in the tree. `SKWOD_MAC_PROFILE=<file>` — see the keychain note below.

**3. Publish** — the irreversible step: from here installs update themselves within a day.

```sh
./publish-release.sh <n>
```

It re-checks the files (notarization tickets, build number, feed URLs), refuses to overwrite an
existing release, runs `gh release create v<n> --repo FlayrLabs/skwod-releases --latest …` with the
five files, then downloads `latest/download/appcast.xml` and `manifest.json` (and the zip and apk)
the way the apps do and compares them byte for byte with what was built. It also warns if GitHub
serves assets from a host the Android app does not allow redirects to (`REDIRECT_HOSTS` in
`Updater.kt`; verified 2026-11-18: `github.com` → `release-assets.githubusercontent.com`).

A published build is never replaced: if something is wrong, bump the build and publish the fix.
(Deleting a bad release in the GitHub UI makes `latest` fall back to the previous one.)

**4. TestFlight** — iOS, same build number.

```sh
SKWOD_PUSH_GATEWAY=https://… apps/apple/upload-ios.sh    # archive + upload with the Apple ID signed in to Xcode
                                     # (the gateway can also come from signing.env; the script refuses to run without one)
                                     # (an API key is used only if ASC_KEY_PATH, ASC_KEY_ID and ASC_ISSUER_ID are all set)
```

Then in App Store Connect add the build to the testing group. `SKWOD_TESTFLIGHT_URL` (step 2) is
what the in-app "Update" banner on iOS opens — it is part of the signed statement, and
`sign-manifest.sh` refuses to sign a link that is not https on `testflight.apple.com` or
`apps.apple.com`.

### macOS keychain entitlement (known limitation)

`Skwod-macOS.entitlements` asks for `keychain-access-groups` (data-protection keychain). Under
Developer ID that needs an **embedded provisioning profile**, which can't be created from the
command line and doesn't exist yet. `package-release.sh` therefore **drops that one entitlement**
for the released build; the app detects this at run time and keeps its secrets in the login
keychain instead (`Sources/Keychain.swift`). To ship with it, create a Developer ID provisioning
profile for `io.skwod.mac` with Keychain Sharing in the Apple Developer portal and pass
`SKWOD_MAC_PROFILE=/path/to/profile.provisionprofile` to `package-release.sh`.

### What the feeds do and do not guarantee (rollback, freeze)

Checked against the sources — Sparkle 2.10.1 as pinned in `apps/apple/Package.resolved` (read in
its SwiftPM checkout: `Sparkle/SUAppcastDriver.m`, `SPUUpdater.m`, `SUAppcastItem.m`,
`SPUExtractSignedFeed.m`, `generate_appcast/FeedXML.swift`), `Updater.kt` and
`UpdateManifest.swift`.

- **Android and iOS (builds with the signed statement).** Everything shown or acted on comes from the manifest's signed
  statement: an unsigned or forged manifest offers nothing; the unsigned copy can say anything
  and is ignored. The apk is additionally bound by `sig2` (build number + digest), a build `<=`
  the installed one is refused before and after the download, and the apk's own `versionCode`
  and package are compared with what was signed. Earlier Android builds read the unsigned fields but
  install only with their apk signature; earlier iOS builds read the link unsigned (the hole M1
  describes) until those installs have updated.
  *Android below 13* has no platform Ed25519: such a device cannot verify the statement, takes
  only the bare build number from the unsigned part ("a newer build exists"), shows no feed
  text, and refuses the in-app install.
- **macOS (builds with `SURequireSignedFeed`).** `SURequireSignedFeed` is on: `SUAppcastDriver` extracts the content
  before the trailing `<!-- sparkle-signatures:` block and verifies its EdDSA signature and
  length against `SUPublicEDKey`; on failure the check ends in an error and no item is shown.
  `SUSignedFeedFailureExpirationInterval` is `0`, which disables Sparkle's built-in fallback
  (default: after 20 days of failing it accepts the feed in a reduced "safe" mode without notes
  or links). `generate_appcast` signs the feed by itself because the archived app's Info.plist
  has the key; `package-release.sh` checks the result with openssl and `publish-release.sh`
  refuses an unsigned feed. Sparkle also refuses a downgrade on its own word, from the
  signature-verified bundle (`SUPlainInstaller.m`, `SUDowngradeError`). The feed URL cannot be
  redirected through user defaults: the delegate's `feedURLString(for:)` wins and a stored
  `SUFeedURL` default is cleared at start.
  **Not exercised end to end here:** no release was packaged and no second Mac updated through a
  signed feed in this change. The first release with it must be tested Mac-to-Mac before
  publishing — an install that requires a signed feed and is served an unsigned one stops
  updating (by design), and the only recovery is a correctly signed feed. Macs on earlier builds
  do not require the signature and ignore the block.
- **Sparkle's limits.** Sparkle has no signed "this feed is current until <date>": an old,
  validly signed appcast can be served again, so a Mac can be held on an older-but-newer signed
  build, or told nothing, and cannot tell (no equivalent of the manifest's `expires`). Sparkle
  also offers one key for archive and feed, no second signer, and no revocation; rotation means
  shipping a build that carries the new `SUPublicEDKey` signed with the old one.
- **Freshness, Android and iOS: bounded, not solved.** The statement expires
  (`SKWOD_MANIFEST_VALID_DAYS`, default 120). Whoever controls the release repo can still
  replay an older signed manifest until it expires; after that a manual check says the app
  cannot confirm it is up to date. There is no monotonic counter remembered across checks, and
  the automatic check stays silent on a stale feed (the Android "Up to date" label in Settings
  is drawn by the screen, not the updater, and does not yet show the stale state). Closing this
  properly is the TUF timestamp role: a short-lived signed "latest" refreshed on a schedule by
  a separate online key.

## Known operational risks

Not code defects; recorded so nobody mistakes them for solved.

### The signing keys are online, plaintext files (audit M3)

**Today.** Four secrets — the Android keystore and its passwords, the Android/iOS update
publisher key, the Sparkle key — live as base64 values in one Infisical project and, after
`fetch-signing-keys.sh`, as plaintext files in the working tree of the build Mac
(`apps/android/`, `apps/apple/`, mode 0600, gitignored), where they stay between releases. The
same machine holds the `gh` login and the notary credential. They are **not offline** and not
in hardware; earlier comments in `Updater.kt` and `SparkleUpdater.swift` that said "offline"
were wrong and have been corrected. Anything that can read that user's files — malware, a
stolen unencrypted backup, an agent or tool run in the checkout — or that can read the secret
store, holds **both update channels and the manifest**: a signed build that installs silently
on every Mac at next quit and on Android after one tap. There is no second signer and no
revocation.

`fetch-signing-keys.sh` now refuses a non-https store URL and tells curl to refuse non-https
redirects, so the token and the keys cannot be sent in clear by a typo. That is the only code
change; the rest is procedure.

**Until the plan below is done:** release from a machine used for nothing else, FileVault on;
delete the four files after each release and re-fetch for the next
(`./fetch-signing-keys.sh --check` shows what is there); use a short-lived, read-only Infisical
token scoped to that one folder; never run tools or agents with file access in a checkout that
holds the keys.

**Plan (in order; none of it is done):**

1. *Split the roles.* Three keys with different exposure: (a) Sparkle archive+feed key,
   (b) Android apk publisher key (`sig2`), (c) manifest statement key. Today (b) and (c) are one
   key; give the manifest its own, so that the key that must be used most often (re-signing the
   statement to keep it fresh) is not the one that authorises a binary.
2. *Move (a) and (b) to hardware.* Ed25519 on a YubiKey 5 (firmware 5.7+) or a Nitrokey via
   PKCS#11; `openssl pkeyutl -sign` works through the `pkcs11` provider, so
   `tools/release/sign-manifest.sh` and the apk signature need only a different `-inkey`.
   Sparkle's `sign_update` / `generate_appcast` read a key file or the Keychain, not a token:
   sign the archive and the feed outside Sparkle's tools (the formats are plain Ed25519 over
   the archive bytes, and over the feed content with the `sparkle-signatures` trailer —
   `package-release.sh` already re-verifies both with openssl) or keep (a) on an offline Mac.
   Touch-to-sign on, so a compromised build machine can sign only while someone is pressing.
   The Android keystore goes to a hardware-backed keystore the same way (`apksigner` supports
   PKCS#11).
3. *Sign offline, publish online.* Build and sign on a machine without the `gh` login; carry
   `releases/<n>/` to the publishing machine, which holds no signing key and only runs
   `publish-release.sh` (it already re-verifies every signature against the pinned public keys).
4. *Rotation.* Each app accepts a **set** of publisher keys (current + next) instead of one:
   `UPDATE_PUBLIC_KEY_B64` / `publisherKeyB64` become lists, the statement names a key id, and a
   release signed by the current key introduces the next. Sparkle: ship the new `SUPublicEDKey`
   in a build signed with the old key, then switch after the installed base has moved (Sparkle
   itself supports no overlap; installs that skip that build must update by hand).
5. *Revocation.* The signed statement gains a `revoked` list (key ids and build numbers) that
   apps honour before anything else, so a leaked key or a bad build can be withdrawn by the
   remaining key. A compromised *only* key cannot be revoked in-band: the fallback is a new app
   identity announced out of band — which is why step 4 (two keys, kept apart) comes first.
6. *Remove the keys from the secret store* once hardware copies and an offline, encrypted
   backup of each exist (two tokens per key, kept in different places).

### Provenance and reproducible builds (audit M4)

**Today.** A release is built on one Mac by one script. What ties it to source, as of this
change: `package-release.sh` refuses a dirty tree, an untagged commit (`skwod-v<n>`) and a
failing `./check-deps.sh`; the commit id is inside the signed manifest statement and in
`releases/<n>/SOURCE`; every cargo invocation that produces a shipped binary passes `--locked`
(the Mac app's bundled server did not before). What is still missing:

- **Not reproducible.** Nobody else can rebuild a release and get the same bytes, so the commit
  id in the statement is a claim by the build machine, not something a third party can check.
  Known sources of difference: Xcode/SDK and NDK versions, embedded paths and timestamps, the
  notarization staple, apk signing. Signal's Android build is reproducible; this one is not.
- **Gradle dependencies are unverified.** There is no `gradle/verification-metadata.xml`, and
  `apps/android/settings.gradle.kts` enables JitPack for every coordinate (LiveKit's
  `audioswitch` comes from it; JitPack builds on demand from GitHub repositories).
- **Swift packages** are pinned to exact versions and revisions in `Package.resolved`, but
  `xcodebuild` is not told to refuse re-resolution.
- **`SKWOD_SKIP_CORE=1`** ships whatever Rust core is already built in the tree, checked only
  for existence.
- **Tags are not required to be signed**, and nothing checks that the tagged commit was reviewed.
- **No CI runs the gate** for this product yet; `check-deps.sh` is CI-able (non-interactive,
  exit status) but is only enforced at packaging time.

**Plan (in order):**

1. CI job on every push and pull request: `./check-deps.sh`, the three
   `test-*.sh` scripts above, `cargo test` for `server/` and `core/`.
2. Gradle: generate `verification-metadata.xml` (`./gradlew --write-verification-metadata
   sha256 help`), review and commit it; restrict JitPack with `exclusiveContent` to the one
   group that needs it. Xcode: `-disableAutomaticPackageResolution
   -onlyUsePackageVersionsFromResolvedFile`.
3. Require a **signed** tag (`git tag -s`) and verify it in `package-release.sh`
   (`git verify-tag`) against the maintainers' keys; remove `SKWOD_SKIP_CORE` from the release
   path (keep it for dry runs, which are already unpublishable).
4. Record provenance: toolchain versions (rustc, Xcode, NDK, Gradle), the lockfile hashes and
   the SHA-256 of every artifact into a `provenance.json` inside the release, signed like the
   manifest.
5. Reproducibility, one artifact at a time, starting where it is tractable: the server binary
   and Docker image (pinned base images and toolchain already; add `SOURCE_DATE_EPOCH`,
   `--remap-path-prefix`), then the Android apk (compare with `apkdiff` ignoring the signing
   block, as Signal does), then the Rust core for Apple. The Mac app bundle last; document
   whatever cannot be made deterministic.
6. A second, independent builder reproduces each release before `publish-release.sh` runs.

### The Docker image (audit M5)

**Workflow.** `.github/workflows/image.yml` in the public repository builds
`ghcr.io/flayrlabs/skwod-server` for linux/amd64 and linux/arm64, each on a native GitHub runner
(no QEMU). It runs only on a `skwod-v<n>` tag: pushed, or re-run by hand with
`gh workflow run image.yml -R FlayrLabs/skwod --ref skwod-v<n>`. It never runs for pull requests.
`deploy/image-release-guard.sh` (tested by `deploy/test-image-release-guard.sh`) refuses unless
`<n>` equals `CURRENT_PROJECT_VERSION` in `apps/apple/project.yml` and the tagged commit is on
`main`, so a tag on an unreviewed commit gets no image.

1. **Build and test, per architecture, with no registry credentials.** The image is built with no
   cache, with SBOM and provenance (`mode=max`) attestations, as an OCI archive.
   `deploy/smoke-test-image.sh` then runs that exact archive twice. The first run uses the Unraid
   template's flags, and the image must become healthy, print the one-time admin token, wait for
   Start, and run as 99:100. The second run uses the compose posture, started at once, and the
   bundled `livekit-server` must be running.
2. **Publish** (the only job with `packages: write` and `id-token: write`). It runs behind the
   `release` environment, so a maintainer approves each run. Before pushing anything it refuses a
   build that is already published, or one that is not newer than the `org.opencontainers.image.version`
   label of the current `latest`. All publishing shares one concurrency group (`image-publish`).
   It then pushes the two tested
   archives byte for byte (`<n>-amd64`, `<n>-arm64`), merges them into one multi-arch index tagged
   `<n>`, and signs that digest keylessly: `cosign sign --yes …@sha256:<digest>`. That is a Fulcio
   certificate bound to the workflow and its ref, with an entry in Rekor; there is no long-lived key
   to steal. The job then checks the signature with `deploy/verify-image.sh`, the same check hosts
   run. **Only then** does it move `latest` to that digest, after checking once more that this only moves
   it forward. The run summary prints the digest; put
   it in the release notes.
3. **Tags.** `<n>` is never overwritten; the workflow refuses. `latest` exists for Unraid's "check for updates" and always points at a
   signed, smoke-tested build. Compose and VPS hosts still pin by digest (`SKWOD_IMAGE` is
   required and has no default).
4. **Hosts verify** with `deploy/verify-image.sh ghcr.io/flayrlabs/skwod-server@sha256:<digest>`
   (cosign 3 or newer). It pins the signer to
   `https://github.com/FlayrLabs/skwod/.github/workflows/image.yml@refs/tags/skwod-v<n>` (the
   workflow path, the repository and a release-tag ref), with the certificate's GitHub
   repository extension set to `FlayrLabs/skwod` and the issuer set to GitHub Actions. If the
   workflow moves, change `IDENTITY_REGEXP` in that script in the same commit.
5. **Repository settings this relies on.** `main` is protected. A tag ruleset lets only
   maintainers create, move or delete `skwod-v*` tags. The `release` environment requires a
   maintainer's approval. These live in the repository's settings, not in code; see
   docs/GOING-PUBLIC.md, section 8, in the monorepo. The GHCR
   package `skwod-server` must be **public**, or hosts cannot pull it. The repository variable
   `SKWOD_DEFAULT_PUSH_GATEWAY` (not a secret) is baked in as the built-in push gateway; when it is
   empty, the workflow warns and the image has none (docs/PUSH.md).
6. **Residual trust.** You still trust GitHub Actions and Sigstore. A compromised workflow run on
   a release tag produces a validly signed image. Reproducible image builds (the plan
   above, step 5) are what would let a host check the digest against source.

### The published Mac build keeps its secrets in the login keychain (L7)

See "macOS keychain entitlement" above: unless `SKWOD_MAC_PROFILE` is passed,
`package-release.sh` deletes `keychain-access-groups` from the entitlements and prints
`keychain: login-keychain fallback`. No Developer ID provisioning profile exists yet, so
**every Mac release so far shipped that way** — check the release log line to be sure of a
given build. Consequence: session tokens and cache keys on a Mac are login-keychain items
protected by the app's code signature ACL, not by the data-protection keychain; other software
running as the user can ask for them (the system prompts unless it is signed by the same
team). `docs/SECURITY.md` describes the login keychain for unsigned local builds; it applies to
the published build too until a profile is used.

### Self-hosted servers

The server still has `/api/updates/*` (it serves whatever is in `<data>/releases`). Mac and Android
builds from 41 on never ask it. Builds ≤ 40 only know that route, and only on an `https://` Skwod:
to move those installs forward, copy the contents of `releases/<n>/` into such a server's
`<data>/releases` once, or have people install the new build by hand. The iOS app reads the TestFlight link from the
public manifest's signed statement, never from the connected server (`Updater.swift`).

## The server's built-in push-gateway host

A server only calls push gateways on its allowlist. The default allowlist is the host the server
binary was **built** with — `SKWOD_DEFAULT_PUSH_GATEWAY` in the build environment (a host name,
e.g. `push.example.org`; `server/src/gateway.rs`). Set it for every server artifact a release
ships, to the host of the `SKWOD_PUSH_GATEWAY` the apps are built with:

- the Mac app's bundled server: `apps/apple/bundle-host-tools.sh` derives it from
  `SKWOD_PUSH_GATEWAY` when it is not set explicitly;
- the Docker image: `docker build --build-arg SKWOD_DEFAULT_PUSH_GATEWAY=<host> .`;
- the Linux/Windows host packages: `host/packaging/build.sh` takes it from the environment (or
  derives it from `SKWOD_PUSH_GATEWAY`) and **stops** when neither is set.

`package-release.sh` likewise stops when it is not set (environment or `signing.env`), and
checks that the bundled `skwod-server` really carries that host. To build a server with no
built-in gateway on purpose, say so: `SKWOD_NO_DEFAULT_PUSH_GATEWAY=1`.

A server built without it has no built-in list: unless the operator sets `SKWOD_PUSH_GATEWAYS`,
the instance owner's own iOS app decides the host when it first registers, and until then no
member's push registration is accepted. An operator's `SKWOD_PUSH_GATEWAYS` always replaces the
built-in value.
