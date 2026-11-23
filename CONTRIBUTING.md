# Contributing to Skwod

Thanks for helping. Skwod is an end-to-end encrypted group chat that people rely on to keep
their conversations private, so the bar for changes is "correct, tested, and explained", not
"works on my machine". This file is how to build each part, how to run the tests, and what a
pull request needs.

- **Security bugs do not go in issues or pull requests.** Report them privately: see
  [`SECURITY.md`](SECURITY.md) (security@skwod.io, or the *Report a vulnerability* button).
- Be kind. [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) applies everywhere in this project.

## The parts

| Path | What | Language |
|---|---|---|
| `core/` | the Rust core every app links: crypto (libsignal), sync engine, p2p, UniFFI surface | Rust |
| `server/` | the self-hostable server (binary `skwod`) | Rust |
| `host/` | tray app that runs the server on Windows and Linux | Rust |
| `apps/apple/` | SwiftUI app for iOS and macOS, plus the notification extension | Swift |
| `apps/android/` | Kotlin / Jetpack Compose app | Kotlin |
| `push-gateway/` | blind APNs wake gateway (Cloudflare Worker) | TypeScript |
| `web/` | the skwod.io site: landing page and `/join` invite page | React + Vite |

The README's [Building](README.md#building) section has the same commands with more context.

## Building and testing

### Prerequisites

- Rust through [rustup](https://rustup.rs). Each workspace pins its toolchain in
  `rust-toolchain.toml` (libsignal sets the minimum), and rustup installs it on first use.
- `protoc` (`brew install protobuf` or `apt install protobuf-compiler`): libsignal compiles its
  protobuf definitions at build time.
- Node.js 22 for `push-gateway/` and `web/`.
- JDK 17 and the Android SDK (platform 35) with the NDK for Android; Xcode 26 and
  [XcodeGen](https://github.com/yonaskolb/XcodeGen) for the Apple apps.

### Server and core

```sh
cd server
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings

cd ../core
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

Some `core/skwod-core/tests/*_live.rs` tests build and start a real server on loopback. They
skip themselves if the server cannot be built.

### Apple (iOS and macOS)

```sh
cd apps/apple
./build-core.sh macos        # Rust core → Generated/ (./build-core.sh all adds the iOS slices)
xcodegen generate
xcodebuild -project Skwod.xcodeproj -scheme Skwod-macOS CODE_SIGNING_ALLOWED=NO build
xcodebuild test -project Skwod.xcodeproj -scheme SkwodLogicTests -destination 'platform=macOS'
```

`SkwodLogicTests` are hostless: no app is launched and nothing is signed in. Running the app on a
device needs your own Apple team and bundle ids (`DEVELOPMENT_TEAM`, `PRODUCT_BUNDLE_IDENTIFIER`
in `project.yml`); never commit those changes. See [`docs/APPLE.md`](docs/APPLE.md).

### Android

```sh
cd apps/android
./build-core.sh x86_64       # Rust core → jniLibs + Kotlin bindings (needs cargo-ndk)
./gradlew testDebugUnitTest  # JVM unit tests
./gradlew assembleDebug      # → app/build/outputs/apk/debug/
```

`./build-core.sh` with no argument builds the two release ABIs; `arm64` builds one for a phone
or an Apple Silicon emulator.

### Push gateway

```sh
cd push-gateway
npm ci
npm run typecheck
npm test
```

The tests run the Worker in a local workerd against a fake APNs. No Cloudflare account is needed.

### Website

```sh
cd web
npm ci
npm test
SKWOD_SITE_OFFLINE=1 npm run build   # → dist/ (offline: the download buttons use the releases page)
```

The site's design is fixed. Change its wording if you need to, but don't restyle it.

### What CI runs

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on every pull request:

- `cargo test` and `cargo clippy -D warnings` for `server/` and `core/`;
- the push gateway's type check and tests;
- the site's tests and build;
- the Android unit tests;
- the Apple logic tests on macOS.

CI has no secrets. A pull request from a fork runs with a read-only token and nothing else.
The full Apple app build, device tests and `host/` are not in CI, so run what you touched
locally and say so in the pull request.

## Pull requests

1. **Open an issue first** for anything bigger than a small fix, so we can agree on the
   approach before you spend time on it.
2. **One change per pull request.** Small, focused pull requests are reviewed fast; a mixed one
   waits.
3. **Tests.** A bug fix comes with a test that fails without it. A feature comes with tests for
   its rules. Run the tests for every part you touched.
4. **Say what you verified and what you did not**, in the pull request template. "Built on
   macOS, did not run on a device" is a fine answer; silence is not.
5. **No new dependencies without a reason.** Every crate, Gradle and npm dependency is attack
   surface. Name it, say why, and pin it (lockfiles are committed; CI uses `--locked` / `npm ci`).
6. **No secrets, keys, personal data or real people's names** in code, tests or screenshots.
   Use `alice`, `bob` and `example.org`.
7. Keep the history readable: clear commit messages, rebased on `main`.
8. **Sign off every commit** (see below).

### Security-sensitive code

Some paths have a second, slower review on purpose. [`.github/CODEOWNERS`](.github/CODEOWNERS)
makes the maintainer a required reviewer for them:

- `core/skwod-crypto/`: the libsignal integration, key stores, attachments, backups;
- `core/skwod-sync/src/engine*`: the sync engine, trust and account logic;
- the server's auth, sessions, key directory and push code;
- `push-gateway/`;
- the release, update and signing code.

Changes there need a written rationale, tests for the failure cases as well as the happy path,
and a note on what an attacker in the threat model ([`docs/SECURITY.md`](docs/SECURITY.md)) could
do with the change. **Do not add or change protocol cryptography.** Skwod uses libsignal as it
ships. Expect questions, and possibly a "no", for anything that weakens an invariant listed
there, however convenient.

## Sign-off (Developer Certificate of Origin)

Every commit must carry a `Signed-off-by:` line with your name and an e-mail address you can be
reached at:

```sh
git commit -s -m "fix(server): …"
```

By signing off you certify the [Developer Certificate of Origin 1.1](https://developercertificate.org):
that you wrote the change, or otherwise have the right to submit it under this project's
licence. CI checks that every commit in a pull request is signed off. To fix a pull request
that isn't, run `git rebase --signoff main` and force-push your branch.

## Licence and trademarks

- **Licence.** Skwod is licensed under the GNU Affero General Public License, version 3 only
  ([`LICENSE`](LICENSE)). Your contribution is licensed under the same terms ("inbound =
  outbound"). You keep the copyright on what you write. Don't submit code you can't license under
  AGPL-3.0-only, such as code copied from a project with an incompatible licence.
- **Third-party code.** If you add a dependency or vendor code, its licence must be compatible
  with AGPL-3.0-only. Add it to [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md) when needed.
- **Trademarks.** The licence covers the code, not the Skwod name or logo; see
  [`TRADEMARKS.md`](TRADEMARKS.md). Contributing doesn't grant any rights in the marks. If you
  publish your own builds or run a service from a fork, give it a different name and icon, and
  point it at your own update feed and push gateway.
