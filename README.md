# Skwod

End-to-end encrypted group chat for small groups of people who know each other, where the
server is a machine one of you owns. Channels, direct messages, attachments, a feed with stories,
and voice and video calls — on iOS, macOS and Android, over one shared Rust core.

There is no central Skwod service. Someone in the group presses **Start server** on a Mac, a home
server or a VPS and sends the others an invite link. The server stores ciphertext, public keys and
routing metadata; it cannot read a message, and neither can whoever runs it.

> **Read this before relying on it.** The message protocol is Signal's own
> [`libsignal`](https://github.com/signalapp/libsignal). What Skwod builds *around* it — the key
> directory, the sealed mailbox, device linking, key backup, call keys, the p2p transport — is
> **our integration, and it has not been independently audited**. Nobody outside the project has
> reviewed it. [`docs/SECURITY.md`](docs/SECURITY.md) describes the model and ends with "Remaining
> gaps versus Signal"; that list is part of the model. If your safety depends on a messenger, use
> Signal.

## What is in the box

| | |
|---|---|
| Clients | iOS and macOS (SwiftUI, one codebase) and Android (Kotlin, Jetpack Compose) |
| Shared core | Rust (`core/`): protocol, sync engine, encrypted on-device cache, p2p transport; bound into Swift and Kotlin with [UniFFI](https://mozilla.github.io/uniffi-rs/) |
| Protocol | `libsignal` v0.108.0: PQXDH (X25519 + Kyber-1024), Double Ratchet + SPQR, Sender Keys, Sealed Sender, safety numbers. No in-house protocol code. |
| Server | One Rust binary (`server/`). SQLite and an encrypted blob directory by default, Postgres optional. |
| Reaching a server | By the server's key over [iroh](https://github.com/n0-computer/iroh) (QUIC, hole punching, relay fallback) — no domain, no port forwarding. An `https://` address on a VPS also works. See [`docs/P2P.md`](docs/P2P.md). |
| Calls | A self-hosted [LiveKit](https://github.com/livekit/livekit) SFU bundled with the server; media frames are encrypted end to end with keys the clients distribute over libsignal sessions. |
| Push (iOS) | An optional blind gateway (`push-gateway/`, a Cloudflare Worker) that is told only "wake this device". See [`docs/PUSH.md`](docs/PUSH.md). |

## Security model

[`docs/SECURITY.md`](docs/SECURITY.md) is the authoritative description: the threat model, what
libsignal provides, what is ours, what metadata the server sees, how devices are linked, how
updates are signed, and the gaps. In short:

- The server is treated as untrusted, even though a member owns it. Content and private keys never
  reach it in plaintext.
- No session without a post-quantum KEM. Calls fail closed.
- The server **does** see the social graph: who is a member, who posts in which channel and when,
  presence. Signal hides most of that; Skwod does not.
- Not audited as integrated. No reproducible builds.

Found a vulnerability? Please report it privately — see [`SECURITY.md`](SECURITY.md).

## Hosting a Skwod

[`docs/SELF-HOSTING.md`](docs/SELF-HOSTING.md) covers each way and says plainly which were
verified and which were not:

- **A Mac** — the Mac app has a **Start server** button; server and LiveKit are bundled.
- **Unraid** — add the template and press Apply: [`docs/UNRAID.md`](docs/UNRAID.md) is a
  step-by-step guide for people who have never used Docker.
- **Docker, Synology** — one container: the published image `ghcr.io/flayrlabs/skwod-server`
  (amd64 and arm64, signed) pinned by digest, or `docker build -t skwod-server .` at the
  repository root, then [`deploy/docker-compose.yml`](deploy/docker-compose.yml).
- **A VPS with your own domain** — `sudo ./deploy/vps-install.sh chat.example.com you@example.com`.
- **A Windows or Linux PC** — the tray app in `host/`. Its packages have not been built or run on
  those systems yet.

Running a server makes you its operator. Read "Content policy & operator responsibilities" in that
guide before inviting people you do not know.

## Building

Everything builds from this repository; nothing is downloaded from the project's own servers.

Common prerequisites: [rustup](https://rustup.rs) (the toolchain, Rust 1.93.1, is pinned by the
`rust-toolchain.toml` files and installed on first use) and `protoc` (`brew install protobuf` /
`apt install protobuf-compiler`) — libsignal compiles its protobuf definitions at build time.

### Server and core

```sh
cd server && cargo build --release      # → target/release/skwod
cargo test

cd ../core && cargo build && cargo test
```

`skwod run --data ./skwod-data` starts a server; `skwod --help` lists the rest.

### iOS and macOS

Needs a Mac with Xcode 26 and [XcodeGen](https://github.com/yonaskolb/XcodeGen)
(`brew install xcodegen`). Rust targets: `rustup target add aarch64-apple-darwin aarch64-apple-ios
aarch64-apple-ios-sim`.

```sh
cd apps/apple
./build-core.sh all        # Rust core → Generated/SkwodCore.xcframework, plus the Mac host tools
                           # (./build-core.sh macos builds the Mac slice only)
xcodegen generate
xcodebuild -project Skwod.xcodeproj -scheme Skwod-macOS CODE_SIGNING_ALLOWED=NO build
```

Details, build switches and what was verified: [`docs/APPLE.md`](docs/APPLE.md). To put a build on
a device or in a store you need your own Apple team, bundle identifiers, app group and push
gateway (`DEVELOPMENT_TEAM`, `PRODUCT_BUNDLE_IDENTIFIER`, `SKWOD_APP_GROUP`,
`SKWOD_PUSH_GATEWAY`, `SKWOD_UPDATE_FEED` in `project.yml`) — and your own name and icon
([`TRADEMARKS.md`](TRADEMARKS.md)).

### Android

Needs JDK 17, the Android SDK (platform 35) with the NDK, and
[cargo-ndk](https://github.com/bbqsrc/cargo-ndk) (`cargo install cargo-ndk`). Rust targets:
`rustup target add aarch64-linux-android armv7-linux-androideabi`.

```sh
cd apps/android
./build-core.sh            # Rust core → jniLibs + Kotlin bindings (./build-core.sh arm64 for one ABI)
./gradlew assembleDebug    # → app/build/outputs/apk/debug/
```

A release build is signed only when `keystore.properties` and a keystore exist; use your own.

### Push gateway (optional)

`push-gateway/` is a Cloudflare Worker; see its [README](push-gateway/README.md). Without a gateway
the iOS app notifies only while it is running.

## Repository layout

```
core/            Rust core, shared by every client
  skwod-crypto/    libsignal integration: stores, certificates, attachments, backup, device links
  skwod-net/       p2p transport (iroh): host, member, invites, loopback proxy, voice tunnel
  skwod-sync/      sync engine, API client, encrypted local cache
  skwod-core/      the UniFFI surface the apps call
server/          the self-hostable server (binary: skwod)
host/            tray app that runs the server on Windows and Linux
apps/apple/      SwiftUI app (iOS + macOS) and the iOS notification service extension
apps/android/    Kotlin / Jetpack Compose app
push-gateway/    blind APNs gateway (Cloudflare Worker)
web/             the skwod.io site: landing page and the /join invite page
deploy/          Docker Compose files, VPS installer, Unraid template, image smoke test
docs/            security model, architecture, decisions, p2p, push, self-hosting, the Apple apps
```

## What is not in this repository

- **Signing keys and store credentials.** Official builds are signed by Flayr Labs LLC; the keys
  are not here and cannot be. [`RELEASE-SIGNING.md`](RELEASE-SIGNING.md) describes how releases
  are signed and published so you can check an official build, or do the same for a fork.
- **The paywall sources.** Both apps have a build switch for a subscription gate
  (`SKWOD_PAYWALL` / `-Pskwod.paywall=true`). It is off by default, the apps build and run without
  it, and the files it would compile are not published. Nothing in this tree asks for payment.

## Contributing

Issues and pull requests are welcome. [`CONTRIBUTING.md`](CONTRIBUTING.md) has the build and test
commands for every part, the pull request rules and the sign-off; [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)
applies. A few things to know first:

- **Security bugs go to [`SECURITY.md`](SECURITY.md), not the issue tracker.**
- Changes under `core/skwod-crypto`, to key handling or to anything in the "Non-negotiable
  invariants" of `docs/SECURITY.md` need a clear rationale and tests, and will be reviewed slowly
  on purpose. Do not add protocol code; Skwod uses libsignal as shipped.
- Run the tests for what you touch (`cargo test` in `core/` and `server/`, `cargo clippy`,
  `./gradlew test` for Android, `npm test` in `push-gateway/`). State in the pull request what you
  ran and what you could not run.
- Say what was verified and what was not. The docs here do, and that is deliberate.
- By contributing you agree that your contribution is licensed under AGPL-3.0-only, the licence
  of this repository.

## Licence

Copyright © the Skwod contributors.

Skwod is free software: you can redistribute it and/or modify it under the terms of the GNU Affero
General Public License, **version 3 only**, as published by the Free Software Foundation. It is
distributed WITHOUT ANY WARRANTY. See [`LICENSE`](LICENSE). The licence is AGPL because the apps
and the server link `libsignal`, which is AGPL-3.0-only.

If you run a modified Skwod server for other people, the AGPL (§13) requires you to offer them the
source of your modified version.

Third-party components and their licences: [`NOTICE`](NOTICE) and
[`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md).

## Name and logo

The code is free; the name is not. "Skwod", the Skwod logo and the app icons are trademarks of
Flayr Labs LLC and are **not** licensed under the AGPL. You may fork, modify and redistribute the
code, but a modified version that you distribute must use a different name and different icons.
The full policy, including what you may do without asking, is in [`TRADEMARKS.md`](TRADEMARKS.md).

Skwod is not affiliated with, endorsed by, or sponsored by Signal Messenger, LLC.
