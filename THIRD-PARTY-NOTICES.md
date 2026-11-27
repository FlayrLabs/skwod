# Third-party notices

Skwod is licensed under the GNU Affero General Public License, version 3 only (`LICENSE`). It
links or bundles the third-party software below. This list covers the components with licence
terms that require notice or that are security-relevant. Licences were read from the packages' own
metadata (`cargo metadata` for the Rust crates at the versions in the lock files; the upstream
repositories for the Swift packages, Gradle dependencies and bundled binaries). The complete
dependency set with exact versions is in `core/Cargo.lock`, `server/Cargo.lock`,
`host/Cargo.lock`, `apps/apple/project.yml`, `apps/android/app/build.gradle.kts` and
`push-gateway/package-lock.json`; `cargo tree --format "{p} {l}"` prints every crate's licence.

Every licence in the Rust dependency graph is compatible with distribution under AGPL-3.0-only.
The crates that are not simply MIT / Apache-2.0 / BSD / ISC / Zlib / Unicode are listed under
"Other licences in the dependency graph".

## Signal

| Component | Version | Licence | Source |
|---|---|---|---|
| libsignal (`libsignal-protocol`, `libsignal-core`, `signal-crypto`) | v0.108.0 (commit `8be00c282001caa3585d18de0f044c6d500348ab`) | AGPL-3.0-only — Copyright Signal Messenger, LLC | https://github.com/signalapp/libsignal |
| SparsePostQuantumRatchet (`spqr`) | v1.7.0 | AGPL-3.0-only — Copyright Signal Messenger, LLC | https://github.com/signalapp/SparsePostQuantumRatchet |

Skwod is not affiliated with, endorsed by, or sponsored by Signal Messenger, LLC. "Signal" is a
trademark of Signal Messenger, LLC.

## Cryptography

| Component | Licence |
|---|---|
| libcrux (`libcrux-ml-kem`, `libcrux-sha3`, …) | Apache-2.0 |
| curve25519-dalek, x25519-dalek, ed25519-dalek | BSD-3-Clause |
| RustCrypto: `aes`, `cbc`, `ctr`, `aes-gcm-siv`, `chacha20poly1305`, `hmac`, `hkdf`, `sha2`, `argon2`, `subtle`, `zeroize` | MIT OR Apache-2.0 |
| RustCrypto, server push signing (jsonwebtoken's `rust_crypto` backend): `rsa`, `p256`, `p384`, `ecdsa`, `elliptic-curve`, `primefield`, `primeorder`, `wnaf`, `rfc6979`, `sec1`, `pkcs1`, `crypto-bigint`; with `crypto-primes` (entropyxyz), `ff` and `group` (zkcrypto) | MIT OR Apache-2.0 |
| secp256k1 (rust-secp256k1 / libsecp256k1) | CC0-1.0 / MIT |
| SQLCipher (via `rusqlite`, bundled) | BSD-3-Clause — Copyright Zetetic LLC |
| OpenSSL (vendored, for SQLCipher) | Apache-2.0 |
| rustls, webpki-roots | Apache-2.0 OR ISC OR MIT / MPL-2.0 |
| ring | Apache-2.0 AND ISC (see its LICENSE) |

## Peer-to-peer transport

| Component | Version | Licence |
|---|---|---|
| iroh (`iroh`, `iroh-base`, `iroh-relay`, `iroh-dns`, `iroh-mainline-address-lookup`) — n0, inc. | 1.4.1 | MIT OR Apache-2.0 |
| noq (QUIC; `noq`, `noq-proto`, `noq-udp`) — n0, inc. | 1.4.0 | MIT OR Apache-2.0 |
| `n0-mainline` (BitTorrent Mainline DHT client), **modified**: `core/vendor/n0-mainline-0.7.2.patch` | 0.7.2 | MIT OR Apache-2.0 |
| `portmapper`, `netwatch` — n0, inc. | 0.19.3 | MIT OR Apache-2.0 |
| `swarm-discovery` (mDNS, opt-in LAN discovery) | 0.6.6 | Apache-2.0 |
| `igd-next` (UPnP), `simple-dns` | 0.17.1, 0.12.0 | MIT |

By default members use the public relay and discovery infrastructure that iroh ships with (run by
n0, inc.) when no direct path exists; see `docs/P2P.md`.

## Voice and video

| Component | Version | Licence |
|---|---|---|
| LiveKit server (`livekit-server`; bundled as a binary in the Mac app, the Docker image and the host packages — pinned in `deploy/livekit.lock`) | 1.13.11 | Apache-2.0 — Copyright LiveKit, Inc. |
| LiveKit Swift SDK (`client-sdk-swift`), with `livekit-ffi-xcframework` | ≥ 2.15.0 | Apache-2.0 |
| LiveKit Android SDK (`io.livekit:livekit-android`) | 2.27.0 | Apache-2.0 |
| WebRTC (`webrtc-xcframework`, and inside the Android SDK) | — | BSD-3-Clause — Copyright The WebRTC project authors |

## Networking, runtime, bindings

| Component | Licence |
|---|---|
| Arti (`arti-client`, `tor-*`) — The Tor Project | MIT OR Apache-2.0 |
| tokio, hyper, reqwest, axum, tower, tungstenite | MIT (some MIT OR Apache-2.0) |
| jsonwebtoken, pem, qrcode, clap, nix (server) | MIT / MIT OR Apache-2.0 |
| aws-lc-rs / aws-lc-sys | ISC AND (Apache-2.0 OR ISC) AND OpenSSL-derived terms (see the crate's LICENSE) |
| webpki-roots, webpki-root-certs (Mozilla CA list) | CDLA-Permissive-2.0 |
| blake3 | CC0-1.0 OR Apache-2.0 |
| sqlx | MIT OR Apache-2.0 |
| prost | Apache-2.0 |
| serde, postcard, uuid, base64, hex | MIT OR Apache-2.0 |
| UniFFI (Mozilla) | MPL-2.0 |
| JNA (Android) | Apache-2.0 OR LGPL-2.1-or-later |

## Apps

| Component | Licence |
|---|---|
| Sparkle (macOS updater) | MIT |
| AndroidX (activity, lifecycle, CameraX, security-crypto), Jetpack Compose, Material 3, Kotlin, kotlinx.coroutines | Apache-2.0 |
| OkHttp (Square) | Apache-2.0 |
| ZXing core (QR decoding and drawing) | Apache-2.0 |
| Tink (via androidx.security) | Apache-2.0 |
| JNA (Android, for UniFFI) | Apache-2.0 OR LGPL-2.1-or-later |

## Host tray app (`host/`, Windows and Linux)

| Component | Licence |
|---|---|
| tray-icon, muda | MIT OR Apache-2.0 |
| tao | Apache-2.0 |
| gtk-rs (`gtk` 0.18) | MIT — links the system GTK 3 (LGPL-2.1-or-later), dynamically |
| libappindicator (Rust bindings) | Apache-2.0 OR MIT — links the system libappindicator/libayatana-appindicator (LGPL), dynamically |
| winreg, windows-sys, ctrlc | MIT / MIT OR Apache-2.0 |

## Deployment

| Component | Licence |
|---|---|
| Caddy (pulled as a container image by `deploy/vps-install.sh`; not redistributed here) | Apache-2.0 |

## Push gateway (`push-gateway/`)

The Worker has no runtime dependencies. Its development tools (wrangler, vitest, TypeScript,
workers-types) are MIT / Apache-2.0 and are not part of what is deployed.

## Other licences in the dependency graph

From `cargo metadata` on `core/` (785 packages; the server and host graphs are subsets of the same
families plus the crates named above):

| Crate | Licence | Note |
|---|---|---|
| `bounded-vec-deque` (via Arti) | GPL-3.0-or-later OR BSD-3-Clause | used under BSD-3-Clause |
| `priority-queue` (via Arti) | LGPL-3.0-or-later OR MPL-2.0 | used under MPL-2.0 |
| `r-efi` | MIT OR Apache-2.0 OR LGPL-2.1-or-later | used under MIT OR Apache-2.0 |
| `async_executors`, `async_io_stream`, `pharos`, `ws_stream_wasm` | Unlicense | public-domain dedication |
| UniFFI crates and other Mozilla crates (13) | MPL-2.0 | file-level copyleft; unmodified |
| ICU4X / Unicode data crates (18) | Unicode-3.0 | |
| `secp256k1` and two more | CC0-1.0 | |
| `ryu` | Apache-2.0 OR BSL-1.0 | |
