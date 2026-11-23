# SkwodCore — UniFFI bindings

The single Rust surface bound into the SwiftUI (iOS/macOS) and Compose (Android) clients (ADR-001).
Re-exports the crypto core and sync engine so both platforms share one implementation.

## Exposed surface

- `SkwodCache` — the SQLCipher-encrypted on-device store (`open`, `setKv`/`getKv`,
  `upsertMessage`, `messages`). Synchronous; verified end-to-end by this repo's tests.
- `computeSafetyNumber(...)` — out-of-band identity verification (order-independent 60-digit number).
- `SkwodClient` — the async network + E2EE engine (`registerDevice`, `encryptDm`, `decryptDm`),
  generated as Swift `async throws` / Kotlin `suspend`. Runs on a tokio runtime inside the binary.

## Generate the bindings

```bash
cd core
cargo build -p skwod-core
LIB=target/debug/libskwod_core.dylib      # .so on Linux, .dylib on macOS
cargo run --bin uniffi-bindgen -- generate --library $LIB --language swift  --out-dir bindings/swift
cargo run --bin uniffi-bindgen -- generate --library $LIB --language kotlin --out-dir bindings/kotlin
```

This produces `bindings/swift/skwod_core.swift` (+ `.h` / `.modulemap`) and
`bindings/kotlin/uniffi/skwod_core/skwod_core.kt`. These are **build artifacts** — regenerate them,
don't edit or commit them.

## What is verified here vs. not

- ✅ The Rust crate compiles (`lib` + `cdylib` + `staticlib`) and its logic is unit-tested.
- ✅ `uniffi-bindgen` generates both Swift and Kotlin without error; the expected objects and async
  methods appear in the output.
- ⬜ **Compiling and running the generated bindings** requires the platform toolchains — Xcode +
  `swiftc` for the XCFramework, the Android SDK/NDK + Gradle for the AAR. That packaging is Phase
  5/6 work and cannot be done in this environment. `swiftformat`/`ktlint` are also absent here, so
  the generated files are un-formatted (functionally identical).
