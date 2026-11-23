//! # skwod-crypto
//!
//! skwod's end-to-end-encryption layer. The message protocol is **Signal's official
//! [`libsignal`](https://github.com/signalapp/libsignal)** (`libsignal-protocol`, pinned to release
//! `v0.108.0` in `Cargo.toml`) — this crate contains **no** protocol cryptography of its own:
//!
//! | Property | Provided by |
//! |---|---|
//! | Session setup: PQXDH (X25519 + Kyber-1024, one-time + last-resort KEM prekeys) | libsignal |
//! | 1:1 sessions: Double Ratchet + SPQR (the "triple ratchet"; mandatory in this release) | libsignal |
//! | Channels: Sender Keys | libsignal |
//! | Sender anonymity: Sealed Sender v1 + sender/server certificates | libsignal |
//! | Safety numbers: numeric fingerprint v2 | libsignal |
//!
//! What this crate adds around it (see `docs/SECURITY.md`, "What is not libsignal"):
//!
//! - [`store`] — a persistent implementation of libsignal's six store traits (identity, prekeys,
//!   signed prekeys, Kyber prekeys, sessions, sender keys) that snapshots into the SQLCipher cache,
//!   plus synchronous wrappers over libsignal's API.
//! - [`certs`] — issuing/validating libsignal sender certificates (the host server is the issuer)
//!   and binding the certificate trust root to the Ed25519 server identity an invite pins.
//! - [`padding`] — Signal's 160-byte-bucket plaintext padding.
//! - [`attachment`] — Signal's attachment scheme (AES-256-CBC + HMAC-SHA256, padded, digest-bound).
//! - [`backup`] — passphrase key backup (Argon2id + ChaCha20-Poly1305).
//! - [`link`] — device linking (an existing device signs a new device's identity key).
//! - [`aead`] / [`instance`] — static-key metadata sealing and the server instance signature.
//!
//! Those extras use audited RustCrypto / dalek crates only. Nothing here has had an independent
//! audit *as integrated*; libsignal itself is the audited, widely-deployed part.

pub mod aead;
pub mod attachment;
pub mod backup;
pub mod certs;
pub mod instance;
pub mod link;
pub mod padding;
pub mod store;

pub use uuid::Uuid;
pub use store::{
    CryptoError, DeviceAddress, IdentityChange, KyberPreKeyUpload, PreKeyBundleData, PreKeyUpload, SealedError,
    new_distribution_id, SealedMessage, SignalStore, SignedPreKeyUpload,
};

/// The E2EE wire-protocol generation. `1` was the in-house protocol shipped in builds 29–40; `2` is
/// libsignal. Clients send it on registration and the server refuses anything older with an
/// explicit "update required" (see `server/src/keydir.rs`).
pub const PROTOCOL_VERSION: u32 = 2;

/// Fill `out` from the OS CSPRNG.
pub fn fill_random(out: &mut [u8]) {
    use rand::TryRngCore as _;
    rand::rngs::OsRng.try_fill_bytes(out).expect("OS RNG failure is fatal");
}

/// Lowercase hex SHA-256 of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// `n` random bytes from the OS CSPRNG.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    fill_random(&mut b);
    b
}
