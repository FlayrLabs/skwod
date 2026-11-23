//! Static-key AEAD for *metadata* that is not a message: channel/space names (sealed under the
//! per-space key), the address beacon note, and the key-backup payload. ChaCha20-Poly1305
//! (RustCrypto, audited) with a fresh random 96-bit nonce per call; output is `nonce || ct`.
//!
//! These keys seal a handful of short values, far below the random-nonce birthday bound.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

/// Seal `plaintext` under `key` with associated data `aad`; returns `nonce(12) || ciphertext`.
pub fn seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let nonce: [u8; 12] = crate::random_bytes();
    let ct = seal_with_nonce(key, &nonce, aad, plaintext);
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    out
}

/// Open the output of [`seal`]. `None` on any authentication failure or truncation.
pub fn open(key: &[u8; 32], aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() < 12 {
        return None;
    }
    let (nonce, ct) = sealed.split_at(12);
    open_with_nonce(key, nonce, aad, ct)
}

/// Seal with a caller-supplied nonce (wire formats that carry the nonce separately).
pub fn seal_with_nonce(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    ChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .expect("ChaCha20-Poly1305 encryption cannot fail for in-memory inputs")
}

/// Open with a caller-supplied nonce.
pub fn open_with_nonce(key: &[u8; 32], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    if nonce.len() != 12 {
        return None;
    }
    ChaCha20Poly1305::new(Key::from_slice(key)).decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad }).ok()
}

/// A keyed, domain-separated tag: `HMAC-SHA256(key, domain ‖ 0x00 ‖ data)`. Used where the server
/// must be able to GROUP equal values (e.g. identical reactions) without learning them.
pub fn keyed_tag(key: &[u8; 32], domain: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(domain);
    mac.update(&[0]);
    mac.update(data);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_tamper() {
        let key = [7u8; 32];
        let sealed = seal(&key, b"aad", b"general");
        assert_eq!(open(&key, b"aad", &sealed).unwrap(), b"general");
        assert!(open(&key, b"other", &sealed).is_none());
        assert!(open(&[8u8; 32], b"aad", &sealed).is_none());
        let mut bad = sealed.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(open(&key, b"aad", &bad).is_none());
        assert!(open(&key, b"aad", &sealed[..5]).is_none());
        assert_ne!(seal(&key, b"aad", b"general"), sealed, "fresh nonce per call");
    }
}
