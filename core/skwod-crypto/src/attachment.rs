//! Attachment encryption — Signal's attachment scheme.
//!
//! Each attachment gets a fresh random 64-byte key (32 AES + 32 HMAC). The blob uploaded to the
//! server is
//!
//! ```text
//! iv(16) || AES-256-CBC-PKCS7( plaintext || zero padding ) || HMAC-SHA256(mac_key, iv || ciphertext)
//! ```
//!
//! and the **pointer** sent inside the end-to-end-encrypted message carries the key, the
//! plaintext length, and `digest = SHA-256(blob)`. The receiver checks the digest (so the server
//! cannot swap in a different blob, even one made with a leaked key), then the MAC, then decrypts
//! and truncates to the real length.
//!
//! **Why CBC+HMAC rather than AES-GCM-SIV:** it is the scheme Signal actually ships for
//! attachments, it is encrypt-then-MAC with an independent digest binding, and it has no
//! per-key message-size ceiling (GCM-family single-shot AEADs cap at ~64 GiB and must hold the
//! whole plaintext to authenticate). The key is single-use, so CBC's IV requirements are met by a
//! random IV.
//!
//! **Size hiding:** the plaintext is zero-padded up to Signal's padded-size bucket
//! (`max(541, floor(1.05^ceil(log1.05(len))))`), so the blob length leaks at most ~5 % granularity.
//!
//! Primitives: RustCrypto `aes`, `cbc`, `hmac`, `sha2`.

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

pub const KEY_LEN: usize = 64;
pub const DIGEST_LEN: usize = 32;
const IV_LEN: usize = 16;
const MAC_LEN: usize = 32;

/// Hard ceiling on a single attachment (bytes). Bounds allocation on both ends.
pub const MAX_ATTACHMENT: usize = 100 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum AttachmentError {
    #[error("attachment too large")]
    TooLarge,
    #[error("attachment key must be 64 bytes")]
    BadKey,
    #[error("attachment digest mismatch")]
    Digest,
    #[error("attachment authentication failed")]
    Mac,
    #[error("attachment malformed")]
    Malformed,
    #[error("could not read or write the attachment file")]
    Io,
}

/// What the sender puts in the encrypted message so the receiver can fetch + open the blob.
pub struct EncryptedAttachment {
    /// The blob to upload (opaque to the server).
    pub ciphertext: Vec<u8>,
    /// 64-byte single-use key (AES-256 key || HMAC key).
    pub key: Vec<u8>,
    /// SHA-256 of `ciphertext`.
    pub digest: Vec<u8>,
    /// Real (unpadded) plaintext length.
    pub plaintext_len: u64,
}

/// Signal's padded attachment size: `max(541, floor(1.05^ceil(log1.05(len))))`.
pub fn padded_size(len: usize) -> usize {
    let bucket = if len == 0 { 0.0 } else { 1.05f64.powf(((len as f64).ln() / 1.05f64.ln()).ceil()).floor() };
    // Guard float rounding: the bucket must never be smaller than the content.
    (bucket as usize).max(541).max(len)
}

/// Encrypt an attachment under a fresh random key.
pub fn encrypt(plaintext: &[u8]) -> Result<EncryptedAttachment, AttachmentError> {
    if plaintext.len() > MAX_ATTACHMENT {
        return Err(AttachmentError::TooLarge);
    }
    let mut key: [u8; KEY_LEN] = crate::random_bytes();
    let iv: [u8; IV_LEN] = crate::random_bytes();
    let mut padded = plaintext.to_vec();
    padded.resize(padded_size(plaintext.len()), 0);

    let body = Aes256CbcEnc::new_from_slices(&key[..32], &iv).map_err(|_| AttachmentError::BadKey)?.encrypt_padded_vec_mut::<Pkcs7>(&padded);
    padded.zeroize();

    let mut blob = Vec::with_capacity(IV_LEN + body.len() + MAC_LEN);
    blob.extend_from_slice(&iv);
    blob.extend_from_slice(&body);
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key[32..]).map_err(|_| AttachmentError::BadKey)?;
    mac.update(&blob);
    blob.extend_from_slice(&mac.finalize().into_bytes());

    let digest = Sha256::digest(&blob).to_vec();
    let out = EncryptedAttachment { ciphertext: blob, key: key.to_vec(), digest, plaintext_len: plaintext.len() as u64 };
    key.zeroize();
    Ok(out)
}

/// Verify (digest, then MAC) and decrypt an attachment blob.
pub fn decrypt(blob: &[u8], key: &[u8], digest: &[u8], plaintext_len: u64) -> Result<Vec<u8>, AttachmentError> {
    if key.len() != KEY_LEN {
        return Err(AttachmentError::BadKey);
    }
    if blob.len() > MAX_ATTACHMENT + MAX_ATTACHMENT / 16 + 1024 {
        return Err(AttachmentError::TooLarge);
    }
    if blob.len() < IV_LEN + 16 + MAC_LEN {
        return Err(AttachmentError::Malformed);
    }
    if !bool::from(Sha256::digest(blob).as_slice().ct_eq(digest)) {
        return Err(AttachmentError::Digest);
    }
    let (authed, their_mac) = blob.split_at(blob.len() - MAC_LEN);
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key[32..]).map_err(|_| AttachmentError::BadKey)?;
    mac.update(authed);
    mac.verify_slice(their_mac).map_err(|_| AttachmentError::Mac)?;

    let (iv, body) = authed.split_at(IV_LEN);
    let mut padded = Aes256CbcDec::new_from_slices(&key[..32], iv)
        .map_err(|_| AttachmentError::BadKey)?
        .decrypt_padded_vec_mut::<Pkcs7>(body)
        .map_err(|_| AttachmentError::Malformed)?;
    let len = usize::try_from(plaintext_len).map_err(|_| AttachmentError::Malformed)?;
    if len > padded.len() {
        padded.zeroize();
        return Err(AttachmentError::Malformed);
    }
    padded.truncate(len);
    Ok(padded)
}

// ---- streamed (file to file) ----
//
// The same blob format, produced and opened without holding the attachment in memory: a 1 GiB
// video costs a few hundred kilobytes of buffers. CBC chains block to block and HMAC/SHA-256
// are incremental, so the output is byte-for-byte what [`encrypt`] would have produced.

/// Largest attachment the streamed path accepts (the server's per-blob ceiling is 2 GiB).
pub const MAX_STREAMED: u64 = 2 * 1024 * 1024 * 1024 - 64 * 1024 * 1024;
const STREAM_BUF: usize = 64 * 1024;

/// The pointer for a blob written by [`encrypt_stream`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamedAttachment {
    pub key: Vec<u8>,
    pub digest: Vec<u8>,
    pub plaintext_len: u64,
    /// Length of the blob written.
    pub blob_len: u64,
}

fn io_err(_: std::io::Error) -> AttachmentError {
    AttachmentError::Io
}

/// Encrypt `plaintext_len` bytes read from `src` into `dst` under a fresh random key.
/// `src` must yield exactly `plaintext_len` bytes (a file that changes size underneath fails).
pub fn encrypt_stream(mut src: impl std::io::Read, mut dst: impl std::io::Write, plaintext_len: u64) -> Result<StreamedAttachment, AttachmentError> {
    use aes::cipher::generic_array::GenericArray;
    if plaintext_len > MAX_STREAMED {
        return Err(AttachmentError::TooLarge);
    }
    let mut key: [u8; KEY_LEN] = crate::random_bytes();
    let iv: [u8; IV_LEN] = crate::random_bytes();
    let padded_len = padded_size(usize::try_from(plaintext_len).map_err(|_| AttachmentError::TooLarge)?) as u64;
    let mut enc = Aes256CbcEnc::new_from_slices(&key[..32], &iv).map_err(|_| AttachmentError::BadKey)?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key[32..]).map_err(|_| AttachmentError::BadKey)?;
    let mut digest = Sha256::new();
    let mut blob_len = 0u64;
    let mut emit = |bytes: &[u8], mac: Option<&mut Hmac<Sha256>>, dst: &mut dyn std::io::Write| -> Result<(), AttachmentError> {
        if let Some(mac) = mac {
            mac.update(bytes);
        }
        digest.update(bytes);
        blob_len += bytes.len() as u64;
        dst.write_all(bytes).map_err(io_err)
    };
    emit(&iv, Some(&mut mac), &mut dst)?;

    // The padded plaintext (content, then zeros), then one PKCS#7 block run.
    let mut buf = vec![0u8; STREAM_BUF];
    let mut produced = 0u64; // bytes of padded plaintext consumed so far
    let mut read_left = plaintext_len;
    while produced < padded_len {
        let want = ((padded_len - produced) as usize).min(STREAM_BUF);
        let from_src = (read_left as usize).min(want);
        src.read_exact(&mut buf[..from_src]).map_err(io_err)?;
        buf[from_src..want].fill(0);
        read_left -= from_src as u64;
        produced += want as u64;
        let last = produced == padded_len;
        let whole = want - want % 16;
        for block in buf[..whole].chunks_exact_mut(16) {
            enc.encrypt_block_mut(GenericArray::from_mut_slice(block));
        }
        emit(&buf[..whole], Some(&mut mac), &mut dst)?;
        if last {
            // PKCS#7: the remainder plus padding — a full block of 16s when it divided evenly.
            let rest = want - whole;
            let mut tail = [(16 - rest) as u8; 16];
            tail[..rest].copy_from_slice(&buf[whole..want]);
            enc.encrypt_block_mut(GenericArray::from_mut_slice(&mut tail));
            emit(&tail, Some(&mut mac), &mut dst)?;
        } else {
            debug_assert_eq!(want % 16, 0, "only the final read may be ragged");
        }
    }
    buf.zeroize();
    // The source must be exhausted: more bytes means it is not the file that was measured.
    let mut extra = [0u8; 1];
    if src.read(&mut extra).map_err(io_err)? != 0 {
        key.zeroize();
        return Err(AttachmentError::Malformed);
    }
    let tag = mac.finalize().into_bytes();
    emit(&tag, None, &mut dst)?;
    dst.flush().map_err(io_err)?;
    let out = StreamedAttachment { key: key.to_vec(), digest: digest.finalize().to_vec(), plaintext_len, blob_len };
    key.zeroize();
    Ok(out)
}

/// Verify (digest, then MAC) the blob in `blob` — `blob_len` bytes, read twice, hence `Seek` —
/// and write the plaintext to `dst`. Nothing is written until the whole blob has verified.
pub fn decrypt_stream<R: std::io::Read + std::io::Seek>(
    mut blob: R,
    blob_len: u64,
    mut dst: impl std::io::Write,
    key: &[u8],
    digest: &[u8],
    plaintext_len: u64,
) -> Result<(), AttachmentError> {
    use aes::cipher::generic_array::GenericArray;
    if key.len() != KEY_LEN {
        return Err(AttachmentError::BadKey);
    }
    let min = (IV_LEN + 16 + MAC_LEN) as u64;
    if blob_len < min || !(blob_len - (IV_LEN + MAC_LEN) as u64).is_multiple_of(16) {
        return Err(AttachmentError::Malformed);
    }
    if blob_len > MAX_STREAMED + MAX_STREAMED / 16 + 1024 {
        return Err(AttachmentError::TooLarge);
    }
    let authed_len = blob_len - MAC_LEN as u64;
    // Pass 1: digest over everything, MAC over everything but the tag.
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key[32..]).map_err(|_| AttachmentError::BadKey)?;
    let mut hash = Sha256::new();
    let mut buf = vec![0u8; STREAM_BUF];
    let mut left = authed_len;
    while left > 0 {
        let want = (left as usize).min(STREAM_BUF);
        blob.read_exact(&mut buf[..want]).map_err(io_err)?;
        mac.update(&buf[..want]);
        hash.update(&buf[..want]);
        left -= want as u64;
    }
    let mut their_mac = [0u8; MAC_LEN];
    blob.read_exact(&mut their_mac).map_err(io_err)?;
    hash.update(their_mac);
    if !bool::from(hash.finalize().as_slice().ct_eq(digest)) {
        return Err(AttachmentError::Digest);
    }
    mac.verify_slice(&their_mac).map_err(|_| AttachmentError::Mac)?;

    // Pass 2: decrypt, writing only the first `plaintext_len` bytes.
    blob.seek(std::io::SeekFrom::Start(0)).map_err(io_err)?;
    let mut iv = [0u8; IV_LEN];
    blob.read_exact(&mut iv).map_err(io_err)?;
    let mut dec = Aes256CbcDec::new_from_slices(&key[..32], &iv).map_err(|_| AttachmentError::BadKey)?;
    let body_len = authed_len - IV_LEN as u64;
    if plaintext_len > body_len {
        return Err(AttachmentError::Malformed);
    }
    let mut left = body_len;
    let mut to_write = plaintext_len;
    while left > 0 {
        let want = (left as usize).min(STREAM_BUF);
        blob.read_exact(&mut buf[..want]).map_err(io_err)?;
        for block in buf[..want].chunks_exact_mut(16) {
            dec.decrypt_block_mut(GenericArray::from_mut_slice(block));
        }
        left -= want as u64;
        if left == 0 {
            // The final block must be valid PKCS#7 (as the in-memory path requires).
            let pad = buf[want - 1] as usize;
            if pad == 0 || pad > 16 || buf[want - pad..want].iter().any(|b| *b as usize != pad) {
                buf.zeroize();
                return Err(AttachmentError::Malformed);
            }
        }
        let n = (to_write as usize).min(want);
        dst.write_all(&buf[..n]).map_err(io_err)?;
        to_write -= n as u64;
    }
    buf.zeroize();
    dst.flush().map_err(io_err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_various_sizes() {
        for len in [0usize, 1, 15, 16, 17, 540, 541, 542, 4096, 100_000] {
            let pt: Vec<u8> = (0..len).map(|i| (i * 7 % 256) as u8).collect();
            let enc = encrypt(&pt).unwrap();
            assert_eq!(decrypt(&enc.ciphertext, &enc.key, &enc.digest, enc.plaintext_len).unwrap(), pt, "len {len}");
        }
    }

    #[test]
    fn size_is_bucketed() {
        assert_eq!(padded_size(0), 541);
        assert_eq!(padded_size(1), 541);
        assert_eq!(padded_size(541), 541);
        for len in [542usize, 1000, 9999, 123_456, 5_000_000] {
            let p = padded_size(len);
            assert!(p >= len && (p as f64) <= len as f64 * 1.05 + 1.0, "len {len} -> {p}");
        }
        // Two different small files produce identically sized blobs.
        assert_eq!(encrypt(&[1u8; 10]).unwrap().ciphertext.len(), encrypt(&[2u8; 500]).unwrap().ciphertext.len());
        // Nearby sizes within one bucket are indistinguishable.
        assert_eq!(padded_size(100_000), padded_size(100_001));
    }

    #[test]
    fn tampering_wrong_key_and_swapped_blob_are_rejected() {
        let enc = encrypt(b"secret photo bytes").unwrap();
        let mut flipped = enc.ciphertext.clone();
        flipped[20] ^= 1;
        assert_eq!(decrypt(&flipped, &enc.key, &enc.digest, enc.plaintext_len), Err(AttachmentError::Digest));
        // Even with a recomputed digest (attacker controls the pointer's digest? no — but belt and
        // braces) the MAC still fails.
        let d2 = Sha256::digest(&flipped).to_vec();
        assert_eq!(decrypt(&flipped, &enc.key, &d2, enc.plaintext_len), Err(AttachmentError::Mac));
        // A different, validly-encrypted blob does not satisfy this pointer's digest.
        let other = encrypt(b"something else").unwrap();
        assert_eq!(decrypt(&other.ciphertext, &enc.key, &enc.digest, enc.plaintext_len), Err(AttachmentError::Digest));
        let mut wrong_key = enc.key.clone();
        wrong_key[40] ^= 1;
        assert_eq!(decrypt(&enc.ciphertext, &wrong_key, &enc.digest, enc.plaintext_len), Err(AttachmentError::Mac));
        assert_eq!(decrypt(&enc.ciphertext, &enc.key[..32], &enc.digest, enc.plaintext_len), Err(AttachmentError::BadKey));
        // A length larger than the padded plaintext is malformed, not a panic.
        assert_eq!(decrypt(&enc.ciphertext, &enc.key, &enc.digest, 10_000_000), Err(AttachmentError::Malformed));
        assert_eq!(decrypt(&enc.ciphertext[..10], &enc.key, &enc.digest, 1), Err(AttachmentError::Malformed));
    }

    #[test]
    fn keys_and_ivs_are_fresh() {
        let a = encrypt(b"same").unwrap();
        let b = encrypt(b"same").unwrap();
        assert_ne!(a.key, b.key);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn the_streamed_path_writes_the_same_format_as_the_in_memory_one() {
        // Sizes around every boundary: empty, under the 541 floor, block edges, buffer edges.
        for len in [0usize, 1, 15, 16, 17, 540, 541, 542, 4096, STREAM_BUF - 1, STREAM_BUF, STREAM_BUF + 1, 3 * STREAM_BUF + 7, 1_000_003] {
            let plain: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();
            let mut blob = Vec::new();
            let p = encrypt_stream(&plain[..], &mut blob, len as u64).unwrap();
            assert_eq!(p.blob_len as usize, blob.len(), "{len}");
            assert_eq!(blob.len(), IV_LEN + (padded_size(len) / 16 + 1) * 16 + MAC_LEN, "{len}: same size as the in-memory blob");
            // The in-memory reader opens what the streamed writer wrote…
            assert_eq!(decrypt(&blob, &p.key, &p.digest, p.plaintext_len).unwrap(), plain, "{len}");
            // …and the streamed reader opens what the in-memory writer wrote.
            let mem = encrypt(&plain).unwrap();
            let mut out = Vec::new();
            decrypt_stream(std::io::Cursor::new(&mem.ciphertext), mem.ciphertext.len() as u64, &mut out, &mem.key, &mem.digest, mem.plaintext_len).unwrap();
            assert_eq!(out, plain, "{len}");
        }
    }

    #[test]
    fn the_streamed_reader_writes_nothing_from_a_blob_that_does_not_verify() {
        let plain = vec![9u8; 200_000];
        let mut blob = Vec::new();
        let p = encrypt_stream(&plain[..], &mut blob, plain.len() as u64).unwrap();
        let open = |blob: &[u8], key: &[u8], digest: &[u8]| {
            let mut out = Vec::new();
            let r = decrypt_stream(std::io::Cursor::new(blob), blob.len() as u64, &mut out, key, digest, p.plaintext_len);
            (r, out.len())
        };
        let mut flipped = blob.clone();
        flipped[100_000] ^= 1;
        assert_eq!(open(&flipped, &p.key, &p.digest), (Err(AttachmentError::Digest), 0));
        // A swapped blob with a matching digest still fails the MAC under the pointer's key.
        let digest = Sha256::digest(&flipped).to_vec();
        assert_eq!(open(&flipped, &p.key, &digest), (Err(AttachmentError::Mac), 0));
        assert_eq!(open(&blob[..blob.len() - 16], &p.key, &p.digest).0, Err(AttachmentError::Digest));
        assert_eq!(open(&blob, &p.key[..10], &p.digest).0, Err(AttachmentError::BadKey));
        // A source that is not the size it was said to be is refused, either way round.
        assert_eq!(encrypt_stream(&plain[..], std::io::sink(), 10).unwrap_err(), AttachmentError::Malformed);
        assert_eq!(encrypt_stream(&plain[..10], std::io::sink(), 11).unwrap_err(), AttachmentError::Io);
    }
}
