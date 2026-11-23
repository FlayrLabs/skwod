//! Signal's plaintext padding: every message body is padded to a multiple of 160 bytes before it
//! is encrypted, so ciphertext length reveals only a coarse bucket, not the message length.
//!
//! Format (identical to Signal's `PushTransportDetails`): `plaintext || 0x80 || 0x00…`, sized so
//! the padded buffer is `ceil((len + 2) / 160) * 160 - 1` bytes.

/// Bucket size in bytes.
pub const BLOCK: usize = 160;

/// Pad `plaintext` for encryption.
pub fn pad(plaintext: &[u8]) -> Vec<u8> {
    let with_terminator = plaintext.len() + 2;
    let padded_len = with_terminator.div_ceil(BLOCK) * BLOCK - 1;
    let mut out = Vec::with_capacity(padded_len);
    out.extend_from_slice(plaintext);
    out.push(0x80);
    out.resize(padded_len, 0);
    out
}

/// Strip the padding added by [`pad`]. Returns `None` if the terminator is missing (malformed).
pub fn unpad(padded: &[u8]) -> Option<&[u8]> {
    let end = padded.iter().rposition(|&b| b != 0)?;
    (padded[end] == 0x80).then(|| &padded[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pads_to_160_byte_buckets_and_roundtrips() {
        for len in [0usize, 1, 5, 157, 158, 159, 160, 161, 317, 318, 319, 1000] {
            let pt: Vec<u8> = (0..len).map(|i| (i % 251) as u8 | 1).collect();
            let padded = pad(&pt);
            assert_eq!((padded.len() + 1) % BLOCK, 0, "len {len}");
            assert!(padded.len() > pt.len());
            assert_eq!(unpad(&padded).unwrap(), &pt[..]);
        }
        // Short messages of different lengths are indistinguishable by size.
        assert_eq!(pad(b"hi").len(), pad(&[b'x'; 150]).len());
        // Plaintext ending in zero bytes / 0x80 survives.
        assert_eq!(unpad(&pad(&[1, 0, 0])).unwrap(), &[1, 0, 0]);
        assert_eq!(unpad(&pad(&[0x80])).unwrap(), &[0x80]);
    }

    #[test]
    fn rejects_missing_terminator() {
        assert!(unpad(&[0u8; 159]).is_none());
        assert!(unpad(b"no terminator").is_none());
        assert!(unpad(&[]).is_none());
    }
}
