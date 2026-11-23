//! Sealed-sender certificates (libsignal `ServerCertificate` / `SenderCertificate`).
//!
//! Chain of trust, anchored in the invite:
//!
//! ```text
//! invite pins  ──►  instance Ed25519 key          (crate::instance; unchanged since build 29)
//!                     │ signs  ROOT_BINDING_TAG || trust_root_public
//!                     ▼
//!                   trust root   (Curve25519, libsignal)      — client pins this
//!                     │ signs
//!                     ▼
//!                   ServerCertificate (key id 1)
//!                     │ signs
//!                     ▼
//!                   SenderCertificate { "user:device", identity key, expiry }
//! ```
//!
//! The host server issues a short-lived `SenderCertificate` to each authenticated device. A sender
//! puts it *inside* the sealed-sender envelope; the recipient validates it against the pinned
//! trust root, so the sender is authenticated to the recipient without the server ever seeing who
//! sent the envelope.

use libsignal_protocol::{
    DeviceId, IdentityKey, KeyPair, PrivateKey, PublicKey, SenderCertificate, ServerCertificate, Timestamp,
};
use rand::TryRngCore as _;

use crate::store::{CryptoError, DeviceAddress};

/// Domain tag for the instance-key signature over the trust root.
pub const ROOT_BINDING_TAG: &[u8] = b"skwod-sealed-sender-root-v1:";
/// The single server-certificate key id this deployment uses.
pub const SERVER_CERT_KEY_ID: u32 = 1;

/// Server-side signing material: the trust root and the certificate-signing key it vouches for.
pub struct CertAuthority {
    /// Serialized trust-root public key (what clients pin).
    pub trust_root_public: Vec<u8>,
    /// Serialized trust-root private key.
    pub trust_root_private: Vec<u8>,
    /// Serialized `ServerCertificate`.
    pub server_certificate: Vec<u8>,
    /// Serialized private key matching the server certificate.
    pub server_private: Vec<u8>,
}

impl CertAuthority {
    /// Mint a fresh authority (once per instance).
    pub fn generate() -> Result<Self, CryptoError> {
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let root = KeyPair::generate(&mut rng);
        let server = KeyPair::generate(&mut rng);
        let cert = ServerCertificate::new(SERVER_CERT_KEY_ID, server.public_key, &root.private_key, &mut rng)?;
        Ok(Self {
            trust_root_public: root.public_key.serialize().to_vec(),
            trust_root_private: root.private_key.serialize(),
            server_certificate: cert.serialized()?.to_vec(),
            server_private: server.private_key.serialize(),
        })
    }

    /// Issue a sender certificate for `sender`, bound to its libsignal identity key, expiring at
    /// `expires_ms` (epoch milliseconds).
    pub fn issue(&self, sender: &DeviceAddress, identity_key: &[u8], expires_ms: u64) -> Result<Vec<u8>, CryptoError> {
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let identity = IdentityKey::decode(identity_key)?;
        let signer = ServerCertificate::deserialize(&self.server_certificate)?;
        let signer_key = PrivateKey::deserialize(&self.server_private).map_err(|e| CryptoError::Invalid(e.to_string()))?;
        let cert = SenderCertificate::new(
            sender.name()?,
            None,
            *identity.public_key(),
            DeviceId::new(1).expect("1 is a valid device id"),
            Timestamp::from_epoch_millis(expires_ms),
            signer,
            &signer_key,
            &mut rng,
        )?;
        Ok(cert.serialized()?.to_vec())
    }
}

/// Message the instance key signs to vouch for a trust root.
pub fn root_binding_message(trust_root_public: &[u8]) -> Vec<u8> {
    let mut m = ROOT_BINDING_TAG.to_vec();
    m.extend_from_slice(trust_root_public);
    m
}

/// Client side: accept `trust_root_public` only if the pinned instance key signed it.
pub fn verify_root_binding(pinned_instance_public: &[u8], trust_root_public: &[u8], signature: &[u8]) -> bool {
    PublicKey::deserialize(trust_root_public).is_ok()
        && crate::instance::verify(pinned_instance_public, &root_binding_message(trust_root_public), signature)
}

/// What a valid sender certificate asserts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertInfo {
    pub sender: DeviceAddress,
    pub identity_key: Vec<u8>,
    pub expires_ms: u64,
}

/// Validate a serialized sender certificate against a trust root at time `now_ms`.
pub fn validate(cert: &[u8], trust_root_public: &[u8], now_ms: u64) -> Result<CertInfo, CryptoError> {
    let cert = SenderCertificate::deserialize(cert)?;
    let root = PublicKey::deserialize(trust_root_public).map_err(|_| CryptoError::Invalid("trust root".into()))?;
    if !cert.validate(&root, Timestamp::from_epoch_millis(now_ms))? {
        return Err(CryptoError::Invalid("sender certificate not valid for this trust root".into()));
    }
    Ok(CertInfo {
        sender: DeviceAddress::parse(cert.sender_uuid()?).ok_or_else(|| CryptoError::Invalid("certificate sender".into()))?,
        identity_key: IdentityKey::new(cert.key()?).serialize().to_vec(),
        expires_ms: cert.expiration()?.epoch_millis(),
    })
}

/// Server-side upload validation: is `signature` the identity key's signature over a serialized
/// (EC or Kyber) prekey public key? Also checks both keys parse.
pub fn verify_prekey_signature(identity_key: &[u8], serialized_public: &[u8], signature: &[u8], kyber: bool) -> bool {
    let Ok(identity) = IdentityKey::decode(identity_key) else { return false };
    let parses = if kyber {
        libsignal_protocol::kem::PublicKey::deserialize(serialized_public).is_ok()
    } else {
        PublicKey::deserialize(serialized_public).is_ok()
    };
    parses && identity.public_key().verify_signature(serialized_public, signature)
}

/// Does `bytes` parse as a serialized libsignal EC public key (33 bytes, type-prefixed)?
pub fn is_valid_public_key(bytes: &[u8]) -> bool {
    PublicKey::deserialize(bytes).is_ok()
}

/// Does `bytes` parse as a serialized libsignal identity key?
pub fn is_valid_identity_key(bytes: &[u8]) -> bool {
    IdentityKey::decode(bytes).is_ok()
}
