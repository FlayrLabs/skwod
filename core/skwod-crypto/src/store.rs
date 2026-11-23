//! Persistent libsignal store + synchronous protocol operations.
//!
//! [`SignalStore`] implements libsignal's six store traits (identity, prekeys, signed prekeys,
//! Kyber prekeys, sessions, sender keys) over plain serializable maps of libsignal's own record
//! encodings. The whole store snapshots to bytes ([`SignalStore::to_bytes`]) for the SQLCipher
//! cache; nothing in it is ever sent to a server.
//!
//! libsignal's API is `async` only because stores *may* do I/O. Ours is in memory, so every
//! libsignal future completes on its first poll; [`now`] drives them synchronously. That keeps the
//! (non-`Send`) libsignal futures out of the UniFFI async methods, which must be `Send`.
//!
//! Every method here is a thin call into libsignal — no cryptographic logic lives in this file.
//! The only policy is identity trust (see [`IdentityStore`]: a key on record is never replaced
//! by anything a peer or the server sends), the pin check and rollback around a sealed receive
//! ([`SignalStore::sealed_decrypt_opened`]) and Kyber prekey bookkeeping (one-time keys are
//! deleted on use; the last-resort key rejects a replayed base key).

use std::collections::HashMap;
use std::future::Future;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use libsignal_protocol::{
    self as signal, kem, CiphertextMessageType, DeviceId, Direction, GenericSignedPreKey, IdentityKey,
    IdentityKeyPair, IdentityKeyStore, KeyPair, KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore, PreKeyBundle,
    PreKeyId, PreKeyRecord, PreKeySignalMessage, PreKeyStore, ProtocolAddress, PublicKey, SenderCertificate,
    SenderKeyDistributionMessage, SenderKeyMessage, SenderKeyRecord, SenderKeyStore, SessionRecord, SessionStore,
    SessionUsabilityRequirements, SignalMessage, SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord,
    SignedPreKeyStore, Timestamp,
};
use rand::TryRngCore as _;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::padding;

type SResult<T> = Result<T, SignalProtocolError>;

/// Drive a future that never suspends (all our stores are in memory).
fn now<F: Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => v,
        Poll::Pending => unreachable!("in-memory libsignal stores never suspend"),
    }
}

fn rng() -> impl rand::Rng + rand::CryptoRng {
    rand::rngs::OsRng.unwrap_err()
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or_default()
}

/// Session setups ONE sender may make on one (last-resort Kyber key, signed prekey) pair. Each
/// is remembered for replay detection until the pair is pruned, so this is what bounds that
/// memory — per sender, never globally: a sender past it is refused on its own (it can still
/// start sessions on one-time keys), and nobody else's session setup is affected. Honest use is
/// a handful: the last-resort key is only served when the one-time keys have run out.
const MAX_LAST_RESORT_SETUPS_PER_SENDER: usize = 64;

/// Setups remembered for the CURRENT pair at which the owner should rotate it early
/// ([`SignalStore::last_resort_pressure`]): a fresh pair starts with an empty memory.
const LAST_RESORT_PRESSURE: usize = 2048;

/// Bytes of the sender tag appended to a remembered base key.
const SENDER_TAG_LEN: usize = 8;

/// Largest prekey id (Signal's `Medium.MAX_VALUE`); ids wrap within `1..=MAX_ID`.
const MAX_ID: u32 = 0x00FF_FFFF;

/// How long a superseded signed prekey / last-resort Kyber key is kept so in-flight session setups
/// against it still complete (Signal keeps them ~30 days).
pub const SIGNED_PREKEY_GRACE: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Safety-number parameters (Signal's: version 2, 5200 iterations).
const FINGERPRINT_VERSION: u32 = 2;
const FINGERPRINT_ITERATIONS: u32 = 5200;

// ---- errors ----

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    /// The peer's identity key differs from the one we have on record (sending is blocked until
    /// the change is accepted).
    #[error("untrusted identity for {0}")]
    UntrustedIdentity(String),
    /// No usable session / sender key for this peer or distribution.
    #[error("no session: {0}")]
    NoSession(String),
    /// A message we already decrypted (replay or duplicate delivery).
    #[error("duplicate message")]
    Duplicate,
    /// A sealed-sender message from ourselves.
    #[error("sealed sender self-send")]
    SelfSend,
    /// Malformed or unauthentic input.
    #[error("invalid: {0}")]
    Invalid(String),
}

impl From<SignalProtocolError> for CryptoError {
    fn from(e: SignalProtocolError) -> Self {
        match e {
            SignalProtocolError::UntrustedIdentity(a) => CryptoError::UntrustedIdentity(a.name().to_string()),
            SignalProtocolError::SessionNotFound(s) => CryptoError::NoSession(s.to_string()),
            SignalProtocolError::NoSenderKeyState { distribution_id } => CryptoError::NoSession(distribution_id.to_string()),
            SignalProtocolError::DuplicatedMessage(..) => CryptoError::Duplicate,
            SignalProtocolError::SealedSenderSelfSend => CryptoError::SelfSend,
            other => CryptoError::Invalid(other.to_string()),
        }
    }
}

/// A sealed-sender decryption failure. `sender` is set when the envelope opened far enough to
/// authenticate who sent it (valid certificate) but the inner session message failed — which is
/// what lets the caller repair the session with that peer.
#[derive(Debug)]
pub struct SealedError {
    pub sender: Option<DeviceAddress>,
    pub error: CryptoError,
}

impl From<CryptoError> for SealedError {
    fn from(error: CryptoError) -> Self {
        SealedError { sender: None, error }
    }
}
impl From<SignalProtocolError> for SealedError {
    fn from(e: SignalProtocolError) -> Self {
        SealedError { sender: None, error: e.into() }
    }
}

// ---- addressing ----

/// One skwod device. Every skwod device has its **own** libsignal identity key, so each maps to a
/// distinct libsignal address `"<user_id>:<device_id>"` with libsignal device id 1.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeviceAddress {
    pub user_id: String,
    pub device_id: String,
}

impl DeviceAddress {
    pub fn new(user_id: impl Into<String>, device_id: impl Into<String>) -> Self {
        Self { user_id: user_id.into(), device_id: device_id.into() }
    }

    /// The libsignal address name. Fails for ids that would make the encoding ambiguous.
    pub fn name(&self) -> Result<String, CryptoError> {
        if self.user_id.is_empty() || self.device_id.is_empty() || self.user_id.contains(':') {
            return Err(CryptoError::Invalid("device address".into()));
        }
        Ok(format!("{}:{}", self.user_id, self.device_id))
    }

    /// Inverse of [`Self::name`].
    pub fn parse(name: &str) -> Option<Self> {
        let (user, device) = name.split_once(':')?;
        (!user.is_empty() && !device.is_empty()).then(|| Self::new(user, device))
    }

    fn protocol(&self) -> Result<ProtocolAddress, CryptoError> {
        Ok(ProtocolAddress::new(self.name()?, DeviceId::new(1).expect("1 is a valid device id")))
    }
}

// ---- wire-format key material (what a device uploads / a bundle carries) ----

/// A signed EC prekey to upload. All byte fields are libsignal's serialized encodings.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedPreKeyUpload {
    pub id: u32,
    pub public: Vec<u8>,
    pub signature: Vec<u8>,
}

/// A signed Kyber-1024 prekey to upload (one-time or last-resort).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KyberPreKeyUpload {
    pub id: u32,
    pub public: Vec<u8>,
    pub signature: Vec<u8>,
}

/// A one-time EC prekey to upload.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreKeyUpload {
    pub id: u32,
    pub public: Vec<u8>,
}

/// A prekey bundle as served by the key directory.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreKeyBundleData {
    pub registration_id: u32,
    pub identity_key: Vec<u8>,
    pub signed_pre_key: SignedPreKeyUpload,
    /// One-time Kyber prekey if the server had one left, else the device's last-resort key.
    pub kyber_pre_key: KyberPreKeyUpload,
    pub pre_key: Option<PreKeyUpload>,
}

/// A sealed-sender envelope whose outer layer is open and whose sender certificate chains to
/// the trust root. Opening changes NOTHING in the store. The certificate is the server's word:
/// `identity_key` is the key the server says `sender` has, and the caller decides — from its own
/// pins, never from this — whether that is true before the inner message is touched
/// ([`SignalStore::sealed_decrypt_opened`]).
#[derive(Debug, Clone)]
pub struct OpenedEnvelope {
    /// Who the certificate names.
    pub sender: DeviceAddress,
    /// The identity key the certificate carries (and that sealed the envelope).
    pub identity_key: Vec<u8>,
    prekey: bool,
    contents: Vec<u8>,
}

/// A decrypted sealed-sender message.
#[derive(Debug)]
pub struct SealedMessage {
    /// Authenticated by the sender certificate + the libsignal session, both under the identity
    /// key the caller pinned for this sender.
    pub sender: DeviceAddress,
    pub plaintext: Vec<u8>,
    /// The message was a PreKey message that REPLACED a session we already had with this sender:
    /// they lost their side (restored from a backup, reinstalled) and started over. Whatever we
    /// handed them over the old session — sender keys above all — they no longer hold.
    pub session_replaced: bool,
}

/// A peer's identity key changed (their safety number is different now).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityChange {
    pub address: DeviceAddress,
    pub at_ms: u64,
    /// The peer had been marked verified under the previous key.
    pub was_verified: bool,
}

// ---- the six stores ----

#[derive(Clone, Serialize, Deserialize)]
struct KnownIdentity {
    key: Vec<u8>,
    verified: bool,
}

/// Identity store. Trust policy:
/// - no key on record: the first one libsignal sees is recorded. The callers never let that be
///   the server's choice: a receive names the key it expects
///   ([`SignalStore::sealed_decrypt_opened`]) and the engine checks a bundle's key against its
///   pin before [`SignalStore::process_bundle`];
/// - a key on record is NEVER replaced by a message or a bundle, in either direction. A
///   different key is refused ([`CryptoError::UntrustedIdentity`]) when receiving exactly as
///   when sending, whether or not the peer was verified: a server that issues certificates must
///   not be able to swap a contact's key by delivering one message;
/// - the only way a recorded key changes is [`SignalStore::accept_identity`], an explicit
///   decision of the application (the user accepted a changed safety number, or the device's
///   own trust chain names another key). It also retires the session with the old key, clears
///   the verified mark and queues an [`IdentityChange`] for the UI.
#[derive(Clone, Serialize, Deserialize)]
struct IdentityStore {
    key_pair: Vec<u8>,
    registration_id: u32,
    known: HashMap<String, KnownIdentity>,
    changes: Vec<IdentityChange>,
}

impl IdentityStore {
    fn record(&mut self, name: &str, key: &IdentityKey) -> bool {
        let bytes = key.serialize().to_vec();
        match self.known.get_mut(name) {
            None => {
                self.known.insert(name.to_string(), KnownIdentity { key: bytes, verified: false });
                false
            }
            Some(k) if k.key == bytes => false,
            Some(k) => {
                let was_verified = k.verified;
                k.key = bytes;
                k.verified = false;
                if let Some(address) = DeviceAddress::parse(name) {
                    self.changes.push(IdentityChange { address, at_ms: now_ms(), was_verified });
                }
                true
            }
        }
    }
}

#[async_trait(?Send)]
impl IdentityKeyStore for IdentityStore {
    async fn get_identity_key_pair(&self) -> SResult<IdentityKeyPair> {
        IdentityKeyPair::try_from(self.key_pair.as_slice())
    }

    async fn get_local_registration_id(&self) -> SResult<u32> {
        Ok(self.registration_id)
    }

    async fn save_identity(&mut self, address: &ProtocolAddress, identity: &IdentityKey) -> SResult<signal::IdentityChange> {
        // libsignal calls this after every successful encrypt and decrypt. It may record a first
        // key; it may never replace one (see the type's policy).
        if self.known.get(address.name()).is_some_and(|k| k.key.as_slice() != &*identity.serialize()) {
            return Err(SignalProtocolError::UntrustedIdentity(address.clone()));
        }
        Ok(signal::IdentityChange::from_changed(self.record(address.name(), identity)))
    }

    async fn is_trusted_identity(&self, address: &ProtocolAddress, identity: &IdentityKey, _direction: Direction) -> SResult<bool> {
        Ok(match self.known.get(address.name()) {
            None => true,
            Some(k) => k.key.as_slice() == &*identity.serialize(),
        })
    }

    async fn get_identity(&self, address: &ProtocolAddress) -> SResult<Option<IdentityKey>> {
        self.known.get(address.name()).map(|k| IdentityKey::decode(&k.key)).transpose()
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct PreKeys {
    records: HashMap<u32, Vec<u8>>,
}

#[async_trait(?Send)]
impl PreKeyStore for PreKeys {
    async fn get_pre_key(&self, id: PreKeyId) -> SResult<PreKeyRecord> {
        PreKeyRecord::deserialize(self.records.get(&u32::from(id)).ok_or(SignalProtocolError::InvalidPreKeyId)?)
    }
    async fn save_pre_key(&mut self, id: PreKeyId, record: &PreKeyRecord) -> SResult<()> {
        self.records.insert(id.into(), record.serialize()?);
        Ok(())
    }
    async fn remove_pre_key(&mut self, id: PreKeyId) -> SResult<()> {
        if let Some(mut r) = self.records.remove(&u32::from(id)) {
            r.zeroize();
        }
        Ok(())
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct SignedPreKeys {
    records: HashMap<u32, Vec<u8>>,
    current: Option<u32>,
}

#[async_trait(?Send)]
impl SignedPreKeyStore for SignedPreKeys {
    async fn get_signed_pre_key(&self, id: SignedPreKeyId) -> SResult<SignedPreKeyRecord> {
        SignedPreKeyRecord::deserialize(self.records.get(&u32::from(id)).ok_or(SignalProtocolError::InvalidSignedPreKeyId)?)
    }
    async fn save_signed_pre_key(&mut self, id: SignedPreKeyId, record: &SignedPreKeyRecord) -> SResult<()> {
        self.records.insert(id.into(), record.serialize()?);
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct KyberEntry {
    record: Vec<u8>,
    last_resort: bool,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct KyberPreKeys {
    records: HashMap<u32, KyberEntry>,
    current_last_resort: Option<u32>,
    /// `(kyber id, signed ec id)` → base keys already used with that pair. A last-resort key is
    /// reusable by design, so a repeated base key is the replay signal. Each entry is the
    /// serialized base key, followed (entries written since build 45) by a short tag of the
    /// sender that used it, which is what the per-sender bound counts.
    base_keys_seen: HashMap<(u32, u32), Vec<Vec<u8>>>,
    /// Who the message being decrypted right now is from (set around a sealed receive).
    #[serde(skip)]
    sender_tag: Option<[u8; SENDER_TAG_LEN]>,
}

fn sender_tag(name: &str) -> [u8; SENDER_TAG_LEN] {
    use sha2::Digest as _;
    let d = sha2::Sha256::new().chain_update(b"skwod/base-key-sender-v1").chain_update(name.as_bytes()).finalize();
    d[..SENDER_TAG_LEN].try_into().expect("a SHA-256 digest is longer than the tag")
}

#[async_trait(?Send)]
impl KyberPreKeyStore for KyberPreKeys {
    async fn get_kyber_pre_key(&self, id: KyberPreKeyId) -> SResult<KyberPreKeyRecord> {
        KyberPreKeyRecord::deserialize(&self.records.get(&u32::from(id)).ok_or(SignalProtocolError::InvalidKyberPreKeyId)?.record)
    }
    async fn save_kyber_pre_key(&mut self, id: KyberPreKeyId, record: &KyberPreKeyRecord) -> SResult<()> {
        // Records saved through the trait are one-time; last-resort keys go through
        // `SignalStore::generate_last_resort_kyber`.
        self.records.insert(id.into(), KyberEntry { record: record.serialize()?, last_resort: false });
        Ok(())
    }
    async fn mark_kyber_pre_key_used(&mut self, id: KyberPreKeyId, ec_id: SignedPreKeyId, base_key: &PublicKey) -> SResult<()> {
        let id = u32::from(id);
        let last_resort = self.records.get(&id).ok_or(SignalProtocolError::InvalidKyberPreKeyId)?.last_resort;
        if !last_resort {
            if let Some(mut e) = self.records.remove(&id) {
                e.record.zeroize();
            }
            return Ok(());
        }
        let seen = self.base_keys_seen.entry((id, ec_id.into())).or_default();
        let mut entry = base_key.serialize().to_vec();
        let base_len = entry.len();
        if seen.iter().any(|e| e.len() >= base_len && e[..base_len] == entry[..]) {
            return Err(SignalProtocolError::InvalidMessage(CiphertextMessageType::PreKey, "reused base key".to_owned()));
        }
        if let Some(tag) = self.sender_tag {
            // Bounded per sender, and only that sender is refused: forgetting old base keys
            // would let them be replayed, and a bound shared by everyone would let one peer
            // close the door on all the others.
            let of_sender = seen.iter().filter(|e| e.len() == base_len + SENDER_TAG_LEN && e[base_len..] == tag).count();
            if of_sender >= MAX_LAST_RESORT_SETUPS_PER_SENDER {
                return Err(SignalProtocolError::InvalidMessage(CiphertextMessageType::PreKey, "too many session setups from this sender".to_owned()));
            }
            entry.extend_from_slice(&tag);
        }
        seen.push(entry);
        Ok(())
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct Sessions {
    records: HashMap<String, Vec<u8>>,
}

#[async_trait(?Send)]
impl SessionStore for Sessions {
    async fn load_session(&self, address: &ProtocolAddress) -> SResult<Option<SessionRecord>> {
        self.records.get(address.name()).map(|b| SessionRecord::deserialize(b)).transpose()
    }
    async fn store_session(&mut self, address: &ProtocolAddress, record: &SessionRecord) -> SResult<()> {
        if let Some(mut old) = self.records.insert(address.name().to_string(), record.serialize()?) {
            old.zeroize();
        }
        Ok(())
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct SenderKeys {
    /// `"<address name>|<distribution uuid>"` → serialized `SenderKeyRecord`.
    records: HashMap<String, Vec<u8>>,
}

fn sender_key_slot(sender: &str, distribution_id: Uuid) -> String {
    format!("{sender}|{distribution_id}")
}

#[async_trait(?Send)]
impl SenderKeyStore for SenderKeys {
    async fn store_sender_key(&mut self, sender: &ProtocolAddress, distribution_id: Uuid, record: &SenderKeyRecord) -> SResult<()> {
        if let Some(mut old) = self.records.insert(sender_key_slot(sender.name(), distribution_id), record.serialize()?) {
            old.zeroize();
        }
        Ok(())
    }
    async fn load_sender_key(&mut self, sender: &ProtocolAddress, distribution_id: Uuid) -> SResult<Option<SenderKeyRecord>> {
        self.records.get(&sender_key_slot(sender.name(), distribution_id)).map(|b| SenderKeyRecord::deserialize(b)).transpose()
    }
}

// ---- the store ----

/// `(last-resort Kyber prekey id, signed EC prekey id)`.
type BaseKeyPair = (u32, u32);

/// The records one sealed receive can touch, as they were before it: the sender's session and
/// recorded identity, the prekeys the message names, and how many identity notices were queued.
struct Undo {
    name: String,
    session: Option<Vec<u8>>,
    known: Option<KnownIdentity>,
    changes: usize,
    pre_key: Option<(u32, Option<Vec<u8>>)>,
    kyber: Option<(u32, Option<KyberEntry>)>,
    base_keys: Option<(BaseKeyPair, Option<Vec<Vec<u8>>>)>,
}

impl Undo {
    fn put<K: std::hash::Hash + Eq, V>(map: &mut HashMap<K, V>, key: K, value: Option<V>) -> Option<V> {
        match value {
            Some(v) => map.insert(key, v),
            None => map.remove(&key),
        }
    }

    /// Put every record back.
    fn restore(mut self, store: &mut SignalStore) {
        if let Some(mut now) = Self::put(&mut store.sessions.records, self.name.clone(), self.session.take()) {
            now.zeroize();
        }
        Self::put(&mut store.identity.known, self.name.clone(), self.known.take());
        store.identity.changes.truncate(self.changes);
        if let Some((id, record)) = self.pre_key.take() {
            if let Some(mut now) = Self::put(&mut store.pre_keys.records, id, record) {
                now.zeroize();
            }
        }
        if let Some((id, entry)) = self.kyber.take() {
            if let Some(mut now) = Self::put(&mut store.kyber.records, id, entry) {
                now.record.zeroize();
            }
        }
        if let Some((pair, seen)) = self.base_keys.take() {
            Self::put(&mut store.kyber.base_keys_seen, pair, seen);
        }
    }

    /// The receive stands; wipe the copies.
    fn discard(self) {}
}

impl Drop for Undo {
    fn drop(&mut self) {
        for v in self.session.iter_mut().chain(self.pre_key.iter_mut().filter_map(|(_, r)| r.as_mut())) {
            v.zeroize();
        }
        if let Some((_, Some(e))) = &mut self.kyber {
            e.record.zeroize();
        }
    }
}

/// Snapshot format version (first byte of [`SignalStore::to_bytes`]).
const SNAPSHOT_VERSION: u8 = 1;

/// One device's complete libsignal state.
#[derive(Clone, Serialize, Deserialize)]
pub struct SignalStore {
    identity: IdentityStore,
    pre_keys: PreKeys,
    signed: SignedPreKeys,
    kyber: KyberPreKeys,
    sessions: Sessions,
    sender_keys: SenderKeys,
    next_pre_key_id: u32,
    next_signed_id: u32,
    next_kyber_id: u32,
}

impl Drop for SignalStore {
    fn drop(&mut self) {
        self.identity.key_pair.zeroize();
        for v in self.pre_keys.records.values_mut().chain(self.signed.records.values_mut()) {
            v.zeroize();
        }
        for v in self.kyber.records.values_mut() {
            v.record.zeroize();
        }
        for v in self.sessions.records.values_mut().chain(self.sender_keys.records.values_mut()) {
            v.zeroize();
        }
    }
}

fn next_id(counter: &mut u32) -> u32 {
    let id = *counter;
    *counter = if id >= MAX_ID { 1 } else { id + 1 };
    id
}

fn random_start() -> u32 {
    (u32::from_le_bytes(crate::random_bytes()) % MAX_ID) + 1
}

impl SignalStore {
    /// A brand-new device identity (fresh identity key + registration id, no prekeys yet).
    pub fn generate() -> Self {
        let mut r = rng();
        let identity = IdentityKeyPair::generate(&mut r);
        // Signal registration ids are 14-bit and non-zero.
        let registration_id = (u32::from_le_bytes(crate::random_bytes()) % 16380) + 1;
        Self::with_identity(identity.serialize().to_vec(), registration_id)
    }

    fn with_identity(key_pair: Vec<u8>, registration_id: u32) -> Self {
        Self {
            identity: IdentityStore { key_pair, registration_id, known: HashMap::new(), changes: Vec::new() },
            pre_keys: PreKeys::default(),
            signed: SignedPreKeys::default(),
            kyber: KyberPreKeys::default(),
            sessions: Sessions::default(),
            sender_keys: SenderKeys::default(),
            next_pre_key_id: random_start(),
            next_signed_id: random_start(),
            next_kyber_id: random_start(),
        }
    }

    // ---- persistence ----

    /// Serialize the whole store for the encrypted on-device cache.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![SNAPSHOT_VERSION];
        out.extend(postcard::to_stdvec(self).expect("store serialization is infallible"));
        out
    }

    /// Restore a store written by [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        match bytes.split_first() {
            Some((&SNAPSHOT_VERSION, rest)) => {
                let store: SignalStore = postcard::from_bytes(rest).map_err(|_| CryptoError::Invalid("store snapshot".into()))?;
                // Fail now rather than at first use if the identity is unreadable.
                IdentityKeyPair::try_from(store.identity.key_pair.as_slice())?;
                Ok(store)
            }
            _ => Err(CryptoError::Invalid("store snapshot version".into())),
        }
    }

    /// The long-term identity only (identity key pair, registration id, known peer identities and
    /// their verified marks) — what a key backup carries. Sessions, sender keys and prekey private
    /// halves are deliberately excluded: they are re-established after a restore, never resumed
    /// from a stale copy.
    pub fn export_identity(&self) -> Vec<u8> {
        let mut fresh = Self::with_identity(self.identity.key_pair.clone(), self.identity.registration_id);
        fresh.identity.known = self.identity.known.clone();
        fresh.to_bytes()
    }

    // ---- identity ----

    fn identity_key_pair(&self) -> IdentityKeyPair {
        IdentityKeyPair::try_from(self.identity.key_pair.as_slice()).expect("validated at construction")
    }

    /// Our serialized public identity key.
    pub fn identity_key(&self) -> Vec<u8> {
        self.identity_key_pair().identity_key().serialize().to_vec()
    }

    pub fn registration_id(&self) -> u32 {
        self.identity.registration_id
    }

    /// The identity key on record for `peer`, and whether the user marked it verified.
    pub fn known_identity(&self, peer: &DeviceAddress) -> Option<(Vec<u8>, bool)> {
        self.identity.known.get(&peer.name().ok()?).map(|k| (k.key.clone(), k.verified))
    }

    /// Explicitly trust `identity_key` for `peer` (first contact, or the user accepting a changed
    /// safety number). Returns true when it replaced a different key.
    ///
    /// When the key changes, the session with the old key is retired here as well: no current
    /// session may outlive the identity it was made with.
    pub fn accept_identity(&mut self, peer: &DeviceAddress, identity_key: &[u8]) -> Result<bool, CryptoError> {
        let key = IdentityKey::decode(identity_key)?;
        let changed = self.identity.record(&peer.name()?, &key);
        if changed || self.session_identity(peer).is_some_and(|k| k != identity_key) {
            self.archive_session(peer)?;
        }
        Ok(changed)
    }

    /// The remote identity key of the CURRENT session with `peer`, if there is one.
    pub fn session_identity(&self, peer: &DeviceAddress) -> Option<Vec<u8>> {
        let record = SessionRecord::deserialize(self.sessions.records.get(&peer.name().ok()?)?).ok()?;
        record.remote_identity_key_bytes().ok().flatten()
    }

    /// [`Self::has_session`], and both the session and the key on record are for exactly
    /// `identity_key`. The only kind of session anything may be sent on.
    pub fn has_session_with(&self, peer: &DeviceAddress, identity_key: &[u8]) -> bool {
        self.has_session(peer)
            && self.session_identity(peer).as_deref() == Some(identity_key)
            && self.known_identity(peer).is_some_and(|(k, _)| k == identity_key)
    }

    /// Mark (or unmark) `peer`'s current identity as verified out-of-band. A verified peer whose
    /// key later changes blocks sending until re-accepted.
    pub fn set_verified(&mut self, peer: &DeviceAddress, verified: bool) -> Result<(), CryptoError> {
        let k = self.identity.known.get_mut(&peer.name()?).ok_or_else(|| CryptoError::NoSession("unknown identity".into()))?;
        k.verified = verified;
        Ok(())
    }

    /// ECDH of our identity private key with `public` (the link bundle's key agreement).
    pub fn identity_agreement(&self, public: &PublicKey) -> Option<Vec<u8>> {
        self.identity_key_pair().private_key().calculate_agreement(public).ok().map(|s| s.to_vec())
    }

    /// Open a link bundle sealed TO this device's identity key (see [`crate::link::seal_bundle`]).
    pub fn open_link_bundle(&self, code: &str, user_id: &str, linker_identity_key: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
        crate::link::open_bundle_with(code, user_id, linker_identity_key, &self.identity_key(), sealed, |ephemeral| self.identity_agreement(ephemeral))
    }

    /// Sign `new_identity_key` as a new device of account `user_id` with our identity key (see
    /// [`crate::link`]).
    pub fn sign_link(&self, user_id: &str, new_identity_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        IdentityKey::decode(new_identity_key)?;
        self.identity_key_pair()
            .private_key()
            .calculate_signature(&crate::link::link_message(user_id, new_identity_key), &mut rng())
            .map(|s| s.to_vec())
            .map_err(|e| CryptoError::Invalid(e.to_string()))
    }

    /// Sign "`member_user_id` is a member of `server_id`" with our identity key (see
    /// [`crate::link::member_approval_message`]).
    pub fn sign_member_approval(&self, server_id: &str, member_user_id: &str, approver_user_id: &str, timestamp_ms: i64) -> Result<Vec<u8>, CryptoError> {
        self.identity_key_pair()
            .private_key()
            .calculate_signature(&crate::link::member_approval_message(server_id, member_user_id, approver_user_id, timestamp_ms), &mut rng())
            .map(|s| s.to_vec())
            .map_err(|e| CryptoError::Invalid(e.to_string()))
    }

    /// Sign an account-level device operation with our identity key (see [`crate::link`]).
    pub fn sign_device_op(&self, op: &str, user_id: &str, target: &str, timestamp_ms: u64, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.identity_key_pair()
            .private_key()
            .calculate_signature(&crate::link::device_op_message(op, user_id, target, timestamp_ms, payload), &mut rng())
            .map(|s| s.to_vec())
            .map_err(|e| CryptoError::Invalid(e.to_string()))
    }

    /// Drain queued "safety number changed" notices.
    pub fn take_identity_changes(&mut self) -> Vec<IdentityChange> {
        std::mem::take(&mut self.identity.changes)
    }

    /// Signal's numeric safety number (60 digits) between us and `peer`, using the identity key
    /// on record for them. Both sides compute the same string.
    pub fn safety_number(&self, local: &DeviceAddress, peer: &DeviceAddress) -> Result<String, CryptoError> {
        let (key, _) = self.known_identity(peer).ok_or_else(|| CryptoError::NoSession("unknown identity".into()))?;
        safety_number(&local.name()?, &self.identity_key(), &peer.name()?, &key)
    }

    // ---- prekeys ----

    /// Generate + store a new signed EC prekey and make it current.
    pub fn generate_signed_prekey(&mut self) -> Result<SignedPreKeyUpload, CryptoError> {
        let mut r = rng();
        let id = next_id(&mut self.next_signed_id);
        let kp = KeyPair::generate(&mut r);
        let public = kp.public_key.serialize().to_vec();
        let signature = self.identity_key_pair().private_key().calculate_signature(&public, &mut r).map_err(|e| CryptoError::Invalid(e.to_string()))?.to_vec();
        let record = SignedPreKeyRecord::new(id.into(), Timestamp::from_epoch_millis(now_ms()), &kp, &signature);
        self.signed.records.insert(id, record.serialize()?);
        self.signed.current = Some(id);
        Ok(SignedPreKeyUpload { id, public, signature })
    }

    fn generate_kyber(&mut self, last_resort: bool) -> Result<KyberPreKeyUpload, CryptoError> {
        let id = next_id(&mut self.next_kyber_id);
        let record = KyberPreKeyRecord::generate(kem::KeyType::Kyber1024, id.into(), self.identity_key_pair().private_key())?;
        let upload = KyberPreKeyUpload { id, public: record.public_key()?.serialize().to_vec(), signature: record.signature()? };
        self.kyber.records.insert(id, KyberEntry { record: record.serialize()?, last_resort });
        if last_resort {
            self.kyber.current_last_resort = Some(id);
        }
        Ok(upload)
    }

    /// Generate + store a new **last-resort** Kyber prekey (served when one-time keys run out) and
    /// make it current.
    pub fn generate_last_resort_kyber(&mut self) -> Result<KyberPreKeyUpload, CryptoError> {
        self.generate_kyber(true)
    }

    /// Generate + store `n` one-time Kyber prekeys.
    pub fn generate_one_time_kyber(&mut self, n: usize) -> Result<Vec<KyberPreKeyUpload>, CryptoError> {
        (0..n).map(|_| self.generate_kyber(false)).collect()
    }

    /// Generate + store `n` one-time EC prekeys.
    pub fn generate_one_time_prekeys(&mut self, n: usize) -> Result<Vec<PreKeyUpload>, CryptoError> {
        let mut r = rng();
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            let id = next_id(&mut self.next_pre_key_id);
            let kp = KeyPair::generate(&mut r);
            self.pre_keys.records.insert(id, PreKeyRecord::new(id.into(), &kp).serialize()?);
            out.push(PreKeyUpload { id, public: kp.public_key.serialize().to_vec() });
        }
        Ok(out)
    }

    /// Age (ms since epoch) of the current signed prekey, for rotation scheduling.
    pub fn signed_prekey_created_ms(&self) -> Option<u64> {
        let id = self.signed.current?;
        let rec = SignedPreKeyRecord::deserialize(self.signed.records.get(&id)?).ok()?;
        rec.timestamp().ok().map(|t| t.epoch_millis())
    }

    /// Drop superseded signed prekeys and last-resort Kyber keys older than the grace period.
    pub fn prune_rotated_keys(&mut self) {
        let cutoff = now_ms().saturating_sub(SIGNED_PREKEY_GRACE.as_millis() as u64);
        let current = self.signed.current;
        self.signed.records.retain(|id, bytes| {
            Some(*id) == current
                || SignedPreKeyRecord::deserialize(bytes).and_then(|r| r.timestamp()).map(|t| t.epoch_millis() >= cutoff).unwrap_or(false)
        });
        let current_lr = self.kyber.current_last_resort;
        self.kyber.records.retain(|id, e| {
            !e.last_resort
                || Some(*id) == current_lr
                || KyberPreKeyRecord::deserialize(&e.record).and_then(|r| r.timestamp()).map(|t| t.epoch_millis() >= cutoff).unwrap_or(false)
        });
        let live: Vec<u32> = self.kyber.records.keys().copied().collect();
        self.kyber.base_keys_seen.retain(|(kyber_id, _), _| live.contains(kyber_id));
    }

    /// Bound the one-time prekey private halves we keep to the newest `keep` of each kind. A
    /// private half normally goes when its key is used; one whose public half the server handed
    /// to a peer that never wrote (or that the server dropped in a re-key) would otherwise stay
    /// forever. Ids are handed out in increasing order (wrapping at [`MAX_ID`]), so "newest" is
    /// "closest below the next id".
    pub fn prune_one_time_prekeys(&mut self, keep: usize) {
        fn oldest(ids: Vec<u32>, next: u32, keep: usize) -> Vec<u32> {
            let mut by_age: Vec<(u32, u32)> = ids.into_iter().map(|id| (next.wrapping_sub(id).wrapping_sub(1) % (MAX_ID + 1), id)).collect();
            by_age.sort();
            by_age.into_iter().skip(keep).map(|(_, id)| id).collect()
        }
        for id in oldest(self.pre_keys.records.keys().copied().collect(), self.next_pre_key_id, keep) {
            if let Some(mut r) = self.pre_keys.records.remove(&id) {
                r.zeroize();
            }
        }
        let one_time: Vec<u32> = self.kyber.records.iter().filter(|(_, e)| !e.last_resort).map(|(id, _)| *id).collect();
        for id in oldest(one_time, self.next_kyber_id, keep) {
            if let Some(mut e) = self.kyber.records.remove(&id) {
                e.record.zeroize();
            }
        }
        let live: Vec<u32> = self.kyber.records.keys().copied().collect();
        self.kyber.base_keys_seen.retain(|(kyber_id, _), _| live.contains(kyber_id));
    }

    /// The replay memory of the CURRENT signed prekey + last-resort Kyber key has grown large
    /// (many peers set sessions up on it): rotate the pair now rather than at the weekly
    /// rotation. A new pair starts with an empty memory; the old one keeps its own until it is
    /// pruned, so nothing that was seen becomes replayable.
    pub fn last_resort_pressure(&self) -> bool {
        match (self.kyber.current_last_resort, self.signed.current) {
            (Some(kyber), Some(signed)) => self.kyber.base_keys_seen.get(&(kyber, signed)).is_some_and(|seen| seen.len() >= LAST_RESORT_PRESSURE),
            _ => false,
        }
    }

    /// How many unused one-time (EC, Kyber) prekey private halves we still hold.
    pub fn one_time_prekey_counts(&self) -> (usize, usize) {
        (self.pre_keys.records.len(), self.kyber.records.values().filter(|e| !e.last_resort).count())
    }

    // ---- sessions ----

    /// Do we hold a usable (fresh, PQXDH-established, SPQR-ratcheting) session to `peer`?
    pub fn has_session(&self, peer: &DeviceAddress) -> bool {
        let Ok(name) = peer.name() else { return false };
        let Some(bytes) = self.sessions.records.get(&name) else { return false };
        let Ok(record) = SessionRecord::deserialize(bytes) else { return false };
        record
            .has_usable_sender_chain(
                SystemTime::now(),
                SessionUsabilityRequirements::NotStale
                    | SessionUsabilityRequirements::EstablishedWithPqxdh
                    | SessionUsabilityRequirements::Spqr,
            )
            .unwrap_or(false)
    }

    /// Archive the current session with `peer` (the next send must set up a fresh one). Old
    /// receiving state is kept so in-flight messages still decrypt.
    pub fn archive_session(&mut self, peer: &DeviceAddress) -> Result<(), CryptoError> {
        let name = peer.name()?;
        if let Some(bytes) = self.sessions.records.get(&name) {
            let mut record = SessionRecord::deserialize(bytes)?;
            record.archive_current_state()?;
            if let Some(mut old) = self.sessions.records.insert(name, record.serialize()?) {
                old.zeroize();
            }
        }
        Ok(())
    }

    /// Start a session to `peer` from their prekey bundle (PQXDH). Verifies both prekey signatures
    /// against the bundle's identity key and enforces the identity trust policy.
    pub fn process_bundle(&mut self, local: &DeviceAddress, peer: &DeviceAddress, bundle: &PreKeyBundleData) -> Result<(), CryptoError> {
        let pre_key = bundle
            .pre_key
            .as_ref()
            .map(|p| Ok::<_, CryptoError>((PreKeyId::from(p.id), PublicKey::deserialize(&p.public).map_err(|e| CryptoError::Invalid(e.to_string()))?)))
            .transpose()?;
        let b = PreKeyBundle::new(
            bundle.registration_id,
            DeviceId::new(1).expect("1 is a valid device id"),
            pre_key,
            bundle.signed_pre_key.id.into(),
            PublicKey::deserialize(&bundle.signed_pre_key.public).map_err(|e| CryptoError::Invalid(e.to_string()))?,
            bundle.signed_pre_key.signature.clone(),
            bundle.kyber_pre_key.id.into(),
            kem::PublicKey::deserialize(&bundle.kyber_pre_key.public)?,
            bundle.kyber_pre_key.signature.clone(),
            IdentityKey::decode(&bundle.identity_key)?,
        )?;
        now(signal::process_prekey_bundle(
            &peer.protocol()?,
            &local.protocol()?,
            &mut self.sessions,
            &mut self.identity,
            &b,
            SystemTime::now(),
            &mut rng(),
        ))?;
        Ok(())
    }

    /// Pad + encrypt `plaintext` to `peer` on the existing session and seal it (Sealed Sender v1)
    /// with our sender certificate. The result is what goes to the server: it reveals neither the
    /// sender nor the content.
    ///
    /// `pinned_identity` is the key the CALLER holds for `peer` from its own trust decisions.
    /// Nothing is encrypted unless the key on record and the session are both for exactly that
    /// key ([`CryptoError::UntrustedIdentity`] otherwise): a session that got here any other way
    /// is never sent on.
    pub fn sealed_encrypt(&mut self, peer: &DeviceAddress, pinned_identity: &[u8], sender_certificate: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let name = peer.name()?;
        if self.known_identity(peer).is_none_or(|(k, _)| k != pinned_identity) || self.session_identity(peer).is_some_and(|k| k != pinned_identity) {
            return Err(CryptoError::UntrustedIdentity(name));
        }
        let cert = SenderCertificate::deserialize(sender_certificate)?;
        let padded = padding::pad(plaintext);
        Ok(now(signal::sealed_sender_encrypt(
            &peer.protocol()?,
            &cert,
            &padded,
            &mut self.sessions,
            &mut self.identity,
            SystemTime::now(),
            &mut rng(),
        ))?)
    }

    /// Open the outer layer of a sealed-sender envelope addressed to us and validate the sender
    /// certificate against `trust_root`. Read-only: the store is not changed, whatever the
    /// envelope holds. See [`OpenedEnvelope`].
    pub fn sealed_open(&self, local: &DeviceAddress, trust_root: &[u8], now_ms: u64, envelope: &[u8]) -> Result<OpenedEnvelope, CryptoError> {
        let root = PublicKey::deserialize(trust_root).map_err(|_| CryptoError::Invalid("trust root".into()))?;
        // libsignal checks here that the key that sealed the envelope is the certificate's key.
        let usmc = now(signal::sealed_sender_decrypt_to_usmc(envelope, &self.identity))?;
        if !usmc.sender()?.validate(&root, Timestamp::from_epoch_millis(now_ms))? {
            return Err(CryptoError::Invalid("sender certificate failed trust-root validation".into()));
        }
        let sender = DeviceAddress::parse(usmc.sender()?.sender_uuid()?).ok_or_else(|| CryptoError::Invalid("certificate sender".into()))?;
        sender.name()?;
        if u8::from(usmc.sender()?.sender_device_id()?) != 1 {
            return Err(CryptoError::Invalid("certificate device id".into()));
        }
        if &sender == local {
            return Err(CryptoError::SelfSend);
        }
        let prekey = match usmc.msg_type()? {
            CiphertextMessageType::Whisper => false,
            CiphertextMessageType::PreKey => true,
            // Channel messages never travel sealed; a sender-key payload here could only be
            // someone burning a channel's message keys.
            other => return Err(SignalProtocolError::InvalidMessage(other, "unexpected sealed-sender payload".into()).into()),
        };
        Ok(OpenedEnvelope {
            sender,
            identity_key: IdentityKey::new(usmc.sender()?.key()?).serialize().to_vec(),
            prekey,
            contents: usmc.contents()?.to_vec(),
        })
    }

    /// Decrypt the inner session message of an [`OpenedEnvelope`] and strip padding.
    ///
    /// `pinned_identity` is the identity key the CALLER holds for the sender from its own trust
    /// decisions (a contact's chain-verified device key, a vouched sibling's key). The message is
    /// refused with [`CryptoError::UntrustedIdentity`], before libsignal sees it, unless
    /// - the certificate's key is that key,
    /// - a PreKey message names that key as its identity, and
    /// - the key already on record for the sender (if any) is that key.
    ///
    /// So a certificate the server minted for a contact under another key can neither start nor
    /// replace a session. A refusal queues an [`IdentityChange`] when a different key was on
    /// record. Whatever else goes wrong, the store is put back exactly as it was: a failed or
    /// refused message leaves no session, no identity, and consumes no prekey.
    ///
    /// `SealedError::sender` is set only for failures of a message that passed those checks —
    /// the only ones that say anything about the session with the real peer.
    pub fn sealed_decrypt_opened(&mut self, local: &DeviceAddress, opened: &OpenedEnvelope, pinned_identity: &[u8]) -> Result<SealedMessage, SealedError> {
        let name = opened.sender.name()?;
        let refuse = |store: &mut Self| {
            if let Some(k) = store.identity.known.get(&name).filter(|k| k.key != opened.identity_key) {
                let was_verified = k.verified;
                store.identity.changes.push(IdentityChange { address: opened.sender.clone(), at_ms: now_ms(), was_verified });
            }
            SealedError { sender: None, error: CryptoError::UntrustedIdentity(name.clone()) }
        };
        if opened.identity_key != pinned_identity || self.identity.known.get(&name).is_some_and(|k| k.key != pinned_identity) {
            return Err(refuse(self));
        }
        let undo = self.snapshot_for(opened)?;
        let result = self.decrypt_inner(local, opened, Some(pinned_identity));
        let result = match result {
            // Belt and braces: what is now the current session must be with the pinned key.
            Ok(m) if self.session_identity(&opened.sender).is_some_and(|k| k != pinned_identity) => {
                drop(m);
                Err(SealedError { sender: None, error: CryptoError::UntrustedIdentity(name.clone()) })
            }
            other => other,
        };
        match result {
            Ok(m) => {
                undo.discard();
                Ok(m)
            }
            Err(e) => {
                undo.restore(self);
                Err(e)
            }
        }
    }

    /// Read what an [`OpenedEnvelope`] says WITHOUT accepting its sender: the inner message is
    /// decrypted as a first contact under the certificate's own key, and then every trace of it
    /// is removed again — no session, no identity, no consumed prekey, whether it worked or not.
    /// For a device the caller has not decided about yet (listed but not vouched for): the text
    /// can be held for the user, and nothing can ever be sent to that key because of it. Only a
    /// PreKey message can be read this way.
    pub fn sealed_peek(&mut self, local: &DeviceAddress, opened: &OpenedEnvelope) -> Result<Vec<u8>, CryptoError> {
        if !opened.prekey {
            return Err(CryptoError::NoSession(opened.sender.name()?));
        }
        let name = opened.sender.name()?;
        let undo = self.snapshot_for(opened)?;
        self.identity.known.remove(&name);
        if let Some(mut old) = self.sessions.records.remove(&name) {
            old.zeroize();
        }
        let result = self.decrypt_inner(local, opened, None);
        undo.restore(self);
        result.map(|m| m.plaintext).map_err(|e| e.error)
    }

    /// One-call form of [`Self::sealed_open`] + [`Self::sealed_decrypt_opened`]: `pinned` returns
    /// the identity key the caller holds for the (certificate-named) sender, or `None` to refuse.
    pub fn sealed_decrypt(
        &mut self,
        local: &DeviceAddress,
        trust_root: &[u8],
        now_ms: u64,
        envelope: &[u8],
        pinned: impl FnOnce(&DeviceAddress) -> Option<Vec<u8>>,
    ) -> Result<SealedMessage, SealedError> {
        let opened = self.sealed_open(local, trust_root, now_ms, envelope)?;
        let Some(pin) = pinned(&opened.sender) else {
            return Err(CryptoError::UntrustedIdentity(opened.sender.name()?).into());
        };
        self.sealed_decrypt_opened(local, &opened, &pin)
    }

    /// What a receive of `opened` could change, as it is now.
    fn snapshot_for(&self, opened: &OpenedEnvelope) -> Result<Undo, CryptoError> {
        let name = opened.sender.name()?;
        let mut undo = Undo {
            session: self.sessions.records.get(&name).cloned(),
            known: self.identity.known.get(&name).cloned(),
            changes: self.identity.changes.len(),
            name,
            pre_key: None,
            kyber: None,
            base_keys: None,
        };
        if opened.prekey {
            // Unauthenticated at this point; it only says which records to keep a copy of.
            let m = PreKeySignalMessage::try_from(opened.contents.as_slice())?;
            if let Some(id) = m.pre_key_id().map(u32::from) {
                undo.pre_key = Some((id, self.pre_keys.records.get(&id).cloned()));
            }
            if let Some(id) = m.kyber_pre_key_id().map(u32::from) {
                let pair = (id, u32::from(m.signed_pre_key_id()));
                undo.kyber = Some((id, self.kyber.records.get(&id).cloned()));
                undo.base_keys = Some((pair, self.kyber.base_keys_seen.get(&pair).cloned()));
            }
        }
        Ok(undo)
    }

    fn decrypt_inner(&mut self, local: &DeviceAddress, opened: &OpenedEnvelope, pinned_identity: Option<&[u8]>) -> Result<SealedMessage, SealedError> {
        let sender = opened.sender.clone();
        let remote = sender.protocol()?;
        let local_addr = local.protocol()?;
        let fail = |e: SignalProtocolError| SealedError { sender: pinned_identity.map(|_| sender.clone()), error: e.into() };
        let mut session_replaced = false;
        let padded = if opened.prekey {
            let m = PreKeySignalMessage::try_from(opened.contents.as_slice()).map_err(fail)?;
            let claimed = m.identity_key().serialize();
            if &*claimed != pinned_identity.unwrap_or(&opened.identity_key) {
                return Err(SealedError { sender: None, error: CryptoError::UntrustedIdentity(sender.name()?) });
            }
                let before = self.session_base_key(&sender);
            // Only a sender the caller pinned leaves a trace in the last-resort replay memory,
            // and it is counted against that sender alone.
            self.kyber.sender_tag = pinned_identity.map(|_| sender_tag(remote.name()));
            let result = now(signal::message_decrypt_prekey(
                &m,
                &remote,
                &local_addr,
                &mut self.sessions,
                &mut self.identity,
                &mut self.pre_keys,
                &self.signed,
                &mut self.kyber,
                &mut rng(),
            ));
            self.kyber.sender_tag = None;
            let opened_message = result.map_err(fail)?.plaintext;
            session_replaced = before.is_some() && before != self.session_base_key(&sender);
            opened_message
        } else {
            let m = SignalMessage::try_from(opened.contents.as_slice()).map_err(fail)?;
            now(signal::message_decrypt_signal(&m, &remote, &local_addr, &mut self.sessions, &mut self.identity, &mut rng())).map_err(fail)?
        };
        let plaintext = padding::unpad(&padded)
            .ok_or_else(|| SealedError { sender: pinned_identity.map(|_| sender.clone()), error: CryptoError::Invalid("padding".into()) })?
            .to_vec();
        Ok(SealedMessage { sender, plaintext, session_replaced })
    }

    fn session_base_key(&self, peer: &DeviceAddress) -> Option<Vec<u8>> {
        let record = SessionRecord::deserialize(self.sessions.records.get(&peer.name().ok()?)?).ok()?;
        record.alice_base_key().ok().map(<[u8]>::to_vec)
    }

    // ---- sender keys (channels) ----

    /// Our sender-key distribution message for `distribution_id` (creating the sender key on first
    /// use). Hand it to each member device over a pairwise sealed session.
    pub fn create_distribution(&mut self, local: &DeviceAddress, distribution_id: Uuid) -> Result<Vec<u8>, CryptoError> {
        let skdm = now(signal::create_sender_key_distribution_message(&local.protocol()?, distribution_id, &mut self.sender_keys, &mut rng()))?;
        Ok(skdm.serialized().to_vec())
    }

    /// The distribution id a distribution message announces, without installing anything.
    pub fn distribution_id_of(skdm: &[u8]) -> Result<Uuid, CryptoError> {
        Ok(SenderKeyDistributionMessage::try_from(skdm)?.distribution_id()?)
    }

    /// Install `sender`'s distribution message. Returns its distribution id.
    pub fn process_distribution(&mut self, sender: &DeviceAddress, skdm: &[u8]) -> Result<Uuid, CryptoError> {
        let skdm = SenderKeyDistributionMessage::try_from(skdm)?;
        let id = skdm.distribution_id()?;
        now(signal::process_sender_key_distribution_message(&sender.protocol()?, &skdm, &mut self.sender_keys))?;
        Ok(id)
    }

    /// Pad + encrypt a channel message under our sender key for `distribution_id`.
    pub fn group_encrypt(&mut self, local: &DeviceAddress, distribution_id: Uuid, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let padded = padding::pad(plaintext);
        let m = now(signal::group_encrypt(&mut self.sender_keys, &local.protocol()?, distribution_id, &padded, &mut rng()))?;
        Ok(m.serialized().to_vec())
    }

    /// The distribution id a sender-key message claims (unauthenticated until decrypted).
    pub fn group_message_distribution_id(message: &[u8]) -> Result<Uuid, CryptoError> {
        Ok(SenderKeyMessage::try_from(message)?.distribution_id())
    }

    /// Where a sender-key message sits in its sender's key schedule: `(distribution id, chain
    /// id, iteration)`. All three are covered by the sender's signature, which
    /// [`Self::group_decrypt`] verifies — so once a message has decrypted they are the SENDER's
    /// statement of the order it was sealed in, not the server's.
    pub fn group_message_position(message: &[u8]) -> Result<(Uuid, u32, u32), CryptoError> {
        let m = SenderKeyMessage::try_from(message)?;
        Ok((m.distribution_id(), m.chain_id(), m.iteration()))
    }

    /// Decrypt a channel message from `sender`; returns `(distribution id, plaintext)`. Verifies the
    /// sender-key signature, rejects replays, strips padding.
    pub fn group_decrypt(&mut self, sender: &DeviceAddress, message: &[u8]) -> Result<(Uuid, Vec<u8>), CryptoError> {
        let id = Self::group_message_distribution_id(message)?;
        let padded = now(signal::group_decrypt(message, &mut self.sender_keys, &sender.protocol()?))?;
        let pt = padding::unpad(&padded).ok_or_else(|| CryptoError::Invalid("padding".into()))?.to_vec();
        Ok((id, pt))
    }

    /// Forget a sender key (ours when rotating, a removed member's when they leave).
    pub fn delete_sender_key(&mut self, sender: &DeviceAddress, distribution_id: Uuid) {
        if let Ok(name) = sender.name() {
            if let Some(mut old) = self.sender_keys.records.remove(&sender_key_slot(&name, distribution_id)) {
                old.zeroize();
            }
        }
    }

    /// Do we hold `sender`'s key for `distribution_id`?
    pub fn has_sender_key(&self, sender: &DeviceAddress, distribution_id: Uuid) -> bool {
        sender.name().is_ok_and(|n| self.sender_keys.records.contains_key(&sender_key_slot(&n, distribution_id)))
    }
}

/// Signal's numeric fingerprint ("safety number") for two parties: 60 digits, identical on both
/// sides. `*_id` are the stable identifiers ("user:device"), `*_identity` serialized identity keys.
pub fn safety_number(local_id: &str, local_identity: &[u8], remote_id: &str, remote_identity: &[u8]) -> Result<String, CryptoError> {
    let fp = signal::Fingerprint::new(
        FINGERPRINT_VERSION,
        FINGERPRINT_ITERATIONS,
        local_id.as_bytes(),
        &IdentityKey::decode(local_identity)?,
        remote_id.as_bytes(),
        &IdentityKey::decode(remote_identity)?,
    )
    .map_err(|e| CryptoError::Invalid(e.to_string()))?;
    fp.display_string().map_err(|e| CryptoError::Invalid(e.to_string()))
}

/// A fresh random (v4) sender-key distribution id. A new one is minted on every rotation.
pub fn new_distribution_id() -> Uuid {
    uuid::Builder::from_random_bytes(crate::random_bytes()).into_uuid()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The replay memory of a last-resort Kyber key is bounded PER SENDER: one sender filling
    /// its share is refused on its own, a base key already seen stays a replay for everyone,
    /// and any other sender still gets through. A large memory asks for an early rotation,
    /// which starts an empty one.
    #[test]
    fn last_resort_base_keys_are_bounded_per_sender_and_never_block_others() {
        let mut store = SignalStore::generate();
        store.generate_signed_prekey().unwrap();
        let signed = store.signed.current.unwrap();
        let id = store.generate_last_resort_kyber().unwrap().id;
        let mut r = rng();
        let mark = |store: &mut SignalStore, sender: Option<&str>, key: &PublicKey| {
            store.kyber.sender_tag = sender.map(sender_tag);
            now(store.kyber.mark_kyber_pre_key_used(id.into(), signed.into(), key))
        };
        let first = KeyPair::generate(&mut r).public_key;
        mark(&mut store, Some("mallory:m1"), &first).unwrap();
        assert!(mark(&mut store, Some("mallory:m1"), &first).is_err(), "replay");
        assert!(mark(&mut store, Some("bob:b1"), &first).is_err(), "a replay under another name is still a replay");
        for _ in 1..MAX_LAST_RESORT_SETUPS_PER_SENDER {
            mark(&mut store, Some("mallory:m1"), &KeyPair::generate(&mut r).public_key).unwrap();
        }
        assert!(mark(&mut store, Some("mallory:m1"), &KeyPair::generate(&mut r).public_key).is_err(), "mallory's share is used up");
        assert_eq!(store.kyber.base_keys_seen[&(id, signed)].len(), MAX_LAST_RESORT_SETUPS_PER_SENDER);
        // Everyone else is unaffected, including an entry written before entries were tagged.
        mark(&mut store, Some("bob:b1"), &KeyPair::generate(&mut r).public_key).unwrap();
        let untagged = KeyPair::generate(&mut r).public_key;
        store.kyber.base_keys_seen.get_mut(&(id, signed)).unwrap().push(untagged.serialize().to_vec());
        assert!(mark(&mut store, Some("carol:c1"), &untagged).is_err(), "an untagged (older) entry is still a replay");

        // Many senders: the memory asks for an early rotation, and a new pair starts empty.
        assert!(!store.last_resort_pressure());
        for n in 0..LAST_RESORT_PRESSURE {
            mark(&mut store, Some(&format!("user{n}:d")), &KeyPair::generate(&mut r).public_key).unwrap();
        }
        assert!(store.last_resort_pressure());
        store.generate_signed_prekey().unwrap();
        store.generate_last_resort_kyber().unwrap();
        assert!(!store.last_resort_pressure());
        // The retired pair keeps its memory until it is pruned: nothing seen became replayable.
        assert!(mark(&mut store, Some("dave:d1"), &first).is_err());
    }
}
