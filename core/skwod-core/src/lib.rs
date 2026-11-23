//! # SkwodCore — the UniFFI umbrella
//!
//! The single Rust surface bound into the SwiftUI (iOS/macOS) and Compose (Android) clients
//! (ADR-001). It re-exports the crypto core and the sync engine through UniFFI so both platforms
//! share one implementation of crypto, the encrypted cache, and the E2EE session/network engine.
//!
//! Two surfaces are exposed here:
//! - **Synchronous:** the encrypted local [`Cache`], attachment encryption, and the safety-number
//!   helper.
//! - **Async network/E2EE engine:** [`SkwodClient`] wraps [`skwod_sync::Engine`] + [`ApiClient`]
//!   behind UniFFI async methods (`async_runtime = "tokio"`).
//!
//! The message protocol is Signal's libsignal (see `skwod-crypto`); this crate is AGPL-3.0-only.
//! See `docs/SECURITY.md` for the security model and its remaining gaps.

use std::path::PathBuf;
use std::sync::Mutex;

use skwod_crypto::backup::{self, KdfParams};
use skwod_sync::cache::{Cache, CachedMessage};
use skwod_sync::{ApiClient, Engine, EngineError, LoadOutcome, PeerId};

uniffi::setup_scaffolding!();

mod content;
mod outbox;
mod upload;
pub use content::{AbuseReport, GroupDm, ReportReceipt};
pub use outbox::{OutboxReport, PendingSend};
pub use upload::{decrypt_attachment_file, PreparedUpload, UploadProgress};
pub mod p2p;
pub mod pairing;
pub use p2p::{p2p_connect, p2p_format_invite, p2p_format_share_link, p2p_parse_invite, P2pInvite, P2pPath, P2pSession, P2pVoiceStats};

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum CoreError {
    #[error("cache error: {detail}")]
    Cache { detail: String },
    #[error("network/engine error: {detail}")]
    Engine { detail: String },
    #[error("invalid argument: {detail}")]
    Invalid { detail: String },
    /// The app and the server speak different E2EE protocol generations. `detail` is a
    /// user-facing sentence ("update required: …"); show it and offer the update.
    #[error("{detail}")]
    UpdateRequired { detail: String },
    /// This account already has a device, so this one cannot simply register: link it from an
    /// existing device (`begin_device_link` / `complete_device_link`), restore a key backup, or —
    /// if every device is lost — `reset_devices`.
    #[error("{detail}")]
    LinkRequired { detail: String },
    /// `reset_devices` was accepted as a REQUEST only (no registration-lock PIN): it completes after
    /// a 7-day wait unless a device of the account cancels it. `detail` is user-facing.
    #[error("{detail}")]
    ResetPending { detail: String },
    /// A peer the user had VERIFIED now has a different safety number. Nothing was sent. Show the
    /// safety-number screen; `SkwodClient::accept_identity_change` unblocks sending.
    #[error("{detail}")]
    IdentityChanged { detail: String },
    // ---- build 44a ----
    /// `reset_devices` on an account with a registration-lock PIN, without the PIN. Show the
    /// PIN screen; if the PIN is forgotten, `reset_devices_forgot_pin` (the 7-day hold).
    #[error("{detail}")]
    PinRequired { detail: String },
    /// The PIN was wrong. `attempts_left` tries remain before a 15-minute lockout (0 = locked).
    #[error("{detail}")]
    PinIncorrect { detail: String, attempts_left: i64 },
    /// This device was restored from a backup on another device. This copy has stopped for
    /// good: show `detail`, offer "Erase this device" and linking it again as a new device.
    #[error("{detail}")]
    DeviceSuperseded { detail: String },
    /// Another device of the account removed this one. Offer: link again, restore, reset.
    #[error("{detail}")]
    DeviceRemoved { detail: String },
    /// A restore was recorded as a REQUEST: approve it on another of the account's devices
    /// (then `retry_restore`), give the PIN (`retry_restore(pin)`), or wait `detail` out.
    #[error("{detail}")]
    RecoveryPending { detail: String },
    /// The account already has the most devices it may have. Show the device list to prune.
    #[error("{detail}")]
    DeviceLimit { detail: String },
    /// `approve_recovery` / `cancel_recovery`: the request the user was shown has been replaced
    /// by another. Nothing was approved or refused; a new `"recovery_requested"` notice follows.
    #[error("{detail}")]
    RecoveryChanged { detail: String },
    /// `kv_read` / `kv_write`: this client has NO cache attached, so there is nothing to read
    /// from or write to. Not "nothing stored" (that is `Ok(None)`), and not a failed read of an
    /// open cache (that is `Cache`).
    #[error("no cache attached: {detail}")]
    NoCache { detail: String },
}

impl From<skwod_sync::CacheError> for CoreError {
    fn from(e: skwod_sync::CacheError) -> Self {
        CoreError::Cache { detail: e.to_string() }
    }
}
impl From<EngineError> for CoreError {
    fn from(e: EngineError) -> Self {
        match e {
            EngineError::UpdateRequired(detail) => CoreError::UpdateRequired { detail },
            EngineError::IdentityChanged(_) => CoreError::IdentityChanged { detail: e.to_string() },
            EngineError::LinkRequired => CoreError::LinkRequired { detail: e.to_string() },
            EngineError::ResetPending(_) => CoreError::ResetPending { detail: e.to_string() },
            EngineError::PinRequired => CoreError::PinRequired { detail: e.to_string() },
            EngineError::PinIncorrect { attempts_left, locked_until } => CoreError::PinIncorrect {
                detail: if locked_until.is_some() { "Too many wrong PINs. Try again in 15 minutes.".into() } else { e.to_string() },
                attempts_left,
            },
            EngineError::Superseded => CoreError::DeviceSuperseded { detail: e.to_string() },
            EngineError::DeviceRemoved => CoreError::DeviceRemoved { detail: e.to_string() },
            EngineError::RecoveryPending(..) => CoreError::RecoveryPending { detail: e.to_string() },
            EngineError::DeviceLimit => CoreError::DeviceLimit { detail: e.to_string() },
            EngineError::RestoreRefused(detail) => CoreError::Invalid { detail },
            EngineError::RecoveryChanged => CoreError::RecoveryChanged { detail: e.to_string() },
            // User-facing as is ("That message is too big to send…").
            EngineError::TooLarge(detail) => CoreError::Invalid { detail: detail.to_string() },
            other => CoreError::Engine { detail: other.to_string() },
        }
    }
}
impl From<skwod_sync::ClientError> for CoreError {
    fn from(e: skwod_sync::ClientError) -> Self {
        CoreError::Engine { detail: e.to_string() }
    }
}

/// A cached (decrypted) message crossing the FFI boundary.
#[derive(Debug, uniffi::Record)]
pub struct RoleInfo {
    pub role_id: String,
    pub name: Option<String>,
    pub permissions: i64,
    pub is_default: bool,
}

#[derive(Debug, uniffi::Record)]
pub struct Message {
    pub message_id: String,
    pub scope: String,
    pub author_id: Option<String>,
    pub content: Option<String>,
    pub created_at: i64,
    pub is_edited: bool,
    pub is_pinned: bool,
    /// The message this one replies to (quoted reply), if any.
    pub reply_to_id: Option<String>,
    /// True when the message was deleted (tombstone) — render as removed.
    pub is_deleted: bool,
    /// Direct messages: when the SENDER says it was sent. `created_at` is when it reached this
    /// device and is what the conversation is ordered by; show this one beside it when the two
    /// differ noticeably. `None` for channel messages and rows from before build 44.
    #[uniffi(default = None)]
    pub sent_at: Option<i64>,
    /// This row is a notice the CORE wrote into the conversation (a membership or security
    /// event; content is `SYSTEM_TAG` + JSON) — a fact about the row, recorded when it was
    /// written. Render a system row when this is set and NEVER because of what the text looks
    /// like or who the author is said to be: nothing a peer sends can set it.
    #[uniffi(default = false)]
    pub is_system: bool,
    /// This row stands in for a message this device could not decrypt (see
    /// [`undecryptable_placeholder`]). Likewise a fact about the row, never about its text.
    #[uniffi(default = false)]
    pub is_undecryptable: bool,
}

impl From<CachedMessage> for Message {
    fn from(m: CachedMessage) -> Self {
        Message {
            message_id: m.message_id,
            scope: m.scope,
            author_id: m.author_id,
            content: m.content,
            created_at: m.created_at,
            is_edited: m.is_edited,
            is_pinned: m.is_pinned,
            reply_to_id: m.reply_to_id,
            is_deleted: m.deleted_at.is_some(),
            is_system: m.kind == skwod_sync::cache::KIND_SYSTEM,
            is_undecryptable: m.kind == skwod_sync::cache::KIND_UNDECRYPTABLE,
            sent_at: None,
        }
    }
}

/// The on-device encrypted cache, exposed to the apps.
#[derive(uniffi::Object)]
pub struct SkwodCache {
    inner: Mutex<Cache>,
}

#[uniffi::export]
impl SkwodCache {
    /// Open (creating if needed) the SQLCipher cache at `path` under a 32-byte hex key.
    /// The key comes from the platform key store (Secure Enclave / StrongBox gated).
    #[uniffi::constructor]
    pub fn open(path: String, key_hex: String) -> Result<std::sync::Arc<Self>, CoreError> {
        let key_bytes =
            hex_to_32(&key_hex).ok_or(CoreError::Invalid { detail: "key must be 64 hex chars".into() })?;
        let cache = Cache::open(&PathBuf::from(path), &key_bytes)?;
        Ok(std::sync::Arc::new(Self { inner: Mutex::new(cache) }))
    }

    pub fn set_kv(&self, key: String, value: String) -> Result<(), CoreError> {
        Ok(self.inner.lock().unwrap_or_else(|e| e.into_inner()).kv_set(&key, &value)?)
    }

    pub fn get_kv(&self, key: String) -> Result<Option<String>, CoreError> {
        Ok(self.inner.lock().unwrap_or_else(|e| e.into_inner()).kv_get(&key)?)
    }

    pub fn upsert_message(&self, m: Message) -> Result<(), CoreError> {
        let cm = CachedMessage {
            message_id: m.message_id,
            scope: m.scope,
            author_id: m.author_id,
            content: m.content,
            reply_to_id: m.reply_to_id,
            is_edited: m.is_edited,
            is_pinned: m.is_pinned,
            deleted_at: if m.is_deleted { Some(m.created_at) } else { None },
            created_at: m.created_at,
            updated_at: m.created_at,
            kind: skwod_sync::cache::KIND_PLAIN,
        };
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).upsert_message(&cm)?;
        Ok(())
    }

    /// Newest-first page of messages in a scope, older than `before` ms.
    pub fn messages(&self, scope: String, before: i64, limit: u32) -> Result<Vec<Message>, CoreError> {
        let rows = self.inner.lock().unwrap_or_else(|e| e.into_inner()).messages(&scope, before, limit as usize)?;
        Ok(rows.into_iter().map(Message::from).collect())
    }
}

/// Signal's 60-digit safety number for two parties, computed from their stable ids
/// (`"<user_id>:<device_id>"`) and hex-encoded libsignal identity keys. Both sides get the same
/// value. (Apps normally use [`SkwodClient::safety_number`], which looks the keys up.)
#[uniffi::export]
pub fn compute_safety_number(
    local_id: String,
    local_identity_key_hex: String,
    remote_id: String,
    remote_identity_key_hex: String,
) -> Result<String, CoreError> {
    let lk = hex::decode(&local_identity_key_hex).map_err(|_| CoreError::Invalid { detail: "local key hex".into() })?;
    let rk = hex::decode(&remote_identity_key_hex).map_err(|_| CoreError::Invalid { detail: "remote key hex".into() })?;
    skwod_crypto::store::safety_number(&local_id, &lk, &remote_id, &rk).map_err(|e| CoreError::Invalid { detail: e.to_string() })
}

/// The E2EE protocol generation this build speaks (2 = Signal's libsignal).
#[uniffi::export]
pub fn e2ee_protocol_version() -> u32 {
    skwod_crypto::PROTOCOL_VERSION
}

// ---- attachments (Signal's attachment scheme; see skwod_crypto::attachment) ----

/// An encrypted attachment: upload `ciphertext` as the blob; put `key`, `digest` and
/// `plaintext_len` in the (end-to-end encrypted) message so recipients can open it.
#[derive(uniffi::Record)]
pub struct EncryptedAttachment {
    pub ciphertext: Vec<u8>,
    /// 64-byte single-use key (AES-256 key ‖ HMAC-SHA256 key).
    pub key: Vec<u8>,
    /// SHA-256 of `ciphertext`.
    pub digest: Vec<u8>,
    pub plaintext_len: u64,
}

/// Encrypt an attachment under a fresh random key: AES-256-CBC + HMAC-SHA256, plaintext padded to
/// Signal's size buckets so the blob length hides the real size.
#[uniffi::export]
pub fn encrypt_attachment(plaintext: Vec<u8>) -> Result<EncryptedAttachment, CoreError> {
    let e = skwod_crypto::attachment::encrypt(&plaintext).map_err(|e| CoreError::Invalid { detail: e.to_string() })?;
    Ok(EncryptedAttachment { ciphertext: e.ciphertext, key: e.key, digest: e.digest, plaintext_len: e.plaintext_len })
}

/// Verify (digest, then MAC) and decrypt an attachment blob fetched from the server.
#[uniffi::export]
pub fn decrypt_attachment(ciphertext: Vec<u8>, key: Vec<u8>, digest: Vec<u8>, plaintext_len: u64) -> Result<Vec<u8>, CoreError> {
    skwod_crypto::attachment::decrypt(&ciphertext, &key, &digest, plaintext_len).map_err(|e| CoreError::Invalid { detail: e.to_string() })
}

/// A fresh 160-bit recovery key for key backup (`XXXX-XXXX-…`, 8 groups). Offer this instead of
/// asking the user to invent a passphrase.
#[uniffi::export]
pub fn generate_recovery_key() -> String {
    backup::generate_recovery_key()
}

/// Why a backup passphrase is unacceptable, or None if it is strong enough. A short PIN is never
/// accepted: the server could brute-force it offline.
#[uniffi::export]
pub fn backup_passphrase_problem(passphrase: String) -> Option<String> {
    backup::check_passphrase(&passphrase).err().map(|e| e.to_string())
}

/// A security event to surface in the UI.
#[derive(uniffi::Record)]
pub struct SecurityNotice {
    /// - `"identity_changed"`: this contact's safety number changed (a device added or removed,
    ///   a reinstall — or someone in the middle). With `was_verified`, sends to them are blocked.
    /// - `"new_device"`: this contact linked device `device_id` (vouched for by their account).
    /// - `"unverified_contact_device"`: the server lists device `device_id` for this contact but
    ///   no device of theirs vouched for it. Nothing is sent to it; what it sends is held until
    ///   the user accepts it (`accept_identity_change`). BLOCKING: needs a decision.
    /// - `"join_request"`: `user_id` asks to be provisioned in `server_id` but nobody this device
    ///   trusts approved them. Show it to the owner with a "Let in" action.
    /// - `"protocol_upgraded"`, `"device_linked"`, `"unverified_device"`, `"reset_blocked"`:
    ///   about THIS account (see the engine's `SecurityNotice`).
    pub kind: String,
    pub user_id: String,
    pub device_id: String,
    pub at_ms: u64,
    /// The peer had been verified under the old key; sending to them is blocked until accepted.
    pub was_verified: bool,
    /// The conversation (`"dm:<id>"`) where this notice was also written as a persistent system
    /// row, if it is about a contact we have a conversation with.
    pub scope: Option<String>,
    /// For `"join_request"`: the server `user_id` is asking to be let into. They used an
    /// auto-join invite (or the server simply lists them); nothing is shared with them until
    /// the user approves (`SkwodClient::approve_member`).
    pub server_id: Option<String>,
    /// For `"recovery_requested"`: the id of THAT request. Pass exactly this to
    /// `approve_recovery` / `cancel_recovery` — a request that replaces it is a new notice
    /// with a new id, and is never approved by an answer to this one.
    #[uniffi(default = None)]
    pub request_id: Option<String>,
    /// For `"recovery_requested"`: the request's short code (`XXXX-XXXX`). The install asking
    /// for the restore shows the same code (`recovery_fingerprint`); show it in the prompt so
    /// the user can tell it is the restore they started.
    #[uniffi(default = None)]
    pub fingerprint: Option<String>,
}

/// Where a contact account stands on this device (see `SkwodClient::contact_status`).
#[derive(Debug, PartialEq, Eq, uniffi::Record)]
pub struct ContactStatus {
    /// The user compared the account safety number, and the contact's devices are still exactly
    /// the ones it covered.
    pub verified: bool,
    /// The contact WAS verified and their device set has changed since (a device added or
    /// removed, or one nobody vouched for). Every send to them fails with `IdentityChanged`
    /// until the user verifies again or accepts the change.
    pub sends_held: bool,
    /// Devices of theirs this device accepts and sends to.
    pub devices: u32,
    /// Devices the server lists for them that no device of theirs vouched for (held).
    pub unvouched_devices: u32,
    /// The device-and-key set "Accept" would take on, as a fingerprint (build 45, audit L2).
    /// Read it with the rest of this status when the banner is drawn and pass it back to
    /// `accept_identity_change`: only that exact set is accepted.
    pub accept_fingerprint: String,
}

/// A device that finished QR pairing: its session and its new device id.
#[derive(uniffi::Record)]
pub struct PairedDevice {
    pub session: AuthSession,
    pub device_id: String,
}

/// A skwod's p2p address as its server reports it (members only).
#[derive(Debug, Clone, uniffi::Record)]
pub struct InstanceP2p {
    pub node_id: String,
    /// The host's current home relay (allow-listed n0 relays only), if it has one.
    pub relay_url: Option<String>,
    /// Whether the host lets new devices pair by QR (`SKWOD_QR_PAIRING`).
    pub qr_pairing: bool,
}

/// Burn a QR pairing `offer` on this device and say why.
fn burn_offer(offer: &pairing::PairingOffer, why: &str) -> CoreError {
    pairing::PairingGuard::consume(&offer.code);
    pairing::forget(&offer.code);
    CoreError::Invalid { detail: why.into() }
}

/// Where a QR pairing stands on the NEW device ([`SkwodClient::pair_poll`]).
#[derive(uniffi::Enum)]
pub enum PairProgress {
    /// Waiting for the other device to see this one.
    Waiting,
    /// The other device has seen this one: show these five emoji until it approves.
    Confirm { emoji: String },
    /// Approved: this device is linked and registered.
    Paired { device: PairedDevice },
}

/// A device asking to be linked through a QR pairing offer (see `pairing.rs`).
#[derive(Debug, Clone, uniffi::Record)]
pub struct PairingCandidate {
    /// The sets to pick from ([`pairing::CHOICES`], shuffled): exactly one is what the new device
    /// shows. The real one is not marked — the person must read it off the new device.
    pub choices: Vec<String>,
    /// The new device's identity key (base64).
    pub identity_key: String,
    /// The server's id for the request — pass the whole candidate back unchanged.
    pub request_id: String,
}

/// The async network + E2EE client bound into the apps. Methods are UniFFI async; the platform
/// awaits them from Swift concurrency / Kotlin coroutines.
#[derive(uniffi::Object)]
pub struct SkwodClient {
    engine: tokio::sync::Mutex<Engine>,
    /// Optional on-device encrypted cache backing engine-state + message persistence.
    cache: std::sync::Arc<Mutex<Option<Cache>>>,
    /// Direct REST access for endpoints the engine doesn't own (e.g. key backup).
    api: ApiClient,
    /// This account's user id once known (mirrors the engine's; refreshed whenever state is
    /// persisted). The cache treats it and [`SELF_AUTHOR`] as the same author.
    self_user: Mutex<Option<String>>,
    /// DMs that arrived (or were synced from another of our devices) and the app has not been
    /// told about yet — whichever call happened to drain the mailbox (`take_dm_events`).
    dm_events: Mutex<Vec<DmEvent>>,
    /// The users this account blocked, as of the last persist. Everything read from the cache
    /// is filtered through it (`history_limit`, `channel_reactions`), so a block hides its
    /// subject everywhere at once and an unblock brings them back.
    blocked: Mutex<std::collections::BTreeSet<String>>,
    /// The recovery key of a restore that is waiting to be handed the backup (the server
    /// withholds one under a young recovery key until another device approves): kept in memory
    /// only, so `retry_restore` can go on without asking for it again. Never persisted — after
    /// a relaunch the app asks for the recovery key again (`restore_key_backup`).
    pending_restore: Mutex<Option<String>>,
    /// One outbox flush at a time (`outbox.rs`).
    outbox_gate: tokio::sync::Mutex<()>,
    /// Where the attached cache lives (for "erase this device").
    cache_path: Mutex<Option<String>>,
    /// Tests and tools only: allow registering with no cache attached.
    ephemeral_ok: std::sync::atomic::AtomicBool,
}

/// Where this install stands with the account (see `SkwodClient::device_state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum DeviceState {
    /// No device registered from this install: register, link, restore or reset.
    Unregistered,
    Active,
    /// Removed by another device of the account.
    Removed,
    /// Restored from a backup on another install; this copy has stopped.
    Superseded,
    /// A restore onto this install is waiting (approval / PIN / 7 days).
    RecoveryPending,
}

/// One device of this account (see `SkwodClient::list_devices`).
#[derive(Debug, Clone, uniffi::Record)]
pub struct DeviceInfo {
    pub device_id: String,
    /// `None` when it has no name yet, or this device does not hold the key it is sealed under.
    pub name: Option<String>,
    pub created_at: i64,
    pub last_active_at: i64,
    pub is_this_device: bool,
    /// Vouched for by this device's own link chain. `false` = the server lists it but none of
    /// our devices approved it (show it flagged; it gets nothing from us).
    pub verified: bool,
}

/// A device that erased itself (see `SkwodClient::erased_devices`).
#[derive(Debug, Clone, uniffi::Record)]
pub struct ErasedDevice {
    pub device_id: String,
    pub identity_key_hex: String,
    pub erased_at: i64,
}

/// The account's devices and how many it may have.
#[derive(Debug, Clone, uniffi::Record)]
pub struct DeviceList {
    pub devices: Vec<DeviceInfo>,
    pub max_devices: u32,
}

/// Whether erasing this device would lock the user out (see `SkwodClient::erase_check`).
#[derive(Debug, Clone, uniffi::Record)]
pub struct EraseCheck {
    /// The account has a key backup on the server (restorable with the recovery key).
    pub has_key_backup: bool,
    /// Other verified devices on the account (any of them can link this one back).
    pub other_devices: u32,
    /// `has_key_backup || other_devices > 0`. When false, erasing leaves only the 7-day reset
    /// — and nothing can bring the message history back. Explain that before allowing it.
    pub safe: bool,
}

/// A direct message that just landed in the local cache.
#[derive(Debug, Clone, uniffi::Record)]
pub struct DmEvent {
    /// `"message"` (a new message: notify unless `from_self`), or a change to an existing one
    /// — `"edit"`, `"delete"`, `"reaction"` — which only needs the conversation redrawn.
    pub kind: String,
    pub conversation_id: String,
    /// The other party of the conversation — enough to add it to the sidebar.
    pub peer_user_id: String,
    pub message_id: String,
    /// `true` for a copy of a message WE sent from another device (list it, do not notify).
    pub from_self: bool,
    pub text: String,
    pub created_at: i64,
    /// Whether the conversation is a GROUP, as the sender sealed it into the message (build
    /// 45) — never the server's `is_group`. A message the server presents under a group's id
    /// but that was sealed as a 1:1 message (or the reverse) is not delivered at all.
    pub is_group: bool,
}

/// A 1:1 conversation this account is in (see `SkwodClient::list_dms`).
#[derive(Debug, Clone, uniffi::Record)]
pub struct DmConversation {
    pub conversation_id: String,
    pub peer_user_id: String,
    pub peer_username: String,
}

/// One reaction on a channel message, as the last sync of that channel saw it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MessageReaction {
    pub message_id: String,
    pub user_id: String,
    pub emoji_hash: String,
    pub emoji: Option<String>,
}

/// A call ringing for this account right now.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RingInfo {
    pub channel_id: String,
    pub server_id: String,
    pub from_user_id: String,
    pub ring_id: String,
    /// Unix ms after which the ring is over; do not show it past this.
    pub expires_at: i64,
}

/// A contact's key fingerprint and whether this device has pinned it.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FingerprintPeek {
    pub fingerprint: String,
    /// `false`: first sight — it is what the server lists right now and nothing has been
    /// trusted. Label it "unverified".
    pub pinned: bool,
}

/// Whether the session this client was built with still works.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SessionState {
    Valid,
    /// The server answered 401: the session expired or was revoked. Forget it and show login.
    SignedOut,
    /// No answer (offline, host asleep, server stopped). Keep the session and retry.
    Unreachable,
}

const CURSOR_PREFIX: &str = "sync-cursor:";
const REACTIONS_PREFIX: &str = "reactions:";
/// Pages a single catch-up may fetch (× 100 messages) before it yields; the next call continues.
const MAX_CATCHUP_PAGES: usize = 50;
/// A first sync keeps walking back until it holds this many CHAT messages (a channel whose
/// recent traffic is mostly a whiteboard would otherwise open empty)…
const FIRST_SYNC_CHAT_TARGET: u32 = 100;
/// …and "load older" until it has added this many, within this many pages.
const OLDER_CHAT_TARGET: u32 = 50;
const MAX_OLDER_PAGES: usize = 20;

const ENGINE_STATE_KEY: &str = "engine-state";

#[uniffi::export(async_runtime = "tokio")]
impl SkwodClient {
    /// Build a client against `base_url` with an existing session `token`.
    #[uniffi::constructor]
    pub fn new(base_url: String, token: String) -> std::sync::Arc<Self> {
        let api = ApiClient::new(base_url).with_token(token);
        std::sync::Arc::new(Self {
            engine: tokio::sync::Mutex::new(Engine::new(api.clone())),
            cache: std::sync::Arc::new(Mutex::new(None)),
            api,
            self_user: Mutex::new(None),
            dm_events: Mutex::new(Vec::new()),
            blocked: Mutex::new(Default::default()),
            pending_restore: Mutex::new(None),
            outbox_gate: tokio::sync::Mutex::new(()),
            cache_path: Mutex::new(None),
            ephemeral_ok: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Attach the on-device encrypted cache at `path` (SQLCipher, 32-byte hex key from the platform
    /// key store). Returns `true` when a libsignal engine state was restored. Returns `false` for a
    /// fresh device **and** for a device upgrading from the pre-libsignal protocol (builds 29–40):
    /// in both cases the caller registers the device (`register_device`). On an upgrade the local
    /// message history and space keys are kept, a fresh identity is generated, and a
    /// `"protocol_upgraded"` notice is queued (see `take_security_notices`).
    pub async fn attach_cache(&self, path: String, key_hex: String) -> Result<bool, CoreError> {
        let key = hex_to_32(&key_hex).ok_or(CoreError::Invalid { detail: "key must be 64 hex chars".into() })?;
        let cache = match Cache::open(&PathBuf::from(&path), &key) {
            Ok(cache) => cache,
            // The file is there but this key does not open it (the key was lost or replaced, or
            // the file is damaged). Failing here on every launch is a loop the user cannot
            // leave; registering without a cache would mint a device that forgets itself. So:
            // move the unreadable file ASIDE (nothing is deleted — it can still be opened if
            // its key turns up), start a fresh cache under this key, and say so. The caller
            // sees "no device restored" and takes the normal recovery path.
            Err(skwod_sync::CacheError::BadKey) => {
                set_aside(&path);
                let cache = Cache::open(&PathBuf::from(&path), &key)?;
                let _ = cache.kv_set(CACHE_RESET_KEY, &now_ms().to_string());
                cache
            }
            Err(e) => return Err(e.into()),
        };
        *self.cache_path.lock().unwrap_or_else(|e| e.into_inner()) = Some(path);
        let outcome = match cache.session_get(ENGINE_STATE_KEY)? {
            Some(bytes) => {
                let mut engine = self.engine.lock().await;
                let outcome = engine.load_state(&bytes);
                *self.self_user.lock().unwrap_or_else(|e| e.into_inner()) = engine.user_id().map(str::to_string);
                *self.blocked.lock().unwrap_or_else(|e| e.into_inner()) = engine.blocked_users().into_iter().collect();
                outcome
            }
            None => LoadOutcome::Unreadable,
        };
        *self.cache.lock().unwrap_or_else(|e| e.into_inner()) = Some(cache);
        // Membership events ("X joined (approved by Y)", "X added a device") are written into the
        // channel BEFORE the engine hands that user or device a key: the engine calls this sink
        // and only proceeds when the row is in the cache.
        let sink_cache = self.cache.clone();
        self.engine.lock().await.set_event_sink(Box::new(move |e| {
            let row = system_row(&e.scope, &e.kind, &e.user_id, &e.device_id, e.by_user_id.as_deref(), false, e.at_ms as i64);
            match sink_cache.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
                Some(cache) => cache.insert_core_row(&row).is_ok(),
                None => false,
            }
        }));
        // Before anything encrypted leaves, the state that sealed it — and the message itself —
        // is written here in one transaction (see `skwod_sync::StateSink`).
        let state_cache = self.cache.clone();
        self.engine.lock().await.set_state_sink(Box::new(move |state, row| {
            let row = row.map(|r| CachedMessage {
                message_id: r.message_id.clone(),
                scope: r.scope.clone(),
                author_id: Some(SELF_AUTHOR.to_string()),
                content: Some(r.text.clone()),
                reply_to_id: r.reply_to_id.clone(),
                is_edited: false,
                is_pinned: false,
                deleted_at: None,
                created_at: r.created_at,
                updated_at: r.created_at,
                kind: skwod_sync::cache::KIND_PLAIN,
            });
            match state_cache.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
                Some(cache) => cache.persist_send(ENGINE_STATE_KEY, state, row.as_ref()).is_ok(),
                None => true,
            }
        }));
        // What was sent is kept (encrypted, ~30 days) to send again from.
        self.engine.lock().await.set_sent_store(Box::new(CacheSentStore(self.cache.clone())));
        if outcome == LoadOutcome::Migrated {
            // Replace the v1 blob now, so the old key material is gone from disk and the migration
            // is not repeated on the next launch.
            self.persist().await;
        }
        Ok(outcome == LoadOutcome::Restored)
    }

    /// Snapshot the engine into the cache, then acknowledge the mailbox envelopes that snapshot
    /// covers (never the other way round: an envelope is only deleted server-side once the state
    /// that consumed it is on disk). Best-effort: persistence failure never fails the op.
    async fn persist(&self) {
        let mut engine = self.engine.lock().await;
        *self.self_user.lock().unwrap_or_else(|e| e.into_inner()) = engine.user_id().map(str::to_string);
        *self.blocked.lock().unwrap_or_else(|e| e.into_inner()) = engine.blocked_users().into_iter().collect();
        // Channel clears and deletions that arrived over sealed sessions (the only kind this
        // device acts on) are applied to the cache BEFORE the state that no longer lists them
        // is stored: a crash in between applies them again, never loses them.
        for (channel_id, cleared_at) in engine.take_channel_clears() {
            self.apply_channel_clear(&channel_id, cleared_at);
        }
        for d in engine.take_channel_deletes() {
            self.apply_channel_delete(&d);
        }
        let bytes = engine.export_state();
        let stored = match self.cache.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            Some(cache) => cache.session_put(ENGINE_STATE_KEY, &bytes, 0).is_ok(),
            // No cache attached: state is memory-only by the caller's choice.
            None => true,
        };
        if stored {
            let _ = engine.ack_inbox().await;
        }
    }

    /// File every DM the engine has decrypted into the cache under its conversation scope. A DM's
    /// id is chosen by its sender and DMs have no edit path, so a row is only ever INSERTED: an id
    /// that already exists in that conversation is ignored, and (the cache keys on scope + id) it
    /// can never address a message of another conversation or channel.
    async fn store_inbound_dms(&self) {
        self.apply_retries().await;
        let dms = self.engine.lock().await.take_dms();
        for m in dms {
            if m.message_id.is_empty() {
                continue;
            }
            let event = DmEvent {
                kind: "message".into(),
                conversation_id: m.conversation_id.clone(),
                peer_user_id: m.peer_user_id,
                message_id: m.message_id.clone(),
                from_self: m.author_id == SELF_AUTHOR,
                text: m.text.clone(),
                created_at: m.created_at,
                is_group: false, // filled in when the events are taken
            };
            let row = CachedMessage {
                message_id: m.message_id,
                scope: format!("dm:{}", m.conversation_id),
                author_id: Some(m.author_id),
                content: Some(m.text),
                reply_to_id: None,
                is_edited: false,
                is_pinned: false,
                deleted_at: None,
                created_at: m.created_at,
                updated_at: m.created_at,
                kind: skwod_sync::cache::KIND_PLAIN,
            };
            // Only a row that is NEW is an event (a redelivered envelope is not a new message).
            // Without a cache there is nowhere to dedupe against: report it.
            let fresh = match self.cache.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
                Some(cache) => {
                    let fresh = cache.insert_message_if_absent(&row).unwrap_or(false);
                    if let (true, Some(sent_at)) = (fresh, m.sent_at) {
                        let _ = cache.set_sent_at(&row.scope, &row.message_id, sent_at);
                    }
                    fresh
                }
                None => true,
            };
            if fresh {
                let mut events = self.dm_events.lock().unwrap_or_else(|e| e.into_inner());
                if events.len() < 5_000 {
                    events.push(event);
                }
            }
        }
        // Edits, deletes, reactions and replies — after the messages they may refer to.
        self.apply_dm_ops().await;
    }

    /// Placeholders for what could not be decrypted, and what happened to them since: shown,
    /// answered (the placeholder goes; the message arrives as itself), or lost for good. And
    /// channel messages their authors sent again, which take their placeholders' place.
    async fn apply_retries(&self) {
        let (events, resent) = {
            let mut engine = self.engine.lock().await;
            (engine.take_retry_events(), engine.take_resent())
        };
        let guard = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        let Some(cache) = guard.as_ref() else { return };
        for event in events {
            match event {
                skwod_sync::RetryEvent::Placeholder { scope, id, author_id, at_ms } => {
                    let _ = cache.insert_core_row(&CachedMessage {
                        message_id: id,
                        scope,
                        content: Some(skwod_sync::undecryptable_body(&author_id, false)),
                        author_id: Some(author_id),
                        reply_to_id: None,
                        is_edited: false,
                        is_pinned: false,
                        deleted_at: None,
                        created_at: at_ms,
                        updated_at: at_ms,
                        kind: KIND_UNDECRYPTABLE,
                    });
                }
                skwod_sync::RetryEvent::Resolved { scope, id } => {
                    // Only ever a row this device wrote as a placeholder.
                    if cache.message(&scope, &id).ok().flatten().is_some_and(|m| m.kind == KIND_UNDECRYPTABLE) {
                        let _ = cache.delete_message(&scope, &id);
                    }
                }
                skwod_sync::RetryEvent::Lost { scope, id } => {
                    if let Some(m) = cache.message(&scope, &id).ok().flatten().filter(|m| m.kind == KIND_UNDECRYPTABLE) {
                        let _ = cache.set_core_content(&scope, &id, KIND_UNDECRYPTABLE, &skwod_sync::undecryptable_body(m.author_id.as_deref().unwrap_or_default(), true));
                    }
                }
            }
        }
        for m in resent {
            let chat = format!("channel:{}", m.channel_id);
            // It replaces the placeholder this device put there for that author — nothing else.
            let Some(placeholder) = cache.message(&chat, &m.message_id).ok().flatten() else { continue };
            if placeholder.author_id.as_deref() != Some(m.author_id.as_str()) || placeholder.kind != KIND_UNDECRYPTABLE {
                continue;
            }
            if skwod_sync::Traffic::of(&m.text).hidden {
                // Game state: it belongs in the aux scope, not in the conversation.
                let _ = cache.delete_message(&chat, &m.message_id);
                let _ = cache.insert_message_if_absent(&CachedMessage { scope: format!("aux:{}", m.channel_id), content: Some(m.text), reply_to_id: m.reply_to_id, is_edited: m.is_edited, kind: skwod_sync::cache::KIND_PLAIN, ..placeholder });
            } else {
                let _ = cache.upsert_message(&CachedMessage { content: Some(m.text), reply_to_id: m.reply_to_id, is_edited: m.is_edited, kind: skwod_sync::cache::KIND_PLAIN, ..placeholder });
            }
        }
    }

    /// Persist a small app-level value (e.g. the sidebar's list of joined spaces/DMs) into the
    /// encrypted cache, so it survives relaunches. LENIENT: a no-op without an attached cache,
    /// and a failed write is not reported. Anything that must know its value was stored uses
    /// [`kv_write`].
    pub async fn kv_set(&self, key: String, value: String) {
        let _ = self.kv_write(key, value).await;
    }

    /// Read an app-level value previously stored with [`kv_set`]. LENIENT: "no cache attached"
    /// and "the read failed" both come back as `None`, exactly like "nothing stored". Anything
    /// that would treat `None` as an empty store and later WRITE over it uses [`kv_read`].
    pub async fn kv_get(&self, key: String) -> Option<String> {
        self.kv_read(key).await.ok().flatten()
    }

    /// Read an app-level value, telling the three cases apart: `Ok(Some)` = stored, `Ok(None)` =
    /// the cache is open and holds nothing under `key`, `Err(NoCache)` = no cache is attached,
    /// `Err(Cache)` = the cache is attached but could not be read.
    pub async fn kv_read(&self, key: String) -> Result<Option<String>, CoreError> {
        let guard = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        let cache = guard.as_ref().ok_or_else(|| CoreError::NoCache { detail: "kv_read".into() })?;
        Ok(cache.kv_get(&key)?)
    }

    /// Store an app-level value, or say why it was not stored (`NoCache`, `Cache`).
    pub async fn kv_write(&self, key: String, value: String) -> Result<(), CoreError> {
        let guard = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        let cache = guard.as_ref().ok_or_else(|| CoreError::NoCache { detail: "kv_write".into() })?;
        Ok(cache.kv_set(&key, &value)?)
    }

    /// Is a cache attached (`attach_cache` succeeded on this client)?
    pub fn cache_attached(&self) -> bool {
        self.cache.lock().unwrap_or_else(|e| e.into_inner()).is_some()
    }

    /// Register this device with the server; returns the device id. Succeeds only for an
    /// account's FIRST device: once an account has a device, a session token alone cannot add
    /// another — this fails with `LinkRequired` and the device must be linked (below).
    pub async fn register_device(&self) -> Result<String, CoreError> {
        self.require_cache()?;
        let id = self.engine.lock().await.register().await?;
        self.persist().await;
        Ok(id)
    }

    // ---- device linking ----
    //
    // New device:      code = begin_device_link()   → show `code` (XXXX-XXXX-XXXX-XXXX)
    // Existing device: approve_device_link(code)    → the user typed the code there
    // New device:      complete_device_link()       → poll until it returns the device id
    //
    // The existing device signs the new device's identity key; the code authenticates both
    // directions, so neither the server nor a stolen session token can link a device.

    /// Start linking this (unregistered) device; returns the code to display.
    pub async fn begin_device_link(&self) -> Result<String, CoreError> {
        self.require_cache()?;
        let code = self.engine.lock().await.begin_link().await?;
        self.persist().await;
        Ok(code)
    }

    /// Poll a link started with `begin_device_link`: null until an existing device approved, then
    /// this device's new id (it is registered and verified at that point).
    pub async fn complete_device_link(&self) -> Result<Option<String>, CoreError> {
        self.require_cache()?;
        let result = self.engine.lock().await.complete_link().await;
        self.persist().await;
        Ok(result?)
    }

    /// On an existing device: approve the new device showing `code`. False if no pending request
    /// matches the code.
    pub async fn approve_device_link(&self, code: String) -> Result<bool, CoreError> {
        let ok = self.engine.lock().await.approve_link(&code).await?;
        self.persist().await;
        Ok(ok)
    }

    // ---- QR pairing (build 48, `pairing.rs`): the existing device mints the code ----

    /// This skwod's p2p address and current home relay (`GET /api/instance/p2p`), for the QR an
    /// existing device shows. `None` when the skwod has no p2p endpoint.
    pub async fn instance_p2p(&self) -> Result<Option<InstanceP2p>, CoreError> {
        let v = self.api.get("/api/instance/p2p").await.map_err(|e| CoreError::Engine { detail: e.to_string() })?;
        if v["enabled"].as_bool() != Some(true) {
            return Ok(None);
        }
        let Some(node_id) = v["node_id"].as_str().filter(|n| skwod_net::invite::parse_node_id(n).is_ok()) else { return Ok(None) };
        let relay_url = v["relay_url"].as_str().and_then(skwod_net::invite::is_allowed_relay);
        let qr_pairing = v["qr_pairing"].as_bool() == Some(true);
        Ok(Some(InstanceP2p { node_id: node_id.to_string(), relay_url, qr_pairing }))
    }

    /// On the NEW device, WITHOUT signing in (no password): start pairing with a scanned offer
    /// (`pairing_qr_decode`), once the person said yes to "Join … as …?". Make this client with
    /// the loopback base URL of a p2p session to `offer.node_id` and an EMPTY token, and attach
    /// its cache first (that creates this device's identity). Then poll [`SkwodClient::pair_poll`]:
    /// the emoji come once the other device has seen this one.
    pub async fn pair_begin(&self, offer: pairing::PairingOffer, now: u64) -> Result<(), CoreError> {
        self.require_cache()?;
        if now > offer.expires_at {
            return Err(CoreError::Invalid { detail: "this code has expired — make a new one on your other device".into() });
        }
        let commitment = pairing::commitment_bytes(&offer.commitment).ok_or_else(|| CoreError::Invalid { detail: "malformed commitment".into() })?;
        self.engine.lock().await.pair_begin(&offer.code, &offer.user_id, &offer.username, commitment).await?;
        self.persist().await;
        Ok(())
    }

    /// Poll a pairing (pass the same offer): [`PairProgress::Confirm`] with the five emoji once
    /// the other device has seen this one (its nonce checked against the QR's commitment); then,
    /// once approved, this device is linked and registered and [`PairProgress::Paired`] carries
    /// the session the server issued for it (store it as for a log-in). Errors when the pairing
    /// expired, was refused, or the nonce does not match the QR.
    pub async fn pair_poll(&self, offer: pairing::PairingOffer) -> Result<PairProgress, CoreError> {
        let mut engine = self.engine.lock().await;
        let polled = engine.pair_poll().await;
        let identity = engine.identity_key();
        drop(engine);
        self.persist().await;
        Ok(match polled? {
            skwod_sync::PairPoll::Waiting => PairProgress::Waiting,
            skwod_sync::PairPoll::Revealed(nonce) => PairProgress::Confirm { emoji: pairing::confirm_emoji(&offer.code, &offer.user_id, &identity, &nonce) },
            skwod_sync::PairPoll::Paired(session, device_id) => PairProgress::Paired {
                device: PairedDevice {
                    session: AuthSession {
                        user_id: session["user_id"].as_str().unwrap_or_default().to_string(),
                        token: session["token"].as_str().unwrap_or_default().to_string(),
                        expires_at: session["expires_at"].as_i64().unwrap_or_default(),
                    },
                    device_id,
                },
            },
        })
    }

    /// On the EXISTING device, before showing the QR: register the offer with the server
    /// (signed by this device). A new device can only ask to pair with a registered offer.
    pub async fn register_pairing_offer(&self, offer: pairing::PairingOffer) -> Result<(), CoreError> {
        let expires_ms = i64::try_from(offer.expires_at).unwrap_or(i64::MAX / 2000) * 1000;
        self.engine.lock().await.register_pair_offer(&offer.code, &offer.username, expires_ms).await?;
        Ok(())
    }

    /// On the EXISTING device showing the QR: the device that asked to be linked with this offer,
    /// if one has, and the sets to pick its emoji from. Approves nothing. `None` while nobody has
    /// asked yet; an error once the offer expired or was used.
    ///
    /// The first time it sees a (proof-verified) request it pins that identity key and releases
    /// the offer's nonce for it — never for another key: a different key later burns the offer.
    /// Two devices presenting the offer's code means someone else has it: the server marks the
    /// offer contested, this burns it and errors — nobody is approved.
    pub async fn pairing_candidate(&self, offer: pairing::PairingOffer, now: u64) -> Result<Option<PairingCandidate>, CoreError> {
        pairing::PairingGuard::check(&offer.code, offer.expires_at, now)?;
        let mut engine = self.engine.lock().await;
        let Some((user_id, request_id, identity, contested)) = engine.find_pair_request(&offer.code).await? else { return Ok(None) };
        if contested {
            return Err(burn_offer(&offer, pairing::TWO_DEVICES));
        }
        let nonce = pairing::offer_nonce(&offer.code).ok_or_else(|| CoreError::Invalid { detail: pairing::OFFER_LOST.into() })?;
        match pairing::pin(&offer.code, &identity) {
            pairing::Pin::New | pairing::Pin::Same => {}
            pairing::Pin::Other => return Err(burn_offer(&offer, pairing::TWO_DEVICES)),
            pairing::Pin::Unknown => return Err(CoreError::Invalid { detail: pairing::OFFER_LOST.into() }),
        }
        match engine.reveal_pair(&request_id, &identity, &nonce).await {
            Ok(()) => {}
            Err(skwod_sync::EngineError::Client(skwod_sync::ClientError::Status { status: 409, .. })) => return Err(burn_offer(&offer, pairing::TWO_DEVICES)),
            Err(e) => return Err(e.into()),
        }
        drop(engine);
        let real = pairing::confirm_emoji(&offer.code, &user_id, &identity, &nonce);
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        Ok(Some(PairingCandidate { choices: pairing::choices_for(&offer.code, &real), identity_key: B64.encode(identity), request_id }))
    }

    /// On the EXISTING device: approve the candidate if `picked` is the set the new device shows.
    /// A wrong pick denies the request and burns the offer (one try). Single use: the offer can
    /// approve one device, and none after it expired. Waits about two seconds and checks once
    /// more that the request is still uncontested and still that device before approving. The
    /// server refuses a contested offer or any other identity key.
    pub async fn approve_pairing(&self, offer: pairing::PairingOffer, candidate: PairingCandidate, picked: String, now: u64) -> Result<bool, CoreError> {
        pairing::PairingGuard::check(&offer.code, offer.expires_at, now)?;
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        let identity = B64.decode(&candidate.identity_key).map_err(|_| CoreError::Invalid { detail: "identity key".into() })?;
        let nonce = pairing::offer_nonce(&offer.code).ok_or_else(|| CoreError::Invalid { detail: pairing::OFFER_LOST.into() })?;
        if pairing::pin(&offer.code, &identity) != pairing::Pin::Same {
            return Err(burn_offer(&offer, pairing::TWO_DEVICES));
        }
        let user_id = self.engine.lock().await.user_id().map(str::to_string).ok_or_else(|| CoreError::Invalid { detail: "not signed in".into() })?;
        if picked != pairing::confirm_emoji(&offer.code, &user_id, &identity, &nonce) {
            let _ = self.engine.lock().await.deny_pair(&candidate.request_id).await;
            return Err(burn_offer(&offer, pairing::WRONG_PICK));
        }
        if !pairing::PairingGuard::consume(&offer.code) {
            return Err(CoreError::Invalid { detail: "this code was already used — make a new one".into() });
        }
        pairing::forget(&offer.code);
        // A moment for a racing second request to land, then look again (without holding the
        // engine for the wait).
        tokio::time::sleep(std::time::Duration::from_millis(pairing::APPROVE_RECHECK_MS)).await;
        let mut engine = self.engine.lock().await;
        match engine.find_pair_request(&offer.code).await? {
            Some((_, id, key, false)) if id == candidate.request_id && key == identity => {}
            Some((_, _, _, true)) => return Err(CoreError::Invalid { detail: pairing::TWO_DEVICES.into() }),
            _ => return Ok(false),
        }
        let result = engine.approve_pair(&offer.code, &candidate.request_id, &identity).await;
        drop(engine);
        self.persist().await;
        match result {
            Ok(()) => Ok(true),
            Err(skwod_sync::EngineError::Client(skwod_sync::ClientError::Status { status: 409, .. })) => Err(CoreError::Invalid { detail: pairing::TWO_DEVICES.into() }),
            Err(e) => Err(e.into()),
        }
    }

    /// On the EXISTING device: refuse the candidate ("None of these", or "not mine"). The offer
    /// is burned too.
    pub async fn deny_pairing(&self, offer: pairing::PairingOffer, candidate: PairingCandidate) -> Result<(), CoreError> {
        pairing::PairingGuard::consume(&offer.code);
        pairing::forget(&offer.code);
        self.engine.lock().await.deny_pair(&candidate.request_id).await?;
        Ok(())
    }

    /// Set, change or remove the registration-lock PIN (`pin = null` removes it; `current_pin` is
    /// required when one is already set). With a PIN in place for at least 7 days, `reset_devices`
    /// completes at once instead of waiting 7 days. Signed by this device.
    pub async fn set_registration_pin(&self, pin: Option<String>, current_pin: Option<String>) -> Result<(), CoreError> {
        Ok(self.engine.lock().await.set_registration_pin(pin.as_deref(), current_pin.as_deref()).await?)
    }

    /// How many devices are waiting to be linked to this account (prompt for the code when > 0).
    pub async fn pending_device_links(&self) -> Result<u32, CoreError> {
        Ok(self.engine.lock().await.pending_link_requests().await?)
    }

    /// Last-resort recovery when every device is lost and there is no key backup: wipe the
    /// account's device list and make this device its only one. Removes all other devices and
    /// changes the safety number contacts see. With a registration-lock PIN set, pass it. Without
    /// one this throws `ResetPending` the first time: the reset is on hold for 7 days so any
    /// device still on the account can cancel it; call again afterwards to complete.
    pub async fn reset_devices(&self, pin: Option<String>) -> Result<String, CoreError> {
        self.require_cache()?;
        let result = self.engine.lock().await.register_reset(pin.as_deref()).await;
        self.persist().await;
        Ok(result?)
    }

    /// `reset_devices` when the registration-lock PIN is forgotten: no shortcut — the same
    /// cancellable 7-day hold as an account without a PIN (`ResetPending`, then call again).
    pub async fn reset_devices_forgot_pin(&self) -> Result<String, CoreError> {
        self.require_cache()?;
        let result = self.engine.lock().await.register_reset_forgot_pin().await;
        self.persist().await;
        Ok(result?)
    }

    // ---- devices ----

    /// Where this install stands. Ask after `attach_cache` and whenever a call fails with
    /// `DeviceRemoved` / `DeviceSuperseded` / `RecoveryPending`.
    pub async fn device_state(&self) -> DeviceState {
        match self.engine.lock().await.device_state() {
            skwod_sync::DeviceState::Unregistered => DeviceState::Unregistered,
            skwod_sync::DeviceState::Active => DeviceState::Active,
            skwod_sync::DeviceState::Removed => DeviceState::Removed,
            skwod_sync::DeviceState::Superseded => DeviceState::Superseded,
            skwod_sync::DeviceState::RecoveryPending => DeviceState::RecoveryPending,
        }
    }

    /// What this device calls itself ("Sam's iPhone", "Pixel 8"). Call right after constructing
    /// the client (before registering) with a sensible default; it is uploaded sealed under a
    /// key only this account's devices hold, so the server never reads it.
    pub async fn set_device_label(&self, name: String) {
        self.engine.lock().await.set_device_label(&name);
    }

    /// Rename this device (the user edited it on the devices screen).
    pub async fn rename_device(&self, name: String) -> Result<(), CoreError> {
        let result = self.engine.lock().await.rename_device(&name).await;
        self.persist().await;
        Ok(result?)
    }

    /// The account's devices — name, created, last active, "this device", verified — and the
    /// limit (5). Remove one with `unregister_device`.
    pub async fn list_devices(&self) -> Result<DeviceList, CoreError> {
        let result = self.engine.lock().await.list_devices().await;
        self.persist().await;
        let (devices, max_devices) = result?;
        Ok(DeviceList {
            devices: devices
                .into_iter()
                .map(|d| DeviceInfo { device_id: d.device_id, name: d.name, created_at: d.created_at, last_active_at: d.last_active_at, is_this_device: d.is_this_device, verified: d.verified })
                .collect(),
            max_devices,
        })
    }

    /// Re-check this account's devices now. Call on the realtime `device_added`,
    /// `device_removed`, `link_request` and `device_recovery_requested` events (topic
    /// `user:<me>`), then `take_security_notices`.
    pub async fn refresh_own_devices(&self) -> Result<(), CoreError> {
        let result = self.engine.lock().await.refresh_own_devices().await;
        self.persist().await;
        Ok(result?)
    }

    /// Re-read `user_id`'s devices now. Call on the realtime `device_removed` event for someone
    /// else (topics `server:<id>` and `user:<me>`): this device then drops the removed device's
    /// keys, rotates what it held and stops sending to it.
    pub async fn refresh_devices_of(&self, user_id: String) -> Result<(), CoreError> {
        let result = self.engine.lock().await.refresh_devices_of(&user_id).await;
        self.persist().await;
        Ok(result?)
    }

    /// Change the account password: needs the old password and this device (it signs the
    /// request). Every OTHER session of the account is ended; this one carries on.
    pub async fn change_password(&self, old_password: String, new_password: String) -> Result<(), CoreError> {
        Ok(self.engine.lock().await.change_password(&old_password, &new_password).await?)
    }

    /// Delete an account on this skwod for good — the signed-in one ("delete all my data"), or,
    /// for the instance owner, any other. Signed by this device: once the calling account has
    /// a device the server refuses a bare session token (`DELETE /api/auth/users/{id}` without
    /// a device proof answers 403). Apps call this instead of making that request themselves.
    pub async fn delete_account(&self, user_id: String) -> Result<(), CoreError> {
        Ok(self.engine.lock().await.delete_account(&user_id).await?)
    }

    /// The instance owner deletes someone else's account and bans it: its username and its
    /// devices' identity keys cannot come back on this instance, and the invite it signed up
    /// with is revoked. Signed like `delete_account`. A determined person returns with a new
    /// name, new keys and a new invite — which the host has to hand out.
    pub async fn delete_account_and_ban(&self, user_id: String) -> Result<(), CoreError> {
        Ok(self.engine.lock().await.delete_account_and_ban(&user_id).await?)
    }

    /// Bind this session to this install of the device, now. **Apps call this right after
    /// `attach_cache`, before their own first authenticated request**: a build-45 server
    /// refuses an unbound session everything but linking, restoring and binding once the
    /// account has a device. `Ok(false)`: this install is not a registered device yet (link
    /// or restore first) — nothing to bind. Throws `Superseded` / `DeviceRemoved` when this
    /// install is no longer the device, and a transport error when the server was not reached
    /// (call again). Cheap after the first success.
    pub async fn bind_session(&self) -> Result<bool, CoreError> {
        let bound = self.engine.lock().await.bind_if_registered().await?;
        if bound {
            self.persist().await;
        }
        Ok(bound)
    }

    /// A restore of `device_id` onto another install is waiting WITHOUT the recovery key (the
    /// `"recovery_requested"` notice: `device_id`, `request_id`, `fingerprint`). Approve THAT
    /// request — pass the notice's `request_id`. If `device_id` is this device, this install
    /// stops once the restore completes. Throws `RecoveryChanged` (nothing approved) when a
    /// different request has taken its place; that one arrives as a new notice.
    pub async fn approve_recovery(&self, device_id: String, request_id: String) -> Result<(), CoreError> {
        let result = self.engine.lock().await.approve_recovery(&device_id, &request_id).await;
        self.persist().await;
        Ok(result?)
    }

    /// Refuse that restore request ("that wasn't me").
    pub async fn cancel_recovery(&self, device_id: String, request_id: String) -> Result<(), CoreError> {
        let result = self.engine.lock().await.cancel_recovery(&device_id, &request_id).await;
        self.persist().await;
        Ok(result?)
    }

    /// From when (unix ms) a restore with the recovery key is instant: 7 days after the key
    /// was set (as of the last `refresh_own_devices` / `list_devices`). Before then a restore
    /// needs another device's approval, the PIN, or the 7-day wait — tell the user when they
    /// save the key ("Instant restore from <date>"). `None`: no recovery key saved.
    pub async fn recovery_key_instant_from(&self) -> Option<i64> {
        self.engine.lock().await.recovery_key_instant_from()
    }

    /// The short code (`XXXX-XXXX`) of the restore THIS install is waiting on. Show it with
    /// "approve this on another of your devices"; the approving device shows the same code.
    pub async fn recovery_fingerprint(&self) -> String {
        self.engine.lock().await.recovery_fingerprint()
    }

    /// When the restore this install is waiting on completes by itself (unix ms) — the end of
    /// the 7-day hold, for the countdown on the waiting screen. `None`: no restore is waiting,
    /// the server has not said yet in this run (call `retry_restore` once to learn it), or it
    /// is contested (`recovery_contested`) and so will not complete by the hold at all.
    pub async fn recovery_completes_at(&self) -> Option<i64> {
        let engine = self.engine.lock().await;
        engine.recovery_pending().filter(|at| *at > 0 && engine.recovery_status_known() && !engine.recovery_contested())
    }

    /// The restore this install is waiting on was contested — another install asked to restore
    /// the same device — so it completes only when one of the account's devices approves it
    /// (or by the PIN), never by the hold. Show "waiting for approval on one of your devices"
    /// in place of the countdown. As of the server's last answer (`retry_restore`).
    pub async fn recovery_contested(&self) -> bool {
        self.engine.lock().await.recovery_contested()
    }

    /// Would erasing this device lock the user out? (Needs the network.)
    pub async fn erase_check(&self) -> Result<EraseCheck, CoreError> {
        let has_key_backup = self.remote_wrapped_key().await?.is_some();
        let (devices, _) = self.engine.lock().await.list_devices().await?;
        let other_devices = devices.iter().filter(|d| !d.is_this_device && d.verified).count() as u32;
        Ok(EraseCheck { has_key_backup, other_devices, safe: has_key_backup || other_devices > 0 })
    }

    /// "Erase this device": unregister it on the server (signed by this device — the others
    /// drop its keys and stop sending to it) and delete everything local: identity, sessions,
    /// history. Irreversible. `even_if_offline = false` fails when the server cannot be told
    /// (so no ghost device is left listed); `true` wipes locally regardless.
    /// The client is unusable afterwards — drop it. Sign-out does NOT do this: signing out
    /// keeps the cache and the identity, so signing back in is the same device.
    pub async fn erase_device(&self, even_if_offline: bool) -> Result<(), CoreError> {
        {
            let mut engine = self.engine.lock().await;
            if let (Some(device_id), skwod_sync::DeviceState::Active) = (engine.device_id().map(str::to_string), engine.device_state()) {
                match engine.delete_device(&device_id).await {
                    Ok(()) | Err(EngineError::DeviceRemoved) | Err(EngineError::Superseded) => {}
                    Err(_) if even_if_offline => {}
                    Err(e) => return Err(e.into()),
                }
            }
            engine.forget_registration();
        }
        *self.cache.lock().unwrap_or_else(|e| e.into_inner()) = None;
        if let Some(path) = self.cache_path.lock().unwrap_or_else(|e| e.into_inner()).take() {
            for suffix in ["", "-wal", "-shm", "-journal"] {
                let _ = std::fs::remove_file(format!("{path}{suffix}"));
            }
        }
        Ok(())
    }

    /// "Erase this device — it was lost / I no longer trust it": like `erase_device`, but a
    /// REMOVAL: this device's identity can never be restored (only linked again by another
    /// device), its siblings tombstone it, and the account's recovery key — which this device
    /// knew — is retired at once (the other devices are prompted for a new one).
    pub async fn erase_device_as_lost(&self, even_if_offline: bool) -> Result<(), CoreError> {
        {
            let mut engine = self.engine.lock().await;
            match engine.delete_self_as_lost().await {
                Ok(()) | Err(EngineError::DeviceRemoved) | Err(EngineError::Superseded) | Err(EngineError::NotRegistered) => {}
                Err(_) if even_if_offline => {}
                Err(e) => return Err(e.into()),
            }
        }
        self.erase_device(true).await
    }

    /// "My recovery key is compromised": retire it NOW (no 7-day overlap — someone else may
    /// hold it). Backup is off on this device afterwards; ask the user to save a new recovery
    /// key (`enable_key_backup`), which becomes instant after 7 days.
    pub async fn report_recovery_key_compromised(&self) -> Result<(), CoreError> {
        self.engine.lock().await.report_recovery_key_compromised().await?;
        self.clear_backup_config();
        self.persist().await;
        Ok(())
    }

    /// Devices of this account that erased themselves (hex identity keys). Offer "This device
    /// was lost or stolen" → `mark_erased_device_removed`.
    pub async fn erased_devices(&self) -> Result<Vec<ErasedDevice>, CoreError> {
        let rows = self.engine.lock().await.erased_devices().await?;
        Ok(rows.into_iter().map(|(device_id, identity, erased_at)| ErasedDevice { device_id, identity_key_hex: hex::encode(identity), erased_at }).collect())
    }

    /// An erased device turned out to be lost or stolen: from now on it is a REMOVED device —
    /// it cannot be restored, and the recovery key it may have known is retired at once.
    pub async fn mark_erased_device_removed(&self, identity_key_hex: String) -> Result<(), CoreError> {
        let identity = hex::decode(&identity_key_hex).map_err(|_| CoreError::Invalid { detail: "identity key hex".into() })?;
        let result = self.engine.lock().await.mark_erased_device_removed(&identity).await;
        self.clear_backup_config();
        self.persist().await;
        Ok(result?)
    }

    /// When an unreadable cache was moved aside and a fresh one started (unix ms), if that ever
    /// happened on this install. Tell the user once: their history on this device is gone and
    /// the device has to be linked or restored again.
    pub async fn cache_was_reset(&self) -> Option<i64> {
        self.kv(CACHE_RESET_KEY).and_then(|v| v.parse().ok())
    }

    /// This install was removed or superseded and the user chose to link it again as a NEW
    /// device: forget the old registration (keeping history keys, pins and contacts), so
    /// `begin_device_link` / `reset_devices` start from a clean identity.
    pub async fn forget_registration(&self) {
        self.engine.lock().await.forget_registration();
        self.persist().await;
    }

    /// This device's id, if it has registered (or was restored from the cache). None on a fresh
    /// client before `register_device` / `attach_cache`.
    pub async fn current_device_id(&self) -> Option<String> {
        self.engine.lock().await.device_id().map(str::to_string)
    }

    /// Pin the server's Ed25519 instance key from the invite (base64, as returned by
    /// `fetch_server_identity`). The sealed-sender trust root is then only accepted when that key
    /// signed it, so the server cannot substitute a certificate authority of its own after the
    /// fact. Call right after constructing the client for a workspace that has a pin.
    pub async fn set_pinned_server_key(&self, server_public_b64: String) -> Result<(), CoreError> {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        let key = B64.decode(server_public_b64.as_bytes()).map_err(|_| CoreError::Invalid { detail: "pinned key is not base64".into() })?;
        if key.len() != 32 {
            return Err(CoreError::Invalid { detail: "pinned key must be 32 bytes".into() });
        }
        self.engine.lock().await.set_pinned_instance_key(key);
        self.persist().await;
        Ok(())
    }

    /// Drain ALL pending security notices. Poll after sends and inbox syncs; show every one of
    /// them (queue them — never just the first). Each notice about a contact is ALSO written here
    /// as a persistent system row in that contact's DM conversation (`scope` says where), so it
    /// stays visible in the conversation after the alert is dismissed.
    pub async fn take_security_notices(&self) -> Vec<SecurityNotice> {
        let (notices, me) = {
            let mut engine = self.engine.lock().await;
            (engine.take_security_notices(), engine.user_id().map(str::to_string))
        };
        let mut out = Vec::with_capacity(notices.len());
        for n in notices {
            let about_contact = !n.user_id.is_empty()
                && me.as_deref() != Some(n.user_id.as_str())
                && matches!(n.kind.as_str(), "identity_changed" | "new_device" | "unverified_contact_device");
            let mut scope = None;
            if about_contact {
                if let Some(conversation) = self.engine.lock().await.dm_conversation_with(&n.user_id).await {
                    let s = format!("dm:{conversation}");
                    let row = system_row(&s, &n.kind, &n.user_id, &n.device_id, None, n.was_verified, n.at_ms as i64);
                    if let Some(cache) = self.cache.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
                        let _ = cache.insert_core_row(&row);
                    }
                    scope = Some(s);
                }
            }
            // A join request carries the server it is for in the engine's device-id slot.
            // So does a refused owner change. A refused channel move names the channel in the
            // device-id slot and the server the channel really belongs to in the user-id slot.
            let (mut device_id, server_id) = match n.kind.as_str() {
                "join_request" | "owner_change_refused" => (String::new(), Some(n.device_id)),
                "channel_remap_refused" => (n.device_id, Some(n.user_id.clone())),
                _ => (n.device_id, None),
            };
            // A recovery request carries its id and short code packed after the device id.
            let (mut request_id, mut fingerprint) = (None, None);
            if n.kind == "recovery_requested" {
                let mut parts = device_id.splitn(3, '|').map(str::to_string);
                let device = parts.next().unwrap_or_default();
                (request_id, fingerprint) = (parts.next(), parts.next());
                device_id = device;
            }
            out.push(SecurityNotice { kind: n.kind, user_id: n.user_id, device_id, at_ms: n.at_ms, was_verified: n.was_verified, scope, server_id, request_id, fingerprint });
        }
        self.persist().await;
        out
    }

    /// The user compared the account safety number with a contact and it matched. Pass the
    /// number EXACTLY AS IT WAS DISPLAYED (`safety_number`; spaces are ignored): the core reads
    /// the directory again, recomputes the number and marks the account verified only if it is
    /// still that one. If the contact's (or this account's) device set changed in between, this
    /// fails with `IdentityChanged` and nothing is marked — show the new number and let the user
    /// compare again. Verification therefore always covers the devices the user actually
    /// compared, never whatever is listed at the moment of the tap.
    ///
    /// Once verified, a later change to the device set — a device added or removed, or one
    /// nobody vouched for — makes sends fail with `IdentityChanged` until they are verified
    /// again or the change is accepted (`accept_identity_change`).
    pub async fn verify_contact(&self, user_id: String, safety_number: String) -> Result<(), CoreError> {
        let result = self.engine.lock().await.verify_contact(&user_id, &safety_number).await;
        self.persist().await;
        Ok(result?)
    }

    /// Remove the verified mark from a contact.
    pub async fn unverify_contact(&self, user_id: String) -> Result<(), CoreError> {
        self.engine.lock().await.set_verified(&PeerId { user_id, device_id: String::new() }, false)?;
        self.persist().await;
        Ok(())
    }

    /// The 30-digit fingerprint of `user_id`'s account as this device holds it: their half of
    /// the safety number, derived from their user id and the identity keys of the devices this
    /// device accepts for them (pinned at first sight, then extended only through their own
    /// link signatures). It does not depend on any name the server reports, so it is what to
    /// show next to a person the user is asked to make a trust decision about (e.g. "Let in").
    /// Looking up someone never seen before pins the devices the directory lists for them now.
    pub async fn account_fingerprint(&self, user_id: String) -> Result<String, CoreError> {
        let result = self.engine.lock().await.contact_fingerprint(&user_id).await;
        self.persist().await;
        Ok(result?)
    }

    /// What this device's safety-number QR code for `user_id` carries. It is DIRECTIONAL (my
    /// fingerprint, then theirs as I hold it), so it only matches when the other party scans
    /// it — not when this device scans its own screen or a picture of it.
    pub async fn safety_qr(&self, user_id: String) -> Result<String, CoreError> {
        let result = self.engine.lock().await.safety_qr(&user_id).await;
        self.persist().await;
        Ok(result?)
    }

    /// Check a code scanned LIVE from `user_id`'s screen. Returns the 60-digit safety number it
    /// stands for when it matches (pass that to `verify_contact`), `None` when the code is not a
    /// safety-number code at all, and fails with `IdentityChanged` when it is one but does not
    /// match (someone may be in the middle — or it is this device's own code). Only ever feed
    /// this a camera scan of the other person's device: a picture received through the
    /// conversation proves nothing, because whoever controls the conversation chose it.
    pub async fn check_safety_qr(&self, user_id: String, scanned: String) -> Result<Option<String>, CoreError> {
        let result = self.engine.lock().await.check_safety_qr(&user_id, &scanned).await;
        self.persist().await;
        Ok(result?)
    }

    /// Devices of this account a backup restore brought back that are not confirmed yet (device
    /// ids; build 45, audit M2). The backup may be older than the account and list a device
    /// removed since: nothing is sent to these, nothing they vouch for is admitted, nothing
    /// they send is read, and none of them can confirm itself or another. One is confirmed by
    /// the sibling set of an already-confirmed device of the account, or by the user
    /// (`confirm_restored_device`). With no confirmed device at all, only the user can.
    pub async fn unconfirmed_restored_devices(&self) -> Vec<String> {
        self.engine.lock().await.unconfirmed_siblings()
    }

    /// The USER answers "Is this your device?" with yes for one device that
    /// `unconfirmed_restored_devices` lists. A device that was removed is never brought back.
    pub async fn confirm_restored_device(&self, device_id: String) -> Result<(), CoreError> {
        let result = self.engine.lock().await.confirm_restored_sibling(&device_id).await;
        self.persist().await;
        Ok(result?)
    }

    /// Whether the user verified this contact for exactly the devices they have now.
    pub async fn is_peer_verified(&self, user_id: String, device_id: String) -> bool {
        self.engine.lock().await.is_verified(&PeerId { user_id, device_id })
    }

    /// Where a contact stands, for the conversation header and the safety-number screen. Reads
    /// local state only (nothing is fetched or sent).
    pub async fn contact_status(&self, user_id: String) -> ContactStatus {
        let engine = self.engine.lock().await;
        let (verified, sends_held, devices, unvouched_devices) = engine.contact_status(&user_id);
        ContactStatus { verified, sends_held, devices, unvouched_devices, accept_fingerprint: engine.accept_fingerprint(&user_id) }
    }

    /// The user chose to continue with a contact whose devices changed or include one nobody
    /// vouched for: accept the devices the banner SHOWED. `shown` is the `accept_fingerprint`
    /// of the `ContactStatus` the banner was drawn from (build 45, audit L2). If the listing has
    /// changed since, nothing is accepted and `IdentityChanged` comes back: read the status
    /// again and show the banner for the new set. Messages held from the accepted devices are
    /// delivered. The verified mark stays cleared until they verify again.
    pub async fn accept_identity_change(&self, user_id: String, device_id: String, shown: String) -> Result<(), CoreError> {
        let result = self.engine.lock().await.accept_identity_change(&PeerId { user_id, device_id }, &shown).await;
        self.store_inbound_dms().await;
        self.persist().await;
        Ok(result?)
    }

    /// "Let in": approve a user the app shows as HELD in a server (the server lists them, but no
    /// member this device trusts approved them — including someone who used an auto-join invite
    /// and is asking to be provisioned). Signs the approval with this device, publishes it, and,
    /// when this device holds the space key, provisions them. Call ONLY from an explicit user
    /// action: this signature is what tells every other member that a person admitted this user.
    pub async fn approve_member(&self, server_id: String, user_id: String) -> Result<(), CoreError> {
        let result = async {
            let mut engine = self.engine.lock().await;
            engine.approve_member(&server_id, &user_id).await?;
            // Best-effort: without the space key (we are not the host) the approval still stands.
            let _ = engine.provision_member(&server_id, &PeerId { user_id: user_id.clone(), device_id: String::new() }).await;
            Ok::<_, EngineError>(())
        }
        .await;
        self.persist().await;
        Ok(result?)
    }

    /// The owner of a space as this device has it PINNED (from our own create or join flow, a key
    /// backup, or a verified sibling device) — never what the server lists. `None` when no owner
    /// is pinned: then nobody's word counts as the owner's. Use it to check server-level
    /// broadcasts, e.g. only the owner's avatar message may set the server icon.
    pub async fn space_owner(&self, server_id: String) -> Option<String> {
        let owner = self.engine.lock().await.space_owner(&server_id).await;
        self.persist().await;
        owner
    }

    /// The account that owns this INSTANCE (the host), pinned the first time the pinned instance
    /// key attests it and never replaced afterwards (the pin lives in this workspace's encrypted
    /// cache). `None` when no instance key is pinned, nothing was attested, or no cache is
    /// attached to hold the pin — or the pin could not be READ (a read error is never taken for
    /// "not pinned yet", and never leads to a new pin). Use it for the skwod (instance) icon only: it is the instance's
    /// word about itself, not a trust anchor for keys or approvals.
    pub async fn instance_owner(&self) -> Option<String> {
        const SLOT: &str = "trust|instance_owner";
        // Read STRICTLY. A pin that cannot be read is not "no pin": answering with a freshly
        // attested owner — and writing it — would let a read error replace the pinned account.
        // So: no cache, or a failed read, is `None`, and nothing is written.
        let pinned = {
            let guard = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref()?.kv_get(SLOT) {
                Ok(pinned) => pinned,
                Err(_) => return None,
            }
        };
        if let Some(owner) = pinned {
            return Some(owner);
        }
        let owner = self.engine.lock().await.attested_instance_owner().await?;
        let guard = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        let cache = guard.as_ref()?;
        // Another call may have pinned meanwhile: the first pin stands. (Read strictly again.)
        match cache.kv_get(SLOT) {
            Ok(Some(existing)) => return Some(existing),
            Ok(None) => {}
            Err(_) => return None,
        }
        cache.kv_set(SLOT, &owner).ok()?;
        Some(owner)
    }

    /// Who the SERVER says owns a space — for labels only. Never trust anything on the strength
    /// of it.
    pub async fn space_owner_claimed(&self, server_id: String) -> Option<String> {
        self.engine.lock().await.space_owner_claimed(&server_id).await
    }

    /// Users the server lists in `server_id` that this device is holding (no trusted approval,
    /// so they get no keys from us).
    pub async fn held_members(&self, server_id: String) -> Vec<String> {
        self.engine.lock().await.held_members(&server_id)
    }

    // ---- real E2EE DM messaging through the server ----

    /// Look up a user by username to start a DM. Returns their user id + a device id.
    pub async fn find_user(&self, username: String) -> Result<FoundUser, CoreError> {
        let (user_id, device_id) = self.engine.lock().await.find_user(&username).await?;
        Ok(FoundUser { user_id, device_id })
    }

    /// The **account** safety number with a contact: one 60-digit value per pair of accounts,
    /// computed over each side's sorted set of device identity keys (`device_id` is ignored). Both
    /// sides see the same value. Compare it in person / over a trusted channel to rule out a
    /// host-in-the-middle; then call `verify_contact` with the number as displayed. It changes whenever either side's
    /// device set changes.
    pub async fn safety_number(&self, my_user_id: String, user_id: String, device_id: String) -> Result<String, CoreError> {
        let peer = PeerId { user_id, device_id };
        let n = self.engine.lock().await.safety_number(&my_user_id, &peer).await?;
        self.persist().await;
        Ok(n)
    }

    /// Open (or reuse) a 1:1 DM conversation with a peer user; returns the conversation id.
    pub async fn open_dm(&self, peer_user_id: String) -> Result<String, CoreError> {
        Ok(self.engine.lock().await.open_dm(&peer_user_id).await?)
    }

    /// Send `text` to the peer **user**: sealed-sender encrypted to every one of their devices (the
    /// `device_id` argument is only a hint) plus a synced copy to our own other devices. The
    /// plaintext is stored in the local cache. Returns the message id.
    pub async fn send_dm(&self, conversation_id: String, user_id: String, device_id: String, text: String) -> Result<String, CoreError> {
        let peer = PeerId { user_id, device_id };
        let result = self.engine.lock().await.send_dm(&conversation_id, &peer, &text).await;
        self.drop_unsent().await;
        // Persist even on failure: sessions may have been established before the error.
        self.persist().await;
        // The message row was written with the ratchet state BEFORE it left (the state sink);
        // this is the no-cache / idempotent path.
        let id = result?;
        self.store(&format!("dm:{conversation_id}"), &id, SELF_AUTHOR, &text, now_ms());
        Ok(id)
    }

    /// DMs that reached this device since the last call — in ANY conversation, including ones
    /// this device never opened and messages we sent from another device. This is what makes an
    /// incoming DM appear: add `conversation_id`/`peer_user_id` to the sidebar if missing, and
    /// notify unless `from_self`. Does not touch the network (see [`SkwodClient::sync_dms`]).
    pub async fn take_dm_events(&self) -> Vec<DmEvent> {
        let mut events = std::mem::take(&mut *self.dm_events.lock().unwrap_or_else(|e| e.into_inner()));
        if !events.is_empty() {
            let engine = self.engine.lock().await;
            for e in &mut events {
                e.is_group = engine.conversation_is_group(&e.conversation_id).unwrap_or(false);
            }
        }
        events
    }

    /// Whether direct conversation `conversation_id` is a group, as fixed on this device the
    /// first time it was used: by the group marker sealed inside the first message received
    /// in it, or by the user's own first send. `None` when it has never been used here — the
    /// server's `is_group` is then all there is, and it is only a label. Use this, not the
    /// conversation list, to decide how a conversation is presented.
    pub async fn dm_is_group(&self, conversation_id: String) -> Option<bool> {
        self.engine.lock().await.conversation_is_group(&conversation_id)
    }

    /// Sync the sealed mailbox now and return the DMs it brought (plus any not yet taken). Call
    /// on the realtime `sealed` event, on a push wake, and on a slow timer.
    /// Try the direct-message deliveries still owed to individual devices now (they are also
    /// retried on every mailbox sync, each on its own backoff). Returns how many remain.
    pub async fn retry_deliveries(&self) -> u32 {
        let remaining = {
            let mut engine = self.engine.lock().await;
            engine.retry_deliveries(true).await;
            engine.pending_deliveries() as u32
        };
        self.persist().await;
        remaining
    }

    pub async fn sync_dms(&self) -> Result<Vec<DmEvent>, CoreError> {
        let result = self.engine.lock().await.sync_inbox().await;
        self.store_inbound_dms().await;
        self.persist().await;
        // Whatever was decrypted is reported even if the pass then failed part-way.
        let events = self.take_dm_events().await;
        if events.is_empty() {
            result?;
        }
        Ok(events)
    }

    /// Every 1:1 conversation this ACCOUNT is in, from the server's list — the way a device
    /// learns of DMs started on another of our devices (or by someone else) while it was not
    /// around. Routing metadata only; the messages come from the mailbox.
    pub async fn list_dms(&self) -> Result<Vec<DmConversation>, CoreError> {
        let rows = self.engine.lock().await.list_dms().await?;
        Ok(rows.into_iter().map(|c| DmConversation { conversation_id: c.conversation_id, peer_user_id: c.peer_user_id, peer_username: c.peer_username }).collect())
    }

    /// Is this client's session still good? Tells "signed out" (401 → clear the session, show
    /// login) apart from "cannot reach the server" (keep it, retry).
    pub async fn session_state(&self) -> SessionState {
        match self.api.get("/api/auth/me").await {
            Ok(_) => SessionState::Valid,
            Err(skwod_sync::ClientError::Status { status: 401, .. }) => SessionState::SignedOut,
            Err(_) => SessionState::Unreachable,
        }
    }

    /// Calls ringing for this account on this server right now. After a call push woke the app,
    /// ask EVERY signed-in server and answer the one that is actually ringing.
    pub async fn pending_rings(&self) -> Result<Vec<RingInfo>, CoreError> {
        let rows = self.engine.lock().await.pending_rings().await?;
        Ok(rows.into_iter().map(|(channel_id, server_id, from_user_id, ring_id, expires_at)| RingInfo { channel_id, server_id, from_user_id, ring_id, expires_at }).collect())
    }

    /// `user_id`'s key fingerprint for DISPLAY, without trusting anything: unlike
    /// [`SkwodClient::account_fingerprint`] this never pins. Use it wherever people are merely
    /// listed (the "Waiting to join" list); pinning happens when the user acts — lets them in,
    /// messages them, verifies them.
    pub async fn peek_account_fingerprint(&self, user_id: String) -> Result<FingerprintPeek, CoreError> {
        let (fingerprint, pinned) = self.engine.lock().await.peek_contact_fingerprint(&user_id).await?;
        Ok(FingerprintPeek { fingerprint, pinned })
    }

    /// Sync the sealed mailbox, file every decrypted DM into its conversation, and return this
    /// conversation's full history (own + peer, chronological). Idempotent.
    pub async fn fetch_dm(&self, conversation_id: String, user_id: String, device_id: String, my_user_id: String) -> Result<Vec<Message>, CoreError> {
        let _ = (user_id, device_id, my_user_id);
        let result = self.engine.lock().await.sync_inbox().await;
        self.store_inbound_dms().await;
        self.persist().await;
        result?;
        Ok(self.history_scope(&format!("dm:{conversation_id}")))
    }

    // ---- real E2EE group channels (Sender Keys + encrypted metadata) ----

    /// Create an E2EE space: a server + a default text channel with encrypted names, plus an invite.
    pub async fn create_space(&self, name: String, channel_name: String) -> Result<Space, CoreError> {
        let h = self.engine.lock().await.create_space(&name, &channel_name).await?;
        self.persist().await;
        Ok(Space { server_id: h.server_id, channel_id: h.channel_id, invite_code: h.invite_code, space_key_hex: h.space_key_hex })
    }

    /// Create a role (E2EE name) with a permission bitmask. Returns the role id.
    pub async fn create_role(&self, server_id: String, name: String, permissions: i64) -> Result<String, CoreError> {
        let id = self.engine.lock().await.create_role(&server_id, &name, permissions).await?;
        Ok(id)
    }

    /// The server's roles, names decrypted with the space key we hold.
    pub async fn list_roles(&self, server_id: String) -> Result<Vec<RoleInfo>, CoreError> {
        let roles = self.engine.lock().await.list_roles(&server_id).await?;
        Ok(roles
            .into_iter()
            .map(|r| RoleInfo { role_id: r.role_id, name: r.name, permissions: r.permissions, is_default: r.is_default })
            .collect())
    }

    /// Delete a role.
    pub async fn delete_role(&self, role_id: String) -> Result<(), CoreError> {
        self.engine.lock().await.delete_role(&role_id).await?;
        Ok(())
    }

    /// Grant a role to a member.
    pub async fn assign_role(&self, server_id: String, user_id: String, role_id: String) -> Result<(), CoreError> {
        self.engine.lock().await.assign_role(&server_id, &user_id, &role_id).await?;
        Ok(())
    }

    /// Revoke a role from a member.
    pub async fn remove_role(&self, server_id: String, user_id: String, role_id: String) -> Result<(), CoreError> {
        self.engine.lock().await.remove_role(&server_id, &user_id, &role_id).await?;
        Ok(())
    }

    /// Add a channel to an existing server we hold the space key for. Returns the new channel id.
    pub async fn create_channel(&self, server_id: String, name: String) -> Result<String, CoreError> {
        let id = self.engine.lock().await.create_channel(&server_id, &name).await?;
        self.persist().await;
        Ok(id)
    }

    /// The user OPENED `channel_id` as a channel of `server_id` (tapped it in that server's
    /// channel list). This confirms where the channel belongs on this device, which is what a
    /// later clear or deletion by that server's owner is checked against; without it (or the
    /// user writing in the channel, creating it, or joining through it) such a clear does not
    /// empty this device's cache. Returns `false`, changing nothing, when the channel is already
    /// confirmed in ANOTHER server (a `channel_remap_refused` notice follows). Call it from the
    /// user's navigation only — never for every channel a listing returns.
    pub async fn channel_opened(&self, server_id: String, channel_id: String) -> bool {
        let confirmed = self.engine.lock().await.confirm_channel(&channel_id, &server_id);
        self.persist().await;
        confirmed
    }

    /// The user's explicit decision to drop everything this device trusts about one space: its
    /// pinned owner, its key, its roster and the sender keys of its channels. For a space they
    /// have left for good, or one whose ownership really changed and that they choose to join
    /// afresh: a join never replaces a pinned owner or a held space key by itself (it fails and
    /// raises an `owner_change_refused` notice), so this is the only way to let a later join pin
    /// a different owner. Call it from a deliberate, confirmed user action only — never in
    /// response to something the server said. Cached messages are not touched.
    pub async fn forget_space(&self, server_id: String) {
        self.engine.lock().await.forget_space(&server_id);
        self.persist().await;
    }

    /// Join a space with an invite code + its space key (hex), for a known channel. If the invite
    /// is a bare code the host must approve — the result's `pending` flag reports that.
    pub async fn join_space(&self, invite_code: String, space_key_hex: String, channel_id: String) -> Result<JoinResult, CoreError> {
        let o = self.engine.lock().await.join_space(&invite_code, &space_key_hex, &channel_id).await;
        // (Also when the join was refused: the notice saying why must not be lost.)
        self.persist().await;
        let o = o?;
        Ok(JoinResult { server_id: o.server_id, pending: o.pending,
            host_user_id: o.host_user_id, host_device_id: o.host_device_id })
    }

    /// Join a space with ONLY an invite code — no space key or channel id to paste.
    /// Channel names + keys arrive automatically once the host approves (they provision you over DM).
    pub async fn join_by_code(&self, invite_code: String) -> Result<JoinResult, CoreError> {
        let o = self.engine.lock().await.join_by_code(&invite_code).await;
        self.persist().await;
        let o = o?;
        Ok(JoinResult { server_id: o.server_id, pending: o.pending,
            host_user_id: o.host_user_id, host_device_id: o.host_device_id })
    }

    /// List every channel in a server we belong to, with names decrypted using the space key we hold
    /// (name is null until the host's provision bundle arrives). This is how a joined member sees the
    /// whole server at once.
    pub async fn list_channels(&self, server_id: String) -> Result<Vec<ChannelInfo>, CoreError> {
        let rows = self.engine.lock().await.list_channels(&server_id).await?;
        // The feed channel is plumbing, not a place to chat: it is never listed (`feed_channel`).
        Ok(rows
            .into_iter()
            .filter(|c| c.purpose.as_deref() != Some("feed"))
            .map(|c| ChannelInfo { channel_id: c.channel_id, name: c.name, kind: c.kind })
            .collect())
    }

    /// The one channel this server's feed and stories live in — the same on every device (see
    /// `Engine::feed_channel`). Post, like, comment and read there, never in "the first channel".
    pub async fn feed_channel(&self, server_id: String) -> Result<String, CoreError> {
        let r = self.engine.lock().await.feed_channel(&server_id).await;
        self.persist().await;
        Ok(r?)
    }

    /// The decrypted name of a joined server (null until its space key arrives). Labels the sidebar.
    pub async fn server_name(&self, server_id: String) -> Result<Option<String>, CoreError> {
        Ok(self.engine.lock().await.server_name(&server_id).await?)
    }

    /// Provision a newly-approved member: relay the space key + every channel's sender key to them
    /// over an E2EE DM so they can see and read the whole server. The host calls this right after
    /// approving a join request. Persists (a new DM session may have been created).
    pub async fn provision_member(&self, server_id: String, user_id: String, device_id: String) -> Result<(), CoreError> {
        let peer = PeerId { user_id, device_id };
        self.engine.lock().await.provision_member(&server_id, &peer).await?;
        self.persist().await;
        Ok(())
    }

    /// Ask the host of `server_id` to provision us — used after a token/username auto-join, where the
    /// host has no approval step to trigger provisioning. The host fulfills it on its next inbox sync.
    pub async fn request_provision(&self, server_id: String, host_user_id: String, host_device_id: String) -> Result<(), CoreError> {
        let host = PeerId { user_id: host_user_id, device_id: host_device_id };
        self.engine.lock().await.request_provision(&server_id, &host).await?;
        self.persist().await;
        Ok(())
    }

    /// Host inbox sync: scan DMs for control traffic and act on it — install relayed keys and fulfill
    /// members' provision requests (auto-join case). Idempotent; call on a timer while signed in.
    /// Returns how many members were newly provisioned this pass.
    pub async fn process_control_inbox(&self, my_user_id: String) -> Result<u32, CoreError> {
        let result = self.engine.lock().await.process_control_inbox(&my_user_id).await;
        self.store_inbound_dms().await;
        self.persist().await;
        Ok(result?)
    }

    /// The notification extension's inbox sync — what it calls INSTEAD of
    /// [`Self::process_control_inbox`]. Reads and decrypts the sealed mailbox like that call,
    /// but puts this client in notification-extension mode first, for the rest of its life:
    /// from here on it never registers a device and never creates, rotates or uploads a key
    /// (no prekey refill, no signed-prekey or delivery-key rotation, no new sender key), in
    /// this call or in any later one (`fetch_channel_messages`, `history`, …). Provision
    /// requests that arrive are kept for the app. See docs/PUSH.md.
    pub async fn process_notification_inbox(&self) -> Result<(), CoreError> {
        let result = self.engine.lock().await.process_inbox_passive().await;
        self.store_inbound_dms().await;
        self.persist().await;
        Ok(result?)
    }

    /// Create an invite for a space. `kind`: "token" (one-time auto-join link), "username"
    /// (auto-join only `reserved_username`), or "code" (host must approve each request).
    pub async fn invite_to_space(&self, server_id: String, kind: String, reserved_username: Option<String>) -> Result<String, CoreError> {
        Ok(self.engine.lock().await.invite_to_space(&server_id, &kind, reserved_username.as_deref()).await?)
    }

    /// The members of a server we belong to (user_id + public username), for the members sidebar.
    pub async fn list_members(&self, server_id: String) -> Result<Vec<MemberInfo>, CoreError> {
        let rows = self.engine.lock().await.list_members(&server_id).await?;
        Ok(rows.into_iter().map(|(user_id, username)| MemberInfo { user_id, username }).collect())
    }

    /// List existing invites for a space we host, so the owner can see and revoke them.
    pub async fn list_invites(&self, server_id: String) -> Result<Vec<InviteInfo>, CoreError> {
        let rows = self.engine.lock().await.list_invites(&server_id).await?;
        Ok(rows
            .into_iter()
            .map(|i| InviteInfo {
                code: i.code,
                max_uses: i.max_uses,
                use_count: i.use_count,
                expires_at: i.expires_at,
                status: i.status,
                waiting: i.waiting,
                waiting_full: i.waiting_full,
            })
            .collect())
    }

    /// Revoke an invite by code — it stops working instantly. To rotate, revoke then mint a new one.
    pub async fn revoke_invite(&self, code: String) -> Result<(), CoreError> {
        Ok(self.engine.lock().await.revoke_invite(&code).await?)
    }

    /// List pending join requests for a space we host.
    pub async fn list_join_requests(&self, server_id: String) -> Result<Vec<JoinRequest>, CoreError> {
        let rows = self.engine.lock().await.list_join_requests(&server_id).await?;
        Ok(rows.into_iter().map(|(user_id, username)| JoinRequest { user_id, username }).collect())
    }

    /// Approve a pending join request (host).
    pub async fn approve_join_request(&self, server_id: String, user_id: String) -> Result<(), CoreError> {
        let result = self.engine.lock().await.approve_join_request(&server_id, &user_id).await;
        self.persist().await;
        Ok(result?)
    }

    /// Deny a pending join request (host).
    pub async fn deny_join_request(&self, server_id: String, user_id: String) -> Result<(), CoreError> {
        Ok(self.engine.lock().await.deny_join_request(&server_id, &user_id).await?)
    }

    // ---- safety: bans / blocks / reports (metadata-only server enforcement) ----

    /// Ban a user from a server: kicks them AND bars every rejoin path until unbanned (this is what
    /// kick alone never did). Requires the `BAN_MEMBERS` permission; `reason` is an optional
    /// moderator note kept for the audit trail.
    pub async fn ban_member(&self, server_id: String, user_id: String, reason: Option<String>) -> Result<(), CoreError> {
        Ok(self.engine.lock().await.ban_member(&server_id, &user_id, reason.as_deref()).await?)
    }

    /// Lift a ban. The user is not re-admitted — they need a fresh invite like anyone else.
    pub async fn unban_member(&self, server_id: String, user_id: String) -> Result<(), CoreError> {
        Ok(self.engine.lock().await.unban_member(&server_id, &user_id).await?)
    }

    /// The server's ban list (requires `BAN_MEMBERS`).
    pub async fn list_bans(&self, server_id: String) -> Result<Vec<BanInfo>, CoreError> {
        let rows = self.engine.lock().await.list_bans(&server_id).await?;
        Ok(rows.into_iter().map(|(user_id, username, reason)| BanInfo { user_id, username, reason }).collect())
    }

    /// Block a user: the server refuses DM creation/sends between the two of you (and stops their
    /// typing indicators) until you unblock. The blocked user is not notified.
    pub async fn block_user(&self, user_id: String) -> Result<(), CoreError> {
        let result = self.engine.lock().await.block_user(&user_id).await;
        self.persist().await;
        Ok(result?)
    }

    /// Unblock a user.
    pub async fn unblock_user(&self, user_id: String) -> Result<(), CoreError> {
        let result = self.engine.lock().await.unblock_user(&user_id).await;
        self.persist().await;
        Ok(result?)
    }

    /// My block list (self-scoped).
    pub async fn list_blocks(&self) -> Result<Vec<BlockInfo>, CoreError> {
        let rows = self.engine.lock().await.list_blocks().await?;
        Ok(rows.into_iter().map(|(user_id, username)| BlockInfo { user_id, username }).collect())
    }

    /// File an abuse report with the instance operator. `body` is YOUR OWN plaintext description or
    /// excerpt you choose to disclose (Signal-style reporting) — the server never decrypts anything.
    /// Returns the report id.
    pub async fn report_abuse(
        &self,
        category: String,
        body: Option<String>,
        subject_user_id: Option<String>,
        server_id: Option<String>,
    ) -> Result<String, CoreError> {
        Ok(self
            .engine
            .lock()
            .await
            .report_abuse(&category, body.as_deref(), subject_user_id.as_deref(), server_id.as_deref())
            .await?)
    }

    /// Share our channel sender key with a member (relayed over their DM); they can then decrypt.
    pub async fn share_group_key(&self, channel_id: String, user_id: String, device_id: String) -> Result<(), CoreError> {
        let peer = PeerId { user_id, device_id };
        self.engine.lock().await.share_group_key(&channel_id, &peer).await?;
        self.persist().await;
        Ok(())
    }

    /// Enforce the membership boundary on one channel's sender key: if anyone we distributed the
    /// current key to is no longer a member (kicked, banned, or left), rotate it and re-distribute
    /// to the remaining members — so removed members can't decrypt anything sent after removal
    /// (chat or voice). Also best-effort shares the key to members who don't hold it yet. Call on
    /// channel open and periodically while it's active. Returns whether a rotation happened.
    pub async fn sync_channel_membership(
        &self,
        channel_id: String,
        server_id: String,
        my_user_id: String,
    ) -> Result<bool, CoreError> {
        let rotated = self.engine.lock().await.sync_channel_membership(&channel_id, &server_id, &my_user_id).await?;
        self.persist().await;
        Ok(rotated)
    }

    /// [`Self::sync_channel_membership`] across EVERY channel of a server (one member-list fetch).
    /// Call immediately after kicking or banning someone so all the server's keys rotate at once.
    pub async fn sync_server_membership(&self, server_id: String, my_user_id: String) -> Result<bool, CoreError> {
        let rotated = self.engine.lock().await.sync_server_membership(&server_id, &my_user_id).await?;
        self.persist().await;
        Ok(rotated)
    }

    /// Encrypt + post a channel message; store the plaintext locally. Returns the message id.
    pub async fn send_channel_message(&self, channel_id: String, text: String) -> Result<String, CoreError> {
        self.send_channel_message_with(channel_id, text, None, Vec::new()).await
    }

    /// Send a channel message as a reply to `reply_to_id` (quoted-reply). Own copy is cached with the
    /// reply link so it renders immediately.
    pub async fn reply_channel_message(&self, channel_id: String, text: String, reply_to_id: String) -> Result<String, CoreError> {
        self.send_channel_message_with(channel_id, text, Some(reply_to_id), Vec::new()).await
    }

    /// Send a channel message whose body refers to uploaded attachments. `blob_ids` are the ids
    /// `POST /api/blobs` returned: the server links them to the message as it stores it, which
    /// is what lets the OTHER members download them. A message that carries an attachment (a
    /// photo, a file, a feed post's media) must be sent with this — otherwise only the uploader
    /// can open it.
    ///
    /// To the server every message is the same. On THIS device, game state (a body tagged
    /// `skwod/game|`) is cached under `aux:<channel>` rather than in the chat history (see
    /// `fetch_aux_messages`). Fails with
    /// `Invalid { detail }` — a sentence to show — when the message is too big to deliver.
    pub async fn send_channel_message_with(&self, channel_id: String, text: String, reply_to_id: Option<String>, blob_ids: Vec<String>) -> Result<String, CoreError> {
        let id = skwod_crypto::new_distribution_id().to_string();
        let sent = self.engine.lock().await.send_channel_message_as(&channel_id, &id, &text, reply_to_id.as_deref(), &blob_ids).await;
        // The row was written with the ratchet state before the message left; a send that
        // then failed takes it back.
        self.drop_unsent().await;
        self.persist().await;
        // Filed under the SERVER's time for it — the one clock every member's ordering shares
        // (the whiteboard's clear cutoff, chess move order and story expiry all read it).
        let created_at = sent?;
        self.note_server_time(created_at);
        let scope = if skwod_sync::Traffic::of(&text).hidden { format!("aux:{channel_id}") } else { format!("channel:{channel_id}") };
        self.store_meta(&scope, &id, SELF_AUTHOR, Some(&text), created_at, reply_to_id.as_deref(), false, false);
        // The row already exists — it was written with the ratchet state, under this device's
        // clock, before the message left — so move it to the server's time explicitly.
        self.with_cache(|c| c.set_message_time(&scope, &id, created_at));
        Ok(id)
    }

    /// Edit a channel message we authored; update our own cached copy immediately (marked edited).
    pub async fn edit_channel_message(&self, channel_id: String, message_id: String, text: String) -> Result<(), CoreError> {
        // The reply target is re-stated inside the edited ciphertext (it is not the server's to
        // supply), so look up what this message replied to.
        let scope = format!("channel:{channel_id}");
        let reply_to = self.history_scope(&scope).into_iter().find(|m| m.message_id == message_id).and_then(|m| m.reply_to_id);
        self.engine.lock().await.edit_channel_message(&channel_id, &message_id, &text, reply_to.as_deref()).await?;
        self.store_meta(&scope, &message_id, SELF_AUTHOR, Some(&text), now_ms(), None, true, false);
        self.persist().await;
        Ok(())
    }

    /// Delete a channel message we authored; tombstone our own cached copy immediately.
    pub async fn delete_channel_message(&self, channel_id: String, message_id: String) -> Result<(), CoreError> {
        self.engine.lock().await.delete_channel_message(&channel_id, &message_id).await?;
        self.store_meta(&format!("channel:{channel_id}"), &message_id, SELF_AUTHOR, None, now_ms(), None, false, true);
        self.persist().await;
        Ok(())
    }

    /// Clear every message in a channel — keeping the channel, members, and roles. Owner/moderator
    /// only (the server enforces MANAGE_MESSAGES). Also purges the local cache for the channel so the
    /// view empties immediately.
    pub async fn clear_channel_messages(&self, channel_id: String) -> Result<(), CoreError> {
        self.engine.lock().await.clear_channel(&channel_id).await?;
        self.apply_channel_clear(&channel_id, self.server_now());
        self.persist().await;
        Ok(())
    }

    /// Whether voice/video is set up on this instance (and the SFU URL if so). Drives the voice
    /// button: when not configured, non-owners see "ask the host", the owner sees the setup panel.
    pub async fn voice_config(&self) -> Result<VoiceConfig, CoreError> {
        let v = self.api.get("/api/voice/config").await?;
        Ok(VoiceConfig {
            configured: v.get("configured").and_then(|x| x.as_bool()).unwrap_or(false),
            url: v.get("url").and_then(|x| x.as_str()).map(str::to_string),
        })
    }

    /// Host-only: set the LiveKit URL + API key/secret so voice/video turns on for everyone on this
    /// skwod. The server enforces instance-owner; a non-owner call is rejected.
    pub async fn set_voice_config(&self, url: String, api_key: String, api_secret: String) -> Result<(), CoreError> {
        Ok(self.engine.lock().await.set_voice_config(&url, &api_key, &api_secret).await?)
    }

    /// Retention purge: delete every channel message of `server_id` older than `older_than_ms`
    /// milliseconds from the server (MANAGE_SERVER). Signed by this device (op
    /// `purge-messages`). Apps must use this rather than calling the route themselves: a
    /// build-45 server refuses the unsigned request.
    pub async fn purge_server_messages(&self, server_id: String, older_than_ms: i64) -> Result<(), CoreError> {
        Ok(self.engine.lock().await.purge_messages(&server_id, older_than_ms).await?)
    }

    /// The skwod's name as its owner set it on the host (`GET /api/instance/name`, signed in).
    /// `None` when no name is set — and from an older host, which has no such route (404).
    /// It is a LABEL the host supplies: apps check it (`SkwodNameRule`) and show the host key
    /// beside it.
    pub async fn instance_name(&self) -> Result<Option<String>, CoreError> {
        match self.api.get("/api/instance/name").await {
            Ok(v) => Ok(v.get("name").and_then(|x| x.as_str()).filter(|n| !n.is_empty()).map(str::to_string)),
            Err(skwod_sync::ClientError::Status { status: 404, .. }) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// The instance owner names the skwod on its host (build 46). Signed by this device (op
    /// `instance-name`, over `name` exactly as given); the host trims it and refuses control or
    /// invisible characters and more than 64 characters. An empty name clears it. Returns the
    /// name the host now keeps. Anyone else is refused (`Engine`, "http status 403"); a name the
    /// host will not keep is "http status 400".
    pub async fn set_instance_name(&self, name: String) -> Result<Option<String>, CoreError> {
        Ok(self.engine.lock().await.set_instance_name(&name).await?)
    }

    /// Delete a space on the server for good (its owner only). Signed by this device (op
    /// `delete-server`). Local trust state is untouched: `forget_space` is a separate choice.
    pub async fn delete_space(&self, server_id: String) -> Result<(), CoreError> {
        Ok(self.engine.lock().await.delete_space(&server_id).await?)
    }

    /// Voice/video E2EE keys for one call — feed each into the LiveKit key provider
    /// (`setKey(identity, key, key_index)`) in the returned order; our own key comes last.
    ///
    /// `call_salt` is the LiveKit room session id. Each device generates a RANDOM media key per
    /// call and sends it, over sealed libsignal sessions only, to the devices of
    /// `participant_user_ids` (the users currently in the room; pass an empty list to mean "every
    /// member of the server"). When someone who received our key is no longer in that list, a new
    /// key is generated at the next key index and sent only to those who remain — so call this
    /// again whenever a participant joins or leaves, and on a timer to pick up others' keys.
    ///
    /// An EMPTY result means E2EE could not be set up: the client MUST refuse to join (ADR-007).
    pub async fn voice_sync(
        &self,
        channel_id: String,
        my_user_id: String,
        call_salt: String,
        participant_user_ids: Vec<String>,
    ) -> Result<Vec<VoiceKey>, CoreError> {
        let participants = (!participant_user_ids.is_empty()).then_some(participant_user_ids.as_slice());
        let keys = self.engine.lock().await.voice_sync(&channel_id, &my_user_id, &call_salt, participants).await;
        self.store_inbound_dms().await;
        self.persist().await;
        Ok(keys?.into_iter().map(|(identity, key, key_index)| VoiceKey { identity, key, key_index }).collect())
    }

    /// Compatibility form of [`Self::voice_sync`] without participant tracking (keys go to every
    /// member of the server and are NOT rotated when someone leaves the call — prefer
    /// `voice_sync`). With `call_salt = None` it is only the pre-join check: a one-element list if
    /// this device can do voice E2EE for the channel, empty (⇒ refuse to join) if not.
    pub async fn voice_keys(
        &self,
        channel_id: String,
        my_user_id: String,
        call_salt: Option<String>,
    ) -> Result<Vec<VoiceKey>, CoreError> {
        match call_salt.filter(|s| !s.is_empty()) {
            Some(salt) => self.voice_sync(channel_id, my_user_id, salt, Vec::new()).await,
            None => {
                let ready = self.engine.lock().await.voice_ready(&channel_id).await;
                self.persist().await;
                Ok(if ready { vec![VoiceKey { identity: my_user_id, key: Vec::new(), key_index: 0 }] } else { Vec::new() })
            }
        }
    }

    /// A LiveKit room token (+ SFU URL) for a voice channel. Server-gated on CONNECT_VOICE; fails if
    /// voice isn't configured on the instance.
    pub async fn voice_token(&self, channel_id: String) -> Result<VoiceToken, CoreError> {
        let (token, room, mut url) = self.engine.lock().await.voice_token(&channel_id).await?;
        // p2p session + the host's own local SFU (plain ws://, not dialable from here): reach
        // LiveKit through the tunnel instead — signaling via the loopback proxy, media via the
        // loopback forwarder this call starts. An external SFU (wss://) is used as-is.
        if let Some(session) = p2p::session_for(self.api.base_url()) {
            if url.as_deref().is_some_and(|u| u.starts_with("ws://")) {
                let bearer = self.api.token().unwrap_or_default().to_string();
                url = Some(session.voice_url(bearer).await?);
            }
        }
        Ok(VoiceToken { token, room, url })
    }

    /// Resolve (or create) the server's voice channel, returning its id. The call view uses it for
    /// the room, the token, and the per-participant E2EE keys.
    pub async fn ensure_voice_channel(&self, server_id: String, name: String) -> Result<String, CoreError> {
        let id = self.engine.lock().await.ensure_voice_channel(&server_id, &name).await?;
        self.persist().await;
        Ok(id)
    }

    /// Clear ALL content in a server — every channel's messages plus its stories and feed posts —
    /// keeping the server, channels, members, and roles. Owner/manager only (the server enforces
    /// MANAGE_SERVER). Purges the local cache for each of the server's channels.
    pub async fn clear_server_messages(&self, server_id: String) -> Result<(), CoreError> {
        // Resolve the channel ids first, so their local caches can be purged after the server clears.
        let channels = self.engine.lock().await.list_channels(&server_id).await.unwrap_or_default();
        self.engine.lock().await.clear_server_content(&server_id).await?;
        let now = self.server_now();
        for ch in &channels {
            self.apply_channel_clear(&ch.channel_id, now);
        }
        self.persist().await;
        Ok(())
    }

    /// React to a message in `channel_id` with `emoji` (any short string: an emoji, or a marker
    /// such as "like"). The server never sees it: it gets `HMAC(space key, emoji)` — enough to
    /// count and de-duplicate equal reactions — plus the emoji sealed under the space key.
    pub async fn add_reaction(&self, channel_id: String, message_id: String, emoji: String) -> Result<(), CoreError> {
        Ok(self.engine.lock().await.add_reaction(&channel_id, &message_id, &emoji).await?)
    }

    /// Remove our `emoji` reaction from a message in `channel_id`.
    pub async fn remove_reaction(&self, channel_id: String, message_id: String, emoji: String) -> Result<(), CoreError> {
        Ok(self.engine.lock().await.remove_reaction(&channel_id, &message_id, &emoji).await?)
    }

    /// The reactions on a message in `channel_id`: who reacted, and with what. Group and count by
    /// `emoji` when present, else by `emoji_hash`.
    pub async fn list_reactions(&self, channel_id: String, message_id: String) -> Result<Vec<ReactionInfo>, CoreError> {
        let rows = self.engine.lock().await.list_reactions(&channel_id, &message_id).await?;
        Ok(rows.into_iter().map(|(user_id, emoji_hash, emoji)| ReactionInfo { user_id, emoji_hash, emoji }).collect())
    }

    /// Bring a channel up to date and return its history (own + others, chronological, the
    /// newest 500 — see `history_page` for older).
    ///
    /// Catch-up is by cursor, not "the last 100": the first sync walks backwards until it meets
    /// a message this device already has (or the beginning); every later one asks the server
    /// for everything that CHANGED since the last — new messages, edits and deletions — and
    /// keeps asking until it has it all. A device that was offline for a thousand messages gets
    /// a thousand messages. Cheap when nothing changed: one empty page.
    pub async fn fetch_channel_messages(&self, channel_id: String, my_user_id: String) -> Result<Vec<Message>, CoreError> {
        let scope = format!("channel:{channel_id}");
        let result = self.catch_up(&channel_id, &my_user_id).await;
        self.store_inbound_dms().await;
        self.persist().await;
        result?;
        Ok(self.history_scope(&scope))
    }

    /// Game state on this channel (whiteboard strokes, chess snapshots): everything cached under
    /// `aux:<channel>`, after bringing the channel up to date. Game traffic travels exactly
    /// like chat — the server cannot tell them apart — and is sorted out HERE, after
    /// decryption, into its own cache scope, so it never crowds chat out of the history the
    /// user sees.
    pub async fn fetch_aux_messages(&self, channel_id: String, my_user_id: String) -> Result<Vec<Message>, CoreError> {
        let result = self.catch_up(&channel_id, &my_user_id).await;
        self.store_inbound_dms().await;
        self.persist().await;
        result?;
        Ok(self.history_limit(&format!("aux:{channel_id}"), i64::MAX, 5_000))
    }

    /// "Load older": fetch channel history before the oldest message this device has — as many
    /// pages as it takes to bring at least a screenful of CHAT (pages full of game traffic do
    /// not count) — and return how many chat messages were added (`0` = the beginning of the
    /// channel). Then read them with `history_page`.
    pub async fn load_older_channel_messages(&self, channel_id: String, my_user_id: String) -> Result<u32, CoreError> {
        let scope = format!("channel:{channel_id}");
        let oldest = |s: &Self, sc: &str| s.history_limit(sc, i64::MAX, 100_000).first().map(|m| m.created_at).unwrap_or(i64::MAX);
        let mut before = oldest(self, &scope).min(oldest(self, &format!("aux:{channel_id}")));
        let mut added = 0u32;
        let result: Result<(), CoreError> = async {
            let mut engine = self.engine.lock().await;
            let _ = engine.sync_inbox().await;
            for _ in 0..MAX_OLDER_PAGES {
                let page = engine.channel_page(&channel_id, &my_user_id, skwod_sync::PageCursor::Before(before)).await?;
                added += self.store_page(&channel_id, &page);
                if page.rows < skwod_sync::PAGE || added >= OLDER_CHAT_TARGET {
                    break;
                }
                before = page.min_created_at;
            }
            Ok(())
        }
        .await;
        self.store_inbound_dms().await;
        self.persist().await;
        result?;
        Ok(added)
    }

    /// Up to `limit` cached messages of `scope` older than `before_ms` (chronological). With
    /// `before_ms = i64::MAX` it is the newest `limit`.
    pub async fn history_page(&self, scope: String, before_ms: i64, limit: u32) -> Vec<Message> {
        self.history_limit(&scope, before_ms, limit.clamp(1, 5_000) as usize)
    }

    /// Every reaction on the channel's messages as of its last sync — one call for the whole
    /// channel, from the local cache. (Reactions arrive with `fetch_channel_messages`.)
    pub async fn channel_reactions(&self, channel_id: String) -> Vec<MessageReaction> {
        let blocked = self.blocked.lock().unwrap_or_else(|e| e.into_inner()).clone();
        self.load_reactions(&channel_id)
            .into_values()
            .flatten()
            .filter(|r| !blocked.contains(&r.user_id))
            .map(|r| MessageReaction { message_id: r.message_id, user_id: r.user_id, emoji_hash: r.emoji_hash, emoji: r.emoji })
            .collect()
    }

    /// The locally-cached message history for a scope ("dm:<id>" / "channel:<id>"), chronological.
    /// Renders instantly at launch and offline, before any network fetch.
    pub async fn history(&self, scope: String) -> Vec<Message> {
        self.history_scope(&scope)
    }

    // ---- passphrase key backup (opt-in; server stores only ciphertext) ----
    //
    // Signal guards PIN recovery with an enclave (SVR) that rate-limits guesses. A self-hosted
    // server has no such thing and its operator is in the threat model, so whatever it stores can
    // be attacked OFFLINE. Backup is therefore opt-in and requires a generated recovery key
    // (`generate_recovery_key`) or a passphrase that passes `backup_passphrase_problem` — never a
    // short PIN. The passphrase is stretched with Argon2id (64 MiB, t=3); parameters travel with
    // the backup and weak ones are refused on restore.
    //
    // Two layers so routine re-uploads never re-run Argon2id: a random 32-byte BACKUP KEY seals
    // the payload (fresh nonce each upload); the passphrase wraps only the backup key.
    //
    // What is backed up: the libsignal identity key pair, registration id, pinned peer identities
    // (+ verified marks), space keys and the server pins. NOT sessions, sender keys or prekeys —
    // those are re-established after a restore, never resumed from a stale copy.

    /// Turn on key backup under `passphrase` and upload the first snapshot. Fails with `Invalid`
    /// if the passphrase is too weak to survive offline guessing.
    pub async fn enable_key_backup(&self, passphrase: String) -> Result<(), CoreError> {
        backup::check_passphrase(&passphrase).map_err(|e| CoreError::Invalid { detail: e.to_string() })?;
        // The config lives in the encrypted cache; without one it has nowhere to persist and
        // "enabled" would be a lie. Fail before doing any work.
        if self.cache.lock().unwrap_or_else(|e| e.into_inner()).is_none() {
            return Err(CoreError::Invalid { detail: "no cache attached — cannot persist backup config".into() });
        }
        let backup_key: [u8; 32] = skwod_crypto::random_bytes();
        let salt: [u8; 16] = skwod_crypto::random_bytes();
        let wrapped_key = backup::wrap_key(&backup_key, &passphrase, &salt, KdfParams::DEFAULT)
            .map_err(|e| CoreError::Invalid { detail: format!("key wrap failed: {e}") })?;
        // Upload FIRST, persist the config only on success. Enable is an explicit user action, so
        // it intentionally replaces any existing backup for the account.
        self.push_backup(&backup_key, &salt, &wrapped_key).await?;
        self.save_backup_config(&backup_key, &salt, &wrapped_key);
        if self.load_backup_config().is_none() {
            return Err(CoreError::Invalid { detail: "backup uploaded but config could not be persisted".into() });
        }
        // The apps say when this key becomes instant right after saving it
        // (`recovery_key_instant_from`). That time is the server's, read with the device list:
        // read it now, or the answer is the one from before this key existed (none — which the
        // apps word as "instant"). Best effort: the key is saved either way.
        let _ = self.engine.lock().await.refresh_own_devices().await;
        self.persist().await;
        Ok(())
    }

    /// Re-seal the current long-term state under the stored backup key and upload it. Returns
    /// false (no-op) when backup was never enabled on this device. Never clobbers a backup this
    /// device doesn't own (another device re-enabled backup under a different passphrase): the
    /// local config is cleared instead and false is returned.
    pub async fn update_key_backup(&self) -> Result<bool, CoreError> {
        let Some((backup_key, salt, wrapped_key)) = self.load_backup_config() else { return Ok(false) };
        if let Some(remote_wrapped) = self.remote_wrapped_key().await? {
            if remote_wrapped != wrapped_key {
                self.clear_backup_config();
                return Ok(false);
            }
        }
        self.push_backup(&backup_key, &salt, &wrapped_key).await?;
        Ok(true)
    }

    /// Turn key backup off: delete the server copy and forget the local backup key.
    pub async fn disable_key_backup(&self) -> Result<(), CoreError> {
        self.engine.lock().await.delete_backup().await?;
        self.clear_backup_config();
        Ok(())
    }

    /// Fetch this account's backup and, if `passphrase` unwraps it, restore the backed-up identity
    /// onto this device: same identity key and device id (so contacts' safety numbers do not
    /// change), all-new prekeys, sessions re-established on demand. Returns false when the server
    /// has no backup; a wrong passphrase is an `Invalid` error.
    ///
    /// Moving a device to this install needs more than the backup: another of the account's
    /// devices approving it, the registration PIN, or a 7-day wait the account's devices can
    /// cancel. Unless one applies already this throws `RecoveryPending` — the restored state is
    /// kept; complete it with `retry_restore`. When it completes, the install the device was on
    /// before stops (`DeviceSuperseded` there).
    pub async fn restore_key_backup(&self, passphrase: String) -> Result<bool, CoreError> {
        self.restore_key_backup_with_pin(passphrase, None).await
    }

    /// Complete a restore left waiting (`RecoveryPending`): after another device approved it,
    /// with the registration PIN, or once the wait is over.
    pub async fn retry_restore(&self, pin: Option<String>) -> Result<bool, CoreError> {
        // Still waiting to be handed the backup (not yet at the re-key step): ask again with
        // the recovery key given earlier in this run.
        if !self.engine.lock().await.rekey_pending() {
            let waiting = self.pending_restore.lock().unwrap_or_else(|e| e.into_inner()).clone();
            if let Some(passphrase) = waiting {
                return self.restore_key_backup_with_pin(passphrase, pin).await;
            }
            // After a relaunch the key given earlier is gone, but the request is still on
            // record for this install: ask how it stands (contested, still waiting, granted).
            let asked = {
                let mut engine = self.engine.lock().await;
                if engine.recovery_pending().is_some() { Some(engine.request_backup_access(pin.as_deref()).await) } else { None }
            };
            if let Some(asked) = asked {
                self.persist().await;
                asked?;
                // Granted — the backup is now handed to this install, opened by the key.
                return Err(CoreError::Invalid { detail: RESTORE_APPROVED_KEY_AGAIN.into() });
            }
        }
        let (result, key_needed) = {
            let mut engine = self.engine.lock().await;
            let result = engine.retry_recovery(pin.as_deref()).await;
            (result, engine.recovery_key_needed())
        };
        self.persist().await;
        result?;
        self.promote_pending_backup_config(key_needed);
        Ok(true)
    }

    /// `restore_key_backup` with the registration PIN (completes at once when the PIN is right).
    pub async fn restore_key_backup_with_pin(&self, passphrase: String, pin: Option<String>) -> Result<bool, CoreError> {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        if self.cache.lock().unwrap_or_else(|e| e.into_inner()).is_none() {
            return Err(CoreError::Invalid { detail: "no cache attached — restored keys could not be persisted".into() });
        }
        let too_new = |e: &skwod_sync::ClientError| matches!(e, skwod_sync::ClientError::Status { status: 409, body } if body.contains("recovery key was set less than 7 days ago"));
        let fetched = self.engine.lock().await.fetch_key_backup().await;
        let resp = match fetched {
            Ok(v) => v,
            Err(skwod_sync::ClientError::Status { status: 404, .. }) => return Ok(false),
            // Build-45 servers hand a backup under a recovery key younger than 7 days only to
            // one of the account's current devices — not to a fresh sign-in like this one. So
            // this install ASKS to restore it: the account's other devices are told and one of
            // them approves (or the registration PIN does, or 7 days pass un-cancelled). Until
            // then this is a restore that is waiting — `RecoveryPending`, `retry_restore`.
            Err(e) if too_new(&e) => {
                let asked = self.engine.lock().await.request_backup_access(pin.as_deref()).await;
                self.persist().await;
                match asked {
                    Ok(()) => {}
                    // The server cannot tell which device the backup restores (written before
                    // it kept track): nothing to approve; it restores once the key is 7 days old.
                    Err(EngineError::Client(e)) if too_new(&e) => return Err(CoreError::Invalid { detail: RECOVERY_KEY_TOO_NEW.into() }),
                    Err(e) => {
                        if matches!(e, EngineError::RecoveryPending(..)) {
                            *self.pending_restore.lock().unwrap_or_else(|e| e.into_inner()) = Some(passphrase.clone());
                        }
                        return Err(e.into());
                    }
                }
                // Granted: the backup is served to the install that asked.
                let granted = self.engine.lock().await.fetch_key_backup().await;
                match granted {
                    Ok(v) => v,
                    Err(e) if too_new(&e) => return Err(CoreError::Invalid { detail: RECOVERY_KEY_TOO_NEW.into() }),
                    Err(e) => return Err(e.into()),
                }
            }
            Err(e) => return Err(e.into()),
        };
        *self.pending_restore.lock().unwrap_or_else(|e| e.into_inner()) = None;
        let field = |v: &serde_json::Value, k: &str| -> Result<Vec<u8>, CoreError> {
            let s = v.get(k).and_then(|v| v.as_str()).ok_or(CoreError::Invalid { detail: format!("backup missing {k}") })?;
            B64.decode(s).map_err(|_| CoreError::Invalid { detail: format!("backup bad b64 in {k}") })
        };
        // The account's backup — and, for 7 days after the recovery key was changed or the
        // backup deleted, the backup(s) it replaced. The recovery key the user typed opens the
        // one that is theirs; one that somebody put in its place simply does not open.
        let mut candidates = vec![resp.clone()];
        candidates.extend(resp.get("alternates").and_then(|a| a.as_array()).cloned().unwrap_or_default().into_iter().take(8));
        let mut opened = None;
        let mut failure = CoreError::Invalid { detail: "wrong passphrase".into() };
        for candidate in &candidates {
            let attempt = (|| {
                if candidate.get("version").and_then(|v| v.as_i64()) != Some(BACKUP_VERSION) {
                    return Err(CoreError::Invalid {
                        detail: "this backup was made before the Signal-protocol upgrade and cannot be restored; set up backup again".into(),
                    });
                }
                let salt = field(candidate, "salt")?;
                // KDF parameters come from the (untrusted) server: `unwrap_key` refuses weak or absurd ones.
                let params: KdfParams = serde_json::from_value(candidate.get("kdf_params").cloned().unwrap_or_default())
                    .map_err(|_| CoreError::Invalid { detail: "backup KDF parameters malformed".into() })?;
                let blob: serde_json::Value =
                    serde_json::from_slice(&field(candidate, "encrypted_blob")?).map_err(|_| CoreError::Invalid { detail: "backup blob malformed".into() })?;
                let wrapped_key = field(&blob, "wrapped_key")?;
                let sealed = field(&blob, "state")?;
                let backup_key = backup::unwrap_key(&wrapped_key, &passphrase, &salt, params).map_err(|e| match e {
                    backup::BackupError::Auth => CoreError::Invalid { detail: "wrong passphrase".into() },
                    other => CoreError::Invalid { detail: other.to_string() },
                })?;
                let bytes = skwod_crypto::aead::open(&backup_key, BACKUP_AAD, &sealed).ok_or(CoreError::Invalid { detail: "backup decrypt failed".into() })?;
                Ok((backup_key, salt, wrapped_key, bytes))
            })();
            match attempt {
                Ok(found) => {
                    opened = Some(found);
                    break;
                }
                Err(e) => failure = e,
            }
        }
        let Some((backup_key, salt, wrapped_key, bytes)) = opened else { return Err(failure) };
        // Kept aside until the restore has actually completed (it may be left waiting).
        self.save_backup_config_as(BACKUP_CONFIG_PENDING_KEY, &backup_key, &salt, &wrapped_key);
        // The backup key proves the recovery key to the server: the restore completes at once.
        let (result, key_needed) = {
            let mut engine = self.engine.lock().await;
            let result = engine.restore_backup(&bytes, pin.as_deref(), Some(backup_key)).await;
            (result, engine.recovery_key_needed())
        };
        self.persist().await;
        result?;
        // Keep backing up from this device without re-asking for the passphrase — unless the
        // restore used the recovery key up (then a new one has to be saved).
        self.promote_pending_backup_config(key_needed);
        Ok(true)
    }

    /// Delete one of this account's registered devices server-side (own devices only). Used to
    /// clean up the interim device a re-login registered before a backup restore replaced it —
    /// otherwise each sign-out/restore cycle leaks a dead device row toward the per-account cap,
    /// and peers can be handed a device nobody can decrypt for.
    pub async fn unregister_device(&self, device_id: String) -> Result<(), CoreError> {
        // Signed with this device's identity key: the server refuses a deletion that only carries
        // the session token.
        let removed_other = {
            let mut engine = self.engine.lock().await;
            let other = engine.device_id() != Some(device_id.as_str());
            engine.delete_device(&device_id).await?;
            other
        };
        // Removing ANOTHER device retires the account's recovery key at once (that device may
        // have known it): this device stops backing up under it. A `recovery_key_needed`
        // notice follows — ask the user to save a new one.
        if removed_other {
            self.clear_backup_config();
        }
        self.persist().await;
        Ok(())
    }

    /// This account's registered device ids, oldest first. Lets recovery ask the user's OWN other
    /// devices (e.g. the phone that created a solo server) to provision this one — without this,
    /// a solo-server owner signing in on a second device has no provisioner at all.
    pub async fn list_own_devices(&self) -> Result<Vec<String>, CoreError> {
        let res = self.api.get("/api/e2ee/devices").await?;
        Ok(res
            .get("devices")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|d| d.get("device_id").and_then(|v| v.as_str()).map(str::to_string))
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Whether key backup was enabled (or restored) on this device.
    pub async fn key_backup_enabled(&self) -> bool {
        self.load_backup_config().is_some()
    }

    /// Whether the server already holds a backup for this account (any device). Lets setup UI warn
    /// that choosing a new passphrase REPLACES the account's existing backup.
    pub async fn has_remote_key_backup(&self) -> Result<bool, CoreError> {
        Ok(self.remote_wrapped_key().await?.is_some())
    }
}

/// AAD binding backup ciphertexts to their purpose (never reused for other AEAD calls).
const BACKUP_AAD: &[u8] = b"skwod-key-backup-v3";
/// Backup format version. 3 = libsignal identity; 1–2 were the pre-libsignal engine snapshot.
const BACKUP_VERSION: i64 = 3;
/// Encrypted-cache kv slot for the local backup config.
const BACKUP_CONFIG_KEY: &str = "key-backup-config";
/// The backup config of a restore that is still waiting to complete.
const BACKUP_CONFIG_PENDING_KEY: &str = "key-backup-config-pending";
/// When an unreadable cache was set aside (unix ms).
const CACHE_RESET_KEY: &str = "cache-reset-at";

/// Move an unreadable cache (and its SQLite side files) out of the way: `<path>.unreadable`.
/// One generation is kept; an older one is replaced.
fn set_aside(path: &str) {
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let (from, to) = (format!("{path}{suffix}"), format!("{path}.unreadable{suffix}"));
        let _ = std::fs::remove_file(&to);
        let _ = std::fs::rename(&from, &to);
    }
}

/// The engine's sent-message store, kept in the encrypted cache.
struct CacheSentStore(std::sync::Arc<Mutex<Option<Cache>>>);

impl skwod_sync::SentStore for CacheSentStore {
    fn put(&self, key: &str, value: &[u8], at_ms: i64) {
        if let Some(cache) = self.0.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            let _ = cache.sent_put(key, value, at_ms);
        }
    }
    fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).as_ref().and_then(|c| c.sent_get(key).ok().flatten())
    }
    fn prune(&self, before_ms: i64) {
        if let Some(cache) = self.0.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            let _ = cache.sent_prune(before_ms);
        }
    }
}

impl SkwodClient {
    /// Persist the local backup config (raw backup key + salt + passphrase-wrapped key) into the
    /// encrypted cache. The raw key never leaves the device; the cache is SQLCipher-encrypted.
    fn save_backup_config(&self, backup_key: &[u8; 32], salt: &[u8], wrapped_key: &[u8]) {
        self.save_backup_config_as(BACKUP_CONFIG_KEY, backup_key, salt, wrapped_key);
    }

    /// A restore completed: its backup config becomes this device's — unless the restore used
    /// up the recovery key (a replaced key's one overlap use): then there is nothing to keep
    /// backing up under, and the user is asked for a new key (`recovery_key_needed` notice).
    ///
    /// `key_needed` is read by the caller from the engine UNDER ITS LOCK (never a `try_lock`
    /// that would quietly skip the check when the engine is busy).
    fn promote_pending_backup_config(&self, key_needed: bool) {
        if key_needed {
            self.kv_put(BACKUP_CONFIG_PENDING_KEY, "");
            return;
        }
        if let Some(cfg) = self.kv(BACKUP_CONFIG_PENDING_KEY).filter(|c| !c.is_empty()) {
            self.kv_put(BACKUP_CONFIG_KEY, &cfg);
            self.kv_put(BACKUP_CONFIG_PENDING_KEY, "");
        }
    }

    /// A send that failed after its row was written (state and message are persisted BEFORE
    /// anything leaves): the message never went out, so its row goes again.
    async fn drop_unsent(&self) {
        if let Some((scope, id)) = self.engine.lock().await.take_unsent() {
            if let Some(cache) = self.cache.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
                let _ = cache.delete_message(&scope, &id);
            }
        }
    }

    /// Never register, link or reset with no cache attached: the device would exist on the
    /// server and be forgotten here at the next launch (a dead device row; the next launch
    /// then cannot register). The apps attach first, always.
    fn require_cache(&self) -> Result<(), CoreError> {
        if self.cache.lock().unwrap_or_else(|e| e.into_inner()).is_some() || self.ephemeral_ok.load(std::sync::atomic::Ordering::Relaxed) {
            Ok(())
        } else {
            Err(CoreError::Cache { detail: "no cache attached — refusing to create a device that could not be remembered".into() })
        }
    }

    /// Tests and tools: a client that deliberately keeps everything in memory.
    #[doc(hidden)]
    pub fn allow_without_cache(&self) {
        self.ephemeral_ok.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    fn save_backup_config_as(&self, slot: &str, backup_key: &[u8; 32], salt: &[u8], wrapped_key: &[u8]) {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        let cfg = serde_json::json!({
            "key": B64.encode(backup_key),
            "salt": B64.encode(salt),
            "wrapped_key": B64.encode(wrapped_key),
        });
        if let Some(cache) = self.cache.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            let _ = cache.kv_set(slot, &cfg.to_string());
        }
    }

    /// Seal the engine's LONG-TERM state under `backup_key` and PUT it to the account's backup
    /// slot. Fresh random nonce per upload.
    async fn push_backup(&self, backup_key: &[u8; 32], salt: &[u8], wrapped_key: &[u8]) -> Result<(), CoreError> {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        let mut engine = self.engine.lock().await;
        let sealed = skwod_crypto::aead::seal(backup_key, BACKUP_AAD, &engine.export_backup());
        let blob = serde_json::json!({
            "v": BACKUP_VERSION,
            "wrapped_key": B64.encode(wrapped_key),
            "state": B64.encode(&sealed),
        });
        // Signed by this device over the exact blob: the server refuses a backup write that only
        // carries the session token, or whose contents the signature does not cover.
        // With the verifier of the recovery proof key (derived from the backup key): a restore
        // that holds the recovery key can prove it and complete at once.
        let verifier = backup::recovery_verifier(backup_key);
        engine.put_backup(blob.to_string().as_bytes(), salt, BACKUP_VERSION, KdfParams::DEFAULT, verifier.as_deref()).await?;
        Ok(())
    }

    /// The `wrapped_key` of the account's current server-side backup, or None when there is none.
    /// This is the ownership marker: matching it proves this device's passphrase wraps that backup.
    async fn remote_wrapped_key(&self) -> Result<Option<Vec<u8>>, CoreError> {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        let resp = match self.api.get("/api/e2ee/key-backup").await {
            Ok(v) => v,
            Err(skwod_sync::ClientError::Status { status: 404, .. }) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let blob_b64 = resp.get("encrypted_blob").and_then(|v| v.as_str()).unwrap_or_default();
        let Ok(blob_bytes) = B64.decode(blob_b64) else { return Ok(None) };
        let Ok(blob) = serde_json::from_slice::<serde_json::Value>(&blob_bytes) else { return Ok(None) };
        Ok(blob.get("wrapped_key").and_then(|v| v.as_str()).and_then(|s| B64.decode(s).ok()))
    }

    /// Drop the local backup config (e.g. after detecting another device took over the account's
    /// backup slot) so `key_backup_enabled` truthfully reports off.
    fn clear_backup_config(&self) {
        if let Some(cache) = self.cache.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            let _ = cache.kv_set(BACKUP_CONFIG_KEY, "");
        }
    }

    /// Read back the local backup config, or None when backup isn't enabled on this device.
    fn load_backup_config(&self) -> Option<([u8; 32], Vec<u8>, Vec<u8>)> {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        let raw = self.cache.lock().unwrap_or_else(|e| e.into_inner()).as_ref()?.kv_get(BACKUP_CONFIG_KEY).ok()??;
        let cfg: serde_json::Value = serde_json::from_str(&raw).ok()?;
        let get = |k: &str| cfg.get(k).and_then(|v| v.as_str()).and_then(|s| B64.decode(s).ok());
        let key: [u8; 32] = get("key")?.try_into().ok()?;
        Some((key, get("salt")?, get("wrapped_key")?))
    }
}

/// Author-id sentinel marking a message this account sent (rendered as "you").
pub use skwod_sync::SELF_AUTHOR;

/// A persistent system row for `scope`: a security or membership event shown in the conversation
/// itself (author [`skwod_sync::SYSTEM_AUTHOR`], content [`skwod_sync::SYSTEM_TAG`] + JSON). Its id
/// is derived from the event, so writing it twice is a no-op.
fn system_row(scope: &str, kind: &str, user_id: &str, device_id: &str, by_user_id: Option<&str>, was_verified: bool, at_ms: i64) -> CachedMessage {
    let body = serde_json::json!({ "kind": kind, "user_id": user_id, "device_id": device_id, "by_user_id": by_user_id, "was_verified": was_verified });
    CachedMessage {
        message_id: format!("sys:{kind}:{user_id}:{device_id}:{at_ms}"),
        scope: scope.to_string(),
        author_id: Some(skwod_sync::SYSTEM_AUTHOR.to_string()),
        content: Some(format!("{}{body}", skwod_sync::SYSTEM_TAG)),
        reply_to_id: None,
        is_edited: false,
        is_pinned: false,
        deleted_at: None,
        created_at: at_ms,
        updated_at: at_ms,
        kind: KIND_SYSTEM,
    }
}

impl SkwodClient {
    /// Upsert a decrypted message into the cache (idempotent by id). No-op without an attached cache.
    fn store(&self, scope: &str, message_id: &str, author_id: &str, text: &str, created_at: i64) {
        self.store_meta(scope, message_id, author_id, Some(text), created_at, None, false, false);
    }

    /// Upsert with the full metadata a channel fetch carries (reply link, edited flag, tombstone).
    #[allow(clippy::too_many_arguments)]
    fn store_meta(&self, scope: &str, message_id: &str, author_id: &str, text: Option<&str>, created_at: i64,
                  reply_to_id: Option<&str>, is_edited: bool, deleted: bool) {
        if message_id.is_empty() {
            return;
        }
        let m = CachedMessage {
            message_id: message_id.to_string(),
            scope: scope.to_string(),
            author_id: Some(author_id.to_string()),
            content: if deleted { None } else { text.map(str::to_string) },
            reply_to_id: reply_to_id.map(str::to_string),
            is_edited,
            is_pinned: false,
            deleted_at: if deleted { Some(created_at) } else { None },
            created_at,
            updated_at: created_at,
            kind: skwod_sync::cache::KIND_PLAIN,
        };
        let me = self.self_user.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if let Some(cache) = self.cache.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            // Updates an existing row only when it is in this scope AND by this author.
            let _ = cache.upsert_message_as(&m, me.as_deref());
        }
    }

    fn has_readable(&self, chat: &str, aux: &str, message_id: &str) -> bool {
        let guard = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        let Some(cache) = guard.as_ref() else { return false };
        [chat, aux].iter().any(|scope| cache.message(scope, message_id).ok().flatten().is_some_and(|m| m.kind != KIND_UNDECRYPTABLE))
    }

    fn kv(&self, key: &str) -> Option<String> {
        self.cache.lock().unwrap_or_else(|e| e.into_inner()).as_ref().and_then(|c| c.kv_get(key).ok().flatten())
    }

    fn kv_put(&self, key: &str, value: &str) {
        if let Some(cache) = self.cache.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            let _ = cache.kv_set(key, value);
        }
    }

    fn load_reactions(&self, channel_id: &str) -> std::collections::BTreeMap<String, Vec<skwod_sync::Reaction>> {
        self.kv(&format!("{REACTIONS_PREFIX}{channel_id}")).and_then(|j| serde_json::from_str(&j).ok()).unwrap_or_default()
    }

    /// File one decrypted page. Each message goes where its CONTENT says — chat into
    /// `channel:<id>`, hidden machine state (game traffic) into `aux:<id>` — a sorting done
    /// here, after decryption, that the server never sees. A tombstone or edit lands in
    /// whichever scope already holds the message. Returns how many chat messages were filed.
    /// Reactions: the page carries the complete set per listed message, so it replaces theirs.
    fn store_page(&self, channel_id: &str, page: &skwod_sync::ChannelPage) -> u32 {
        let (chat, aux) = (format!("channel:{channel_id}"), format!("aux:{channel_id}"));
        // `page.cleared_at` is the SERVER saying the channel was cleared. It deletes nothing
        // here: a clear reaches this device as a sealed message from the server's owner (or
        // one of our own devices) and is applied in `persist` (`apply_channel_clear`).
        let mut filed = 0;
        for m in &page.messages {
            if m.deleted {
                // The SERVER says this message was deleted. That is not its author saying so:
                // a message this device already holds stays (its deletion arrives sealed from
                // the author — `apply_channel_delete`). For a message this device never had
                // there is nothing to protect, and it is shown as removed.
                let held = [&chat, &aux].iter().any(|scope| self.with_cache(|c| c.message(scope, &m.message_id).ok().flatten()).flatten().is_some());
                if !held {
                    self.store_meta(&chat, &m.message_id, &m.author_id, None, m.created_at, None, false, true);
                }
                continue;
            }
            // A placeholder never replaces a message this device can already read (a row
            // re-served after its author sent it again).
            if m.undecryptable {
                // The engine's stand-in for a row it could not decrypt — the one way a
                // placeholder row comes to be. It never replaces anything this device holds:
                // not a message it can read, and not the placeholder already there.
                if !self.has_readable(&chat, &aux, &m.message_id) {
                    self.with_cache(|c| {
                        c.insert_core_row(&CachedMessage {
                            message_id: m.message_id.clone(),
                            scope: chat.clone(),
                            author_id: Some(m.author_id.clone()),
                            content: Some(m.text.clone()),
                            reply_to_id: None,
                            is_edited: false,
                            is_pinned: false,
                            deleted_at: None,
                            created_at: m.created_at,
                            updated_at: m.created_at,
                            kind: KIND_UNDECRYPTABLE,
                        })
                    });
                }
                continue;
            }
            let hidden = skwod_sync::Traffic::of(&m.text).hidden;
            self.store_meta(if hidden { &aux } else { &chat }, &m.message_id, &m.author_id, Some(&m.text), m.created_at, m.reply_to_id.as_deref(), m.is_edited, false);
            filed += u32::from(!hidden);
        }
        if page.ids.is_empty() {
            return filed;
        }
        let mut all = self.load_reactions(channel_id);
        let before = all.clone();
        for id in &page.ids {
            all.remove(id);
        }
        for r in &page.reactions {
            all.entry(r.message_id.clone()).or_default().push(r.clone());
        }
        if all != before {
            if let Ok(json) = serde_json::to_string(&all) {
                self.kv_put(&format!("{REACTIONS_PREFIX}{channel_id}"), &json);
            }
        }
        filed
    }

    /// The cursor-driven sync behind `fetch_channel_messages` / `fetch_aux_messages`.
    async fn catch_up(&self, channel_id: &str, my_user_id: &str) -> Result<(), CoreError> {
        use skwod_sync::PageCursor;
        let scope = format!("channel:{channel_id}");
        let cursor_key = format!("{CURSOR_PREFIX}{scope}");
        let mut engine = self.engine.lock().await;
        // Sender keys that arrived since the last sync.
        let _ = engine.sync_inbox().await;
        // After a restore onto an install that already has a cache (the device was moved away
        // and back), the cursor is ahead of the gap: while this install was stopped it still
        // paged past rows it could not use. Walk back once, as on a first sync — the walk
        // stops at the first page that holds a message this cache already has.
        let restored_key = format!("sync-restored:{scope}");
        let restored = engine.restored_at().map(|at| at.to_string());
        let rewind = restored.is_some() && self.kv(&restored_key) != restored;
        match self.kv(&cursor_key).and_then(|c| c.parse::<i64>().ok()).filter(|_| !rewind) {
            Some(mut cursor) => {
                for _ in 0..MAX_CATCHUP_PAGES {
                    let page = engine.channel_page(channel_id, my_user_id, PageCursor::After(cursor)).await?;
                    self.store_page(channel_id, &page);
                    let full = page.rows >= skwod_sync::PAGE;
                    // A full page whose rows all share one timestamp cannot move the cursor by
                    // itself; step past it rather than fetch it forever.
                    let next = if full && page.max_updated_at <= cursor { cursor + 1 } else { page.max_updated_at.max(cursor) };
                    if next != cursor {
                        cursor = next;
                        self.kv_put(&cursor_key, &cursor.to_string());
                    }
                    if !full {
                        break;
                    }
                }
            }
            None => {
                // First sync on this device (or the first since upgrading): walk backwards from
                // now until a message we already hold or the start of the channel — and, since
                // the server cannot leave game traffic out for us, until the pages hold enough
                // CHAT to fill the window (or the page limit). Then decrypt oldest-first.
                let mut known: std::collections::HashSet<String> = self.history_limit(&scope, i64::MAX, 100_000).into_iter().map(|m| m.message_id).collect();
                known.extend(self.history_limit(&format!("aux:{channel_id}"), i64::MAX, 100_000).into_iter().map(|m| m.message_id));
                let mut pages = Vec::new();
                let mut before = i64::MAX;
                let mut newest = 0;
                let mut chat = 0u32;
                for _ in 0..MAX_CATCHUP_PAGES {
                    let page = engine.channel_page(channel_id, my_user_id, PageCursor::Before(before)).await?;
                    newest = newest.max(page.max_updated_at);
                    chat += page.messages.iter().filter(|m| !m.deleted && !skwod_sync::Traffic::of(&m.text).hidden).count() as u32;
                    let met_known = page.ids.iter().any(|id| known.contains(id));
                    let done = page.rows < skwod_sync::PAGE || met_known || chat >= FIRST_SYNC_CHAT_TARGET;
                    before = page.min_created_at;
                    pages.push(page);
                    if done {
                        break;
                    }
                }
                // NOTE: pages were decrypted newest-first (libsignal keeps the skipped message
                // keys); they are FILED oldest-first so an edit lands after its original.
                for page in pages.iter().rev() {
                    self.store_page(channel_id, page);
                }
                // Never backwards: a rewind re-reads the past, it does not forget how far
                // this cache had come.
                let newest = newest.max(self.kv(&cursor_key).and_then(|c| c.parse::<i64>().ok()).unwrap_or(0));
                self.kv_put(&cursor_key, &newest.to_string());
                if let Some(at) = &restored {
                    self.kv_put(&restored_key, at);
                }
            }
        }
        Ok(())
    }

    /// Read a scope's history from the cache, oldest-first.
    fn history_scope(&self, scope: &str) -> Vec<Message> {
        self.history_limit(scope, i64::MAX, 500)
    }

    fn history_limit(&self, scope: &str, before: i64, limit: usize) -> Vec<Message> {
        let Some(cache) = self.cache.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(|c| c.messages(scope, before, limit)) else {
            return Vec::new();
        };
        // Two things every reader of history gets for free:
        // - nothing written by someone this account blocked (chat, feed posts, stories,
        //   comments, game moves — they are all rows here); unblocking brings it back;
        // - this account's own messages are always authored `__me__`, also the ones another of
        //   its devices sent (the cache holds those under the real user id).
        let blocked = self.blocked.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let me = self.self_user.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let mut rows: Vec<Message> = cache
            .unwrap_or_default()
            .into_iter()
            .filter(|m| m.author_id.as_ref().is_none_or(|a| !blocked.contains(a)))
            .map(|mut m| {
                if m.author_id.is_some() && m.author_id == me {
                    m.author_id = Some(SELF_AUTHOR.to_string());
                }
                Message::from(m)
            })
            .collect();
        if scope.starts_with("dm:") {
            if let Some(cache) = self.cache.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
                for m in &mut rows {
                    m.sent_at = cache.sent_at(scope, &m.message_id);
                }
            }
        }
        rows.reverse(); // cache returns newest-first; render oldest-first
        rows
    }
}

/// A newly created E2EE space, ready to share with members.
#[derive(uniffi::Record)]
pub struct Space {
    pub server_id: String,
    pub channel_id: String,
    pub invite_code: String,
    pub space_key_hex: String,
}

/// The outcome of joining a space: joined outright, or awaiting host approval (`pending`). Carries
/// the host (owner) identity so the joining app can poll that DM for the auto-provision bundle.
#[derive(uniffi::Record)]
pub struct JoinResult {
    pub server_id: String,
    pub pending: bool,
    pub host_user_id: Option<String>,
    pub host_device_id: Option<String>,
}

/// A pending join request a host can approve or deny.
#[derive(uniffi::Record)]
pub struct JoinRequest {
    pub user_id: String,
    pub username: String,
}

/// What `restore_key_backup` says when the server will not hand the backup to a new sign-in
/// yet AND there is no request another device could approve (user-facing as is).
pub const RESTORE_APPROVED_KEY_AGAIN: &str = "This restore was approved. Enter your recovery key again to finish restoring.";
pub const RECOVERY_KEY_TOO_NEW: &str = "This account's recovery key was set less than 7 days ago, so its backup can't be restored on a new device yet. Try again once the key is 7 days old, or link this device from one that is still signed in.";

/// An existing invite a host can show or revoke (rotate = revoke + mint new).
#[derive(uniffi::Record)]
pub struct InviteInfo {
    pub code: String,
    pub max_uses: Option<i64>,
    pub use_count: i64,
    pub expires_at: Option<i64>,
    pub status: String,
    /// Accounts that signed up with this invite and still wait to be let in (0 when the
    /// server does not say — an older one).
    pub waiting: i64,
    /// No one else can sign up with this invite until some of those are approved.
    pub waiting_full: bool,
}

/// A server member for the members sidebar. `username` is the public login identity (not E2EE).
#[derive(uniffi::Record)]
pub struct MemberInfo {
    pub user_id: String,
    pub username: String,
}

/// Whether voice/video is set up on this instance, and the SFU URL clients connect to (if so).
#[derive(uniffi::Record)]
pub struct VoiceConfig {
    pub configured: bool,
    pub url: Option<String>,
}

/// One participant's voice/video E2EE key for a room: a raw 32-byte AES-256 key registered under
/// `identity` (the member's user id) at `key_index` in LiveKit's per-participant keyring.
#[derive(uniffi::Record)]
pub struct VoiceKey {
    pub identity: String,
    pub key: Vec<u8>,
    pub key_index: u32,
}

/// A LiveKit room-access token plus where to connect.
#[derive(uniffi::Record)]
pub struct VoiceToken {
    pub token: String,
    pub room: String,
    pub url: Option<String>,
}

/// A banned user in a server's ban list (username/reason may be absent).
#[derive(uniffi::Record)]
pub struct BanInfo {
    pub user_id: String,
    pub username: Option<String>,
    pub reason: Option<String>,
}

/// A user on my block list.
#[derive(uniffi::Record)]
pub struct BlockInfo {
    pub user_id: String,
    pub username: String,
}

/// One reaction on a message: who reacted, the tag the server groups it by (a keyed hash of the
/// emoji — opaque without the space key), and the decrypted emoji when this device could open it.
#[derive(uniffi::Record)]
pub struct ReactionInfo {
    pub user_id: String,
    pub emoji_hash: String,
    pub emoji: Option<String>,
}

/// A channel discovered in a joined server. `name` is null until the space key arrives (the host
/// provisions it on approval), at which point the channel name decrypts.
#[derive(uniffi::Record)]
pub struct ChannelInfo {
    pub channel_id: String,
    pub name: Option<String>,
    pub kind: String,
}

/// A user found by lookup, ready to DM.
#[derive(uniffi::Record)]
pub struct FoundUser {
    pub user_id: String,
    pub device_id: String,
}

/// A logged-in session returned to the app after signup/login.
#[derive(uniffi::Record)]
pub struct AuthSession {
    pub user_id: String,
    pub token: String,
    pub expires_at: i64,
}

/// Create an account on the self-hosted server at `base_url`. Login identity is the username; skwod
/// collects no email (it never sends mail). `join_code` is required by initialized instances (empty
/// string = none). The crypto identity is created on-device via [`SkwodClient::register_device`].
#[uniffi::export(async_runtime = "tokio")]
pub async fn signup(
    base_url: String,
    username: String,
    password: String,
    join_code: String,
) -> Result<AuthSession, CoreError> {
    let code = if join_code.trim().is_empty() { None } else { Some(join_code.trim()) };
    let s = ApiClient::new(base_url).signup_with_code(&username, &password, code).await?;
    Ok(AuthSession { user_id: s.user_id, token: s.token, expires_at: s.expires_at })
}

/// Log in to an existing account by username; returns a bearer session for [`SkwodClient::new`].
#[uniffi::export(async_runtime = "tokio")]
pub async fn login(base_url: String, username: String, password: String) -> Result<AuthSession, CoreError> {
    let s = ApiClient::new(base_url).login(&username, &password).await?;
    Ok(AuthSession { user_id: s.user_id, token: s.token, expires_at: s.expires_at })
}

/// A fresh download capability for one attachment (see `new_blob_download_token`).
#[derive(Debug, Clone, uniffi::Record)]
pub struct BlobDownloadToken {
    /// Goes INSIDE the encrypted attachment descriptor, and in the `x-skwod-blob-token` header
    /// when downloading. Never sent to the server at upload time.
    pub token: String,
    /// Goes in `download_token_hash` when creating the blob (`POST /api/blobs`).
    pub hash_hex: String,
}

/// Make the download token for an attachment that travels in a DIRECT MESSAGE. A sealed DM
/// leaves no row on the server that access could hang on, so the uploader registers the hash
/// of a random token with the blob and puts the token in the E2EE descriptor: whoever can read
/// the message can fetch the file, and the server never learns who that is.
#[uniffi::export]
pub fn new_blob_download_token() -> BlobDownloadToken {
    let token = hex::encode(skwod_crypto::random_bytes::<32>());
    let hash_hex = skwod_crypto::sha256_hex(token.as_bytes());
    BlobDownloadToken { token, hash_hex }
}

/// Should the user be notified of a message with this (decrypted) body from someone else?
/// `false` for game state, likes, comments, avatar/address updates and system rows. The one
/// place this is decided — after decryption, on the device: the server pushes a contentless
/// wake for every message alike and is never told which kind it carried.
#[uniffi::export]
pub fn message_notifies(text: String) -> bool {
    skwod_sync::Traffic::notifies(&text)
}

use skwod_sync::cache::{KIND_SYSTEM, KIND_UNDECRYPTABLE};

/// What a placeholder row says (see [`undecryptable_placeholder`]).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct UndecryptablePlaceholder {
    /// The user id of whoever wrote the message this device could not decrypt.
    pub from_user_id: String,
    /// `false`: their device has been asked to send it again — "Couldn't decrypt this message —
    /// asking X to resend". `true`: it cannot be sent again — "Couldn't decrypt this message".
    pub is_final: bool,
}

/// If `message` is the row the core shows in place of a message this device could not decrypt,
/// what it says; `None` for every other row. Decided by the ROW (`is_undecryptable`, set only
/// by the core when it wrote the row) — never by the text: a message whose body merely looks
/// like a placeholder is a message, and is shown as the plain text it is. The one parser for
/// both apps. The row is replaced in place (a channel) or removed (a DM) when the message is
/// sent again.
#[uniffi::export]
pub fn undecryptable_placeholder(message: Message) -> Option<UndecryptablePlaceholder> {
    if !message.is_undecryptable {
        return None;
    }
    let json = message.content.as_deref()?.strip_prefix(skwod_sync::UNDECRYPTABLE_TAG)?;
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    Some(UndecryptablePlaceholder { from_user_id: v["from"].as_str().unwrap_or_default().to_string(), is_final: v["final"].as_bool().unwrap_or(false) })
}

/// Is this (decrypted) body hidden machine state (game traffic) rather than conversation?
#[uniffi::export]
pub fn message_is_hidden(text: String) -> bool {
    skwod_sync::Traffic::of(&text).hidden
}

/// Swap a session token for a fresh one (same sign-in, same absolute lifetime). Apps call this
/// every week or so at launch — BEFORE building the `SkwodClient` — and store the result; the
/// old token keeps working for a few minutes and then stops. A push registration made under
/// the old token moves to the new one on the server.
#[uniffi::export(async_runtime = "tokio")]
pub async fn rotate_session(base_url: String, token: String) -> Result<AuthSession, CoreError> {
    let v = ApiClient::new(base_url).with_token(token).post("/api/auth/rotate", serde_json::json!({})).await?;
    match (v["user_id"].as_str(), v["token"].as_str(), v["expires_at"].as_i64()) {
        (Some(user_id), Some(token), Some(expires_at)) => Ok(AuthSession { user_id: user_id.to_string(), token: token.to_string(), expires_at }),
        _ => Err(CoreError::Invalid { detail: "unexpected server response".into() }),
    }
}

/// What the server says about an invite code before anyone signs up with it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct InviteCheck {
    pub valid: bool,
    /// When not valid: `"expired"`, `"used"` (revoked or used up) or `"unknown"`.
    pub reason: Option<String>,
    /// The host has to let the newcomer in.
    pub requires_approval: bool,
}

/// Ask the server at `base_url` whether `join_code` would still let someone in — with no
/// account. Call it when an invite link is opened, BEFORE the name/password screen, so an
/// expired link is reported up front. A server too old to answer counts as "valid" (the join
/// itself still decides); a server that cannot be reached is an error.
#[uniffi::export(async_runtime = "tokio")]
pub async fn check_invite(base_url: String, join_code: String) -> Result<InviteCheck, CoreError> {
    let code: String = join_code.trim().chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').collect();
    if code.is_empty() {
        return Ok(InviteCheck { valid: false, reason: Some("unknown".into()), requires_approval: false });
    }
    match ApiClient::new(base_url).get(&format!("/api/invites/{code}/check")).await {
        Ok(v) => Ok(InviteCheck {
            valid: v["valid"].as_bool().unwrap_or(false),
            reason: v["reason"].as_str().map(str::to_string),
            requires_approval: v["requires_approval"].as_bool().unwrap_or(false),
        }),
        Err(skwod_sync::ClientError::Status { status: 404 | 405, .. }) => Ok(InviteCheck { valid: true, reason: None, requires_approval: false }),
        Err(e) => Err(e.into()),
    }
}

// ---- server identity (pin-on-join, verify-on-reconnect for movable addresses) ----

/// A skwod server's stable, pinnable identity. `server_public` is its Ed25519 signing key (unique
/// per instance, survives address changes); `instance_id` is a short hash of it for quick matching.
#[derive(uniffi::Record)]
pub struct ServerIdentity {
    pub instance_id: String,
    pub server_public: String,
}

/// An instance id that is safe to use as a key, a file name or a path component: the server's
/// own value when it is 1–64 characters of `[A-Za-z0-9-]` (the rule the apps apply), otherwise a
/// fixed-length hash of it — stable, so the same server still maps to the same id, and unable
/// to carry a separator, a dot, a control character or megabytes of text. The id is a label for
/// matching; what identifies a server is `server_public`.
#[uniffi::export]
pub fn safe_instance_id(raw: &str) -> String {
    let ok = (1..=64).contains(&raw.len()) && raw.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    if ok {
        return raw.to_string();
    }
    let digest = skwod_crypto::aead::keyed_tag(&[0u8; 32], b"skwod/instance-id-v1", raw.as_bytes());
    format!("h-{}", hex::encode(&digest[..16]))
}

/// Fetch the identity of the server at `base_url` (unauthenticated) — used to PIN it on first join
/// and to MATCH a moved address to an existing skwod.
#[uniffi::export(async_runtime = "tokio")]
pub async fn fetch_server_identity(base_url: String) -> Result<ServerIdentity, CoreError> {
    let v = ApiClient::new(base_url).get("/api/instance/identity").await?;
    let instance_id = safe_instance_id(v["instance_id"].as_str().ok_or(CoreError::Invalid { detail: "unexpected server response".into() })?);
    let server_public = v["server_public"].as_str().ok_or(CoreError::Invalid { detail: "unexpected server response".into() })?.to_string();
    Ok(ServerIdentity { instance_id, server_public })
}

/// The origin a proof for `base_url` must be bound to: `skwod-p2p:<node id>` when `base_url` is
/// the loopback proxy of a live p2p session (the address the user actually dialed is the host's
/// key, not the proxy's port), otherwise the URL's own `scheme://host[:port]`.
///
/// A loopback URL that is NOT one of our p2p proxies is refused unless `allow_local`: anything
/// can listen on a loopback port, and a loopback origin proves nothing about a remote skwod. The
/// only legitimate case is the host app talking to the server it runs itself
/// ([`verify_local_server_identity`]).
fn proof_origin(base_url: &str, allow_local: bool) -> Option<String> {
    if let Some(session) = p2p::session_for(base_url) {
        return Some(skwod_crypto::instance::p2p_origin(&session.node_id()));
    }
    let origin = skwod_crypto::instance::normalize_origin(base_url)?;
    (allow_local || !skwod_crypto::instance::is_loopback_origin(&origin)).then_some(origin)
}

/// Check a `/api/instance/prove` response for `origin`: the presented key is the pinned one and
/// the signature covers `nonce` AND `origin` under it.
fn proof_holds(pinned: &[u8], nonce: &[u8], origin: &str, v: &serde_json::Value) -> bool {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    let field = |k: &str| v[k].as_str().and_then(|s| B64.decode(s).ok());
    let (Some(presented), Some(sig)) = (field("server_public"), field("signature")) else { return false };
    let Some(msg) = skwod_crypto::instance::proof_message_v2(nonce, origin) else { return false };
    presented == pinned && skwod_crypto::instance::verify(pinned, &msg, &sig)
}

/// SECURITY GATE for movable addresses: does the server at `base_url` actually HOLD the private key
/// matching `pinned_server_public_b64` — **and is `base_url` an address that server serves**?
///
/// Sends a fresh random nonce plus the origin we dialed; the server signs
/// `TAG ‖ nonce ‖ origin` and only for an origin of its own. The origin binding is what stops a
/// relay: an impostor can forward our challenge to the real server, but the real server refuses to
/// sign for the impostor's address, and a signature for its own address fails our check. Returns
/// true only on success, so an impostor is rejected before we trust the address or send any token.
///
/// A server that predates origin-bound proofs cannot pass this (returns false): fail closed.
#[uniffi::export(async_runtime = "tokio")]
pub async fn verify_server_identity(base_url: String, pinned_server_public_b64: String) -> Result<bool, CoreError> {
    prove_identity(base_url, pinned_server_public_b64, false).await
}

/// [`verify_server_identity`] for the ONE case where a plain loopback address is legitimate: the
/// host app checking the server it runs itself on this machine (the address it started that
/// server on — never one that came from a link, an invite or the network). The server signs a
/// loopback origin only for a direct, un-proxied loopback connection.
#[uniffi::export(async_runtime = "tokio")]
pub async fn verify_local_server_identity(base_url: String, pinned_server_public_b64: String) -> Result<bool, CoreError> {
    prove_identity(base_url, pinned_server_public_b64, true).await
}

async fn prove_identity(base_url: String, pinned_server_public_b64: String, allow_local: bool) -> Result<bool, CoreError> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;

    let pinned = B64.decode(pinned_server_public_b64.as_bytes()).map_err(|_| CoreError::Invalid { detail: "unexpected server response".into() })?;
    let Some(origin) = proof_origin(&base_url, allow_local) else { return Ok(false) };
    let nonce: [u8; 32] = skwod_crypto::random_bytes();

    let api = ApiClient::new(base_url);
    let v = match api.post("/api/instance/prove", serde_json::json!({ "nonce": B64.encode(nonce), "origin": origin })).await {
        Ok(v) => v,
        // "I do not serve that address": the answer to a relayed challenge.
        Err(skwod_sync::ClientError::Status { status: 403, .. }) => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    Ok(proof_holds(&pinned, &nonce, &origin, &v))
}

/// A verified address record: the instance says it is served at `address` as of `ts`.
#[derive(Debug, PartialEq, Eq, uniffi::Record)]
pub struct AddressRecord {
    /// A normalized `https://host[:port]` origin.
    pub address: String,
    /// Unix ms; persist it and pass it back as `last_ts` so an old record is never replayed.
    pub ts: i64,
}

/// Validate a raw address record against the pinned key: signed by it, strictly newer than
/// `last_ts`, not dated in the future, and naming a public `https://` origin.
fn check_address_record(pinned: &[u8], v: &serde_json::Value, last_ts: i64, now: i64) -> Option<AddressRecord> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    let address = v["address"].as_str()?;
    let ts = v["ts"].as_i64()?;
    let sig = B64.decode(v["signature"].as_str()?).ok()?;
    let canonical = skwod_crypto::instance::normalize_origin(address)?;
    if canonical != address || !address.starts_with("https://") || skwod_crypto::instance::is_loopback_origin(address) {
        return None;
    }
    if ts <= last_ts || ts > now + 10 * 60 * 1000 {
        return None;
    }
    skwod_crypto::instance::verify_address_record(pinned, address, ts, &sig).then(|| AddressRecord { address: address.to_string(), ts })
}

/// Ask the skwod we are connected to (at `base_url`) for its signed address record and return it
/// if it is valid under `pinned_server_public_b64` and newer than `last_ts`. This is the only
/// accepted source of a NEW address for a skwod we already belong to — a moved https server, or
/// the https fallback of a p2p host. A channel message, an invite parameter or an unsigned field
/// is never one. The caller must still run [`verify_server_identity`] against the new address
/// before using it, and should ask the user before switching transports.
#[uniffi::export(async_runtime = "tokio")]
pub async fn fetch_address_record(base_url: String, pinned_server_public_b64: String, last_ts: i64) -> Result<Option<AddressRecord>, CoreError> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    let pinned = B64.decode(pinned_server_public_b64.as_bytes()).map_err(|_| CoreError::Invalid { detail: "pinned key is not base64".into() })?;
    let v = match ApiClient::new(base_url).get("/api/instance/address-record").await {
        Ok(v) => v,
        Err(skwod_sync::ClientError::Status { status: 404, .. }) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    Ok(check_address_record(&pinned, &v, last_ts, now_ms()))
}

// ---- Decentralized address beacon (Nostr, over Tor) --------------------------------------------

/// A throwaway beacon identity for a skwod. `secret_hex` stays on the host; `pubkey_hex` goes into
/// every invite so members can look up the skwod's current address if their cached one goes dead.
#[derive(uniffi::Record)]
pub struct BeaconKeypair {
    pub secret_hex: String,
    pub pubkey_hex: String,
}

/// Host-side: mint a fresh beacon keypair (once per skwod). No account, no signup — just a keypair.
#[uniffi::export]
pub fn generate_beacon_key() -> BeaconKeypair {
    let k = skwod_sync::beacon::generate_beacon_key();
    BeaconKeypair { secret_hex: k.secret_hex, pubkey_hex: k.pubkey_hex }
}

fn beacon_relays(relays: Vec<String>) -> Vec<String> {
    if relays.is_empty() {
        skwod_sync::beacon::DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect()
    } else {
        relays
    }
}

/// Host-side: publish "my address is now `address`" to the relays over Tor (so the host's real IP is
/// never exposed). Content is AEAD-encrypted with `content_key_hex` (shared via the invite) so relays
/// store only ciphertext. Best-effort: returns true if at least one relay accepted the note. Pass an
/// empty `relays` to use the built-in default relay set.
#[uniffi::export(async_runtime = "tokio")]
pub async fn publish_beacon_address(
    beacon_secret_hex: String,
    content_key_hex: String,
    address: String,
    relays: Vec<String>,
) -> bool {
    skwod_sync::beacon::publish_address_private(
        &beacon_secret_hex,
        &content_key_hex,
        &address,
        &beacon_relays(relays),
    )
    .await
    .is_ok()
}

/// Debug probe for the beacon's Tor path: reports the last bootstrap error (if any) and a
/// connect/TLS probe of each default relay over Tor. For surfacing platform-specific failures
/// (Android dirs, censored networks) in app logs — not used by product flows.
#[uniffi::export(async_runtime = "tokio")]
pub async fn beacon_tor_diagnose(beacon_pubkey_hex: String, content_key_hex: String) -> String {
    let probe = skwod_sync::beacon::tor_probe(&beacon_relays(vec![])).await;
    let query =
        skwod_sync::beacon::tor_probe_query(&beacon_pubkey_hex, &content_key_hex, &beacon_relays(vec![])).await;
    format!("{probe} | query: {query}")
}

/// The result of a verified beacon resolve: the new address, its signed `created_at` (so the caller
/// can persist a freshness floor against rollback), all only returned AFTER proof-of-possession.
#[derive(uniffi::Record)]
pub struct BeaconResolution {
    pub address: String,
    pub created_at: u64,
}

/// Member-side: resolve a skwod's CURRENT address from its beacon AND prove the resolved server
/// holds the pinned key, in one call — so the anti-redirect proof-of-possession is enforced IN CODE
/// rather than left to the caller's discipline. Over Tor (relays never learn who is looking).
///
/// - Verifies the note's schnorr signature and decrypts with `content_key_hex`.
/// - Rejects notes with `created_at <= min_created_at` (relay rollback/suppression protection).
/// - Runs `verify_server_identity` against `pinned_server_public_b64` before returning the address.
///
/// Returns None if no fresh valid note existed OR the resolved address failed the fingerprint proof
/// (i.e. it's an impostor / re-registered hostname). A caller that gets `Some` can trust + connect.
#[uniffi::export(async_runtime = "tokio")]
pub async fn resolve_beacon_verified(
    beacon_pubkey_hex: String,
    content_key_hex: String,
    pinned_server_public_b64: String,
    min_created_at: u64,
    relays: Vec<String>,
) -> Option<BeaconResolution> {
    let (created_at, address) = skwod_sync::beacon::resolve_address_private(
        &beacon_pubkey_hex,
        &content_key_hex,
        &beacon_relays(relays),
        min_created_at,
    )
    .await?;
    // Fold the proof-of-possession in: never hand back a usable address until the resolved server
    // proves possession of the pinned key. A forged/suppressed note can't get past this.
    match verify_server_identity(address.clone(), pinned_server_public_b64).await {
        Ok(true) => Some(BeaconResolution { address, created_at }),
        _ => None,
    }
}

/// Wall-clock milliseconds since the Unix epoch, for locally-authored message timestamps.
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_default()
}

fn hex_to_32(s: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(s).ok()?;
    <[u8; 32]>::try_from(bytes.as_slice()).ok()
}

#[cfg(test)]
impl SkwodClient {
    /// Tests only: make every kv read and write on the attached cache fail.
    pub fn break_kv_for_test(&self) {
        if let Some(cache) = self.cache.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            cache.break_kv_for_test();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A server-chosen instance id is used as it is only when it is 1–64 characters of
    /// `[A-Za-z0-9-]`; anything else becomes a fixed-length hash that is itself such an id.
    #[test]
    fn a_server_chosen_instance_id_is_validated_or_hashed() {
        let valid = |id: &str| (1..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
        for ok in ["a", "AbC-123", "3f9c2d1e-0b7a-4c55-9e21-aa00bb11cc22", &"x".repeat(64)] {
            assert_eq!(safe_instance_id(ok), ok);
        }
        let long = "x".repeat(65);
        let huge = "a".repeat(1_000_000);
        for bad in ["", "../../etc/passwd", "a/b", "a.b", "a b", "a_b", "id\0", "id\n", "caf\u{e9}", "a%2fb", long.as_str(), huge.as_str()] {
            let safe = safe_instance_id(bad);
            assert_ne!(safe, bad);
            assert!(valid(&safe) && safe.len() == 34, "{bad:?} -> {safe:?}");
            assert_eq!(safe, safe_instance_id(bad), "stable: the same server maps to the same id");
        }
        assert_ne!(safe_instance_id("a/b"), safe_instance_id("a.b"));
    }

    /// A cache that is attached but cannot be read is `Err(Cache)` — not `NoCache`, and above
    /// all not "nothing stored". The instance-owner pin fails closed on it.
    #[tokio::test]
    async fn a_failed_read_is_an_error_not_nothing_stored() {
        let client = SkwodClient::new("http://127.0.0.1:9".into(), "t".into());
        let dir = tempfile::tempdir().unwrap();
        client.attach_cache(dir.path().join("c.sqlite3").to_string_lossy().to_string(), "ab".repeat(32)).await.unwrap();
        client.kv_write("k".into(), "v".into()).await.unwrap();
        client.kv_write("trust|instance_owner".into(), "u-owner".into()).await.unwrap();
        assert_eq!(client.instance_owner().await.as_deref(), Some("u-owner"));

        client.break_kv_for_test();
        assert!(client.cache_attached());
        assert!(matches!(client.kv_read("k".into()).await, Err(CoreError::Cache { .. })));
        assert!(matches!(client.kv_write("k".into(), "v2".into()).await, Err(CoreError::Cache { .. })));
        // The lenient read flattens it — which is why nothing that is later written back may use it.
        assert_eq!(client.kv_get("k".into()).await, None);
        // The pin cannot be read: no owner is reported, and nothing is attested or pinned anew.
        assert_eq!(client.instance_owner().await, None);
    }

    /// Without a cache the lenient read says "nothing" and the strict one says WHY; with a
    /// cache, "nothing stored" is `Ok(None)` — the three are never the same answer.
    #[tokio::test]
    async fn strict_kv_tells_no_cache_from_nothing_stored() {
        let client = SkwodClient::new("http://127.0.0.1:9".into(), "t".into());
        assert!(!client.cache_attached());
        assert_eq!(client.kv_get("k".into()).await, None);
        assert!(matches!(client.kv_read("k".into()).await, Err(CoreError::NoCache { .. })));
        assert!(matches!(client.kv_write("k".into(), "v".into()).await, Err(CoreError::NoCache { .. })));
        client.kv_set("k".into(), "v".into()).await; // lenient: no-op, no panic

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.sqlite3").to_string_lossy().to_string();
        client.attach_cache(path, "ab".repeat(32)).await.unwrap();
        assert!(client.cache_attached());
        assert_eq!(client.kv_read("k".into()).await.unwrap(), None);
        client.kv_write("k".into(), "v".into()).await.unwrap();
        assert_eq!(client.kv_read("k".into()).await.unwrap().as_deref(), Some("v"));
        assert_eq!(client.kv_get("k".into()).await.as_deref(), Some("v"));
    }

    #[test]
    fn cache_object_roundtrips_through_ffi_types() {
        let dir = std::env::temp_dir().join(format!("skwod-core-test-{}", std::process::id()));
        let _ = std::fs::remove_file(&dir);
        let key = "aa".repeat(32);
        let cache = SkwodCache::open(dir.to_string_lossy().to_string(), key).unwrap();
        cache.set_kv("k".into(), "v".into()).unwrap();
        assert_eq!(cache.get_kv("k".into()).unwrap().as_deref(), Some("v"));
        cache
            .upsert_message(Message {
                message_id: "m1".into(),
                scope: "channel:c".into(),
                author_id: Some("alice".into()),
                content: Some("hello".into()),
                created_at: 100,
                is_edited: false,
                is_pinned: false,
                reply_to_id: None,
                is_deleted: false,
                sent_at: None,
                is_system: false,
                is_undecryptable: false,
            })
            .unwrap();
        let msgs = cache.messages("channel:c".into(), i64::MAX, 10).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].content.as_deref(), Some("hello"));
        let _ = std::fs::remove_file(&dir);
    }

    #[test]
    fn safety_number_is_symmetric() {
        let a = hex::encode(skwod_crypto::SignalStore::generate().identity_key());
        let b = hex::encode(skwod_crypto::SignalStore::generate().identity_key());
        let ab = compute_safety_number("alice:d1".into(), a.clone(), "bob:d1".into(), b.clone()).unwrap();
        let ba = compute_safety_number("bob:d1".into(), b, "alice:d1".into(), a).unwrap();
        assert_eq!(ab, ba);
        assert_eq!(ab.len(), 60);
        assert!(compute_safety_number("a".into(), "zz".into(), "b".into(), "11".into()).is_err());
    }

    #[test]
    fn attachment_ffi_roundtrip() {
        let enc = encrypt_attachment(b"photo".to_vec()).unwrap();
        assert_eq!(enc.key.len(), 64);
        assert_eq!(decrypt_attachment(enc.ciphertext.clone(), enc.key.clone(), enc.digest.clone(), enc.plaintext_len).unwrap(), b"photo");
        assert!(decrypt_attachment(enc.ciphertext, enc.key, vec![0; 32], enc.plaintext_len).is_err());
        assert!(backup_passphrase_problem("123456".into()).is_some());
        assert!(backup_passphrase_problem(generate_recovery_key()).is_none());
        assert_eq!(e2ee_protocol_version(), 2);
    }

    /// H3 (client half): a proof is accepted only for the origin we dialed. A signature the real
    /// server made for ITS address (what a relaying impostor can obtain) fails for the impostor's,
    /// and the old nonce-only proof fails everywhere.
    #[test]
    fn relayed_instance_proof_is_rejected() {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine;
        let (secret, public) = skwod_crypto::instance::generate();
        let nonce = [7u8; 32];
        let respond = |msg: Vec<u8>| serde_json::json!({
            "server_public": B64.encode(public),
            "signature": B64.encode(skwod_crypto::instance::sign(&secret, &msg).unwrap()),
        });
        let real = respond(skwod_crypto::instance::proof_message_v2(&nonce, "https://real.example").unwrap());
        assert!(proof_holds(&public, &nonce, "https://real.example", &real));
        assert!(!proof_holds(&public, &nonce, "https://evil.example", &real), "relayed proof accepted for the impostor's address");
        let mut v1 = b"skwod-instance-proof-v1:".to_vec();
        v1.extend_from_slice(&nonce);
        let legacy = respond(v1.clone());
        // This is exactly what build 42 accepted, from ANY address: a valid nonce-only signature.
        let legacy_sig = B64.decode(legacy["signature"].as_str().unwrap()).unwrap();
        assert!(skwod_crypto::instance::verify(&public, &v1, &legacy_sig));
        assert!(!proof_holds(&public, &nonce, "https://evil.example", &legacy), "nonce-only proof accepted");
        assert!(!proof_holds(&public, &nonce, "https://real.example", &legacy));
        assert!(!proof_holds(&skwod_crypto::instance::generate().1, &nonce, "https://real.example", &real));
        // The origin of a plain URL is its scheme://host[:port]; nothing else leaks in.
        assert_eq!(proof_origin("https://Real.Example/api", false).as_deref(), Some("https://real.example"));
        assert_eq!(proof_origin("skwod://join/abc", false), None);
        // A loopback address that is not a live p2p proxy is never a provable origin — except
        // for the host app's own local server, which asks for it explicitly.
        for lo in ["http://127.0.0.1:3000", "http://localhost:3000/x", "http://[::1]:9"] {
            assert_eq!(proof_origin(lo, false), None, "{lo}");
            assert!(proof_origin(lo, true).is_some(), "{lo}");
        }
    }

    /// An address move is accepted only as an instance-signed record, newer than the last one.
    #[test]
    fn address_record_must_be_signed_fresh_and_https() {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine;
        let (secret, public) = skwod_crypto::instance::generate();
        let rec = |address: &str, ts: i64, key: &[u8]| serde_json::json!({
            "address": address, "ts": ts,
            "signature": B64.encode(skwod_crypto::instance::sign_address_record(key, address, ts).unwrap()),
        });
        let now = 1_000_000;
        let good = rec("https://new.example", 5000, &secret);
        assert_eq!(check_address_record(&public, &good, 0, now), Some(AddressRecord { address: "https://new.example".into(), ts: 5000 }));
        assert_eq!(check_address_record(&public, &good, 5000, now), None, "replayed (not newer)");
        assert_eq!(check_address_record(&public, &good, 9000, now), None, "rolled back");
        let other = skwod_crypto::instance::generate().0;
        assert_eq!(check_address_record(&public, &rec("https://new.example", 5000, &other), 0, now), None, "not the pinned key");
        let mut moved = good.clone();
        moved["address"] = "https://evil.example".into();
        assert_eq!(check_address_record(&public, &moved, 0, now), None, "address not covered by the signature");
        assert_eq!(check_address_record(&public, &rec("http://new.example", 5000, &secret), 0, now), None, "not https");
        assert_eq!(check_address_record(&public, &rec("https://new.example/path", 5000, &secret), 0, now), None, "not an origin");
        assert_eq!(check_address_record(&public, &rec("https://new.example", now + 3_600_000, &secret), 0, now), None, "future-dated");
    }

    /// A placeholder (and a system notice) is a fact about the ROW, recorded by the core when
    /// it wrote it. Text that merely looks like one — which any peer can send — is a message.
    #[test]
    fn a_row_is_a_placeholder_or_a_notice_only_if_the_core_wrote_it_as_one() {
        use skwod_sync::cache::{KIND_PLAIN, KIND_SYSTEM, KIND_UNDECRYPTABLE};
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::open(&dir.path().join("c.db"), &[7u8; 32]).unwrap();
        let row = |id: &str, author: &str, content: String, kind: u8| CachedMessage {
            message_id: id.into(),
            scope: "channel:c".into(),
            author_id: Some(author.into()),
            content: Some(content),
            reply_to_id: None,
            is_edited: false,
            is_pinned: false,
            deleted_at: None,
            created_at: 1,
            updated_at: 1,
            kind,
        };
        let get = |id: &str| Message::from(cache.message("channel:c", id).unwrap().unwrap());

        // The core's own rows.
        assert!(cache.insert_core_row(&row("p1", "bob", skwod_sync::undecryptable_body("bob", false), KIND_UNDECRYPTABLE)).unwrap());
        assert!(cache.insert_core_row(&system_row("channel:c", "member_joined", "bob", "", None, false, 5)).unwrap());
        let p1 = get("p1");
        assert!(p1.is_undecryptable && !p1.is_system);
        assert_eq!(undecryptable_placeholder(p1), Some(UndecryptablePlaceholder { from_user_id: "bob".into(), is_final: false }));
        let notice = Message::from(cache.messages("channel:c", i64::MAX, 10).unwrap().into_iter().find(|m| m.kind == KIND_SYSTEM).unwrap());
        assert!(notice.is_system && !notice.is_undecryptable);
        cache.set_core_content("channel:c", "p1", KIND_UNDECRYPTABLE, &skwod_sync::undecryptable_body("bob", true)).unwrap();
        assert_eq!(undecryptable_placeholder(get("p1")).map(|p| p.is_final), Some(true));

        // Mallory sends the same bytes as a MESSAGE — naming Bob, and a fake notice about Bob,
        // through every door a peer's text comes in by (a new row, an upsert, an edit).
        let forged = skwod_sync::undecryptable_body("bob", false);
        let fake_notice = format!("{}{}", skwod_sync::SYSTEM_TAG, r#"{"kind":"identity_changed","user_id":"bob"}"#);
        assert!(cache.insert_message_if_absent(&row("f1", "mallory", forged.clone(), KIND_UNDECRYPTABLE)).unwrap(), "stored — as a message");
        assert!(cache.upsert_message(&row("f2", "mallory", fake_notice.clone(), KIND_SYSTEM)).unwrap());
        assert!(cache.upsert_message(&row("f3", "mallory", "hi".into(), KIND_PLAIN)).unwrap());
        assert!(cache.revise_message("channel:c", "f3", "mallory", None, Some(&forged), 9).unwrap());
        for id in ["f1", "f2", "f3"] {
            let m = get(id);
            assert!(!m.is_undecryptable && !m.is_system, "{id} is a message");
            let text = m.content.clone().unwrap();
            assert!(!text.starts_with('\u{2}'), "{id}: the control character is gone: {text:?}");
            assert!(text.starts_with("skwod/"), "{id}: and what is left is shown as the plain text it is");
            assert!(message_notifies(text), "{id}: a message notifies like any other");
            assert_eq!(undecryptable_placeholder(m), None, "{id}");
        }
        // Even a row built by hand with the flag is only parsed if its text is the core's.
        assert_eq!(undecryptable_placeholder(Message { is_undecryptable: true, ..get("f3") }), None);
        // The reserved author cannot be written as a message at all.
        assert!(!cache.insert_message_if_absent(&row("f4", skwod_sync::SYSTEM_AUTHOR, fake_notice.clone(), KIND_PLAIN)).unwrap());
        assert!(!cache.upsert_message(&row("f5", skwod_sync::SYSTEM_AUTHOR, fake_notice, KIND_SYSTEM)).unwrap());
        assert!(cache.message("channel:c", "f4").unwrap().is_none() && cache.message("channel:c", "f5").unwrap().is_none());
        // A message can neither be turned into a core row nor a core row rewritten as a message
        // by the plain writers.
        cache.set_core_content("channel:c", "f3", KIND_UNDECRYPTABLE, &forged).unwrap();
        assert!(!get("f3").is_undecryptable);
        cache.set_content("channel:c", "p1", "rewritten").unwrap();
        assert!(get("p1").is_undecryptable && get("p1").content.unwrap().starts_with(skwod_sync::UNDECRYPTABLE_TAG));
        assert!(!cache.revise_message("channel:c", "p1", "bob", None, Some("rewritten"), 9).unwrap());

        // The author really sends it again: the placeholder becomes that message.
        assert!(cache.upsert_message(&row("p1", "bob", "what I actually said".into(), KIND_PLAIN)).unwrap());
        let p1 = get("p1");
        assert!(!p1.is_undecryptable);
        assert_eq!(p1.content.as_deref(), Some("what I actually said"));
    }

    /// A cache written by a build before rows had a kind: the system rows that build wrote are
    /// recognised once, at the upgrade; nothing else is.
    #[test]
    fn an_older_cache_gets_its_system_rows_marked_at_upgrade() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.db");
        let key = [3u8; 32];
        {
            let cache = Cache::open(&path, &key).unwrap();
            cache.insert_core_row(&system_row("dm:x", "new_device", "bob", "d", None, false, 5)).unwrap();
            cache.insert_message_if_absent(&CachedMessage {
                message_id: "m".into(),
                scope: "dm:x".into(),
                author_id: Some("bob".into()),
                content: Some("hello".into()),
                reply_to_id: None,
                is_edited: false,
                is_pinned: false,
                deleted_at: None,
                created_at: 1,
                updated_at: 1,
                kind: 0,
            })
            .unwrap();
            cache.downgrade_for_test();
        }
        let cache = Cache::open(&path, &key).unwrap();
        let rows: Vec<Message> = cache.messages("dm:x", i64::MAX, 10).unwrap().into_iter().map(Message::from).collect();
        assert_eq!(rows.iter().filter(|m| m.is_system).count(), 1);
        assert!(rows.iter().find(|m| m.message_id == "m").is_some_and(|m| !m.is_system && !m.is_undecryptable));
    }

    #[test]
    fn rejects_bad_key_length() {
        let err = SkwodCache::open("/tmp/x".into(), "abcd".into());
        assert!(matches!(err, Err(CoreError::Invalid { .. })));
    }
}
