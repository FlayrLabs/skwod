//! Accounts, devices and recovery (build 44a).
//!
//! What lives here, on top of the session manager in `engine.rs`:
//!
//! - **Which install this is.** A device has a *generation* on the server, bumped whenever it is
//!   re-keyed (a key-backup restore). This install holds a random *install secret*; the server
//!   holds its hash and binds a session to the device only for the install that presents the
//!   secret together with a signature by the device's identity key. An install the device was
//!   restored FROM shares the identity key but not the secret: it is refused (409) and stops
//!   ([`EngineError::Superseded`]) instead of living on as a clone.
//! - **Device management**: the account's device list with names (sealed under an *account key*
//!   only this account's devices hold), removing a device, renaming, the password change.
//! - **Linking**: what an approving device hands the new one with its approval (sibling set,
//!   account key, space keys, owner pins), sealed under the link code.
//! - **Retry and resend**: a sent-message store to resend from, per-device delivery retries for
//!   direct messages, placeholders for what could not be decrypted and the requests that get it
//!   sent again.
//! - **Backup**: the trust state a key backup carries beyond the identity.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Mutex;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use skwod_crypto::{aead, DeviceAddress};

use super::{enc, now_ms, trust, Content, Engine, EngineError, InboundMessage, SecurityNotice, MAX_SERVER_ARRAY, MAX_TEXT};
use crate::client::ClientError;

/// Tag of the accounts section in a persisted engine state / a backup.
pub(super) const SECTION_ACCOUNTS: u8 = 0xA1;
/// Backup section (build 45, audit M2): the CONTACTS' removed devices
/// (`AccountsState::contact_tombstones`). A section of its own so that `BackupExt` — postcard,
/// not self-describing — keeps its shape and every older backup stays readable.
pub(super) const SECTION_CONTACT_TOMBSTONES: u8 = 0xA2;

/// How long a sent message can be resent from, and an unanswered delivery is retried.
pub const SENT_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1000;
/// Ids one retry request may carry / one pass may answer.
const MAX_RETRY_IDS: usize = 200;
/// Outstanding "please resend" records kept.
const MAX_RETRY_ASKS: usize = 5_000;
/// A request that got no answer may be made again after this long.
const RETRY_REASK_MS: i64 = 10 * 60 * 1000;
/// Per-device DM deliveries still owed, at most.
const MAX_PENDING_DELIVERIES: usize = 2_000;
/// Deliveries retried per mailbox pass.
const DELIVERIES_PER_PASS: usize = 25;
/// Times a sibling is re-sent our sibling set before we stop waiting for its acknowledgement
/// (a build that predates acknowledgements never answers).
const SIBLING_SYNC_ATTEMPTS: u32 = 20;
pub(super) const SIBLING_SYNC_INTERVAL_MS: i64 = 2 * 60 * 1000;
/// One-time prekey private halves kept per kind.
pub(super) const ONE_TIME_PREKEYS_KEPT: usize = 300;
/// Tombstones of our OWN account (and erase claims) kept; at the cap the OLDEST goes.
const MAX_TOMBSTONES: usize = 1024;
/// Most device generations remembered (our siblings' and contacts' devices together).
const MAX_KNOWN_GENERATIONS: usize = 8192;
/// Removal tombstones kept PER CONTACT. An account has at most a handful of devices, so a
/// contact that fills this is misbehaving: its further entries are refused (never by evicting
/// what is there) and nothing of that contact's is re-admitted on its own word again.
const MAX_CONTACT_TOMBSTONES: usize = 64;
/// Contacts tombstones are kept for. Past this, a NEW contact's removals cannot be recorded —
/// and no contact without a record is re-admitted on its own word (`contact_tombstones_full`).
const MAX_TOMBSTONE_CONTACTS: usize = 8192;
/// Unconfirmed erase claims kept per claimant account.
const MAX_ERASE_CLAIMS_PER_USER: usize = 16;
/// One resend envelope carries at most this much text.
const RESEND_CHUNK_BYTES: usize = 64 * 1024;

/// Content prefix of the row shown in place of a message this device could not decrypt. A JSON
/// object follows: `{"from": <user id>, "final": <bool>}` — `final` once it is known that the
/// message cannot be sent again.
pub const UNDECRYPTABLE_TAG: &str = "\u{2}skwod/undecryptable|";

/// The placeholder body for a message from `from` that could not be decrypted.
pub fn undecryptable_body(from: &str, lost: bool) -> String {
    format!("{UNDECRYPTABLE_TAG}{}", serde_json::json!({ "from": from, "final": lost }))
}

/// Is `text` a placeholder for an undecryptable message?
pub fn is_undecryptable(text: &str) -> bool {
    text.starts_with(UNDECRYPTABLE_TAG)
}

// ---- persisted state ----

/// A direct message that reached some of the recipient's devices but not this one yet.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct PendingDelivery {
    pub message_id: String,
    pub device: DeviceAddress,
    pub attempts: u32,
    pub next_at_ms: i64,
    pub created_ms: i64,
}

/// "We asked `device` to send this again."
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct RetryAsk {
    pub device: DeviceAddress,
    pub at_ms: i64,
    /// Where the placeholder is (`dm:<id>` / `channel:<id>`), if one is shown.
    pub scope: Option<String>,
}

/// Something the application must do to a placeholder row. Drained with
/// [`Engine::take_retry_events`]; persisted until then.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RetryEvent {
    /// Show a placeholder ("couldn't decrypt this message: asking X to resend") in `scope`.
    Placeholder { scope: String, id: String, author_id: String, at_ms: i64 },
    /// The request was answered — the message itself arrives as an ordinary one (or it turned
    /// out not to be a message at all): take the placeholder away.
    Resolved { scope: String, id: String },
    /// The sender no longer has it. The placeholder stays, saying so.
    Lost { scope: String, id: String },
}

/// A channel message its author sent again, in the clear of a sealed session, because this
/// device could not decrypt the channel copy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResentMessage {
    pub channel_id: String,
    pub message_id: String,
    /// The (authenticated) sender of the resend — and, checked against the request we made,
    /// the author of the message.
    pub author_id: String,
    pub text: String,
    pub reply_to_id: Option<String>,
    pub is_edited: bool,
}

/// Engine state added in build 44a. Its own tagged section after the build-43 state, so other
/// additions can sit beside it and an older build skips it.
#[derive(Clone, Default, Serialize, Deserialize)]
pub(super) struct AccountsState {
    /// Known only to THIS install of the device (never backed up, never sent to a sibling).
    pub install_secret: Option<[u8; 32]>,
    /// The server said this install was superseded by a restore elsewhere. Terminal.
    pub superseded: bool,
    /// The server said this device is no longer on the account.
    pub removed: bool,
    /// Seals device names; shared among the account's verified devices only.
    pub account_key: Option<[u8; 32]>,
    /// What this device calls itself (the app supplies a default; the user may change it).
    pub device_name: Option<String>,
    pub name_uploaded: bool,
    pub pending_dm: Vec<PendingDelivery>,
    /// Siblings that have not acknowledged our sibling set: device id → (attempts, next try).
    pub sibling_sync: BTreeMap<String, (u32, i64)>,
    pub retry_asked: BTreeMap<String, RetryAsk>,
    pub retry_events: Vec<RetryEvent>,
    pub resent: Vec<ResentMessage>,
    /// A restore still owes everyone a session reset (it was offline when it finished).
    pub announce_pending: bool,
    /// When this install was restored from a backup (unix ms): everything in its channels from
    /// before then was sealed with keys it no longer has, and may be asked for again.
    pub restored_at: Option<i64>,
    /// Receiving side: when a sender key from a user first reached us for a scope
    /// (`"<scope>|<user>"`). A message from before that was never ours to read (we had not
    /// joined, or they had not let us in): it is skipped, not asked for.
    pub first_key_at: BTreeMap<String, i64>,
    /// Sending side: since when a device has held our key for a scope (`"<scope>|<device>"`).
    /// A resend never reaches further back than that: asking again must not hand a newcomer
    /// history from before it was let in.
    pub keyed_at: BTreeMap<String, i64>,
    /// The backup key of a restore in progress (what proves the recovery key to the server).
    /// Cleared when the restore completes.
    pub recovery_backup_key: Option<[u8; 32]>,
    /// The account's recovery key was used up or retired; a new one has to be saved.
    pub recovery_key_needed: bool,
    /// When THIS device last wrote the backup (so it does not flag its own change of key).
    pub recovery_key_set_at: Option<i64>,
    /// The generation each sibling device was last seen at (a rise = it was restored elsewhere).
    pub device_generations: BTreeMap<String, i64>,
    /// Identity keys of siblings that have left the account (see `refresh_siblings`).
    pub past_siblings: BTreeSet<Vec<u8>>,
    /// Identity keys of devices — our own or a contact's — that announced they were erasing
    /// THEMSELVES. Only these may come back by themselves under a new device row.
    pub erased_identities: BTreeSet<Vec<u8>>,
    /// Identity keys of devices REMOVED from our own account by one of its devices, oldest
    /// first. Permanent; shared with siblings and kept in the backup. Never re-admitted without
    /// a link approval.
    pub tombstones: Vec<Vec<u8>>,
    /// "I am erasing myself" CLAIMS not yet corroborated by the server's record:
    /// `(the claimant's account, its identity key)`. A claim does nothing by itself, and only
    /// the server's record of THAT account can corroborate it (see `confirm_erase_claims`).
    pub erase_claims: Vec<(String, Vec<u8>)>,
    /// Identity keys of CONTACTS' devices that a device of theirs told us they removed, per
    /// contact (user id → identities). Each contact's set is capped by itself and never
    /// evicted from: nothing one contact sends can push out another contact's removals.
    pub contact_tombstones: BTreeMap<String, BTreeSet<Vec<u8>>>,
    /// A removal could not be recorded because [`MAX_TOMBSTONE_CONTACTS`] was reached. From
    /// then on a contact with no tombstone record is never re-admitted on its own word.
    pub contact_tombstones_full: bool,
    /// A restore is waiting for the server to move the device to this install: when it can
    /// complete by itself (unix ms; 0 = not asked yet). Until then this install is not the
    /// device.
    pub recovery_pending: Option<i64>,
}

/// What a key backup carries beyond the build-43 `BackupState`: the trust state, so a restore
/// does not come back having forgotten who was verified and who owns what.
#[derive(Default, Serialize, Deserialize)]
pub(super) struct BackupExt {
    pub contacts: BTreeMap<String, trust::ContactTrust>,
    pub owner_sources: BTreeMap<String, trust::OwnerSource>,
    pub account_key: Option<[u8; 32]>,
    pub device_name: Option<String>,
    /// Devices removed from the account: they stay untrusted after a restore too.
    pub tombstones: Vec<Vec<u8>>,
}

/// Append one tagged section (`tag`, little-endian length, body).
pub(super) fn write_section(out: &mut Vec<u8>, tag: u8, body: &[u8]) {
    out.push(tag);
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(body);
}

/// The tagged sections in `bytes`, or `None` if they do not parse exactly (a truncated or
/// damaged tail is a damaged state, not a shorter one).
pub(super) fn read_sections(mut bytes: &[u8]) -> Option<Vec<(u8, &[u8])>> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let header = bytes.get(..5)?;
        let len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize;
        let body = bytes.get(5..5usize.checked_add(len)?)?;
        out.push((header[0], body));
        bytes = &bytes[5 + len..];
    }
    Some(out)
}

// ---- the sent-message store ----

/// Where the engine keeps what it sent, to send it again: a direct message some device could
/// not decrypt, a channel message a restored device asks for, a delivery that did not reach
/// every device. The application backs it with its encrypted cache; entries older than
/// [`SENT_RETENTION_MS`] are pruned.
pub trait SentStore: Send + Sync {
    fn put(&self, key: &str, value: &[u8], at_ms: i64);
    fn get(&self, key: &str) -> Option<Vec<u8>>;
    fn prune(&self, before_ms: i64);
}

/// In-memory [`SentStore`] (tools, tests, and an engine without a cache).
#[derive(Default)]
pub struct MemorySentStore(Mutex<HashMap<String, (Vec<u8>, i64)>>);

impl SentStore for MemorySentStore {
    fn put(&self, key: &str, value: &[u8], at_ms: i64) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).insert(key.to_string(), (value.to_vec(), at_ms));
    }
    fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).get(key).map(|(v, _)| v.clone())
    }
    fn prune(&self, before_ms: i64) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).retain(|_, (_, at)| *at >= before_ms);
    }
}

/// A direct message as the sent store keeps it.
#[derive(Serialize, Deserialize)]
struct SentDm {
    conversation_id: String,
    peer_user_id: String,
    text: String,
    sent_at: i64,
    /// The message it quotes, if it was a reply (sent again as one).
    reply_to: Option<String>,
}

/// A channel message as the sent store keeps it.
#[derive(Serialize, Deserialize)]
struct SentChannel {
    reply_to: Option<String>,
    edited: bool,
    text: String,
    at_ms: i64,
}

/// What one sealed envelope we deposited was.
#[derive(Serialize, Deserialize)]
enum SentEnvelope {
    /// Keys, resets, receipts: nothing a person would miss; it repairs itself.
    Control,
    /// A direct message (`message_id`) for `device`.
    Chat { message_id: String, device: DeviceAddress },
}

/// The id a sender and a receiver both derive for one sealed envelope: a hash of its bytes.
pub(super) fn envelope_id(envelope: &[u8]) -> String {
    hex::encode(&Sha256::digest(envelope)[..16])
}

/// A message the application must have on disk — together with the engine state that sealed
/// it — before it leaves.
#[derive(Clone, Debug)]
pub struct OutgoingRow {
    pub scope: String,
    pub message_id: String,
    pub text: String,
    pub created_at: i64,
    pub reply_to_id: Option<String>,
}

/// Called with the engine state right after something was encrypted and BEFORE it is sent,
/// together with the outgoing message when there is one. The application writes both in ONE
/// transaction and returns whether that succeeded; on `false` nothing is sent. A ratchet that
/// has advanced is therefore never ahead of what is on disk.
pub type StateSink = Box<dyn Fn(&[u8], Option<&OutgoingRow>) -> bool + Send + Sync>;

/// Where this install stands with the account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceState {
    /// No device registered from this install yet.
    Unregistered,
    Active,
    /// Removed from the account by another device.
    Removed,
    /// Restored from a backup on another install; this copy has stopped.
    Superseded,
    /// A restore onto this install is waiting for approval, the PIN, or the 7-day hold.
    RecoveryPending,
}

/// One device of this account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    pub device_id: String,
    /// Its name, when this device holds the account key it was sealed under.
    pub name: Option<String>,
    pub created_at: i64,
    pub last_active_at: i64,
    pub is_this_device: bool,
    /// Vouched for by this device's link chain (this device itself counts).
    pub verified: bool,
}

/// What the approving device hands a new device with its approval (see
/// `skwod_crypto::link::seal_bundle`).
#[derive(Default, Serialize, Deserialize)]
struct LinkBundle {
    siblings: Vec<(String, Vec<u8>)>,
    account_key: Option<[u8; 32]>,
    spaces: Vec<(String, [u8; 32])>,
    owner_pins: Vec<(String, String)>,
}

fn backoff_ms(attempts: u32) -> i64 {
    (30_000i64 << attempts.min(10)).min(6 * 60 * 60 * 1000)
}

impl Engine {
    // ---- where this install stands ----

    pub fn device_state(&self) -> DeviceState {
        if self.acct.superseded {
            DeviceState::Superseded
        } else if self.acct.removed {
            DeviceState::Removed
        } else if self.acct.recovery_pending.is_some() || self.b45.backup_request_pending.is_some() {
            DeviceState::RecoveryPending
        } else if self.device_id.is_some() && self.user_id.is_some() {
            DeviceState::Active
        } else {
            DeviceState::Unregistered
        }
    }

    /// The account's key backup, as THIS install may fetch it. A backup under a recovery key
    /// younger than the hold is handed only to a current device — or to the install whose
    /// request to restore it was granted ([`Engine::request_backup_access`]), which shows it
    /// is that install by presenting its secret. (`409` otherwise; `404` when there is none.)
    pub async fn fetch_key_backup(&mut self) -> Result<serde_json::Value, ClientError> {
        let secret = B64.encode(self.install_secret());
        self.api.get_with_header("/api/e2ee/key-backup", "x-skwod-install-secret", &secret).await
    }

    /// Ask to restore the account's backup on this install while the server withholds it (the
    /// recovery key is younger than the hold). This is the restore-by-approval request: every
    /// device of the account is told and shown [`Engine::recovery_fingerprint`]; any of them
    /// approves or refuses it; the seasoned registration PIN grants it; un-cancelled it
    /// completes after the hold. `Ok` = granted (fetch the backup now). `RecoveryPending` =
    /// waiting, and this install says so ([`Engine::device_state`]) until it is granted.
    pub async fn request_backup_access(&mut self, pin: Option<&str>) -> Result<(), EngineError> {
        if self.passive {
            return Err(EngineError::Protocol("the notification extension restores nothing"));
        }
        let mut body = serde_json::json!({ "install_hash": B64.encode(self.install_hash()) });
        if let Some(pin) = pin {
            body["pin"] = serde_json::json!(pin);
        }
        match self.api.post("/api/e2ee/key-backup/request", body).await {
            Ok(_) => {
                self.b45.backup_request_pending = None;
                Ok(())
            }
            Err(e) => {
                let e = EngineError::from(e);
                self.b45.backup_request_pending = match &e {
                    EngineError::RecoveryPending(at, contested) => {
                        self.recovery_contested = Some(*contested);
                        Some(*at)
                    }
                    _ => self.b45.backup_request_pending,
                };
                Err(e)
            }
        }
    }

    /// Note a server answer that ends this install's life as its device, and pass the error on.
    pub(super) fn fatal(&mut self, e: EngineError) -> EngineError {
        match e {
            EngineError::Superseded => self.acct.superseded = true,
            EngineError::DeviceRemoved => self.acct.removed = true,
            _ => {}
        }
        e
    }

    pub(super) fn install_secret(&mut self) -> [u8; 32] {
        *self.acct.install_secret.get_or_insert_with(skwod_crypto::random_bytes)
    }

    pub(super) fn install_hash(&mut self) -> Vec<u8> {
        Sha256::digest(self.install_secret()).to_vec()
    }

    /// Make this session speak for this device ("signed back in": the same device, no re-link).
    /// The server binds it only for a signature by this device's identity key over the session
    /// AND this install's secret. Once per engine; a network failure is retried on the next
    /// call, a refusal is final ([`EngineError::Superseded`] / [`EngineError::DeviceRemoved`]).
    pub async fn ensure_bound(&mut self) -> Result<(), EngineError> {
        if self.bound {
            return Ok(());
        }
        let local = self.local()?;
        let Some(token) = self.api.token().map(str::to_string) else { return Ok(()) };
        if self.passive && self.acct.install_secret.is_none() {
            // The notification extension makes no secrets; the app binds first.
            return Err(EngineError::Protocol("this install has not been bound by the app yet"));
        }
        let secret = self.install_secret();
        let payload = skwod_crypto::link::op_payload(&[&Sha256::digest(token.as_bytes()), &Sha256::digest(secret)]);
        let proof = self.device_proof("bind-session", &local.device_id, &payload)?;
        let body = serde_json::json!({ "install_secret": B64.encode(secret) });
        match self.api.signed(reqwest::Method::POST, &format!("/api/e2ee/devices/{}/bind", enc(&local.device_id)), Some(body), &proof).await {
            Ok(_) => {
                self.bound = true;
                self.upload_name_if_needed().await;
                Ok(())
            }
            // A server from before device-bound sessions has no such route: nothing to bind.
            Err(ClientError::Status { status: 404 | 405, .. }) => {
                self.bound = true;
                Ok(())
            }
            Err(e) => Err(self.fatal(e.into())),
        }
    }

    /// [`Engine::ensure_bound`] for an app's start-up: `Ok(false)` when this install is not a
    /// device of the account (not registered yet, or a restore still waiting to become one).
    pub async fn bind_if_registered(&mut self) -> Result<bool, EngineError> {
        if self.device_id.is_none() || self.acct.recovery_pending.is_some() {
            return Ok(false);
        }
        self.ensure_bound().await.map(|_| true)
    }

    /// Forget this install's registration but keep what belongs to the person rather than to
    /// the device: history keys (space keys), owner pins, contacts and their verified marks.
    /// For a device that was removed or superseded and is about to be linked again as a NEW
    /// device — with a new identity key, since the old one is another install's now.
    pub fn forget_registration(&mut self) {
        let keep = (
            self.user_id.clone(),
            self.spaces.clone(),
            self.expected_provisioner.clone(),
            self.owner_sources.clone(),
            self.pinned_instance_key.clone(),
            self.trust_root.clone(),
            self.contacts.clone(),
            self.blocked.clone(),
            self.acct.device_name.clone(),
        );
        self.reset();
        (self.user_id, self.spaces, self.expected_provisioner, self.owner_sources, self.pinned_instance_key, self.trust_root, self.contacts, self.blocked, self.acct.device_name) =
            keep;
    }

    // ---- device names ----

    const NAME_AAD: &'static [u8] = b"skwod/device-name";

    fn seal_device_name(&self) -> Option<String> {
        let (key, name) = (self.acct.account_key.as_ref()?, self.acct.device_name.as_ref()?);
        Some(B64.encode(aead::seal(key, Self::NAME_AAD, name.as_bytes())))
    }

    /// The name to register with (sealing it needs an account key: the first device of an
    /// account makes one; a linked device got it with the approval).
    pub(super) fn name_for_registration(&mut self, first_device: bool) -> Option<String> {
        if first_device && self.acct.account_key.is_none() {
            self.acct.account_key = Some(skwod_crypto::random_bytes());
        }
        let sealed = self.seal_device_name();
        self.acct.name_uploaded = sealed.is_some();
        sealed
    }

    /// What this device calls itself. Local until [`Engine::ensure_bound`] / registration
    /// uploads it (sealed); call before registering so the name goes up with the device.
    pub fn set_device_label(&mut self, name: &str) {
        let name: String = name.chars().filter(|c| !c.is_control()).take(64).collect();
        let name = name.trim().to_string();
        if !name.is_empty() && self.acct.device_name.as_deref() != Some(name.as_str()) {
            self.acct.device_name = Some(name);
            self.acct.name_uploaded = false;
        }
    }

    pub(super) async fn upload_name_if_needed(&mut self) {
        if self.acct.name_uploaded || self.acct.device_name.is_none() {
            return;
        }
        let Ok(local) = self.local() else { return };
        if self.passive {
            return; // may have to make the account key: the app's job
        }
        if self.acct.account_key.is_none() {
            // An account from before names existed. A lone device makes the key; one with
            // siblings waits for whichever of them shares it (`AccountSync`), so two devices
            // do not each invent one.
            if !self.siblings.is_empty() {
                return;
            }
            self.acct.account_key = Some(skwod_crypto::random_bytes());
        }
        let Some(sealed) = self.seal_device_name() else { return };
        let body = serde_json::json!({ "device_name_ciphertext": sealed });
        if self.api.put(&format!("/api/e2ee/devices/{}/name", enc(&local.device_id)), body).await.is_ok() {
            self.acct.name_uploaded = true;
        }
    }

    /// Rename this device (shown to the account's other devices only).
    pub async fn rename_device(&mut self, name: &str) -> Result<(), EngineError> {
        self.ensure_bound().await?;
        self.set_device_label(name);
        self.acct.name_uploaded = false;
        self.upload_name_if_needed().await;
        if self.acct.name_uploaded {
            Ok(())
        } else {
            Err(EngineError::Protocol("the device name could not be saved; try again"))
        }
    }

    /// This account's devices and the most it may have. Names are opened with the account key;
    /// `verified` is this device's own judgement (link signatures), not the server's listing.
    pub async fn list_devices(&mut self) -> Result<(Vec<DeviceInfo>, u32), EngineError> {
        let _ = self.ensure_bound().await;
        let _ = self.refresh_siblings(true).await;
        let v = self.api.get("/api/e2ee/devices").await?;
        let key = self.acct.account_key;
        let devices = v["devices"]
            .as_array()
            .into_iter()
            .flatten()
            .take(MAX_SERVER_ARRAY)
            .filter_map(|d| {
                let device_id = d["device_id"].as_str()?.to_string();
                let name = key.as_ref().and_then(|k| {
                    let sealed = B64.decode(d["device_name_ciphertext"].as_str()?).ok()?;
                    String::from_utf8(aead::open(k, Self::NAME_AAD, &sealed)?).ok()
                });
                let is_this_device = self.device_id.as_deref() == Some(device_id.as_str());
                Some(DeviceInfo {
                    verified: is_this_device || self.siblings.contains_key(&device_id),
                    is_this_device,
                    name,
                    created_at: d["created_at"].as_i64().unwrap_or_default(),
                    last_active_at: d["last_active_at"].as_i64().unwrap_or_default(),
                    device_id,
                })
            })
            .collect();
        Ok((devices, v["max_devices"].as_u64().unwrap_or(5) as u32))
    }

    /// Change the account password. The server wants the old password AND this device's
    /// signature over the new one, and ends every other session of the account.
    pub async fn change_password(&mut self, old_password: &str, new_password: &str) -> Result<(), EngineError> {
        self.ensure_bound().await?;
        let proof = self.device_proof("password", "", new_password.as_bytes())?;
        let body = serde_json::json!({ "old_password": old_password, "new_password": new_password });
        self.api.signed(reqwest::Method::POST, "/api/auth/password", Some(body), &proof).await?;
        Ok(())
    }

    /// Delete an account on this skwod for good: our own ("delete all my data"), or — for the
    /// instance owner — anyone else's. Once the calling account has a device the server takes
    /// this only with a proof signed by that device, on a session bound to it: a session token
    /// alone (stolen, or from a password-only sign-in) cannot destroy an account.
    pub async fn delete_account(&mut self, user_id: &str) -> Result<(), EngineError> {
        self.ensure_bound().await?;
        let proof = self.device_proof("delete-account", user_id, &[])?;
        self.api.signed(reqwest::Method::DELETE, &format!("/api/auth/users/{}", enc(user_id)), None, &proof).await?;
        Ok(())
    }

    /// The instance owner deletes someone else's account AND bans it (server audit H-2): the
    /// username and the identity keys of its devices cannot sign up or register here again, and
    /// the invite it signed up with is revoked. Signed like [`Engine::delete_account`].
    pub async fn delete_account_and_ban(&mut self, user_id: &str) -> Result<(), EngineError> {
        self.ensure_bound().await?;
        let proof = self.device_proof("delete-account", user_id, &[])?;
        self.api.signed(reqwest::Method::DELETE, &format!("/api/auth/users/{}?ban=1", enc(user_id)), None, &proof).await?;
        Ok(())
    }

    /// `peer` was restored onto ANOTHER install (its generation in the directory went up: the
    /// server's `device_rekeyed`). The device and its identity key are the same, so nothing
    /// about trust changes — but the install it left still holds every key we handed that
    /// device, and an honest server now refuses it everything. What it holds of ours rotates:
    /// our delivery key, and the sender key of every scope it was a holder of (the next send
    /// there distributes a new one). Sessions are left to the restore's own session reset.
    pub(super) fn install_replaced(&mut self, peer: &DeviceAddress) {
        self.delivery_key_exposed();
        for (scope, key) in &self.send_keys {
            if key.holders.contains(peer) {
                self.stale_scopes.insert(scope.clone());
            }
        }
        for call in &mut self.voice {
            call.sent_to.remove(peer);
        }
    }

    /// Note the generation the directory lists for a CONTACT's device; `true` when it rose
    /// since this device last looked. Kept beside our own siblings' (`device_generations`),
    /// under `"<user>|<device>"`; bounded, and a full map only stops learning NEW devices.
    pub(super) fn note_peer_generation(&mut self, user: &str, device: &str, generation: i64) -> bool {
        let key = format!("{user}|{device}");
        if !self.acct.device_generations.contains_key(&key) && self.acct.device_generations.len() >= MAX_KNOWN_GENERATIONS {
            return false;
        }
        self.acct.device_generations.insert(key, generation).is_some_and(|known| generation > known)
    }

    /// A device of `peer`'s account (or our own) is gone from the directory: drop what it gave
    /// us, mark what it holds of ours for rotation, and stop owing it anything.
    pub(super) fn device_gone(&mut self, peer: &DeviceAddress) {
        // A removed device keeps the delivery key it was handed; it must stop working.
        self.delivery_key_exposed();
        let dropped: Vec<String> = self.recv_keys.iter().filter(|(_, r)| &r.sender == peer).map(|(id, _)| id.clone()).collect();
        for id in dropped {
            self.recv_keys.remove(&id);
            self.recv_order.retain(|o| o != &id);
            if let Ok(uuid) = id.parse::<skwod_crypto::Uuid>() {
                self.store.delete_sender_key(peer, uuid);
            }
        }
        for (scope, key) in &self.send_keys {
            if key.holders.contains(peer) {
                self.stale_scopes.insert(scope.clone());
            }
        }
        for call in &mut self.voice {
            call.sent_to.remove(peer);
        }
        let _ = self.store.archive_session(peer);
        if let Ok(name) = peer.name() {
            self.peer_delivery.remove(&name);
        }
        self.acct.pending_dm.retain(|p| &p.device != peer);
        self.acct.sibling_sync.remove(&peer.device_id);
        self.acct.device_generations.remove(&format!("{}|{}", peer.user_id, peer.device_id));
        if let Ok(name) = peer.name() {
            let suffix = format!("|{name}");
            self.acct.keyed_at.retain(|k, _| !k.ends_with(&suffix));
        }
        for roster in self.rosters.values_mut() {
            for cleared in roster.cleared.values_mut() {
                cleared.remove(peer);
            }
        }
    }

    /// Re-read `user_id`'s devices now (the server's `device_removed` / `device_added` event).
    /// The event is only a nudge: what counts is the directory and the link chain.
    pub async fn refresh_devices_of(&mut self, user_id: &str) -> Result<(), EngineError> {
        if self.user_id.as_deref() == Some(user_id) {
            return self.refresh_siblings(true).await;
        }
        self.fetch_devices(user_id).await.map(|_| ())
    }

    // ---- linking: the approval bundle ----

    /// What we hand a device we are approving, sealed for the device showing `code`.
    pub(super) fn link_bundle_for(&mut self, code: &str, user_id: &str, new_identity: &[u8]) -> Option<String> {
        if self.acct.account_key.is_none() {
            self.acct.account_key = Some(skwod_crypto::random_bytes());
            self.acct.name_uploaded = false;
        }
        let bundle = LinkBundle {
            siblings: self.siblings.iter().map(|(d, k)| (d.clone(), k.clone())).collect(),
            account_key: self.acct.account_key,
            spaces: self.spaces.iter().map(|(s, k)| (s.clone(), *k)).take(MAX_SERVER_ARRAY).collect(),
            owner_pins: self.owner_pins_to_share(),
        };
        let bytes = postcard::to_stdvec(&bundle).expect("bundle serialization is infallible");
        // Encrypted TO the new device's identity key; the code only authenticates it.
        skwod_crypto::link::seal_bundle(code, user_id, &self.store.identity_key(), new_identity, &bytes).map(|sealed| B64.encode(sealed))
    }

    /// Take what the approving device handed us. Authenticated by the link code and bound to
    /// both identity keys, so it comes from the device the user typed the code into — the same
    /// trust the approval itself rests on.
    pub(super) fn apply_link_bundle(&mut self, code: &str, user_id: &str, linker_identity: &[u8], sealed_b64: Option<&str>) {
        let Some(sealed) = sealed_b64.and_then(|s| B64.decode(s).ok()) else { return };
        let Some(bytes) = self.store.open_link_bundle(code, user_id, linker_identity, &sealed) else { return };
        let Ok(bundle) = postcard::from_bytes::<LinkBundle>(&bytes) else { return };
        for (device, identity) in bundle.siblings.into_iter().take(16) {
            if !self.own_tombstoned(&identity) {
                self.siblings.entry(device).or_insert(identity);
            }
        }
        if bundle.account_key.is_some() {
            self.acct.account_key = bundle.account_key;
        }
        for (server, key) in bundle.spaces.into_iter().take(MAX_SERVER_ARRAY) {
            if server.len() <= 128 {
                self.spaces.entry(server).or_insert(key);
            }
        }
        self.accept_sibling_pins(bundle.owner_pins);
    }

    /// Keep sending our sibling set (and the account key) to newly linked siblings until each
    /// acknowledges it — a set that got lost would leave the newcomer ignoring its siblings.
    pub(super) async fn sync_siblings(&mut self) {
        let Ok(local) = self.local() else { return };
        let now = now_ms() as i64;
        self.acct.sibling_sync.retain(|device, (attempts, _)| self.siblings.contains_key(device) && *attempts < SIBLING_SYNC_ATTEMPTS);
        let due: Vec<String> = self.acct.sibling_sync.iter().filter(|(_, (_, next))| *next <= now).map(|(d, _)| d.clone()).collect();
        if due.is_empty() {
            return;
        }
        let targets: Vec<DeviceAddress> = due.iter().map(|d| DeviceAddress::new(local.user_id.clone(), d.clone())).collect();
        let devices: Vec<(String, Vec<u8>)> = self.siblings.iter().map(|(d, k)| (d.clone(), k.clone())).collect();
        let _ = self.send_content(&targets, &Content::Siblings { devices }).await;
        if let Some(account_key) = self.acct.account_key {
            let _ = self.send_content(&targets, &Content::AccountSync { account_key }).await;
        }
        if !self.acct.tombstones.is_empty() {
            let identities: Vec<Vec<u8>> = self.acct.tombstones.clone();
            let _ = self.send_content(&targets, &Content::Tombstones { identities }).await;
        }
        let pins = self.owner_pins_to_share();
        if !pins.is_empty() {
            let _ = self.send_content(&targets, &Content::OwnerPins { pins }).await;
        }
        for device in due {
            if let Some((attempts, next)) = self.acct.sibling_sync.get_mut(&device) {
                *attempts += 1;
                *next = now + SIBLING_SYNC_INTERVAL_MS;
            }
        }
    }

    /// A verified sibling shared the account key. Two devices of an older account may each have
    /// made one: the smaller wins on both, so they converge.
    pub(super) fn adopt_account_key(&mut self, key: [u8; 32]) {
        if self.acct.account_key.is_none_or(|mine| key < mine) {
            self.acct.account_key = Some(key);
            self.acct.name_uploaded = false;
        }
    }

    /// A restore answered `recovery_key_consumed`: the key that made it was a replaced one's
    /// single overlap use. This device must not go on backing up under it as if nothing
    /// happened — the user saves a NEW recovery key.
    pub(super) fn note_recovery_key_consumed(&mut self, resp: &serde_json::Value) {
        if resp["recovery_key_consumed"].as_bool() == Some(true) {
            self.acct.recovery_key_needed = true;
            let user_id = self.user_id.clone().unwrap_or_default();
            self.notices.push(SecurityNotice { kind: "recovery_key_needed".into(), user_id, device_id: String::new(), at_ms: now_ms(), was_verified: false });
        }
    }

    // ---- why a device left ----

    /// One of our devices REMOVED the device with this identity key. For good.
    ///
    /// - The SECURITY EFFECT always happens, whatever the state of the list: the identity stops
    ///   being re-admittable (out of `erased_identities`, `erase_claims`, `past_siblings`'
    ///   re-admission) before anything else is considered.
    /// - Only a real identity key that was a device of OURS (a sibling, a past sibling, this
    ///   device) is recorded, so the list cannot be filled with junk.
    /// - The list is bounded by evicting the OLDEST entry, never by dropping the new one.
    pub(super) fn tombstone(&mut self, identity: Vec<u8>) {
        self.acct.erased_identities.remove(&identity);
        self.acct.erase_claims.retain(|(_, c)| c != &identity);
        let ours = self.acct.past_siblings.contains(&identity)
            || self.siblings.values().any(|k| k == &identity)
            || self.unconfirmed_siblings.values().any(|k| k == &identity)
            || self.store.identity_key() == identity;
        if !ours || !skwod_crypto::certs::is_valid_identity_key(&identity) {
            return;
        }
        Self::remember_bounded(&mut self.acct.tombstones, identity.clone());
        // A restored sibling still waiting for confirmation that turns out to be removed: gone.
        self.unconfirmed_siblings.retain(|_, k| *k != identity);
        // Enforced at once, not only against a later re-admission: a device with this identity
        // that is a sibling RIGHT NOW (the server kept, or put back, its row) stops being one.
        // Nothing more is sent to it or accepted from it, and what it held of ours rotates.
        let evicted: Vec<String> = self.siblings.iter().filter(|(_, k)| **k == identity).map(|(d, _)| d.clone()).collect();
        for device_id in evicted {
            self.siblings.remove(&device_id);
            if self.acct.past_siblings.len() < 64 {
                self.acct.past_siblings.insert(identity.clone());
            }
            if let Some(user_id) = self.user_id.clone() {
                self.device_gone(&DeviceAddress::new(user_id.clone(), device_id.clone()));
                self.notices.push(SecurityNotice { kind: "device_removed".into(), user_id, device_id, at_ms: now_ms(), was_verified: false });
            }
        }
    }

    /// Was the device with this identity key REMOVED from our own account? Such an identity is
    /// never a sibling again by anything the server lists or an old link signature says.
    pub(super) fn own_tombstoned(&self, identity: &[u8]) -> bool {
        self.acct.tombstones.iter().any(|t| t == identity)
    }

    /// A device of contact `user_id` told us they removed the device with this identity key
    /// (the caller has checked it IS an identity we accepted for that contact).
    ///
    /// The security effect always happens: the identity stops being re-admittable. The record
    /// is kept PER CONTACT and each contact's set is capped by itself — a full set refuses that
    /// contact's new entries and never evicts, so no contact can crowd out another's removals;
    /// and whatever could not be recorded is denied by default (`may_readmit_contact_identity`).
    pub(super) fn tombstone_contact_identity(&mut self, user_id: &str, identity: Vec<u8>) {
        self.acct.erased_identities.remove(&identity);
        self.acct.erase_claims.retain(|(_, c)| c != &identity);
        if !skwod_crypto::certs::is_valid_identity_key(&identity) {
            return;
        }
        if !self.acct.contact_tombstones.contains_key(user_id) && self.acct.contact_tombstones.len() >= MAX_TOMBSTONE_CONTACTS {
            self.acct.contact_tombstones_full = true;
            return;
        }
        let set = self.acct.contact_tombstones.entry(user_id.to_string()).or_default();
        // At the cap the entry is refused; the full set itself is what denies it from now on.
        if set.len() < MAX_CONTACT_TOMBSTONES {
            set.insert(identity.clone());
        }
        // Enforced at once: a device of theirs with this identity that we still count as live
        // (the server goes on listing it) is retired now, whatever the next listing says.
        let retired: Vec<String> = self
            .contacts
            .get(user_id)
            .map(|c| c.live.iter().filter(|d| c.vouched.get(*d) == Some(&identity)).cloned().collect())
            .unwrap_or_default();
        for device in retired {
            if let Some(c) = self.contacts.get_mut(user_id) {
                c.live.remove(&device);
            }
            self.device_gone(&DeviceAddress::new(user_id, device));
        }
    }

    /// Is this identity recorded as removed by ANY contact (or might be: see the caps)?
    fn contact_tombstoned(&self, identity: &[u8]) -> bool {
        self.acct.contact_tombstones.values().any(|set| set.contains(identity))
    }

    /// Append `identity` (once), evicting the oldest entry at the cap.
    fn remember_bounded(list: &mut Vec<Vec<u8>>, identity: Vec<u8>) {
        if list.contains(&identity) {
            return;
        }
        if list.len() >= MAX_TOMBSTONES {
            list.remove(0);
        }
        list.push(identity);
    }

    /// The device of account `user_id` with this identity key SAID it was erasing itself.
    /// Recorded as a claim only, under the account that made it — and only for an identity we
    /// know (a sibling's, or one a contact's device presents).
    pub(super) fn claim_self_erase(&mut self, user_id: &str, identity: Vec<u8>) {
        if self.acct.tombstones.contains(&identity) || self.contact_tombstoned(&identity) || !skwod_crypto::certs::is_valid_identity_key(&identity) {
            return;
        }
        if self.acct.erase_claims.iter().any(|(u, c)| u == user_id && c == &identity) {
            return;
        }
        // One account cannot crowd out the claims of others: its own are capped by themselves.
        // (A claim that is not kept only means that device is not re-admitted by itself.)
        if self.acct.erase_claims.iter().filter(|(u, _)| u == user_id).count() >= MAX_ERASE_CLAIMS_PER_USER {
            return;
        }
        if self.acct.erase_claims.len() >= MAX_TOMBSTONES {
            self.acct.erase_claims.remove(0);
        }
        self.acct.erase_claims.push((user_id.to_string(), identity));
    }

    /// Turn the erase claims of account `user_id` into fact where the server's record OF THAT
    /// ACCOUNT corroborates them: the identity is NOT among the devices registered now
    /// (`devices`) and IS in the server's list of identities that erased themselves (`erased`:
    /// base64 strings for a contact, objects with `identity_key` for our own account). A claim
    /// from a device that is still listed stays a claim: a live device cannot make itself
    /// "erased". A claim made by any OTHER account is not looked at: one contact's record says
    /// nothing about another contact's device.
    pub(super) fn confirm_erase_claims(&mut self, user_id: &str, devices: &serde_json::Value, erased: &serde_json::Value, own: bool) {
        if !self.acct.erase_claims.iter().any(|(u, _)| u == user_id) {
            return;
        }
        let key = |v: &serde_json::Value| v.as_str().and_then(|s| B64.decode(s).ok());
        let listed: Vec<Vec<u8>> = devices.as_array().into_iter().flatten().take(MAX_SERVER_ARRAY).filter_map(|d| key(&d["identity_key"])).collect();
        let recorded: Vec<Vec<u8>> =
            erased.as_array().into_iter().flatten().take(MAX_SERVER_ARRAY).filter_map(|e| if own { key(&e["identity_key"]) } else { key(e) }).collect();
        let confirmed: Vec<Vec<u8>> =
            self.acct.erase_claims.iter().filter(|(u, c)| u == user_id && recorded.contains(c) && !listed.contains(c)).map(|(_, c)| c.clone()).collect();
        for identity in confirmed {
            self.acct.erase_claims.retain(|(u, c)| !(u == user_id && c == &identity));
            self.note_self_erased(identity);
        }
    }

    /// The device with this identity key erased itself (corroborated). Never for an identity
    /// that was removed.
    pub(super) fn note_self_erased(&mut self, identity: Vec<u8>) {
        if self.acct.tombstones.contains(&identity) || self.contact_tombstoned(&identity) {
            return;
        }
        if self.acct.erased_identities.len() >= MAX_TOMBSTONES {
            if let Some(first) = self.acct.erased_identities.iter().next().cloned() {
                self.acct.erased_identities.remove(&first);
            }
        }
        self.acct.erased_identities.insert(identity);
    }

    /// Tell our contacts' devices (every server member, every DM partner) that devices with
    /// these identity keys were REMOVED from our account.
    pub(super) async fn tell_contacts_removed(&mut self, identities: Vec<Vec<u8>>) {
        let Ok(local) = self.local() else { return };
        let mut targets: BTreeSet<DeviceAddress> = BTreeSet::new();
        if let Ok(servers) = self.api.get("/api/servers").await {
            for s in servers["servers"].as_array().into_iter().flatten().take(MAX_SERVER_ARRAY) {
                if let Some(server_id) = s["server_id"].as_str() {
                    if let Ok(devices) = self.fetch_member_devices(server_id).await {
                        targets.extend(devices);
                    }
                }
            }
        }
        if let Ok(dms) = self.list_dms().await {
            for dm in dms.into_iter().take(200) {
                if let Ok(devices) = self.fetch_devices(&dm.peer_user_id).await {
                    targets.extend(devices.into_iter().map(|(d, _)| d));
                }
            }
        }
        let targets: Vec<DeviceAddress> = targets.into_iter().filter(|d| d.user_id != local.user_id).collect();
        for chunk in targets.chunks(100) {
            let _ = self.send_content(chunk, &Content::Tombstones { identities: identities.clone() }).await;
        }
    }

    /// May an own-account device with NO link signature be taken back as the sibling whose
    /// identity key it presents? Only if that identity was a sibling of ours, left by erasing
    /// itself (it told us so), and was never removed by one of our devices.
    pub(super) fn may_readmit_sibling(&self, identity: &[u8]) -> bool {
        self.acct.past_siblings.contains(identity) && self.acct.erased_identities.contains(identity) && !self.acct.tombstones.iter().any(|t| t == identity)
    }

    /// May a contact's device with no link signature be accepted because it presents an
    /// identity key we already accepted for that contact? Only if that device announced its
    /// own erasure — a device its owner removed (we were not told it erased itself) stays out
    /// until a device of theirs vouches for it.
    ///
    /// Denied whenever the removal record cannot rule it out: the identity is tombstoned (for
    /// this contact or any other), this contact's tombstone set is full (an entry of theirs may
    /// have been refused), or a removal could not be recorded at all and this contact has no
    /// record.
    pub(super) fn may_readmit_contact_identity(&self, user_id: &str, identity: &[u8]) -> bool {
        if !self.acct.erased_identities.contains(identity) || self.contact_tombstoned(identity) {
            return false;
        }
        match self.acct.contact_tombstones.get(user_id) {
            Some(set) => set.len() < MAX_CONTACT_TOMBSTONES,
            None => !self.acct.contact_tombstones_full,
        }
    }

    /// Before unregistering ourselves: tell siblings and contacts that this device is erasing
    /// itself (so a later restore of this identity is recognised rather than held).
    pub(super) async fn announce_self_erase(&mut self) {
        let Ok(local) = self.local() else { return };
        let _ = self.refresh_siblings(true).await;
        let mut targets: BTreeSet<DeviceAddress> = self.siblings.keys().map(|d| DeviceAddress::new(local.user_id.clone(), d.clone())).collect();
        if let Ok(servers) = self.api.get("/api/servers").await {
            for s in servers["servers"].as_array().into_iter().flatten().take(MAX_SERVER_ARRAY) {
                if let Some(server_id) = s["server_id"].as_str() {
                    if let Ok(devices) = self.fetch_member_devices(server_id).await {
                        targets.extend(devices);
                    }
                }
            }
        }
        if let Ok(dms) = self.list_dms().await {
            for dm in dms.into_iter().take(200) {
                if let Ok(devices) = self.fetch_devices(&dm.peer_user_id).await {
                    targets.extend(devices.into_iter().map(|(d, _)| d));
                }
            }
        }
        targets.remove(&local);
        let targets: Vec<DeviceAddress> = targets.into_iter().collect();
        for chunk in targets.chunks(100) {
            let _ = self.send_content(chunk, &Content::SelfErased).await;
        }
    }

    // ---- persistence before sending ----

    /// Install the sink that persists the engine state (and an outgoing message) before a send.
    pub fn set_state_sink(&mut self, sink: StateSink) {
        self.state_sink = Some(sink);
    }

    /// Install the store sent messages are kept in.
    pub fn set_sent_store(&mut self, store: Box<dyn SentStore>) {
        self.sent = store;
    }

    /// Persist now: something was encrypted and is about to leave. Fails the send if the
    /// application could not write it.
    pub(super) fn checkpoint(&mut self, row: Option<&OutgoingRow>) -> Result<(), EngineError> {
        match &self.state_sink {
            Some(sink) if !sink(&self.export_state(), row) => Err(EngineError::Protocol("could not save to this device; nothing was sent")),
            _ => {
                if let Some(row) = row {
                    // On disk, not yet out: if the send now fails the application takes it back.
                    self.unsent = Some((row.scope.clone(), row.message_id.clone()));
                }
                Ok(())
            }
        }
    }

    /// The message row a send that just FAILED had already written (scope, id): it never went
    /// out, so the application removes it again. `None` after a send that succeeded.
    pub fn take_unsent(&mut self) -> Option<(String, String)> {
        self.unsent.take()
    }

    // ---- the sent store ----

    pub(super) fn remember_envelope(&self, envelope: &[u8], content: &Content, device: &DeviceAddress) {
        let record = match content {
            Content::Chat { message_id, .. } | Content::DmReply { message_id, .. } | Content::ChatResend { message_id, .. } => SentEnvelope::Chat { message_id: message_id.clone(), device: device.clone() },
            _ => SentEnvelope::Control,
        };
        if let Ok(bytes) = postcard::to_stdvec(&record) {
            self.sent.put(&format!("env:{}", envelope_id(envelope)), &bytes, now_ms() as i64);
        }
    }

    pub(super) fn remember_dm(&self, message_id: &str, conversation_id: &str, peer_user_id: &str, text: &str, sent_at: i64, reply_to: Option<&str>) {
        let record = SentDm {
            conversation_id: conversation_id.to_string(),
            peer_user_id: peer_user_id.to_string(),
            text: text.to_string(),
            sent_at,
            reply_to: reply_to.map(str::to_string),
        };
        if let Ok(bytes) = postcard::to_stdvec(&record) {
            self.sent.put(&format!("dm:{message_id}"), &bytes, sent_at);
        }
    }

    pub(super) fn remember_channel_message(&self, channel_id: &str, message_id: &str, reply_to: Option<&str>, edited: bool, text: &str) {
        // An edit keeps the time the message was first sent (that is what decides who may be
        // sent it again).
        let key = format!("ch:{channel_id}:{message_id}");
        let first_sent = self.sent.get(&key).and_then(|b| postcard::from_bytes::<SentChannel>(&b).ok()).map(|m| m.at_ms);
        let record = SentChannel { reply_to: reply_to.map(str::to_string), edited, text: text.to_string(), at_ms: first_sent.unwrap_or(now_ms() as i64) };
        if let Ok(bytes) = postcard::to_stdvec(&record) {
            self.sent.put(&key, &bytes, now_ms() as i64);
        }
    }

    // ---- per-device delivery of direct messages ----

    /// `message_id` reached some devices but not `missed`: owe it to each of them.
    pub(super) fn owe_deliveries(&mut self, message_id: &str, missed: impl IntoIterator<Item = DeviceAddress>) {
        let now = now_ms() as i64;
        for device in missed {
            if self.acct.pending_dm.len() >= MAX_PENDING_DELIVERIES {
                self.acct.pending_dm.remove(0);
            }
            self.acct.pending_dm.push(PendingDelivery { message_id: message_id.to_string(), device, attempts: 0, next_at_ms: now + backoff_ms(0), created_ms: now });
        }
    }

    /// How many per-device deliveries are still owed (for tests and diagnostics).
    pub fn pending_deliveries(&self) -> usize {
        self.acct.pending_dm.len()
    }

    /// Try the deliveries that are due again. Each device is retried on its own schedule
    /// (30 s doubling to 6 h) for up to 30 days, or until it leaves the directory.
    pub async fn retry_deliveries(&mut self, force: bool) {
        let Ok(local) = self.local() else { return };
        let now = now_ms() as i64;
        self.acct.pending_dm.retain(|p| now - p.created_ms < SENT_RETENTION_MS);
        let due: Vec<usize> =
            self.acct.pending_dm.iter().enumerate().filter(|(_, p)| force || p.next_at_ms <= now).map(|(i, _)| i).take(DELIVERIES_PER_PASS).collect();
        let mut done = Vec::new();
        let mut refreshed: BTreeSet<String> = BTreeSet::new();
        for i in due {
            let p = self.acct.pending_dm[i].clone();
            let Some(dm) = self.sent.get(&format!("dm:{}", p.message_id)).and_then(|b| postcard::from_bytes::<SentDm>(&b).ok()) else {
                done.push(i); // nothing left to send it from
                continue;
            };
            // Is the device still theirs? (Once per user per pass.)
            if p.device.user_id != local.user_id && refreshed.insert(p.device.user_id.clone()) {
                let _ = self.fetch_devices(&p.device.user_id).await;
            }
            let own = p.device.user_id == local.user_id;
            if (own && !self.siblings.contains_key(&p.device.device_id)) || (!own && !self.contact_device_trusted(&p.device)) {
                // Removed, or not (or no longer) vouched for. `device_gone` clears removed ones;
                // an unvouched one is dropped here: nothing is ever sent to it.
                done.push(i);
                continue;
            }
            let chat = super::content::dm_message(&dm.conversation_id, &p.message_id, &dm.text, dm.sent_at, dm.reply_to.as_deref(), own.then_some(dm.peer_user_id));
            match self.send_content(std::slice::from_ref(&p.device), &chat).await {
                Ok(delivered) if delivered.contains(&p.device) => done.push(i),
                _ => {
                    // `device_gone` may have emptied the list meanwhile.
                    if let Some(entry) = self.acct.pending_dm.get_mut(i).filter(|e| e.message_id == p.message_id && e.device == p.device) {
                        entry.attempts += 1;
                        entry.next_at_ms = now + backoff_ms(entry.attempts);
                    }
                }
            }
        }
        let mut i = 0;
        self.acct.pending_dm.retain(|_| {
            i += 1;
            !done.contains(&(i - 1))
        });
        self.sent.prune(now - SENT_RETENTION_MS);
    }

    // ---- retry: asking ----

    /// Drain what the application must do to placeholder rows.
    pub fn take_retry_events(&mut self) -> Vec<RetryEvent> {
        std::mem::take(&mut self.acct.retry_events)
    }

    /// Drain channel messages their authors sent again.
    pub fn take_resent(&mut self) -> Vec<ResentMessage> {
        std::mem::take(&mut self.acct.resent)
    }

    fn note_ask(&mut self, key: String, device: &DeviceAddress, scope: Option<String>) -> bool {
        let now = now_ms() as i64;
        if self.acct.retry_asked.get(&key).is_some_and(|a| now - a.at_ms < RETRY_REASK_MS) {
            return false;
        }
        if self.acct.retry_asked.len() >= MAX_RETRY_ASKS {
            if let Some(oldest) = self.acct.retry_asked.iter().min_by_key(|(_, a)| a.at_ms).map(|(k, _)| k.clone()) {
                self.acct.retry_asked.remove(&oldest);
            }
        }
        self.acct.retry_asked.insert(key, RetryAsk { device: device.clone(), at_ms: now, scope });
        true
    }

    /// A sealed envelope from `sender` did not decrypt (the session is gone or has diverged).
    /// After the session has been repaired: show a placeholder where their messages go and ask
    /// that device to send it again, naming the envelope by its hash.
    pub(super) async fn ask_envelope_again(&mut self, sender: &DeviceAddress, envelope: &[u8], received_at: i64) {
        let id = envelope_id(envelope);
        let own = self.user_id.as_deref() == Some(sender.user_id.as_str());
        let scope = if own { None } else { self.dm_conversation_with(&sender.user_id).await.map(|c| format!("dm:{c}")) };
        if !self.note_ask(format!("env:{id}"), sender, scope.clone()) {
            return;
        }
        if let Some(scope) = scope {
            self.acct.retry_events.push(RetryEvent::Placeholder { scope, id: format!("retry:{id}"), author_id: sender.user_id.clone(), at_ms: received_at });
        }
        let _ = self.send_content(std::slice::from_ref(sender), &Content::RetryRequest { channel_id: None, ids: vec![id] }).await;
    }

    /// Should a channel row from `author` that did not decrypt get a placeholder and a retry
    /// request? Yes if we were already receiving from them in this scope when it was written
    /// (it was ours to read and got lost), or if it predates this install's restore (it was
    /// ours to read with keys that are gone). No for what was written before we were let in.
    pub(super) fn should_ask_again(&self, scope: &str, author: &str, created_at: i64) -> bool {
        self.acct.first_key_at.get(&format!("{scope}|{author}")).is_some_and(|since| created_at >= *since) || self.acct.restored_at.is_some_and(|at| created_at <= at)
    }

    /// When this install last became the device by a restore (unix ms), if it ever did.
    /// Channel sync re-reads the recent past once after each restore: what was written while
    /// the device lived on another install was skipped or unreadable when this one last looked.
    pub fn restored_at(&self) -> Option<i64> {
        self.acct.restored_at
    }

    /// States from before these were recorded: whoever holds a key already held it "always".
    pub(super) fn backfill_key_times(&mut self) {
        for r in self.recv_keys.values() {
            self.acct.first_key_at.entry(format!("{}|{}", r.scope, r.sender.user_id)).or_insert(0);
        }
        for (scope, key) in &self.send_keys {
            for holder in &key.holders {
                if let Ok(name) = holder.name() {
                    self.acct.keyed_at.entry(format!("{scope}|{name}")).or_insert(0);
                }
            }
        }
    }

    /// The placeholder for a channel row from `author` this device could not decrypt.
    pub(super) fn channel_placeholder(mid: &str, author: &str, created_at: i64) -> InboundMessage {
        InboundMessage {
            message_id: mid.to_string(),
            author_id: author.to_string(),
            text: undecryptable_body(author, false),
            created_at,
            reply_to_id: None,
            is_edited: false,
            deleted: false,
            undecryptable: true,
        }
    }

    /// Ask each author device for the channel messages we could not decrypt — which also tells
    /// it we lack its sender key for this channel.
    pub(super) async fn ask_channel_again(&mut self, channel_id: &str, missing: BTreeMap<DeviceAddress, Vec<String>>) {
        let scope = format!("channel:{channel_id}");
        for (device, ids) in missing {
            let fresh: Vec<String> = ids.into_iter().filter(|mid| self.note_ask(format!("ch:{channel_id}:{mid}"), &device, Some(scope.clone()))).collect();
            for chunk in fresh.chunks(MAX_RETRY_IDS) {
                let request = Content::RetryRequest { channel_id: Some(channel_id.to_string()), ids: chunk.to_vec() };
                let _ = self.send_content(std::slice::from_ref(&device), &request).await;
            }
        }
    }

    // ---- retry: answering ----

    /// `sender` asks us to send something again.
    pub(super) async fn on_retry_request(&mut self, local: &DeviceAddress, sender: &DeviceAddress, channel_id: Option<String>, ids: Vec<String>) {
        let ids: Vec<String> = ids.into_iter().filter(|i| i.len() <= 128).take(MAX_RETRY_IDS).collect();
        let Some(channel_id) = channel_id else {
            let (mut settled, mut lost) = (Vec::new(), Vec::new());
            for id in ids {
                match self.sent.get(&format!("env:{id}")).and_then(|b| postcard::from_bytes::<SentEnvelope>(&b).ok()) {
                    // Only the device it was sealed for may have it again.
                    Some(SentEnvelope::Chat { message_id, device }) if &device == sender => {
                        match self.sent.get(&format!("dm:{message_id}")).and_then(|b| postcard::from_bytes::<SentDm>(&b).ok()) {
                            Some(dm) => {
                                let resend = Content::ChatResend {
                                    retry_id: id,
                                    conversation_id: dm.conversation_id,
                                    message_id,
                                    text: dm.text,
                                    sent_at: dm.sent_at,
                                    sync_peer: (sender.user_id == local.user_id).then_some(dm.peer_user_id),
                                    reply_to: dm.reply_to,
                                };
                                let _ = self.send_content(std::slice::from_ref(sender), &resend).await;
                            }
                            None => lost.push(id),
                        }
                    }
                    Some(SentEnvelope::Control) => settled.push(id),
                    _ => lost.push(id),
                }
            }
            for (ids, lost) in [(settled, false), (lost, true)] {
                if !ids.is_empty() {
                    let _ = self.send_content(std::slice::from_ref(sender), &Content::RetryNone { channel_id: None, ids, lost }).await;
                }
            }
            return;
        };
        if channel_id.len() > 128 {
            return;
        }
        // Channel history goes only to a device that may hold our key for that channel: a
        // verified sibling, or a device of an accepted member whose arrival was shown there.
        let scope = format!("channel:{channel_id}");
        let Ok(server_id) = self.channel_server(&channel_id).await else { return };
        let Ok(members) = self.fetch_member_devices(&server_id).await else { return };
        let own = sender.user_id == local.user_id;
        let eligible = members.contains(sender)
            && (own
                || self.rosters.get(&server_id).is_some_and(|r| r.members.contains(&sender.user_id) && r.cleared.get(&scope).is_some_and(|c| c.contains(sender))));
        // …and only what was sent since it has held our key: a retry request is not a way for
        // a member to be handed history from before they were let in.
        let Some(since) = sender.name().ok().and_then(|n| self.acct.keyed_at.get(&format!("{scope}|{n}")).copied()).filter(|_| eligible) else {
            return;
        };
        // It evidently lacks our current key: hand it over again.
        if let Some(key) = self.send_keys.get_mut(&scope) {
            key.holders.remove(sender);
        }
        let _ = self.sync_channel_key(&channel_id, &server_id).await;
        let (mut batch, mut size, mut lost) = (Vec::new(), 0usize, Vec::new());
        for id in ids {
            match self.sent.get(&format!("ch:{channel_id}:{id}")).and_then(|b| postcard::from_bytes::<SentChannel>(&b).ok()).filter(|m| m.at_ms >= since) {
                Some(m) => {
                    if size + m.text.len() > RESEND_CHUNK_BYTES && !batch.is_empty() {
                        let messages = std::mem::take(&mut batch);
                        let _ = self.send_content(std::slice::from_ref(sender), &Content::ChannelResend { channel_id: channel_id.clone(), messages }).await;
                        size = 0;
                    }
                    size += m.text.len();
                    batch.push((id, m.reply_to, m.edited, m.text));
                }
                None => lost.push(id),
            }
        }
        if !batch.is_empty() {
            let _ = self.send_content(std::slice::from_ref(sender), &Content::ChannelResend { channel_id: channel_id.clone(), messages: batch }).await;
        }
        if !lost.is_empty() {
            let _ = self.send_content(std::slice::from_ref(sender), &Content::RetryNone { channel_id: Some(channel_id), ids: lost, lost: true }).await;
        }
    }

    /// Take the record of having asked `sender` for `key` — the only thing that makes an
    /// unsolicited "resend" acceptable. `None` if we never asked that device.
    pub(super) fn answered(&mut self, key: &str, sender: &DeviceAddress) -> Option<RetryAsk> {
        if self.acct.retry_asked.get(key).is_some_and(|a| &a.device == sender) {
            self.acct.retry_asked.remove(key)
        } else {
            None
        }
    }

    /// `sender` has nothing to send again for these ids.
    pub(super) fn on_retry_none(&mut self, sender: &DeviceAddress, channel_id: Option<String>, ids: Vec<String>, lost: bool) {
        for id in ids.into_iter().take(MAX_RETRY_IDS) {
            let (key, placeholder) = match &channel_id {
                Some(c) => (format!("ch:{c}:{id}"), id.clone()),
                None => (format!("env:{id}"), format!("retry:{id}")),
            };
            let Some(ask) = self.answered(&key, sender) else { continue };
            let Some(scope) = ask.scope else { continue };
            self.acct.retry_events.push(if lost { RetryEvent::Lost { scope, id: placeholder } } else { RetryEvent::Resolved { scope, id: placeholder } });
        }
    }

    /// `sender` sent channel messages again. Each is taken only if we asked that very device
    /// for that very message — a member cannot slip a message past the server this way.
    pub(super) fn on_channel_resend(&mut self, sender: &DeviceAddress, channel_id: String, messages: Vec<(String, Option<String>, bool, String)>) {
        for (message_id, reply_to_id, is_edited, text) in messages.into_iter().take(MAX_RETRY_IDS) {
            if text.len() > MAX_TEXT || self.answered(&format!("ch:{channel_id}:{message_id}"), sender).is_none() {
                continue;
            }
            let text = crate::cache::neutralize_reserved(&text).to_string();
            self.acct.resent.push(ResentMessage { channel_id: channel_id.clone(), message_id, author_id: sender.user_id.clone(), text, reply_to_id, is_edited });
        }
    }

    // ---- backup: the trust state ----

    pub(super) fn backup_ext(&self) -> Vec<u8> {
        let ext = BackupExt {
            contacts: self.contacts.clone(),
            owner_sources: self.owner_sources.clone(),
            account_key: self.acct.account_key,
            device_name: self.acct.device_name.clone(),
            tombstones: self.acct.tombstones.clone(),
        };
        let mut out = Vec::new();
        write_section(&mut out, SECTION_ACCOUNTS, &postcard::to_stdvec(&ext).expect("backup serialization is infallible"));
        let contact_tombstones = (&self.acct.contact_tombstones, self.acct.contact_tombstones_full);
        write_section(&mut out, SECTION_CONTACT_TOMBSTONES, &postcard::to_stdvec(&contact_tombstones).expect("backup serialization is infallible"));
        out
    }

    pub(super) fn apply_backup_ext(&mut self, tail: &[u8]) {
        let sections = read_sections(tail).unwrap_or_default();
        // The contacts' removed devices (build 45; absent from older backups): a device a
        // contact removed stays removed here after a restore too. Bounded as when recorded.
        if let Some((sets, full)) = sections
            .iter()
            .find(|(t, _)| *t == SECTION_CONTACT_TOMBSTONES)
            .and_then(|(_, b)| postcard::from_bytes::<(BTreeMap<String, BTreeSet<Vec<u8>>>, bool)>(b).ok())
        {
            self.acct.contact_tombstones = sets.into_iter().take(MAX_TOMBSTONE_CONTACTS).map(|(u, set)| (u, set.into_iter().take(MAX_CONTACT_TOMBSTONES).collect())).collect();
            self.acct.contact_tombstones_full = full;
        }
        let Some(ext) = sections.into_iter().find(|(t, _)| *t == SECTION_ACCOUNTS).and_then(|(_, b)| postcard::from_bytes::<BackupExt>(b).ok()) else {
            return;
        };
        self.contacts = ext.contacts;
        // Only for pins the backup itself carries.
        self.owner_sources = ext.owner_sources.into_iter().filter(|(server, _)| self.expected_provisioner.contains_key(server)).collect();
        self.acct.account_key = ext.account_key;
        self.acct.device_name = ext.device_name;
        // Our own backup, authenticated by the recovery key: taken as written (bounded).
        self.acct.tombstones = ext.tombstones.into_iter().rev().take(MAX_TOMBSTONES).rev().collect();
        // A sibling the backup still lists but that was removed since is not a sibling.
        let tombstones = &self.acct.tombstones;
        self.siblings.retain(|_, identity| !tombstones.contains(identity));
    }

    /// Put the trust state a restore brought back through the same rules as everything else:
    ///
    /// - an owner pin stays trusted under its recorded source — unless the instance, under the
    ///   key we pinned, now attests a DIFFERENT owner: then the pin is demoted to
    ///   `legacy-unknown` (it authorizes nothing) and the user is told;
    /// - every restored contact is read from the directory again: devices added since the
    ///   backup must chain to ones the backup vouched for, and a verified contact whose device
    ///   set has changed is held until verified again.
    pub(super) async fn reconfirm_restored(&mut self) {
        let pins: Vec<(String, String)> = self.expected_provisioner.iter().filter(|(s, _)| self.owner_sources.contains_key(*s)).map(|(s, o)| (s.clone(), o.clone())).collect();
        for (server_id, pinned_owner) in pins.into_iter().take(MAX_SERVER_ARRAY) {
            let Some(instance_key) = self.pinned_instance_key.clone() else { break };
            let Ok(v) = self.api.get(&format!("/api/servers/{}/owner-attestation", enc(&server_id))).await else { continue };
            let (Some(owner), Some(sig)) = (v["owner_id"].as_str(), v["signature"].as_str().and_then(|s| B64.decode(s).ok())) else { continue };
            if owner != pinned_owner && skwod_crypto::instance::verify_owner_attestation(&instance_key, &server_id, owner, &sig) {
                self.owner_sources.remove(&server_id);
                self.notices.push(SecurityNotice { kind: "owner_changed".into(), user_id: owner.to_string(), device_id: server_id, at_ms: now_ms(), was_verified: false });
            }
        }
        let contacts: Vec<String> = self.contacts.keys().take(MAX_SERVER_ARRAY).cloned().collect();
        for user in contacts {
            let _ = self.fetch_devices(&user).await;
        }
    }

    /// After a restore every session this device had is gone. Tell every device that may hold
    /// one — siblings, every member device of every server, DM partners — so each drops its
    /// side and hands us its sender keys again, instead of finding out one failed message at a
    /// time. Best-effort; repeated from the mailbox sync until it has gone out once.
    pub(super) async fn announce_restore(&mut self) {
        let Ok(local) = self.local() else { return };
        self.acct.announce_pending = true;
        let _ = self.refresh_siblings(true).await;
        let mut targets: BTreeSet<DeviceAddress> = self.siblings.keys().map(|d| DeviceAddress::new(local.user_id.clone(), d.clone())).collect();
        let Ok(servers) = self.api.get("/api/servers").await else { return };
        for s in servers["servers"].as_array().into_iter().flatten().take(MAX_SERVER_ARRAY) {
            let Some(server_id) = s["server_id"].as_str() else { continue };
            if let Ok(devices) = self.fetch_member_devices(server_id).await {
                targets.extend(devices);
            }
        }
        if let Ok(dms) = self.list_dms().await {
            for dm in dms.into_iter().take(200) {
                if let Ok(devices) = self.fetch_devices(&dm.peer_user_id).await {
                    targets.extend(devices.into_iter().map(|(d, _)| d));
                }
            }
        }
        targets.remove(&local);
        // (The restored siblings nobody has confirmed get nothing, not even this: audit M2. One
        // the user confirms is sent its reset then — `confirm_restored_sibling`.)
        let targets: Vec<DeviceAddress> = targets.into_iter().collect();
        let mut reached_all = true;
        for chunk in targets.chunks(100) {
            reached_all &= self.send_content(chunk, &Content::SessionReset).await.is_ok() || chunk.is_empty();
        }
        if reached_all {
            self.acct.announce_pending = false;
        }
    }
}
