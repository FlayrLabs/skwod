//! E2EE session manager — wires libsignal (via `skwod-crypto`) to the server's key directory.
//!
//! One [`Engine`] is one device. It owns that device's libsignal store and does four things:
//!
//! 1. **Registers** the device: publishes its identity key, a signed prekey, a last-resort Kyber
//!    prekey and batches of one-time EC + Kyber prekeys; keeps them topped up and rotated.
//! 2. **Pairwise traffic** — direct messages and every control message (sender-key hand-offs,
//!    space keys, provisioning, voice keys) — goes over PQXDH-established Double Ratchet (+SPQR)
//!    sessions, **sealed-sender** wrapped, into the recipient device's sealed mailbox. The deposit
//!    request carries no credentials, so the server learns the recipient device and nothing else.
//!    A message to a user is fanned out to **every device** of that user (and to our own other
//!    devices).
//! 3. **Channels** use libsignal Sender Keys. Each device owns one sender key per channel and
//!    hands it to every device of every member over (2). When a holder stops being a member — or a
//!    holder device disappears — the key is rotated before the next send.
//! 4. **Voice**: per-call random media keys, handed only to call participants over (2) and rotated
//!    when a participant leaves.
//!
//! Everything the server sees is ciphertext, public keys, or routing metadata. Engine state is
//! serializable for the on-device encrypted [`crate::cache::Cache`] — never for the server.

mod accounts;
mod content;
mod guard;
mod legacy;
mod rest;
mod trust;

pub use accounts::{
    is_undecryptable, undecryptable_body, DeviceInfo, DeviceState, MemorySentStore, OutgoingRow, ResentMessage, RetryEvent, SentStore, StateSink, SENT_RETENTION_MS,
    UNDECRYPTABLE_TAG,
};
pub use content::{DmOp, DmOpKind, InboundReport, MAX_GROUP_DM, MAX_REPORT_EXCERPT};

pub use guard::ChannelDelete;
pub use trust::{EventSink, SystemEvent};

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use skwod_crypto::certs;
use skwod_crypto::store::{CryptoError, KyberPreKeyUpload, PreKeyBundleData, PreKeyUpload, SignedPreKeyUpload};
use skwod_crypto::{aead, DeviceAddress, SealedError, SignalStore, Uuid, PROTOCOL_VERSION};

use crate::client::{ApiClient, ClientError};

/// A peer device. (Alias kept from protocol v1; identical to `skwod_crypto::DeviceAddress`.)
pub type PeerId = DeviceAddress;

/// Author-id sentinel for a message this account sent (from this device or a sibling device).
pub const SELF_AUTHOR: &str = "__me__";

/// Author-id of a row the app itself wrote into a conversation: a security or membership event
/// ("X added a device", "X joined (approved by Y)"). Never a message anyone sent.
pub const SYSTEM_AUTHOR: &str = "__system__";
/// Content prefix of such a row; a JSON object follows (`kind`, `user_id`, `device_id`,
/// `by_user_id`, `was_verified`).
pub const SYSTEM_TAG: &str = "\u{2}skwod/sys|";

/// One-time prekeys of each kind uploaded per batch, and the low-water mark that triggers a refill.
const PREKEY_BATCH: usize = 50;
const PREKEY_LOW_WATER: i64 = 15;
/// Signed prekey + last-resort Kyber key rotation period.
const SIGNED_PREKEY_ROTATION_MS: u64 = 7 * 24 * 60 * 60 * 1000;
/// Refresh the sender certificate when it has less than this left.
const CERT_REFRESH_MARGIN_MS: u64 = 60 * 60 * 1000;
/// Minimum spacing of prekey maintenance checks and of session repairs per peer.
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(30 * 60);
const REPAIR_INTERVAL: Duration = Duration::from_secs(10 * 60);
/// The least time between two EARLY rotations of the signed prekey + last-resort key.
const PRESSURE_ROTATION_GAP: Duration = Duration::from_secs(60 * 60);

/// Max size (bytes) of anything server-relayed we will try to parse.
const MAX_WIRE_ENVELOPE: usize = 256 * 1024;
/// The most text one message may carry. Encryption, padding and base64 add to it, and the
/// result has to stay under [`MAX_WIRE_ENVELOPE`] — a receiver drops anything bigger, so a
/// bigger message would be accepted by the server and then silently never appear. Photos and
/// files do not count: they travel as attachments, and only a small descriptor (and, for feed
/// posts, a small thumbnail) is in the text.
pub const MAX_TEXT: usize = 150 * 1024;
const TOO_LARGE: &str = "That message is too big to send. Shorten it, or send the photo or file as an attachment.";
/// One page of channel history.
pub const PAGE: usize = 100;
/// Defensive cap on rows iterated from any single server array response (the server is untrusted).
const MAX_SERVER_ARRAY: usize = 1000;
/// Cap on remembered sender-key bindings and buffered inbound DMs (memory bound against a peer or
/// server that floods us).
const MAX_RECV_KEYS: usize = 20_000;
/// …and on how many of those one sender (user) may occupy. At the cap that sender's OLDEST
/// distribution is evicted, so a flood only ever costs the flooder their own history — it can
/// neither fill the table for everyone nor lock out their own later (legitimate) rotations.
const MAX_RECV_KEYS_PER_SENDER: usize = 512;
const MAX_BUFFERED_DMS: usize = 5_000;
/// Voice keys that arrived for a call this device has not (yet) joined: kept briefly, a few per
/// sender, and used only if we do join that call. They never create or evict a call.
const MAX_PENDING_VOICE: usize = 64;
const MAX_PENDING_VOICE_PER_SENDER: usize = 4;
const PENDING_VOICE_TTL: Duration = Duration::from_secs(120);
/// Minimum spacing of directory re-checks triggered by inbound traffic from one user.
const DIRECTORY_RECHECK: Duration = Duration::from_secs(30);
/// How often one device can be reported for arriving under a key that is not the pinned one.
const IDENTITY_REJECT_NOTICE: Duration = Duration::from_secs(60 * 60);
/// LiveKit's per-participant keyring size; voice key indexes wrap within it.
const VOICE_KEYRING: u32 = 16;
const MAX_VOICE_CALLS: usize = 8;

/// First byte of a channel message on the wire. `3`: the sender-key plaintext is a
/// [`ChannelBody`] carrying the message id / reply / edit metadata, authenticated with the text.
/// `2` (build 42): the plaintext is the bare text and there is no authenticated metadata.
///
/// This byte sits OUTSIDE the ciphertext, so it is only the server's claim and nothing is
/// decided by it. What a message is, is decided by what is inside (M2, the downgrade rule —
/// see [`Engine::open_channel_message`]):
///
/// - a plaintext that is a [`ChannelBody`] is a v3 message whatever the byte says: a v3
///   message relabelled as v2 keeps its sealed id, reply target and edit flag;
/// - anything else is a build-42 message: shown as plain text, with NO reply link and NO edit
///   marker (the server's `reply_to_id` / `is_edited` are ignored for it);
/// - and once a sender device has been seen writing v3 in a channel, a build-42 body it sealed
///   LATER (by its own signed sender-key counter) is refused ([`V3Seen`]).
///
/// Almost all history from before build 44 is v2, so it must stay readable. No build that can
/// still send writes v2 (the server answers their sends 426, `oldbuilds.rs`).
const CHANNEL_WIRE_V2: u8 = 2;
const CHANNEL_WIRE_V3: u8 = 3;
/// The refusal of a build-42 body sealed after its sender device moved to v3. Final: no
/// placeholder, and nobody is asked to send it again.
const V2_AFTER_V3: &str = "a build-42 channel message sealed after its sender moved to v3";
/// A pairwise send had no device to go to, or none took it.
const NO_RECIPIENT: &str = "the message reached no device of the recipient";
/// Engine-state section holding [`Build45Ext`].
const SECTION_BUILD45: u8 = 0xB5;
/// Engine-state section holding the siblings a restore brought back that no live sibling (or
/// the user) has confirmed yet (`Engine::unconfirmed_siblings`, audit M2).
const SECTION_UNCONFIRMED: u8 = 0xB6;
/// Most (channel, sender device) pairs remembered as having moved to v3.
const MAX_V3_SEEN: usize = 8192;
/// Most provision requests held over from a notification-extension pass.
const MAX_DEFERRED_PROVISIONS: usize = 256;

/// One sender device in one channel has been seen writing wire v3 (M2). Recorded at the first
/// v3 message that decrypts, and persisted.
///
/// From then on that device's build-42 (v2) bodies are read only where its OWN key schedule
/// says they were sealed before it moved: each sender-key message carries, under the sender's
/// signature, the distribution id, chain id and iteration (a counter that only goes up) it was
/// sealed at. The server cannot change them without breaking the signature.
///
/// - `legacy` are the distributions this device had been handed by that sender device when
///   its first v3 was seen. A v2 body under any OTHER distribution — one announced after the
///   sender had moved to v3 — is refused.
/// - Within a legacy distribution, the value is, per chain id, the LOWEST iteration at which a
///   v3 body has been seen. A v2 body at a higher iteration on that chain was sealed after a
///   v3 one and is refused; a lower one is older history and is read (so scrolling back
///   through old pages after seeing new v3 messages still works: the old rows really are
///   earlier on the sender's counter, whatever order they are fetched in).
///
/// Neither a clock nor anything the server says is used.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct V3Seen {
    legacy: BTreeMap<String, BTreeMap<u32, u32>>,
}

/// Engine state added in build 45 (one tagged section; a build that does not know it skips it).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Build45Ext {
    /// `"{scope}|{sender device name}"` → that device has moved to wire v3 there.
    v3_seen: BTreeMap<String, V3Seen>,
    /// Provision requests that arrived while this state was open in the notification extension
    /// (which hands out no keys — see [`Engine::set_passive`]); the app fulfils them next.
    deferred_provisions: Vec<(DeviceAddress, String)>,
    /// The servers this account was a member of when last asked (M6, `check_own_servers`);
    /// `None` until the first answer.
    servers: Option<BTreeSet<String>>,
    /// A request to restore the account's backup on this install is waiting for another
    /// device's approval (`request_backup_access`): when it completes by itself, unix ms.
    backup_request_pending: Option<i64>,
}
/// First byte of a sealed payload: content-format version.
const CONTENT_V1: u8 = 1;
/// Magic prefix of a persisted v2 engine state (a v1 blob is a bare postcard struct).
const STATE_MAGIC: &[u8; 4] = b"SKE2";
/// State section (build 45): hashes of the envelopes read without accepting their sender.
const SECTION_PEEKED: u8 = 0xE1;
/// Envelope hashes remembered for that. Above the most that can be held at once.
const MAX_PEEKED: usize = 1024;

/// RFC 3986 "unreserved" set kept as-is; everything else in a dynamic path/query segment is
/// percent-encoded so a hostile identifier can't inject extra path/query structure.
const SEG: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'~');

/// Percent-encode a user/server-controlled identifier before interpolating it into a REST path or
/// query string.
fn enc(s: &str) -> String {
    utf8_percent_encode(s, SEG).to_string()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or_default()
}

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("client error: {0}")]
    Client(ClientError),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("no session with {0}")]
    NoSession(String),
    #[error("serialization error")]
    Serde,
    #[error("protocol error: {0}")]
    Protocol(&'static str),
    /// A peer we had marked **verified** now presents a different identity key. Nothing is sent to
    /// them until the user accepts the change (`accept_identity_change`).
    #[error("safety number changed for {0}; verify it again before sending")]
    IdentityChanged(String),
    /// The other side speaks a different E2EE protocol generation. The string is user-facing.
    #[error("{0}")]
    UpdateRequired(String),
    /// The message is bigger than a server will carry. The string is user-facing.
    #[error("{0}")]
    TooLarge(&'static str),
    /// This device has not registered yet.
    #[error("device not registered")]
    NotRegistered,
    /// The account already has a device. A new one must be linked from an existing device
    /// (`begin_link` here, `approve_link` there) — or the account reset / restored from backup.
    #[error("this account already has a device; link this one from it")]
    LinkRequired,
    /// An account reset was requested without the registration-lock PIN. It is on hold until the
    /// given time (unix ms) so the account's existing devices can cancel it; repeat the call then.
    #[error("reset requested — it can complete in about {} day(s), unless one of this account's devices cancels it", (.0.saturating_sub(now_ms() as i64) / 86_400_000).max(1))]
    ResetPending(i64),
    /// The account has a registration-lock PIN and the reset did not carry it. Ask for the PIN
    /// (or, if it is forgotten, go through the 7-day hold).
    #[error("this account is protected by a PIN; enter it to reset")]
    PinRequired,
    /// The PIN was wrong. `attempts_left` before a lockout; `locked_until` (unix ms) during one.
    #[error("that PIN is not right")]
    PinIncorrect { attempts_left: i64, locked_until: Option<i64> },
    /// This install's device was restored from a key backup on another install. This copy has
    /// stopped for good: two installs must never run one identity.
    #[error("this device was restored from a backup on another device; this copy has stopped")]
    Superseded,
    /// Another device of the account removed this device.
    #[error("this device was removed from your account")]
    DeviceRemoved,
    /// The restore request the user was shown is no longer the one pending for that device: a
    /// different request took its place. Nothing was approved (or refused); the request that is
    /// pending now has been raised as a fresh notice.
    #[error("that restore request was replaced by another one; nothing was approved — check the new request")]
    RecoveryChanged,
    /// A restore asked the server to move the device to this install. That needs another of the
    /// account's devices to approve it, the registration PIN, or a 7-day wait (unix ms) during
    /// which the account's devices can cancel it. `true`: the request is CONTESTED (another
    /// install asked to restore the same device), so the wait alone never completes it — only
    /// an approval or the PIN does.
    #[error("{}", recovery_pending_text(*.0, *.1))]
    RecoveryPending(i64, bool),
    /// The account already has as many devices as it may; remove one first.
    #[error("this account already has the most devices it can have; remove one first")]
    DeviceLimit,
    /// The server refused a NEW restore request (server audit L1): another restore of the
    /// device is already approved, or several are waiting. The server's own sentence.
    #[error("{0}")]
    RestoreRefused(String),
}

/// What a waiting restore says to the person: a contested one waits for an approval, never
/// for the hold.
fn recovery_pending_text(completes_at: i64, contested: bool) -> String {
    if contested {
        "restore requested — waiting for approval on one of your devices".into()
    } else {
        format!("restore requested — approve it on another of your devices, or it can complete in about {} day(s)", (completes_at.saturating_sub(now_ms() as i64) / 86_400_000).max(1))
    }
}

impl From<ClientError> for EngineError {
    fn from(e: ClientError) -> Self {
        match e {
            ClientError::Status { status: 403, body } if body.contains("device link required") => EngineError::LinkRequired,
            ClientError::Status { status: 403, body } if body.contains("device reset pending") => EngineError::ResetPending(
                serde_json::from_str::<serde_json::Value>(&body).ok().and_then(|v| v["completes_at"].as_i64()).unwrap_or_default(),
            ),
            ClientError::Status { status: 403, body } if body.contains("device recovery pending") => {
                let v = serde_json::from_str::<serde_json::Value>(&body).unwrap_or_default();
                // `contested_at`: build-45 servers and later; older ones never contest.
                EngineError::RecoveryPending(v["completes_at"].as_i64().unwrap_or_default(), v["contested_at"].as_i64().is_some())
            }
            ClientError::Status { status: 403, body } if body.contains("registration pin required") => EngineError::PinRequired,
            ClientError::Status { status: 403, body } if body.contains("registration pin incorrect") => {
                let v = serde_json::from_str::<serde_json::Value>(&body).unwrap_or_default();
                EngineError::PinIncorrect { attempts_left: v["attempts_left"].as_i64().unwrap_or(0), locked_until: v["locked_until"].as_i64() }
            }
            ClientError::Status { status: 403, body } if body.contains("device removed") => EngineError::DeviceRemoved,
            ClientError::Status { status: 409, body } if body.contains("device superseded") => EngineError::Superseded,
            ClientError::Status { status: 409, body } if body.contains("5 devices") => EngineError::DeviceLimit,
            ClientError::Status { status: 409, body } if body.contains("restore") && body.contains("this device") => EngineError::RestoreRefused(
                serde_json::from_str::<serde_json::Value>(&body).ok().and_then(|v| v["error"].as_str().map(str::to_string)).unwrap_or_else(|| "this restore was refused".into()),
            ),
            ClientError::Status { status: 426, body } => {
                let msg = serde_json::from_str::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|v| v["error"].as_str().map(str::to_string))
                    .unwrap_or_else(|| "update required".to_string());
                EngineError::UpdateRequired(msg)
            }
            other => EngineError::Client(other),
        }
    }
}

impl From<CryptoError> for EngineError {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::NoSession(s) => EngineError::NoSession(s),
            CryptoError::UntrustedIdentity(s) => EngineError::IdentityChanged(s),
            other => EngineError::Crypto(other.to_string()),
        }
    }
}

/// What travels inside a sealed envelope (after libsignal decryption + unpadding).
#[derive(Serialize, Deserialize)]
enum Content {
    /// A direct message. `sync_peer` is set on the copy a sender fans out to its OWN other devices
    /// and names the conversation's other party.
    Chat { conversation_id: String, message_id: String, text: String, sent_at: i64, sync_peer: Option<String> },
    /// Our sender key for a channel (a libsignal `SenderKeyDistributionMessage`).
    SenderKey { channel_id: String, skdm: Vec<u8> },
    /// A space key, so a newly admitted member can read channel/server names.
    SpaceKey { server_id: String, key: [u8; 32] },
    /// "Please provision me for this server" (auto-join invites have no approval step to hang it on).
    ProvisionRequest { server_id: String },
    /// A per-call media key for the sender's outgoing voice/video frames.
    VoiceKey { channel_id: String, call_id: String, index: u32, key: Vec<u8> },
    /// Sent on a freshly established session after the previous one failed to decrypt: completes
    /// the new session and tells the peer to hand us their sender keys again.
    SessionReset,
    /// From one of our own approved devices: the sibling devices it has verified (device id →
    /// identity key), so a newly linked device learns the ones linked before it.
    Siblings { devices: Vec<(String, Vec<u8>)> },
    /// From one of our own approved devices: the server owners it has pinned (server id → owner
    /// user id). A newly linked device gets its trust anchors from a sibling — never from what
    /// the server lists. (Appended after build 42; older builds ignore it.)
    OwnerPins { pins: Vec<(String, String)> },
    // ---- build 44a (appended; older builds ignore what they cannot decode) ----
    /// "I could not decrypt this — send it again." Without a channel: `ids` name sealed
    /// envelopes by their hash. With one: `ids` are channel message ids (and the sender evidently
    /// lacks our sender key for that channel).
    RetryRequest { channel_id: Option<String>, ids: Vec<String> },
    /// A direct message sent again in answer to a retry request for envelope `retry_id`.
    /// `reply_to`: the message it quotes, when what is sent again was a reply (`DmReply`).
    ChatResend { retry_id: String, conversation_id: String, message_id: String, text: String, sent_at: i64, sync_peer: Option<String>, reply_to: Option<String> },
    /// Channel messages sent again, pairwise: `(message id, reply target, edited, text)`.
    ChannelResend { channel_id: String, messages: Vec<(String, Option<String>, bool, String)> },
    /// Nothing to send again for these ids: it was not a message (`lost = false`), or it is no
    /// longer in the sender's sent store (`lost = true`).
    RetryNone { channel_id: Option<String>, ids: Vec<String>, lost: bool },
    /// From a newly linked sibling: "I have your sibling set" (stops the re-sends).
    SiblingsAck,
    /// From one of our own approved devices: the account key (seals device names).
    AccountSync { account_key: [u8; 32] },
    /// "I am erasing myself" — sent by a device right before it unregisters, to its siblings
    /// and its contacts. Only a device that said so may come back by itself (a later restore,
    /// under a new device row, with the same identity key).
    SelfErased,
    /// From one of our own approved devices: identity keys of devices REMOVED from our account
    /// (lost, stolen, no longer trusted). Never trusted again without a link approval.
    Tombstones { identities: Vec<Vec<u8>> },
    // ---- build 44b (`content.rs`), appended after 44a's; build 43 cannot decode these and drops them ----
    /// A direct message that quotes another (`Chat` cannot grow a field).
    DmReply { conversation_id: String, message_id: String, text: String, sent_at: i64, reply_to: String, sync_peer: Option<String> },
    /// New text for a direct message the sender wrote.
    DmEdit { conversation_id: String, message_id: String, text: String, sync_peer: Option<String> },
    /// The sender deleted a direct message it wrote, for everyone.
    DmDelete { conversation_id: String, message_id: String, sync_peer: Option<String> },
    /// The sender reacted to a direct message (or removed its reaction).
    DmReaction { conversation_id: String, message_id: String, emoji: String, remove: bool, sync_peer: Option<String> },
    /// An abuse report, sealed to the instance owner.
    Report { report: content::InboundReport },
    // ---- build 45, appended; older builds cannot decode it and drop it ----
    /// "I cleared this channel": from the server's owner (or one of our own devices) to every
    /// member device. The only thing that makes a device drop cached channel history — the
    /// server's own `cleared_at` is not believed.
    /// `server_id` is the server the sender speaks for; the receiver must have the channel
    /// placed in exactly that server.
    ChannelClear { server_id: String, channel_id: String, cleared_at: i64 },
    /// "I deleted this channel message": from its author (or the server's owner) to every
    /// member device. A tombstone the server serves does not delete a message a device holds.
    ChannelDelete { server_id: String, channel_id: String, message_id: String },
    /// A direct-message payload (`inner`: an encoded `Chat`, `DmReply`, `DmEdit`, … ) that
    /// belongs to a GROUP conversation of exactly `members` (everyone in it, the sender and us
    /// included). Whether a conversation is a group, and who is in it, is thereby the SENDER's
    /// statement inside the ciphertext: a direct-message payload that arrives bare is a 1:1
    /// message and is never filed in a group; one that arrives wrapped is never filed in a 1:1.
    Grouped { members: Vec<String>, inner: Vec<u8> },
}

impl Content {
    fn encode(&self) -> Result<Vec<u8>, EngineError> {
        let mut out = vec![CONTENT_V1];
        out.extend(postcard::to_stdvec(self).map_err(|_| EngineError::Serde)?);
        Ok(out)
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        match bytes.split_first() {
            Some((&CONTENT_V1, rest)) if rest.len() <= MAX_WIRE_ENVELOPE => postcard::from_bytes(rest).ok(),
            _ => None,
        }
    }

    /// The direct conversation this payload is filed in, if it is a direct-message payload.
    fn dm_conversation(&self) -> Option<&str> {
        match self {
            Content::Chat { conversation_id, .. }
            | Content::ChatResend { conversation_id, .. }
            | Content::DmReply { conversation_id, .. }
            | Content::DmEdit { conversation_id, .. }
            | Content::DmDelete { conversation_id, .. }
            | Content::DmReaction { conversation_id, .. } => Some(conversation_id),
            _ => None,
        }
    }
}

/// The sender-key plaintext of a channel message (wire v3): the text together with the metadata
/// the server would otherwise be free to rewrite.
#[derive(Serialize, Deserialize)]
struct ChannelBody {
    /// The id of the message this ciphertext belongs to. A receiver drops a ciphertext served
    /// under any other id, so the server cannot move content between messages.
    id: String,
    /// The message this one replies to.
    reply_to: Option<String>,
    /// This ciphertext is an edit of message `id` (not its original text).
    edited: bool,
    text: String,
}

/// A decrypted channel message and how much of its metadata the sender authenticated.
pub struct ChannelPlaintext {
    pub text: String,
    /// `Some` for a v3 body: `(message id, reply target, edited)` as the SENDER stated them
    /// inside the ciphertext. `None` for a build-42 body, which states none: it has no reply
    /// target and no edit marker, whatever the row it was served in claims.
    pub meta: Option<(String, Option<String>, bool)>,
}

/// Our sender key for one channel and the devices that hold it.
#[derive(Clone, Serialize, Deserialize)]
struct SendKey {
    distribution_id: [u8; 16],
    /// Devices we handed the CURRENT key to. The rotation check compares this with the live
    /// member-device list; it is cleared whenever the key rotates.
    holders: BTreeSet<DeviceAddress>,
}

/// Which channel and sender a received distribution id belongs to. A sender-key message is only
/// decrypted in the scope its distribution was announced for, so a server cannot replay one
/// channel's ciphertext into another.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RecvKey {
    scope: String,
    sender: DeviceAddress,
}

/// A security event the UI must show.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityNotice {
    /// - `"identity_changed"`: a peer's safety number changed.
    /// - `"protocol_upgraded"`: this device moved to the Signal protocol and re-keyed.
    /// - `"new_device"`: a contact added a device (their messages now also go to/come from it).
    /// - `"device_linked"`: a device was linked to OUR account (by us, on another device).
    /// - `"reset_blocked"`: someone signed in to OUR account tried to reset its devices; this
    ///   device cancelled it. The password is compromised.
    /// - `"unverified_device"`: the server lists a device on OUR account that no device of ours
    ///   vouched for. It is ignored (nothing is sent to it or accepted from it).
    pub kind: String,
    pub user_id: String,
    pub device_id: String,
    pub at_ms: u64,
    /// The peer had been verified under the old key (sending to them is blocked until accepted).
    pub was_verified: bool,
}

/// A decrypted inbound direct message and the conversation it belongs to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundDm {
    pub conversation_id: String,
    pub message_id: String,
    /// The sender's user id, or [`SELF_AUTHOR`] for a copy synced from one of our own devices.
    pub author_id: String,
    pub text: String,
    pub created_at: i64,
    /// The OTHER party of the conversation (also for a copy synced from our own device), so a
    /// device that never opened this conversation can list it.
    pub peer_user_id: String,
    /// When the sender says it was sent (`created_at` is when it reached us, which is what
    /// conversations are ordered by). Not persisted with the engine state.
    #[serde(skip)]
    pub sent_at: Option<i64>,
}

/// A DM conversation as the server lists it (routing metadata only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmConversation {
    pub conversation_id: String,
    pub peer_user_id: String,
    pub peer_username: String,
}

/// What a decrypted channel message is FOR, decided on the device from its plaintext. The
/// apps mark machine bodies with a `\u{2}skwod/<kind>|` prefix; a body without one is chat.
///
/// This never leaves the device. The server is given no hint of it — no "silent" flag, no
/// separate lane: every message is the same opaque envelope there, stored and pushed alike.
/// The recipient uses it after decrypting:
/// - `hidden`: state that is not part of the conversation (whiteboard strokes, chess
///   snapshots). Kept in its own local cache scope so it cannot push chat out of the window
///   the user sees, and never notified;
/// - `quiet`: part of the channel but not worth a notification (a like, a comment, an avatar
///   or address update, a system row).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Traffic {
    pub hidden: bool,
    pub quiet: bool,
}

impl Traffic {
    pub fn of(text: &str) -> Self {
        let Some(kind) = text.strip_prefix("\u{2}skwod/").and_then(|r| r.split_once('|')).map(|(k, _)| k) else { return Self::default() };
        match kind {
            "game" => Self { hidden: true, quiet: true },
            "comment" | "like" | "avatar" | "addr" | "sys" | "undecryptable" => Self { hidden: false, quiet: true },
            // A post, a story, an attachment, a shared track: people want to hear about those.
            _ => Self::default(),
        }
    }

    /// Should the user be notified of a message with this body from someone else?
    pub fn notifies(text: &str) -> bool {
        !Self::of(text).quiet
    }
}

/// One reaction as the message list carries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reaction {
    pub message_id: String,
    pub user_id: String,
    pub emoji_hash: String,
    pub emoji: Option<String>,
}

/// One page of channel traffic, decrypted.
#[derive(Debug, Default)]
pub struct ChannelPage {
    pub messages: Vec<InboundMessage>,
    /// Rows the server returned (decryptable or not) — a full page means "ask again".
    pub rows: usize,
    /// Highest `updated_at` among the rows (the next `after` cursor).
    pub max_updated_at: i64,
    /// Lowest `created_at` among the rows (the next `before` cursor).
    pub min_created_at: i64,
    /// Ids of every row on the page.
    pub ids: Vec<String>,
    /// The reactions of every message on the page (complete per message).
    pub reactions: Vec<Reaction>,
    /// When the channel was last cleared (server time), if ever. Everything cached from before
    /// it is gone on the server and must go here too.
    pub cleared_at: Option<i64>,
}

/// Where to read a channel from.
#[derive(Debug, Clone, Copy)]
pub enum PageCursor {
    /// The newest messages before this `created_at` (history, newest page first).
    Before(i64),
    /// Everything changed at or after this `updated_at`, oldest change first (catch-up).
    After(i64),
}

/// Result of one inbox pass.
#[derive(Debug, Default)]
pub struct InboxOutcome {
    /// Envelopes processed this pass.
    pub processed: u32,
    /// Members newly provisioned (host side).
    pub provisioned: u32,
    /// The server has more queued; ack and call again.
    pub more: bool,
}

/// How a persisted state blob was loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadOutcome {
    /// A v2 state was restored; the device keeps its identity and sessions.
    Restored,
    /// A protocol-v1 state was found. Space keys were carried over, a fresh libsignal identity was
    /// generated, and the device must register again.
    Migrated,
    /// The blob is unreadable; nothing was loaded.
    Unreadable,
}

/// Persisted engine state (postcard, behind [`STATE_MAGIC`]).
#[derive(Serialize, Deserialize)]
struct EngineState {
    store: Vec<u8>,
    user_id: Option<String>,
    device_id: Option<String>,
    delivery_key: [u8; 32],
    spaces: HashMap<String, [u8; 32]>,
    expected_provisioner: HashMap<String, String>,
    pinned_instance_key: Option<Vec<u8>>,
    trust_root: Option<Vec<u8>>,
    cert: Option<(Vec<u8>, u64)>,
    peer_delivery: HashMap<String, Vec<u8>>,
    send_keys: HashMap<String, SendKey>,
    recv_keys: HashMap<String, RecvKey>,
    legacy_peers: BTreeSet<String>,
    notices: Vec<SecurityNotice>,
    pending_acks: Vec<String>,
    inbox_dms: Vec<InboundDm>,
    blocked: BTreeSet<String>,
    siblings: BTreeMap<String, Vec<u8>>,
    pending_link: Option<(String, String)>,
    known_devices: HashMap<String, BTreeSet<String>>,
}

/// What a key backup carries: the long-term identity and what cannot be re-derived. No sessions,
/// no sender keys, no prekey private halves.
#[derive(Serialize, Deserialize)]
struct BackupState {
    identity: Vec<u8>,
    user_id: Option<String>,
    device_id: Option<String>,
    spaces: HashMap<String, [u8; 32]>,
    expected_provisioner: HashMap<String, String>,
    pinned_instance_key: Option<Vec<u8>>,
    trust_root: Option<Vec<u8>>,
    siblings: BTreeMap<String, Vec<u8>>,
}

/// Per-call voice key state (in memory only; a call does not outlive the process).
struct VoiceCall {
    channel_id: String,
    call_id: String,
    own_key: Vec<u8>,
    own_index: u32,
    /// Devices holding our CURRENT key.
    sent_to: BTreeSet<DeviceAddress>,
    /// Users our current key was handed to (to detect a leaver).
    audience: BTreeSet<String>,
    /// Other participants' keys: user id → key index → key.
    peers: BTreeMap<String, BTreeMap<u32, Vec<u8>>>,
}

/// A newly created E2EE space, ready to share with members.
pub struct SpaceHandle {
    pub server_id: String,
    pub channel_id: String,
    pub invite_code: String,
    /// Hex space key — hand to invitees out-of-band (or over a DM) so they can read channel names.
    pub space_key_hex: String,
}

/// The result of attempting to join a space: joined outright, or awaiting host approval. Carries the
/// host (server owner) identity so the member can ask them for the provision bundle.
pub struct JoinOutcome {
    pub server_id: String,
    pub pending: bool,
    pub host_user_id: Option<String>,
    pub host_device_id: Option<String>,
}

/// An existing invite for a space, as the host sees it in the manage/revoke list.
pub struct InviteInfo {
    pub code: String,
    /// Remaining/allowed uses (None = unlimited).
    pub max_uses: Option<i64>,
    pub use_count: i64,
    /// Epoch-ms expiry (None = never — legacy invites only; new ones always expire).
    pub expires_at: Option<i64>,
    /// "active", "revoked", or "expired".
    pub status: String,
    /// Accounts that signed up with this invite and are still waiting to be let in (0 from a
    /// server that does not say).
    pub waiting: i64,
    /// The invite has as many waiting accounts as it may have: nobody else can sign up with it
    /// until some are approved (or it is revoked).
    pub waiting_full: bool,
}

/// A role on a server: E2EE name (None without the space key) + permission bitmask.
pub struct RoleMeta {
    pub role_id: String,
    pub name: Option<String>,
    pub permissions: i64,
    pub is_default: bool,
}

/// A channel as seen after discovery: its id, decrypted name (None until we hold the space key), type.
pub struct ChannelMeta {
    pub channel_id: String,
    pub name: Option<String>,
    pub kind: String,
    /// `Some("feed")` for the server's hidden feed channel.
    pub purpose: Option<String>,
}

/// A decrypted inbound message with the metadata needed to persist + dedupe it locally.
#[derive(Debug, Clone)]
pub struct InboundMessage {
    pub message_id: String,
    pub author_id: String,
    pub text: String,
    pub created_at: i64,
    /// The message this one replies to (quoted reply), if any.
    pub reply_to_id: Option<String>,
    /// The author edited this message after sending.
    pub is_edited: bool,
    /// The message was deleted (server tombstone) — render as removed, drop cached content.
    pub deleted: bool,
    /// Not a message: the engine's stand-in for a row this device could not decrypt (`text` is
    /// [`undecryptable_body`]). The ONLY way a placeholder comes to be — a decrypted body that
    /// merely looks like one is neutralized (`cache::neutralize_reserved`) and is a message.
    pub undecryptable: bool,
}

/// The E2EE engine for one device.
pub struct Engine {
    api: ApiClient,
    /// Credential-less client used ONLY for sealed-sender deposits.
    sealed_api: ApiClient,
    store: SignalStore,
    user_id: Option<String>,
    device_id: Option<String>,
    /// Capability peers present to deposit sealed envelopes for us.
    delivery_key: [u8; 32],
    /// Per-space (server) symmetric keys used to encrypt channel/space names (metadata E2EE).
    spaces: HashMap<String, [u8; 32]>,
    /// The host (server owner) user id we expect to provision us for a given server. A space key is
    /// only accepted for a server from this host (or from our own other devices).
    expected_provisioner: HashMap<String, String>,
    /// The server's Ed25519 instance key pinned by the invite (if the app supplied one).
    pinned_instance_key: Option<Vec<u8>>,
    /// The sealed-sender trust root, pinned once verified against the instance key.
    trust_root: Option<Vec<u8>>,
    /// Our current sender certificate and its expiry (ms).
    cert: Option<(Vec<u8>, u64)>,
    /// Delivery keys of peer devices we know (address name → key).
    peer_delivery: HashMap<String, Vec<u8>>,
    /// Our sender keys per scope (`"channel:<id>"`).
    send_keys: HashMap<String, SendKey>,
    /// Received distributions: distribution id → (scope, sender).
    recv_keys: HashMap<String, RecvKey>,
    /// Users we had a protocol-v1 session with; each gets one "safety number changed" notice.
    legacy_peers: BTreeSet<String>,
    notices: Vec<SecurityNotice>,
    /// Envelope ids processed but not yet acknowledged (ack happens after state is persisted).
    pending_acks: Vec<String>,
    /// Decrypted DMs not yet taken by the application.
    inbox_dms: Vec<InboundDm>,
    /// Users we blocked. The server stops handing them our delivery key; this is the client-side
    /// half: anything they still get through is dropped unread.
    blocked: BTreeSet<String>,
    /// Our account's OTHER devices that this device has verified (device id → identity key): each
    /// was vouched for by a chain of link signatures ending at this device or at the device that
    /// linked us. Sync copies and keys go only to these, and "own device" privileges (synced DMs,
    /// space keys, provisioning) are granted only to these — never to a device merely because the
    /// server lists it under our account.
    siblings: BTreeMap<String, Vec<u8>>,
    /// A link we started on this (not yet registered) device: (link code, request id).
    pending_link: Option<(String, String)>,
    /// Device ids we have seen per contact, to notice when one adds a device.
    known_devices: HashMap<String, BTreeSet<String>>,

    // ---- in-memory only ----
    /// Members we've already provisioned this session ("<server_id>|<user>"), so repeated
    /// provision requests don't re-send the bundle every poll.
    provisioned: HashSet<String>,
    /// Provision requests decrypted from the inbox but not yet fulfilled: (requester, server).
    prov_queue: Vec<(DeviceAddress, String)>,
    /// channel_id → server_id for every channel this engine has placed: the confirmed ones
    /// (`guard.channel_servers`, persisted) plus what listings said about the rest (`guard.rs`).
    channel_servers: HashMap<String, String>,
    /// The LISTED (unconfirmed) channel placements, least recently listed first.
    listed_channels: VecDeque<String>,
    /// The members the direct-message payload being handled RIGHT NOW was wrapped with (a group
    /// message), or `None` for a bare one (a 1:1 message). Set per payload by `handle_content`.
    dm_group_claim: Option<Vec<String>>,
    /// Scopes whose current sender key reached someone since removed; rotated on the next check.
    stale_scopes: HashSet<String>,
    /// conversation_id → participant user ids (from the server's DM list).
    dm_participants: HashMap<String, Vec<String>>,
    voice: Vec<VoiceCall>,
    repaired: HashMap<String, Instant>,
    last_maintenance: Option<Instant>,
    /// When the signed prekey + last-resort key were last rotated EARLY (replay-memory pressure).
    last_pressure_rotation: Option<Instant>,
    last_sibling_check: Option<Instant>,
    /// Unverified own-account devices already reported this session.
    flagged_devices: HashSet<String>,
    /// When we last re-checked a user's directory entry because of inbound traffic.
    dir_refreshed: HashMap<String, Instant>,
    /// When an envelope under a certificate naming a device we hold ANOTHER key for was last
    /// reported (device name → when): one notice an hour per device, however many arrive.
    identity_rejects: HashMap<String, Instant>,
    /// Voice keys for calls we have not joined: (sender user, channel, call, index, key, when).
    pending_voice: Vec<(String, String, String, u32, Vec<u8>, Instant)>,
    /// Provenance of each owner pin in `expected_provisioner`; no entry = `legacy-unknown`.
    owner_sources: BTreeMap<String, trust::OwnerSource>,
    /// When a `legacy-unknown` owner pin was last put to the instance for re-confirmation.
    owner_rechecked: HashMap<String, Instant>,
    /// What the server says the owner of each server is. DISPLAY ONLY — see `note_claimed_owners`.
    claimed_owners: HashMap<String, String>,
    /// (server, user) provision requests from users we do not accept, seen before we kept a
    /// roster for that server.
    join_requests: HashSet<(String, String)>,
    /// Where membership events are shown (see [`EventSink`]).
    event_sink: Option<EventSink>,

    // ---- persisted, added after build 42 (see `trust::EngineExt`) ----
    /// What we trust about each contact's devices.
    contacts: BTreeMap<String, trust::ContactTrust>,
    /// The members we accept per server.
    rosters: BTreeMap<String, trust::Roster>,
    /// Membership events not yet shown (only without an event sink).
    events: Vec<SystemEvent>,
    /// Inbound payloads from listed-but-unvouched contact devices.
    held_inbound: Vec<trust::HeldInbound>,
    /// SHA-256 of every envelope whose content is in (or went through) `held_inbound`, oldest
    /// first. Reading one keeps no session, so libsignal's own replay protection never sees
    /// it; this is what stops the same envelope being held, and later delivered, twice.
    peeked: VecDeque<[u8; 32]>,
    /// What the server may not rewrite: conversation bindings, authenticated clears, the newest
    /// backup seen (`guard.rs`).
    guard: guard::GuardState,
    /// Sequence number of the backup exported last (recorded once its upload succeeds).
    exported_backup_seq: std::sync::atomic::AtomicU64,
    /// Received distribution ids, oldest first.
    recv_order: std::collections::VecDeque<String>,

    // ---- build 44a (see `accounts`) ----
    /// Persisted in its own state section.
    acct: accounts::AccountsState,
    /// What we sent, to send it again.
    sent: Box<dyn SentStore>,
    /// Persists the state (and an outgoing message) before anything encrypted leaves.
    state_sink: Option<StateSink>,
    /// This session has been bound to this device (in memory: once per engine).
    bound: bool,
    /// Recovery requests on this account already reported this session.
    flagged_recoveries: HashSet<String>,
    /// The row of a message that was persisted but has not gone out yet (see `take_unsent`).
    unsent: Option<(String, String)>,
    /// From when a recovery-key restore is instant (as last listed by the server).
    recovery_key_instant_from: Option<i64>,
    // ---- persisted, added in build 44 (see `content::ContentExt`) ----
    /// Decrypted DM edits / deletes / reactions / replies not yet applied by the application.
    dm_ops: Vec<content::DmOp>,
    /// When our sealed-mailbox delivery key was last replaced, and whether a membership change
    /// is waiting for the next replacement (persisted; see `rest::DeliveryRotation`).
    delivery: rest::DeliveryRotation,
    /// Last attempt to replace the delivery key (in memory: a failed attempt is not repeated
    /// on every sync).
    delivery_attempt: Option<Instant>,
    /// When the list of servers we are in was last compared with what we remember (in memory).
    servers_checked: Option<Instant>,
    /// Sender devices seen writing wire v3, and provision requests held over (persisted).
    b45: Build45Ext,
    /// What the server's last "waiting" answer in this run said: contested or not. In memory
    /// only — `None` after a launch until the waiting screen has asked again (and it asks at
    /// once), so a request contested while the app was closed never shows a countdown.
    recovery_contested: Option<bool>,
    /// Siblings a backup restore brought back, NOT yet confirmed (audit M2): device id →
    /// identity key. A backup may be stale — the host can serve an older blob that still opens
    /// under the recovery key — and list a device that was removed since. These are no
    /// siblings: nothing is sent to them, nothing they vouch for is admitted, and nothing they
    /// send is read. An unconfirmed device can never confirm itself or anyone else. One is
    /// confirmed only by the sibling set of an ALREADY-CONFIRMED sibling (`Content::Siblings`),
    /// or by the user, one device at a time ([`Engine::confirm_restored_sibling`]). A restored
    /// install with no confirmed sibling at all therefore keeps every restored sibling
    /// unconfirmed until the user confirms it. Persisted.
    unconfirmed_siblings: BTreeMap<String, Vec<u8>>,
    /// This install took its identity from a backup (audit M2). Every link signature this
    /// identity made BEFORE then is the host's to replay — also for a device linked after the
    /// backup was written and removed since — so a device vouched for by such a signature alone
    /// joins `unconfirmed_siblings` instead of the siblings. Persisted with them.
    restored_install: bool,
    /// Identity keys of devices THIS install linked after its restore: their link signatures
    /// are its own, and admit them as usual. Persisted with the above; bounded.
    linked_here: BTreeSet<Vec<u8>>,
    /// This engine runs in the notification extension: it reads mail and creates, rotates and
    /// uploads NO keys ([`Engine::set_passive`]). In memory, never persisted.
    passive: bool,
    /// Abuse reports sealed to this account as the instance owner, not yet taken.
    reports: Vec<content::InboundReport>,
}

impl Engine {
    /// Create an engine for a fresh device identity (call [`Engine::register`] next).
    pub fn new(api: ApiClient) -> Self {
        let sealed_api = api.anonymous();
        Self {
            api,
            sealed_api,
            store: SignalStore::generate(),
            user_id: None,
            device_id: None,
            delivery_key: skwod_crypto::random_bytes(),
            spaces: HashMap::new(),
            expected_provisioner: HashMap::new(),
            pinned_instance_key: None,
            trust_root: None,
            cert: None,
            peer_delivery: HashMap::new(),
            send_keys: HashMap::new(),
            recv_keys: HashMap::new(),
            legacy_peers: BTreeSet::new(),
            notices: Vec::new(),
            pending_acks: Vec::new(),
            inbox_dms: Vec::new(),
            blocked: BTreeSet::new(),
            siblings: BTreeMap::new(),
            pending_link: None,
            known_devices: HashMap::new(),
            provisioned: HashSet::new(),
            prov_queue: Vec::new(),
            channel_servers: HashMap::new(),
            listed_channels: VecDeque::new(),
            dm_group_claim: None,
            stale_scopes: HashSet::new(),
            dm_participants: HashMap::new(),
            voice: Vec::new(),
            repaired: HashMap::new(),
            last_maintenance: None,
            last_pressure_rotation: None,
            last_sibling_check: None,
            flagged_devices: HashSet::new(),
            dir_refreshed: HashMap::new(),
            identity_rejects: HashMap::new(),
            pending_voice: Vec::new(),
            owner_sources: BTreeMap::new(),
            owner_rechecked: HashMap::new(),
            claimed_owners: HashMap::new(),
            join_requests: HashSet::new(),
            event_sink: None,
            contacts: BTreeMap::new(),
            rosters: BTreeMap::new(),
            events: Vec::new(),
            held_inbound: Vec::new(),
            peeked: VecDeque::new(),
            guard: guard::GuardState::default(),
            exported_backup_seq: std::sync::atomic::AtomicU64::new(0),
            recv_order: std::collections::VecDeque::new(),
            acct: accounts::AccountsState::default(),
            sent: Box::new(MemorySentStore::default()),
            state_sink: None,
            bound: false,
            flagged_recoveries: HashSet::new(),
            unsent: None,
            recovery_key_instant_from: None,
            dm_ops: Vec::new(),
            delivery: rest::DeliveryRotation::default(),
            delivery_attempt: None,
            servers_checked: None,
            b45: Build45Ext::default(),
            recovery_contested: None,
            unconfirmed_siblings: BTreeMap::new(),
            restored_install: false,
            linked_here: BTreeSet::new(),
            passive: false,
            reports: Vec::new(),
        }
    }

    /// A fresh engine on the same server connection, keeping what belongs to the application
    /// rather than to the identity (the event sink).
    fn reset(&mut self) {
        let sink = self.event_sink.take();
        let state_sink = self.state_sink.take();
        let sent = std::mem::replace(&mut self.sent, Box::new(MemorySentStore::default()));
        *self = Engine::new(self.api.clone());
        self.event_sink = sink;
        self.state_sink = state_sink;
        self.sent = sent;
    }

    pub fn device_id(&self) -> Option<&str> {
        self.device_id.as_deref()
    }

    pub fn user_id(&self) -> Option<&str> {
        self.user_id.as_deref()
    }

    /// This device's libsignal address. Errors until the device has registered.
    fn local(&self) -> Result<DeviceAddress, EngineError> {
        // An install that was superseded or removed does nothing more as that device; one whose
        // restore is waiting for approval is not that device yet.
        if self.acct.superseded {
            return Err(EngineError::Superseded);
        }
        if self.acct.removed {
            return Err(EngineError::DeviceRemoved);
        }
        if let Some(completes_at) = self.acct.recovery_pending {
            return Err(EngineError::RecoveryPending(completes_at, self.recovery_contested == Some(true)));
        }
        match (&self.user_id, &self.device_id) {
            (Some(u), Some(d)) => Ok(DeviceAddress::new(u.clone(), d.clone())),
            _ => Err(EngineError::NotRegistered),
        }
    }

    // ---- persistence ----

    /// Snapshot the engine's persistable state (everything but the network client).
    pub fn export_state(&self) -> Vec<u8> {
        let state = EngineState {
            store: self.store.to_bytes(),
            user_id: self.user_id.clone(),
            device_id: self.device_id.clone(),
            delivery_key: self.delivery_key,
            spaces: self.spaces.clone(),
            expected_provisioner: self.expected_provisioner.clone(),
            pinned_instance_key: self.pinned_instance_key.clone(),
            trust_root: self.trust_root.clone(),
            cert: self.cert.clone(),
            peer_delivery: self.peer_delivery.clone(),
            send_keys: self.send_keys.clone(),
            recv_keys: self.recv_keys.clone(),
            legacy_peers: self.legacy_peers.clone(),
            notices: self.notices.clone(),
            pending_acks: self.pending_acks.clone(),
            inbox_dms: self.inbox_dms.clone(),
            blocked: self.blocked.clone(),
            siblings: self.siblings.clone(),
            pending_link: self.pending_link.clone(),
            known_devices: self.known_devices.clone(),
        };
        let ext = trust::EngineExt {
            contacts: self.contacts.clone(),
            rosters: self.rosters.clone(),
            events: self.events.clone(),
            held_inbound: self.held_inbound.clone(),
            recv_order: self.recv_order.clone(),
            owner_sources: self.owner_sources.clone(),
        };
        let mut out = STATE_MAGIC.to_vec();
        out.extend(postcard::to_stdvec(&state).expect("engine state serialization is infallible"));
        // Everything added after build 42 follows the original struct (which can never grow:
        // postcard is not self-describing), behind a version byte. Build 42 ignores the tail.
        out.push(trust::EXT_VERSION);
        out.extend(postcard::to_stdvec(&ext).expect("engine state serialization is infallible"));
        // Later additions: tagged, length-prefixed sections, each skippable by a build that
        // does not know it. Build 44 writes two: accounts (44a) and content (44b).
        // Build 45: delivery-key rotation bookkeeping (written first so the two build-44
        // sections stay last). Skipped by a build that does not know it.
        // (Audit M2, written first so the later sections keep their order at the end.)
        let restore_trust = (&self.unconfirmed_siblings, self.restored_install, &self.linked_here);
        accounts::write_section(&mut out, SECTION_UNCONFIRMED, &postcard::to_stdvec(&restore_trust).expect("engine state serialization is infallible"));
        accounts::write_section(&mut out, SECTION_PEEKED, &postcard::to_stdvec(&self.peeked).expect("engine state serialization is infallible"));
        accounts::write_section(&mut out, guard::SECTION_GUARD, &postcard::to_stdvec(&self.guard).expect("engine state serialization is infallible"));
        accounts::write_section(&mut out, rest::SECTION_DELIVERY, &postcard::to_stdvec(&self.delivery).expect("engine state serialization is infallible"));
        accounts::write_section(&mut out, SECTION_BUILD45, &postcard::to_stdvec(&self.b45_for_export()).expect("engine state serialization is infallible"));
        accounts::write_section(&mut out, accounts::SECTION_ACCOUNTS, &postcard::to_stdvec(&self.acct).expect("engine state serialization is infallible"));
        let content = content::ContentExt { dm_ops: self.dm_ops.clone(), reports: self.reports.clone() };
        accounts::write_section(&mut out, content::SECTION_CONTENT, &postcard::to_stdvec(&content).expect("engine state serialization is infallible"));
        out
    }

    /// Load a persisted state blob: a v2 state is restored as-is; a protocol-v1 state (builds
    /// 29–40) is **migrated** — see [`LoadOutcome::Migrated`].
    pub fn load_state(&mut self, bytes: &[u8]) -> LoadOutcome {
        if let Some(rest) = bytes.strip_prefix(STATE_MAGIC) {
            let Ok((s, tail)) = postcard::take_from_bytes::<EngineState>(rest) else { return LoadOutcome::Unreadable };
            let Ok(store) = SignalStore::from_bytes(&s.store) else { return LoadOutcome::Unreadable };
            // No tail: a build-42 state (contacts are pinned and rosters baselined on first use).
            let (ext, sections) = match tail.split_first() {
                None => (trust::EngineExt::default(), &[][..]),
                Some((&trust::EXT_VERSION, body)) => match postcard::take_from_bytes::<trust::EngineExt>(body) {
                    Ok(parsed) => parsed,
                    Err(_) => return LoadOutcome::Unreadable,
                },
                Some(_) => return LoadOutcome::Unreadable,
            };
            // No sections: a build-43 state (defaults; the install secret is made on first use
            // and recorded by the server when this device first binds). A section this build
            // does not know (a NEWER build's) is skipped: nothing in it is needed to keep the
            // identity and sessions.
            let Some(sections) = accounts::read_sections(sections) else { return LoadOutcome::Unreadable };
            let section = |tag: u8| sections.iter().find(|(t, _)| *t == tag).map(|(_, body)| *body);
            self.acct = match section(accounts::SECTION_ACCOUNTS) {
                Some(body) => match postcard::from_bytes(body) {
                    Ok(acct) => acct,
                    Err(_) => return LoadOutcome::Unreadable,
                },
                None => accounts::AccountsState::default(),
            };
            let content = match section(content::SECTION_CONTENT) {
                Some(body) => match postcard::from_bytes::<content::ContentExt>(body) {
                    Ok(c) => c,
                    Err(_) => return LoadOutcome::Unreadable,
                },
                None => content::ContentExt::default(),
            };
            self.dm_ops = content.dm_ops;
            self.reports = content.reports;
            // Absent (a build ≤ 44 state): never rotated, so the first maintenance pass does.
            self.delivery = section(rest::SECTION_DELIVERY).and_then(|body| postcard::from_bytes(body).ok()).unwrap_or_default();
            // Absent (a build ≤ 44 state): nothing was ever read that way.
            self.peeked = section(SECTION_PEEKED).and_then(|body| postcard::from_bytes(body).ok()).unwrap_or_default();
            // Absent: conversations are bound on their next use; no backup has been seen.
            self.guard = Self::bound_guard(section(guard::SECTION_GUARD).and_then(|body| postcard::from_bytes(body).ok()).unwrap_or_default());
            // Confirmed placements are kept across restarts; listed ones are rebuilt from the
            // listings (and can never displace a confirmed one).
            self.channel_servers = self.guard.channel_servers.iter().map(|(c, s)| (c.clone(), s.clone())).collect();
            self.listed_channels.clear();
            // Absent (a build ≤ 44 state): no sender has been seen on v3 yet, nothing held over.
            self.b45 = section(SECTION_BUILD45).and_then(|body| postcard::from_bytes(body).ok()).unwrap_or_default();
            // Absent: no restore is waiting for its siblings to confirm.
            let restore_trust: (BTreeMap<String, Vec<u8>>, bool, BTreeSet<Vec<u8>>) =
                section(SECTION_UNCONFIRMED).and_then(|body| postcard::from_bytes(body).ok()).unwrap_or_default();
            (self.unconfirmed_siblings, self.restored_install, self.linked_here) = restore_trust;
            self.bound = false;
            // (after recv_keys / send_keys are in place, below)
            self.contacts = ext.contacts;
            self.rosters = ext.rosters;
            self.events = ext.events;
            self.held_inbound = ext.held_inbound;
            self.recv_order = ext.recv_order;
            // Pins with no recorded source (every pin of a build-42 state) stay `legacy-unknown`.
            self.owner_sources = ext.owner_sources;
            self.store = store;
            self.user_id = s.user_id;
            self.device_id = s.device_id;
            self.delivery_key = s.delivery_key;
            self.spaces = s.spaces;
            self.expected_provisioner = s.expected_provisioner;
            self.pinned_instance_key = s.pinned_instance_key;
            self.trust_root = s.trust_root;
            self.cert = s.cert;
            self.peer_delivery = s.peer_delivery;
            self.send_keys = s.send_keys;
            self.recv_keys = s.recv_keys;
            self.legacy_peers = s.legacy_peers;
            self.notices = s.notices;
            self.pending_acks = s.pending_acks;
            self.inbox_dms = s.inbox_dms;
            self.blocked = s.blocked;
            self.siblings = s.siblings;
            self.pending_link = s.pending_link;
            self.known_devices = s.known_devices;
            self.backfill_key_times();
            self.reset_session_bookkeeping();
            return LoadOutcome::Restored;
        }
        match legacy::parse(bytes) {
            Some(old) => {
                // Explicit protocol migration: nothing of the v1 identity or sessions is reused.
                self.reset();
                self.spaces = old.spaces;
                self.expected_provisioner = old.expected_provisioner;
                self.legacy_peers = old.peers;
                self.notices.push(SecurityNotice {
                    kind: "protocol_upgraded".into(),
                    user_id: String::new(),
                    device_id: old.old_device_id.unwrap_or_default(),
                    at_ms: now_ms(),
                    was_verified: false,
                });
                LoadOutcome::Migrated
            }
            None => LoadOutcome::Unreadable,
        }
    }

    fn reset_session_bookkeeping(&mut self) {
        self.provisioned.clear();
        self.prov_queue.clear();
        self.stale_scopes.clear();
        self.dm_participants.clear();
        self.voice.clear();
        self.repaired.clear();
        self.last_maintenance = None;
        self.last_sibling_check = None;
        self.flagged_devices.clear();
        self.dir_refreshed.clear();
        self.identity_rejects.clear();
        self.pending_voice.clear();
        self.flagged_recoveries.clear();
    }

    /// The long-term state a key backup stores: the identity, space keys, owner pins WITH their
    /// provenance, and what this device trusts about its contacts (their devices and verified
    /// marks) — never sessions, sender keys, prekeys or the install secret.
    pub fn export_backup(&self) -> Vec<u8> {
        let mut out = postcard::to_stdvec(&BackupState {
            identity: self.store.export_identity(),
            user_id: self.user_id.clone(),
            device_id: self.device_id.clone(),
            spaces: self.spaces.clone(),
            expected_provisioner: self.expected_provisioner.clone(),
            pinned_instance_key: self.pinned_instance_key.clone(),
            trust_root: self.trust_root.clone(),
            siblings: self.siblings.clone(),
        })
        .expect("backup serialization is infallible");
        // Build 44a's additions follow as a tagged section (a build-43 restore ignores them).
        out.extend(self.backup_ext());
        // Build 45: the backup's sequence number, inside what the recovery key seals.
        accounts::write_section(&mut out, guard::SECTION_BACKUP_SEQ, &postcard::to_stdvec(&self.next_backup_seq()).expect("backup serialization is infallible"));
        out
    }

    /// Replace this engine's identity with one from a backup and bring it back online: the restored
    /// device keeps its identity key and device id (so peers' safety numbers do not change) but
    /// gets all-new prekeys, because prekey private halves are never backed up. If the server no
    /// longer knows the device, it is registered again under the restored identity.
    ///
    /// Moving a device to this install is a RECOVERY on the server: unless this install already
    /// is the device's current one, it needs approval from another of the account's devices,
    /// the registration PIN (`pin`), or a 7-day wait the account's devices can cancel. Until
    /// then this fails with [`EngineError::RecoveryPending`]; the restored state is kept and
    /// [`Engine::retry_recovery`] completes it. Once it completes, the install the device was on
    /// before is superseded and stops.
    ///
    /// `backup_key` is the key the backup was sealed under — which only the recovery key
    /// unwraps. With it the restore PROVES the recovery key to the server and completes at
    /// once; so does a restore whose device was erased (it comes back as a device of its own).
    pub async fn restore_backup(&mut self, backup: &[u8], pin: Option<&str>, backup_key: Option<[u8; 32]>) -> Result<(), EngineError> {
        let (b, tail) = postcard::take_from_bytes::<BackupState>(backup).map_err(|_| EngineError::Serde)?;
        let store = SignalStore::from_bytes(&b.identity)?;
        // Before anything is replaced: not a backup older than one this install has seen.
        let backup_seq = self.check_backup_fresh(tail)?.max(self.guard.backup_seq);
        let interim_device = self.device_id.clone();
        // The install secret is this INSTALL's, not the identity's: a restore request filed
        // before the backup could be fetched (`request_backup_access`) was made with its hash,
        // and the re-key below must come from the same install.
        let install_secret = self.acct.install_secret;
        self.reset();
        self.acct.install_secret = install_secret;
        self.guard.backup_seq = backup_seq;
        self.store = store;
        self.user_id = b.user_id;
        self.device_id = b.device_id;
        self.spaces = b.spaces;
        self.expected_provisioner = b.expected_provisioner;
        self.pinned_instance_key = b.pinned_instance_key;
        self.trust_root = b.trust_root;
        self.siblings = b.siblings;
        self.apply_backup_ext(tail);
        // The backup's siblings are UNCONFIRMED (audit M2): it may be an older blob than the
        // account's latest, listing a device removed since. Kept aside until a live sibling
        // confirms the current set, or the user does.
        self.unconfirmed_siblings = std::mem::take(&mut self.siblings);
        self.restored_install = true;
        self.acct.recovery_backup_key = backup_key;
        match self.device_id.clone() {
            Some(device_id) if Some(&device_id) != interim_device.as_ref() => {
                // Not this device until the server has moved it here.
                self.acct.recovery_pending = Some(0);
                self.retry_recovery(pin).await
            }
            _ => {
                self.device_id = None;
                self.register_restored().await?;
                self.finish_restore().await;
                Ok(())
            }
        }
    }

    /// The restored identity has no device row (it was erased, or never had one): seat it as a
    /// device of its own — on proof of the recovery key when we hold it, else as any device.
    async fn register_restored(&mut self) -> Result<String, EngineError> {
        let was = self.acct.recovery_pending.take();
        match self.register_with(None, None, self.acct.recovery_backup_key.is_some()).await {
            Ok(id) => Ok(id),
            Err(e) => {
                self.acct.recovery_pending = was;
                Err(e)
            }
        }
    }

    /// A recovery-key proof for `purpose` on `target`: a signature, by the key derived from the
    /// backup key, over a nonce the server just issued. `None` when we hold no backup key or
    /// the account's backup has no verifier (made before build 44).
    async fn recovery_auth(&mut self, purpose: &str, target: &[u8]) -> Option<String> {
        let key = self.acct.recovery_backup_key?;
        let user_id = self.user_id.clone()?;
        let v = self.api.post("/api/e2ee/key-backup/challenge", serde_json::json!({})).await.ok()?;
        let message = skwod_crypto::backup::recovery_auth_message(&user_id, purpose, target, v["nonce"].as_str()?, &self.install_hash());
        skwod_crypto::backup::sign_recovery_auth(&key, &message).map(|sig| B64.encode(sig))
    }

    /// The short code of the restore THIS install is asking for (`XXXX-XXXX`): show it next to
    /// "approve this on another device". The approving device shows the same code for the same
    /// request.
    pub fn recovery_fingerprint(&mut self) -> String {
        skwod_crypto::backup::recovery_fingerprint(&self.install_hash())
    }

    /// Complete a restore that was left waiting ([`EngineError::RecoveryPending`]): ask the
    /// server again — after another device approved, with the PIN, or once the wait is over.
    pub async fn retry_recovery(&mut self, pin: Option<&str>) -> Result<(), EngineError> {
        let (Some(device_id), Some(_)) = (self.device_id.clone(), self.acct.recovery_pending) else {
            return Err(EngineError::Protocol("no restore is waiting"));
        };
        // The keys generated for an attempt that was refused are dropped again.
        let snapshot = self.store.to_bytes();
        let (mut body, payload) = self.key_upload_body()?;
        let install_hash = self.install_hash();
        body["delivery_key"] = serde_json::json!(B64.encode(self.delivery_key));
        body["install_hash"] = serde_json::json!(B64.encode(&install_hash));
        // The secret itself: the server completes a recovery only for the install that holds
        // the preimage of the hash the request was made with.
        body["install_secret"] = serde_json::json!(B64.encode(self.install_secret()));
        body["device_name_ciphertext"] = serde_json::json!(self.name_for_registration(false));
        if let Some(pin) = pin {
            body["pin"] = serde_json::json!(pin);
        }
        // Proof of the recovery key: with it the server moves the device here at once.
        if let Some(auth) = self.recovery_auth("rekey", device_id.as_bytes()).await {
            body["recovery_auth"] = serde_json::json!(auth);
        }
        // Signed by the restored identity over exactly these keys and this install's secret
        // hash: the server refuses a rekey on a session token alone.
        let payload = skwod_crypto::link::op_payload(&[&payload, &install_hash]);
        let ts = now_ms();
        let user_id = self.user_id.clone().ok_or(EngineError::NotRegistered)?;
        let proof = format!("{ts}.{}", B64.encode(self.store.sign_device_op("rekey", &user_id, &device_id, ts, &payload)?));
        match self.api.signed(reqwest::Method::POST, &format!("/api/e2ee/devices/{}/rekey", enc(&device_id)), Some(body), &proof).await {
            Ok(resp) => {
                self.note_recovery_key_consumed(&resp);
                self.acct.recovery_pending = None;
                self.acct.recovery_backup_key = None;
                self.bound = true;
                self.finish_restore().await;
                Ok(())
            }
            // The device is no longer on the account at all (it was erased): come back as a
            // device of our own, under the same identity.
            Err(ClientError::Status { status: 404, .. }) => {
                if let Ok(store) = SignalStore::from_bytes(&snapshot) {
                    self.store = store;
                }
                self.device_id = None;
                self.register_restored().await?;
                self.acct.recovery_backup_key = None;
                self.finish_restore().await;
                Ok(())
            }
            Err(e) => {
                if let Ok(store) = SignalStore::from_bytes(&snapshot) {
                    self.store = store;
                }
                let e = EngineError::from(e);
                if let EngineError::RecoveryPending(at, contested) = &e {
                    self.acct.recovery_pending = Some(*at);
                    self.recovery_contested = Some(*contested);
                }
                Err(e)
            }
        }
    }

    /// When a waiting restore can complete by itself (unix ms), if one is waiting.
    pub fn recovery_pending(&self) -> Option<i64> {
        self.acct.recovery_pending.or(self.b45.backup_request_pending)
    }

    /// Whether the waiting restore was CONTESTED, as of the server's last answer: another
    /// install asked to restore the same device, so it completes only by an approval (or the
    /// PIN), never by the hold.
    pub fn recovery_contested(&self) -> bool {
        self.recovery_contested == Some(true) && self.recovery_pending().is_some()
    }

    /// Whether the server has answered about the waiting restore in this run — until it has,
    /// whether it is contested is not known (it may have been contested while the app was
    /// closed), so no countdown is promised.
    pub fn recovery_status_known(&self) -> bool {
        self.recovery_contested.is_some()
    }

    /// Whether a restore is waiting at the re-key step (the backup is already open here), as
    /// opposed to waiting to be handed the backup at all.
    pub fn rekey_pending(&self) -> bool {
        self.acct.recovery_pending.is_some()
    }

    async fn finish_restore(&mut self) {
        self.acct.restored_at = Some(now_ms() as i64);
        self.reconfirm_restored().await;
        self.announce_restore().await;
        // Restored devices of the account wait for a confirmation (audit M2): say so once, so
        // the user knows to open Devices ("Is this your device?").
        if !self.unconfirmed_siblings.is_empty() {
            let user_id = self.user_id.clone().unwrap_or_default();
            self.notices.push(SecurityNotice { kind: "restored_devices_unconfirmed".into(), user_id, device_id: String::new(), at_ms: now_ms(), was_verified: false });
        }
    }

    // ---- security notices / verification ----

    /// Drain pending security notices ("safety number changed", "protocol upgraded").
    pub fn take_security_notices(&mut self) -> Vec<SecurityNotice> {
        self.collect_identity_changes();
        std::mem::take(&mut self.notices)
    }

    fn collect_identity_changes(&mut self) {
        for c in self.store.take_identity_changes() {
            self.notices.push(SecurityNotice {
                kind: "identity_changed".into(),
                user_id: c.address.user_id,
                device_id: c.address.device_id,
                at_ms: c.at_ms,
                was_verified: c.was_verified,
            });
        }
    }

    /// First libsignal contact with a user we had a v1 session with: their keys are all new, so
    /// say so once (the protocol-upgrade equivalent of "safety number changed").
    fn note_legacy_peer(&mut self, peer: &DeviceAddress) {
        if self.legacy_peers.remove(&peer.user_id) {
            self.notices.push(SecurityNotice {
                kind: "identity_changed".into(),
                user_id: peer.user_id.clone(),
                device_id: peer.device_id.clone(),
                at_ms: now_ms(),
                was_verified: false,
            });
        }
    }

    /// Pin the server's Ed25519 instance key (from the invite). The sealed-sender trust root is only
    /// accepted if this key signed it. Changing the pin drops any root accepted under another key.
    pub fn set_pinned_instance_key(&mut self, key: Vec<u8>) {
        if self.pinned_instance_key.as_ref() != Some(&key) {
            self.pinned_instance_key = Some(key);
            self.trust_root = None;
            self.cert = None;
        }
    }

    // ---- registration + prekey upkeep ----

    fn b64_signed(k: &SignedPreKeyUpload) -> serde_json::Value {
        serde_json::json!({ "id": k.id, "public": B64.encode(&k.public), "signature": B64.encode(&k.signature) })
    }
    fn b64_kyber(k: &KyberPreKeyUpload) -> serde_json::Value {
        serde_json::json!({ "id": k.id, "public": B64.encode(&k.public), "signature": B64.encode(&k.signature) })
    }
    fn b64_prekey(k: &PreKeyUpload) -> serde_json::Value {
        serde_json::json!({ "id": k.id, "public": B64.encode(&k.public) })
    }

    /// One uploaded batch of public keys as a single length-prefixed blob — a field of a
    /// device-proof payload (the server builds the same bytes from what it received).
    fn keys_blob<'a>(keys: impl Iterator<Item = &'a Vec<u8>>) -> Vec<u8> {
        let keys: Vec<&[u8]> = keys.map(Vec::as_slice).collect();
        skwod_crypto::link::op_payload(&keys)
    }

    /// Generate a full set of fresh prekeys and return the upload body (shared by register/rekey)
    /// together with the device-proof payload a REKEY must sign: every key in the body plus
    /// `delivery_key`, so the proof cannot be reused with other keys.
    fn key_upload_body(&mut self) -> Result<(serde_json::Value, Vec<u8>), EngineError> {
        let signed = self.store.generate_signed_prekey()?;
        let last_resort = self.store.generate_last_resort_kyber()?;
        let one_time = self.store.generate_one_time_prekeys(PREKEY_BATCH)?;
        let one_time_kyber = self.store.generate_one_time_kyber(PREKEY_BATCH)?;
        let payload = skwod_crypto::link::op_payload(&[
            &self.store.registration_id().to_be_bytes(),
            &signed.public,
            &last_resort.public,
            &self.delivery_key,
            &Self::keys_blob(one_time.iter().map(|k| &k.public)),
            &Self::keys_blob(one_time_kyber.iter().map(|k| &k.public)),
        ]);
        let body = serde_json::json!({
            "protocol_version": PROTOCOL_VERSION,
            "registration_id": self.store.registration_id(),
            "identity_key": B64.encode(self.store.identity_key()),
            "signed_prekey": Self::b64_signed(&signed),
            "last_resort_kyber_prekey": Self::b64_kyber(&last_resort),
            "one_time_prekeys": one_time.iter().map(Self::b64_prekey).collect::<Vec<_>>(),
            "one_time_kyber_prekeys": one_time_kyber.iter().map(Self::b64_kyber).collect::<Vec<_>>(),
        });
        Ok((body, payload))
    }

    /// Register this device with the server: publish the identity key, signed prekey, last-resort
    /// Kyber prekey and one-time prekeys. Returns the device id.
    ///
    /// Refuses (with [`EngineError::UpdateRequired`]) a server that does not speak protocol v2.
    pub async fn register(&mut self) -> Result<String, EngineError> {
        self.register_with(None, None, false).await
    }

    /// Recovery when no device of the account is left to link from (and there is no key backup):
    /// **reset** the account's device list and register this device as its only one. Every other
    /// device of the account is removed and contacts see the safety number change.
    ///
    /// A session token is not enough for this. With a registration-lock PIN set, `pin` must be
    /// right. Without one, the first call only *requests* the reset and fails with
    /// [`EngineError::ResetPending`]: the account's existing devices are told and any of them
    /// cancels it automatically; if none does within 7 days, calling again (same device, same
    /// identity) completes it.
    pub async fn register_reset(&mut self, pin: Option<&str>) -> Result<String, EngineError> {
        self.register_reset_with(pin, false).await
    }

    /// [`Engine::register_reset`] for an account whose registration-lock PIN is lost: the reset
    /// goes through the full 7-day hold (never the PIN's shortcut), as if no PIN were set.
    pub async fn register_reset_forgot_pin(&mut self) -> Result<String, EngineError> {
        self.register_reset_with(None, true).await
    }

    async fn register_reset_with(&mut self, pin: Option<&str>, forgot_pin: bool) -> Result<String, EngineError> {
        // A reset is a new start for this install: whatever said it had been removed or
        // superseded as a device of the old set no longer applies.
        let was = (self.acct.removed, self.acct.superseded, self.acct.recovery_pending.take());
        (self.acct.removed, self.acct.superseded) = (false, false);
        match self.register_with(None, Some((pin, forgot_pin)), false).await {
            Ok(id) => {
                self.siblings.clear();
                Ok(id)
            }
            Err(e) => {
                (self.acct.removed, self.acct.superseded, self.acct.recovery_pending) = was;
                Err(e)
            }
        }
    }

    async fn register_with(&mut self, link: Option<(String, Vec<u8>)>, reset: Option<(Option<&str>, bool)>, recovered: bool) -> Result<String, EngineError> {
        self.refuse_if_passive()?;
        let identity = self.api.get("/api/instance/identity").await?;
        match identity["e2ee_protocol"].as_u64() {
            Some(v) if v == PROTOCOL_VERSION as u64 => {}
            Some(v) if v > PROTOCOL_VERSION as u64 => {
                return Err(EngineError::UpdateRequired("update required: this skwod uses a newer encryption protocol than this app".into()))
            }
            _ => {
                return Err(EngineError::UpdateRequired(
                    "this skwod's server has not been updated to the Signal protocol yet; ask the host to update it".into(),
                ))
            }
        }
        // Prekeys made for a registration the server refuses (link required, reset pending, PIN
        // needed) are dropped again rather than piling up with every attempt.
        let snapshot = self.store.to_bytes();
        let (mut body, _) = self.key_upload_body()?;
        body["delivery_key"] = serde_json::json!(B64.encode(self.delivery_key));
        // Known only to this install; the server keeps the hash and binds sessions against it.
        body["install_hash"] = serde_json::json!(B64.encode(self.install_hash()));
        if let Some((device_id, signature)) = &link {
            body["link"] = serde_json::json!({ "device_id": device_id, "signature": B64.encode(signature) });
        }
        if let Some((pin, forgot_pin)) = reset {
            body["force"] = serde_json::json!(true);
            body["pin"] = serde_json::json!(pin);
            body["forgot_pin"] = serde_json::json!(forgot_pin);
            // A reset starts the account's device set over; so does its account key.
            self.acct.account_key = None;
        }
        // A restore whose device row is gone: proof of the recovery key admits it.
        if recovered {
            let identity = self.store.identity_key();
            if let Some(auth) = self.recovery_auth("register", &identity).await {
                body["recovery_auth"] = serde_json::json!(auth);
            }
        }
        // A first (or reset) device makes the account key; a linked one got it with the approval
        // (a restored one, from the backup).
        body["device_name_ciphertext"] = serde_json::json!(self.name_for_registration(link.is_none() && !recovered));
        let resp = match self.api.post("/api/e2ee/devices/register", body).await {
            Ok(resp) => resp,
            Err(e) => {
                if let Ok(store) = SignalStore::from_bytes(&snapshot) {
                    self.store = store;
                }
                return Err(e.into());
            }
        };
        // The delivery key just registered is brand new: nobody to take it back from yet.
        self.delivery = rest::DeliveryRotation { rotated_at: now_ms(), due_since: None };
        self.note_recovery_key_consumed(&resp);
        let device_id = resp["device_id"].as_str().ok_or(EngineError::Protocol("missing device_id"))?.to_string();
        let user_id = resp["user_id"].as_str().ok_or(EngineError::Protocol("missing user_id"))?.to_string();
        self.device_id = Some(device_id.clone());
        self.user_id = Some(user_id);
        self.cert = None;
        // The registering session IS this device's, as far as the server is concerned.
        self.bound = true;
        Ok(device_id)
    }

    /// Keep the server stocked: refill one-time prekeys when they run low and rotate the signed
    /// prekey + last-resort Kyber key weekly. Cheap; throttled to once per half hour.
    pub async fn maintain_keys(&mut self) -> Result<(), EngineError> {
        if self.passive {
            return Ok(()); // the notification extension creates, rotates and uploads nothing
        }
        // Did we leave a server, or were we removed from one? (M6; at most every few minutes.)
        self.check_own_servers().await;
        // Not behind the half-hour gate: a membership change should cost the people who left
        // their deposit capability within minutes, not at the next maintenance pass.
        self.maintain_delivery_key().await;
        // Under pressure on the last-resort key the pass is not put off — but an early rotation
        // happens at most once an hour, so nobody can make this device rotate in a loop.
        let pressure = self.store.last_resort_pressure() && self.last_pressure_rotation.is_none_or(|t| t.elapsed() >= PRESSURE_ROTATION_GAP);
        if !pressure && self.last_maintenance.is_some_and(|t| t.elapsed() < MAINTENANCE_INTERVAL) {
            return Ok(());
        }
        let device_id = self.local()?.device_id;
        self.ensure_bound().await?;
        let counts = self.api.get(&format!("/api/e2ee/prekeys/count?device_id={}", enc(&device_id))).await.map_err(|e| self.fatal(e.into()))?;
        let ec_left = counts["remaining"].as_i64().unwrap_or(0);
        let kyber_left = counts["kyber_remaining"].as_i64().unwrap_or(0);
        if ec_left < PREKEY_LOW_WATER || kyber_left < PREKEY_LOW_WATER {
            // Keys the server did not take must not stay behind as private halves nobody can
            // ever be handed the public half of: on a failed upload, put the store back.
            let snapshot = self.store.to_bytes();
            let ec = if ec_left < PREKEY_LOW_WATER { self.store.generate_one_time_prekeys(PREKEY_BATCH)? } else { Vec::new() };
            let kyber = if kyber_left < PREKEY_LOW_WATER { self.store.generate_one_time_kyber(PREKEY_BATCH)? } else { Vec::new() };
            // Device-signed over exactly the uploaded keys (a session token alone is refused).
            let payload = skwod_crypto::link::op_payload(&[&Self::keys_blob(ec.iter().map(|k| &k.public)), &Self::keys_blob(kyber.iter().map(|k| &k.public))]);
            let proof = self.device_proof("replenish", &device_id, &payload)?;
            let uploaded = self
                .api
                .signed(
                    reqwest::Method::POST,
                    "/api/e2ee/prekeys/replenish",
                    Some(serde_json::json!({
                        "device_id": device_id,
                        "one_time_prekeys": ec.iter().map(Self::b64_prekey).collect::<Vec<_>>(),
                        "one_time_kyber_prekeys": kyber.iter().map(Self::b64_kyber).collect::<Vec<_>>(),
                    })),
                    &proof,
                )
                .await;
            if let Err(e) = uploaded {
                if let Ok(store) = SignalStore::from_bytes(&snapshot) {
                    self.store = store;
                }
                return Err(e.into());
            }
            // Unused private halves from long ago (their public halves were served to peers that
            // never wrote, or wiped by a re-key) are let go.
            self.store.prune_one_time_prekeys(accounts::ONE_TIME_PREKEYS_KEPT);
        }
        let age = now_ms().saturating_sub(self.store.signed_prekey_created_ms().unwrap_or(0));
        if age > SIGNED_PREKEY_ROTATION_MS || pressure {
            if pressure {
                self.last_pressure_rotation = Some(Instant::now());
            }
            // A rotation the server did not take is rolled back: otherwise this device would
            // count the new key as current (and not try again for a week) while the server
            // goes on serving the old one.
            let snapshot = self.store.to_bytes();
            let signed = self.store.generate_signed_prekey()?;
            let last_resort = self.store.generate_last_resort_kyber()?;
            let payload = skwod_crypto::link::op_payload(&[&signed.public, &last_resort.public]);
            let proof = self.device_proof("spk-rotate", &device_id, &payload)?;
            let rotated = self
                .api
                .signed(
                    reqwest::Method::POST,
                    "/api/e2ee/spk/rotate",
                    Some(serde_json::json!({
                        "device_id": device_id,
                        "signed_prekey": Self::b64_signed(&signed),
                        "last_resort_kyber_prekey": Self::b64_kyber(&last_resort),
                    })),
                    &proof,
                )
                .await;
            if let Err(e) = rotated {
                if let Ok(store) = SignalStore::from_bytes(&snapshot) {
                    self.store = store;
                }
                return Err(e.into());
            }
            self.store.prune_rotated_keys();
        }
        self.last_maintenance = Some(Instant::now());
        Ok(())
    }

    // ---- device linking (see skwod_crypto::link) ----

    /// Start linking THIS (unregistered) device to an account that already has one. Returns the
    /// link code to show the user; they type it into an existing device (`approve_link`), then this
    /// device calls [`Engine::complete_link`] until it returns a device id. Calling again while a
    /// link is pending returns the same code.
    pub async fn begin_link(&mut self) -> Result<String, EngineError> {
        if let Some((code, request_id)) = &self.pending_link {
            if self.api.get(&format!("/api/e2ee/link-requests/{}", enc(request_id))).await.is_ok() {
                return Ok(code.clone());
            }
        }
        let user_id = self.account_user_id().await?;
        let code = skwod_crypto::link::generate_code();
        let identity = self.store.identity_key();
        let resp = self
            .api
            .post(
                "/api/e2ee/link-requests",
                serde_json::json!({
                    "identity_key": B64.encode(&identity),
                    "proof": B64.encode(skwod_crypto::link::request_proof(&code, &user_id, &identity)),
                }),
            )
            .await?;
        let request_id = resp["request_id"].as_str().ok_or(EngineError::Protocol("link request response"))?.to_string();
        self.pending_link = Some((code.clone(), request_id));
        Ok(code)
    }

    /// Finish a link started with [`Engine::begin_link`]: `Ok(None)` while no existing device has
    /// approved yet; `Ok(Some(device_id))` once this device is linked and registered. The approval
    /// is only accepted if it carries a MAC under the link code — i.e. it comes from the device
    /// the user typed the code into, not from a device the server made up.
    pub async fn complete_link(&mut self) -> Result<Option<String>, EngineError> {
        let Some((code, request_id)) = self.pending_link.clone() else { return Err(EngineError::Protocol("no link in progress")) };
        let user_id = self.account_user_id().await?;
        let v = match self.api.get(&format!("/api/e2ee/link-requests/{}", enc(&request_id))).await {
            Ok(v) => v,
            Err(ClientError::Status { status: 404, .. }) => {
                self.pending_link = None;
                return Err(EngineError::Protocol("link request expired; start again"));
            }
            Err(e) => return Err(e.into()),
        };
        if v["approved"].as_bool() != Some(true) {
            return Ok(None);
        }
        let field = |k: &str| v[k].as_str().and_then(|s| B64.decode(s).ok()).ok_or(EngineError::Protocol("link approval response"));
        let linker_device = v["device_id"].as_str().ok_or(EngineError::Protocol("link approval response"))?.to_string();
        let linker_identity = field("identity_key")?;
        let signature = field("signature")?;
        let mac = field("approval_mac")?;
        let identity = self.store.identity_key();
        if !skwod_crypto::link::verify_approval_mac(&code, &user_id, &linker_identity, &identity, &mac)
            || !skwod_crypto::link::verify_link(&linker_identity, &user_id, &identity, &signature)
        {
            self.pending_link = None;
            return Err(EngineError::Protocol("link approval did not come from the device the code was entered on"));
        }
        // What the approving device handed over with its approval: its sibling set, the account
        // key, space keys and owner pins — sealed under the link code, so the server could
        // neither read nor replace it. Taken BEFORE registering (the name is sealed under the
        // account key).
        self.apply_link_bundle(&code, &user_id, &linker_identity, v["bundle"].as_str());
        let device_id = self.register_with(Some((linker_device.clone(), signature)), None, false).await?;
        self.siblings.insert(linker_device.clone(), linker_identity);
        self.pending_link = None;
        // Tell the linker its set arrived (it re-sends until it hears this).
        let linker = DeviceAddress::new(user_id, linker_device);
        let _ = self.send_content(std::slice::from_ref(&linker), &Content::SiblingsAck).await;
        Ok(Some(device_id))
    }

    /// On an EXISTING device: approve the pending link request that matches `code` (the code shown
    /// on the new device). Signs the new device's identity key with ours. Returns false when no
    /// pending request matches the code — a wrong code, an expired request, or a request made by
    /// someone who is not holding the device that shows that code.
    pub async fn approve_link(&mut self, code: &str) -> Result<bool, EngineError> {
        let local = self.local()?;
        self.ensure_bound().await?;
        let v = self.api.get("/api/e2ee/link-requests").await?;
        for r in v["requests"].as_array().into_iter().flatten().take(MAX_SERVER_ARRAY) {
            let (Some(id), Some(identity), Some(proof)) = (
                r["request_id"].as_str(),
                r["identity_key"].as_str().and_then(|s| B64.decode(s).ok()),
                r["proof"].as_str().and_then(|s| B64.decode(s).ok()),
            ) else {
                continue;
            };
            if !skwod_crypto::link::verify_request_proof(code, &local.user_id, &identity, &proof) {
                continue;
            }
            let signature = self.store.sign_link(&local.user_id, &identity)?;
            // Signed by THIS install after its restore: a link of its own (audit M2).
            if self.restored_install && self.linked_here.len() < 64 {
                self.linked_here.insert(identity.clone());
            }
            let mac = skwod_crypto::link::approval_mac(code, &local.user_id, &self.store.identity_key(), &identity);
            // The new device has no device id yet, so nothing sealed can reach it: the sibling
            // set, account key, space keys and owner pins ride with the approval instead.
            let bundle = self.link_bundle_for(code, &local.user_id, &identity);
            self.api
                .post(
                    &format!("/api/e2ee/link-requests/{}/approve", enc(id)),
                    serde_json::json!({ "device_id": local.device_id, "signature": B64.encode(signature), "approval_mac": B64.encode(mac), "bundle": bundle }),
                )
                .await
                .map_err(|e| self.fatal(e.into()))?;
            self.last_sibling_check = None; // pick the new device up on the next sync
            return Ok(true);
        }
        Ok(false)
    }

    /// How many link requests are waiting on this account (so the UI can prompt for the code).
    pub async fn pending_link_requests(&self) -> Result<u32, EngineError> {
        let v = self.api.get("/api/e2ee/link-requests").await?;
        Ok(v["requests"].as_array().map(|a| a.len() as u32).unwrap_or(0))
    }

    /// The device-proof header value for an account-security request: a fresh signature by this
    /// device's identity key over the operation, target and a hash of `payload` (the server
    /// refuses these requests on a session token alone, refuses a payload the signature does not
    /// cover, and accepts each signature once).
    pub fn device_proof(&self, op: &str, target: &str, payload: &[u8]) -> Result<String, EngineError> {
        let user_id = self.user_id.clone().ok_or(EngineError::NotRegistered)?;
        let ts = now_ms();
        Ok(format!("{ts}.{}", B64.encode(self.store.sign_device_op(op, &user_id, target, ts, payload)?)))
    }

    /// Set, change (`current_pin` required) or remove (`pin = None`) the registration-lock PIN.
    /// A PIN lets a lost-everything reset skip the 7-day hold — but only once it has been in place
    /// for 7 days itself.
    pub async fn set_registration_pin(&mut self, pin: Option<&str>, current_pin: Option<&str>) -> Result<(), EngineError> {
        self.local()?;
        self.ensure_bound().await?;
        let proof = self.device_proof("set-pin", if pin.is_some() { "enable" } else { "disable" }, pin.unwrap_or("").as_bytes())?;
        let body = serde_json::json!({ "enable": pin.is_some(), "pin": pin, "current_pin": current_pin });
        self.api.signed(reqwest::Method::POST, "/api/e2ee/registration-pin", Some(body), &proof).await?;
        Ok(())
    }

    /// Remove a device from our account. The server requires proof from a device currently on the
    /// account, so the request is signed with our identity key (a session token alone cannot
    /// delete devices).
    pub async fn delete_device(&mut self, device_id: &str) -> Result<(), EngineError> {
        self.delete_device_as(device_id, false).await
    }

    /// [`Engine::delete_device`] for THIS device being erased because it was lost or is no
    /// longer safe: a removal, not an erase — its identity never comes back by itself and the
    /// account's recovery key (which it knew) is retired at once.
    pub async fn delete_self_as_lost(&mut self) -> Result<(), EngineError> {
        let device_id = self.local()?.device_id;
        self.delete_device_as(&device_id, true).await
    }

    async fn delete_device_as(&mut self, device_id: &str, lost: bool) -> Result<(), EngineError> {
        let user_id = self.account_user_id().await?;
        // The server wants the signature AND this session to be this device's current install.
        self.ensure_bound().await?;
        let erasing_self = self.device_id.as_deref() == Some(device_id);
        if erasing_self && lost {
            // Not "I erased myself, expect me back": the siblings tombstone this identity.
            let _ = self.refresh_siblings(true).await;
            let mut identities: Vec<Vec<u8>> = self.acct.tombstones.clone();
            identities.push(self.store.identity_key());
            let targets: Vec<DeviceAddress> = self.siblings.keys().map(|d| DeviceAddress::new(user_id.clone(), d.clone())).collect();
            let _ = self.send_content(&targets, &Content::Tombstones { identities }).await;
            self.tell_contacts_removed(vec![self.store.identity_key()]).await;
        } else if erasing_self {
            // Say so first, to siblings and contacts: only a device that announced its own
            // erasure may later come back by itself (a restore under a new device row).
            self.announce_self_erase().await;
        } else {
            let _ = self.refresh_siblings(true).await;
        }
        let removed_identity = self.siblings.get(device_id).cloned();
        let proof = self.device_proof("delete", device_id, if lost { b"lost" } else { b"" })?;
        let path = format!("/api/e2ee/devices/{}{}", enc(device_id), if lost { "?lost=1" } else { "" });
        self.api.signed(reqwest::Method::DELETE, &path, None, &proof).await.map_err(|e| self.fatal(e.into()))?;
        if self.device_id.as_deref() == Some(device_id) {
            // We unregistered ourselves ("erase this device").
            self.acct.removed = true;
        } else {
            self.siblings.remove(device_id);
            // Its receive keys go, and every key of ours it held rotates before the next send.
            self.device_gone(&DeviceAddress::new(user_id.clone(), device_id));
            // REMOVED, not erased: its identity is tombstoned for good — on this device, on
            // every sibling (told now and with every sibling sync) and in the backup. It is
            // never trusted again by itself, whatever row it reappears under.
            if let Some(identity) = removed_identity {
                self.acct.past_siblings.insert(identity.clone());
                self.tombstone(identity.clone());
                let identities: Vec<Vec<u8>> = self.acct.tombstones.clone();
                let targets: Vec<DeviceAddress> = self.siblings.keys().map(|d| DeviceAddress::new(user_id.clone(), d.clone())).collect();
                let _ = self.send_content(&targets, &Content::Tombstones { identities }).await;
                // One deposit can be dropped. Every sibling is sent the removals again (with
                // the sibling set) until it acknowledges.
                let now = now_ms() as i64;
                for device in self.siblings.keys() {
                    self.acct.sibling_sync.insert(device.clone(), (0, now + accounts::SIBLING_SYNC_INTERVAL_MS));
                }
                // …and our contacts are told too (from this device, which they verify), so a
                // removed device's identity is not taken back by THEM on a claim of its own.
                self.tell_contacts_removed(vec![identity]).await;
            }
        }
        Ok(())
    }

    /// Approve the restore request `request_id` of `device_id` onto another install — the
    /// request the user was SHOWN (the `"recovery_requested"` notice carries its id and its
    /// short code). `device_id` may be this very device: "yes, move me there" — this install
    /// then stops. If a different request is pending for the device by now, nothing is signed:
    /// [`EngineError::RecoveryChanged`], and the request that IS pending is raised as a new notice.
    pub async fn approve_recovery(&mut self, device_id: &str, request_id: &str) -> Result<(), EngineError> {
        self.recovery_decision(device_id, request_id, "approve").await
    }

    /// Refuse the restore request `request_id` of `device_id` (it was not us).
    pub async fn cancel_recovery(&mut self, device_id: &str, request_id: &str) -> Result<(), EngineError> {
        self.recovery_decision(device_id, request_id, "cancel").await
    }

    async fn recovery_decision(&mut self, device_id: &str, request_id: &str, decision: &str) -> Result<(), EngineError> {
        self.ensure_bound().await?;
        // Look again, but only to notice a swap: what gets signed is the id the user saw, never
        // "whatever is listed for that device now".
        let v = self.api.get("/api/e2ee/devices").await?;
        self.note_recoveries(&v);
        let still_pending = v["recoveries"].as_array().into_iter().flatten().any(|r| r["device_id"].as_str() == Some(device_id) && r["request_id"].as_str() == Some(request_id));
        if !still_pending {
            return Err(EngineError::RecoveryChanged);
        }
        let proof = self.device_proof(&format!("{decision}-recovery"), device_id, request_id.as_bytes())?;
        let body = serde_json::json!({ "request_id": request_id });
        match self.api.signed(reqwest::Method::POST, &format!("/api/e2ee/devices/{}/recovery/{decision}", enc(device_id)), Some(body), &proof).await {
            Ok(_) => Ok(()),
            // Replaced between our look and the server's: the server refuses on the id too.
            Err(ClientError::Status { status: 409, body }) if body.contains("recovery request changed") => {
                if let Ok(v) = self.api.get("/api/e2ee/devices").await {
                    self.note_recoveries(&v);
                }
                Err(EngineError::RecoveryChanged)
            }
            Err(e) => Err(self.fatal(e.into())),
        }
    }

    /// Raise a `"recovery_requested"` notice for every pending restore request not yet shown —
    /// keyed by REQUEST id, so a request that replaces another is a new notice. The notice's
    /// `device_id` packs `"<device id>|<request id>|<short code>"` (see `SkwodClient`).
    fn note_recoveries(&mut self, listing: &serde_json::Value) {
        // `XXXX-XXXX-XXXX-XXXX` (build 45; `recovery_fingerprint`): all of it, or the code the
        // approving device shows never matches the one on the restoring install.
        const RECOVERY_CODE_LEN: usize = 19;
        let Some(user_id) = self.user_id.clone() else { return };
        for r in listing["recoveries"].as_array().into_iter().flatten().take(MAX_SERVER_ARRAY) {
            let (Some(device), Some(request_id)) = (r["device_id"].as_str(), r["request_id"].as_str()) else { continue };
            if r["approved"].as_bool() == Some(true) || device.contains('|') || request_id.contains('|') || request_id.len() > 128 {
                continue;
            }
            if self.flagged_recoveries.insert(request_id.to_string()) {
                let code: String = r["fingerprint"].as_str().unwrap_or_default().chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-').take(RECOVERY_CODE_LEN).collect();
                self.notices.push(SecurityNotice {
                    kind: "recovery_requested".into(),
                    user_id: user_id.clone(),
                    device_id: format!("{device}|{request_id}|{code}"),
                    at_ms: now_ms(),
                    was_verified: false,
                });
            }
        }
    }

    /// Upload the (already sealed) key backup, signed by this device over its exact contents.
    ///
    /// `verifier` is the public half of the recovery proof key (`skwod_crypto::backup::
    /// recovery_verifier`), stored with the backup and covered by the signature: it is what
    /// lets a later restore prove the recovery key and complete at once.
    pub async fn put_backup(&mut self, blob: &[u8], salt: &[u8], version: i64, kdf: skwod_crypto::backup::KdfParams, verifier: Option<&[u8]>) -> Result<(), EngineError> {
        self.local()?;
        self.ensure_bound().await?;
        let payload = skwod_crypto::link::op_payload(&[
            blob,
            salt,
            &version.to_be_bytes(),
            &(kdf.m_kib as u64).to_be_bytes(),
            &(kdf.t as u64).to_be_bytes(),
            &(kdf.p as u64).to_be_bytes(),
        ]);
        let payload = match verifier {
            Some(v) => skwod_crypto::link::op_payload(&[&payload, v]),
            None => payload,
        };
        let proof = self.device_proof("backup-put", "backup", &payload)?;
        // (So this device does not raise "your recovery key was changed" about its own change.)
        self.acct.recovery_key_set_at = Some(now_ms() as i64);
        self.acct.recovery_key_needed = false;
        let body = serde_json::json!({
            "auth_verifier": verifier.map(|v| B64.encode(v)),
            "encrypted_blob": B64.encode(blob),
            "salt": B64.encode(salt),
            "version": version,
            "kdf_params": { "m_kib": kdf.m_kib, "t": kdf.t, "p": kdf.p },
        });
        self.api.signed(reqwest::Method::PUT, "/api/e2ee/key-backup", Some(body), &proof).await?;
        self.backup_uploaded();
        Ok(())
    }

    /// "My recovery key is compromised" (someone else may have it): it is retired at once — no
    /// overlap, never accepted again — and every device is told to save a new one.
    pub async fn report_recovery_key_compromised(&mut self) -> Result<(), EngineError> {
        self.local()?;
        self.ensure_bound().await?;
        let proof = self.device_proof("backup-compromised", "backup", b"")?;
        self.api.signed(reqwest::Method::POST, "/api/e2ee/key-backup/compromised", None, &proof).await.map_err(|e| self.fatal(e.into()))?;
        self.acct.recovery_key_set_at = Some(now_ms() as i64);
        Ok(())
    }

    /// Devices of this account that erased themselves: `(device id, identity key, when)`.
    /// One that turns out to have been lost or stolen: [`Engine::mark_erased_device_removed`].
    pub async fn erased_devices(&mut self) -> Result<Vec<(String, Vec<u8>, i64)>, EngineError> {
        let v = self.api.get("/api/e2ee/devices").await?;
        Ok(v["erased"]
            .as_array()
            .into_iter()
            .flatten()
            .take(MAX_SERVER_ARRAY)
            .filter_map(|d| Some((d["device_id"].as_str()?.to_string(), B64.decode(d["identity_key"].as_str()?).ok()?, d["erased_at"].as_i64().unwrap_or_default())))
            .collect())
    }

    /// An erased device was in fact lost or stolen: treat it as REMOVED from now on. Its
    /// identity is tombstoned here, on every sibling and on the server (it can no longer be
    /// restored), and the recovery key it may have known is retired.
    pub async fn mark_erased_device_removed(&mut self, identity_key: &[u8]) -> Result<(), EngineError> {
        let local = self.local()?;
        self.ensure_bound().await?;
        let proof = self.device_proof("tombstone-remove", "tombstone", identity_key)?;
        let body = serde_json::json!({ "identity_key": B64.encode(identity_key) });
        self.api.signed(reqwest::Method::POST, "/api/e2ee/devices/tombstones/remove", Some(body), &proof).await.map_err(|e| self.fatal(e.into()))?;
        // The server just converted its record for exactly this identity: it was ours.
        self.acct.past_siblings.insert(identity_key.to_vec());
        self.tombstone(identity_key.to_vec());
        let identities: Vec<Vec<u8>> = self.acct.tombstones.clone();
        let targets: Vec<DeviceAddress> = self.siblings.keys().map(|d| DeviceAddress::new(local.user_id.clone(), d.clone())).collect();
        let _ = self.send_content(&targets, &Content::Tombstones { identities }).await;
        self.tell_contacts_removed(vec![identity_key.to_vec()]).await;
        Ok(())
    }

    /// The restore that just completed used up a recovery key that had been replaced (its one
    /// overlap use): the account has no recovery key now. Cleared by [`Engine::put_backup`].
    pub fn recovery_key_needed(&self) -> bool {
        self.acct.recovery_key_needed
    }

    /// From when (unix ms) a restore with the recovery key completes at once — 7 days after
    /// the key was set — as of the last device refresh. `None`: no recovery key on record.
    pub fn recovery_key_instant_from(&self) -> Option<i64> {
        self.recovery_key_instant_from
    }

    /// Delete the server's copy of the key backup (signed by this device).
    pub async fn delete_backup(&mut self) -> Result<(), EngineError> {
        self.local()?;
        self.ensure_bound().await?;
        let proof = self.device_proof("backup-delete", "backup", b"")?;
        self.api.signed(reqwest::Method::DELETE, "/api/e2ee/key-backup", None, &proof).await?;
        Ok(())
    }

    /// Re-check our account's device list now (call on the server's `device_added` realtime event).
    pub async fn refresh_own_devices(&mut self) -> Result<(), EngineError> {
        self.refresh_siblings(true).await
    }

    /// The siblings a restore brought back that nobody has confirmed yet (device ids).
    pub fn unconfirmed_siblings(&self) -> Vec<String> {
        self.unconfirmed_siblings.keys().cloned().collect()
    }

    /// The USER confirms one restored sibling ("Is this your device?" — yes): it becomes a
    /// sibling again under the key the backup had for it, and is told this device starts over
    /// (it then sends back the current set and removals). A device that was removed is never
    /// brought back by this.
    pub async fn confirm_restored_sibling(&mut self, device_id: &str) -> Result<(), EngineError> {
        let local = self.local()?;
        let identity = self.unconfirmed_siblings.get(device_id).cloned().ok_or(EngineError::Protocol("not a restored device waiting for confirmation"))?;
        if self.own_tombstoned(&identity) {
            self.unconfirmed_siblings.remove(device_id);
            return Err(EngineError::Protocol("that device was removed from the account"));
        }
        self.unconfirmed_siblings.remove(device_id);
        self.siblings.insert(device_id.to_string(), identity);
        let _ = self.send_content(&[DeviceAddress::new(local.user_id.clone(), device_id.to_string())], &Content::SessionReset).await;
        self.refresh_siblings(true).await
    }

    /// Whether `device_id` is a verified device of our own account.
    pub fn is_sibling(&self, device_id: &str) -> bool {
        self.siblings.contains_key(device_id)
    }

    async fn account_user_id(&mut self) -> Result<String, EngineError> {
        if let Some(u) = &self.user_id {
            return Ok(u.clone());
        }
        let v = self.api.get("/api/e2ee/devices").await?;
        let user_id = v["user_id"].as_str().ok_or(EngineError::Protocol("device list response"))?.to_string();
        self.user_id = Some(user_id.clone());
        Ok(user_id)
    }

    /// Re-derive which of our account's other devices are verified. A device is approved when it
    /// carries a valid link signature from this device or from an already-approved sibling; the
    /// server's say-so is never enough. Newly approved devices are announced (`"device_linked"`)
    /// and told about the siblings we know; listed-but-unvouched devices raise
    /// `"unverified_device"` and are otherwise ignored. Throttled.
    async fn refresh_siblings(&mut self, force: bool) -> Result<(), EngineError> {
        if !force && self.last_sibling_check.is_some_and(|t| t.elapsed() < Duration::from_secs(60)) {
            return Ok(());
        }
        let local = self.local()?;
        let v = self.api.get("/api/e2ee/devices").await?;
        self.last_sibling_check = Some(Instant::now());
        // Someone asked to move one of this account's devices to another install WITHOUT the
        // recovery key (a copy of its identity key and a session, nothing more). It waits for
        // one of our devices to approve, or 7 days. That is for the person to decide, so it is
        // shown — once per request — never answered automatically.
        self.note_recoveries(&v);
        // Erase claims of our own devices that the server's record now corroborates.
        self.confirm_erase_claims(&local.user_id, &v["devices"], &v["erased"], true);
        // The recovery key was changed or removed (a backup under another key, a deleted
        // backup, a device removed): every device says so, once per change. If it was not the
        // user: the key it replaced still restores at once for 7 days, and using it retires
        // the new one — or simply save a new recovery key from a device you trust.
        if let Some(changed_at) = v["recovery_key_changed_at"].as_i64() {
            if self.flagged_recoveries.insert(format!("recovery-key:{changed_at}")) && self.acct.recovery_key_set_at != Some(changed_at) {
                self.notices.push(SecurityNotice { kind: "recovery_key_changed".into(), user_id: local.user_id.clone(), device_id: String::new(), at_ms: changed_at.max(0) as u64, was_verified: false });
            }
        }
        self.recovery_key_instant_from = v["recovery_key_instant_from"].as_i64();
        // The account had a recovery key and has none in force (retired as compromised, or
        // used up): say so once per session, on every device.
        if v["recovery_key_needed"].as_bool() == Some(true) && self.flagged_recoveries.insert("recovery-key-needed".into()) {
            self.acct.recovery_key_needed = true;
            self.notices.push(SecurityNotice { kind: "recovery_key_needed".into(), user_id: local.user_id.clone(), device_id: String::new(), at_ms: now_ms(), was_verified: false });
        }
        // A device whose generation went up was restored onto another install (with the
        // recovery key, or an approval): every other device says so.
        for d in v["devices"].as_array().into_iter().flatten().take(MAX_SERVER_ARRAY) {
            let (Some(device), Some(generation)) = (d["device_id"].as_str(), d["generation"].as_i64()) else { continue };
            if device == local.device_id {
                continue;
            }
            let known = self.acct.device_generations.insert(device.to_string(), generation);
            if known.is_some_and(|g| generation > g) {
                self.notices.push(SecurityNotice { kind: "account_restored".into(), user_id: local.user_id.clone(), device_id: device.to_string(), at_ms: now_ms(), was_verified: false });
                // The install it left keeps what we handed that device: rotate it.
                self.install_replaced(&DeviceAddress::new(local.user_id.clone(), device));
                // What it restored may be older than what the account knows now: send it the
                // sibling set and the removals, until it says it has them — that is what
                // confirms its restored siblings (audit M2).
                if self.siblings.contains_key(device) {
                    self.acct.sibling_sync.insert(device.to_string(), (0, now_ms() as i64));
                }
            }
        }
        // Someone holding a session for this account asked to reset its devices. We are a live
        // device of the account, so it was not us having lost everything: veto it, and say so.
        if v["reset_completes_at"].as_i64().is_some() {
            let _ = self.ensure_bound().await;
            if let Ok(proof) = self.device_proof("cancel-reset", &local.device_id, b"") {
                let body = serde_json::json!({ "device_id": local.device_id });
                if self.api.signed(reqwest::Method::POST, "/api/e2ee/devices/reset/cancel", Some(body), &proof).await.is_ok() {
                    self.notices.push(SecurityNotice {
                        kind: "reset_blocked".into(),
                        user_id: local.user_id.clone(),
                        device_id: String::new(),
                        at_ms: now_ms(),
                        was_verified: false,
                    });
                }
            }
        }
        struct Row {
            device_id: String,
            identity: Vec<u8>,
            link: Option<(String, Vec<u8>)>,
        }
        let rows: Vec<Row> = v["devices"]
            .as_array()
            .into_iter()
            .flatten()
            .take(MAX_SERVER_ARRAY)
            .filter_map(|d| {
                Some(Row {
                    device_id: d["device_id"].as_str()?.to_string(),
                    identity: B64.decode(d["identity_key"].as_str()?).ok()?,
                    link: d["linked_by"].as_str().map(str::to_string).zip(d["link_sig"].as_str().and_then(|s| B64.decode(s).ok())),
                })
            })
            .filter(|r| r.device_id != local.device_id)
            .collect();
        // Devices the server no longer lists are no longer siblings: what they gave us goes and
        // what they held of ours rotates.
        // A restored sibling still unconfirmed that the server no longer lists is simply dropped
        // (it never was a sibling here, and was given nothing).
        self.unconfirmed_siblings.retain(|id, _| rows.iter().any(|r| &r.device_id == id));
        let gone: Vec<String> = self.siblings.keys().filter(|id| !rows.iter().any(|r| &r.device_id == *id)).cloned().collect();
        for id in gone {
            // Its identity is remembered: if the SAME key comes back as a device of its own
            // it is that device again — but only if it left by erasing ITSELF and said so
            // (`SelfErased`), never if one of us removed it (`may_readmit_sibling`).
            if let Some(identity) = self.siblings.remove(&id) {
                if self.acct.past_siblings.len() < 64 {
                    self.acct.past_siblings.insert(identity);
                }
            }
            self.device_gone(&DeviceAddress::new(local.user_id.clone(), id));
        }
        let own_identity = self.store.identity_key();
        let mut newly = Vec::new();
        let mut restored_siblings: Vec<String> = Vec::new();
        loop {
            let mut progressed = false;
            for r in &rows {
                if self.siblings.contains_key(&r.device_id) {
                    continue;
                }
                // A restored sibling waits for its confirmation (audit M2): not re-admitted by a
                // link signature (which stays valid forever, also for a device removed since).
                if self.unconfirmed_siblings.contains_key(&r.device_id) {
                    continue;
                }
                // A device one of ours REMOVED is not taken back: not by its row being listed
                // again, and not by the link signature it was first admitted with (which stays
                // valid forever and is the server's to replay). It is flagged below like any
                // other device nobody vouched for; returning takes a fresh link.
                if self.own_tombstoned(&r.identity) {
                    continue;
                }
                let Some((linker, sig)) = &r.link else {
                    // No link: the restored identity of a sibling we had vouched for. Only its
                    // holder can speak for that key, whatever row the server lists it under.
                    if self.may_readmit_sibling(&r.identity) {
                        self.siblings.insert(r.device_id.clone(), r.identity.clone());
                        restored_siblings.push(r.device_id.clone());
                        progressed = true;
                    }
                    continue;
                };
                // Signed by this identity before this install restored it (audit M2): a signature
                // the host can replay for any device this identity ever linked, removed since or
                // not, under any row. Such a device is asked about, never simply trusted.
                if self.restored_install && linker == &local.device_id && !self.linked_here.contains(&r.identity) {
                    if skwod_crypto::link::verify_link(&own_identity, &local.user_id, &r.identity, sig) {
                        self.unconfirmed_siblings.insert(r.device_id.clone(), r.identity.clone());
                    }
                    continue;
                }
                let linker_identity = if linker == &local.device_id { Some(own_identity.clone()) } else { self.siblings.get(linker).cloned() };
                let Some(linker_identity) = linker_identity.filter(|k| !self.own_tombstoned(k)) else { continue };
                if skwod_crypto::link::verify_link(&linker_identity, &local.user_id, &r.identity, sig) {
                    self.siblings.insert(r.device_id.clone(), r.identity.clone());
                    newly.push(r.device_id.clone());
                    progressed = true;
                }
            }
            if !progressed {
                break;
            }
        }
        for r in &rows {
            // An approved sibling whose directory key no longer matches what was vouched for is
            // treated exactly like an unvouched device.
            let trusted = self.siblings.get(&r.device_id).is_some_and(|k| k == &r.identity);
            // A restored sibling waiting for confirmation, under the key the backup had for it:
            // not flagged again (the Devices screen asks the user about it), nothing goes to it.
            // Anything else not trusted — a device vouched for only by an unconfirmed one
            // included — is flagged as usual; its trust is decided once its linker is confirmed.
            let waiting = self.unconfirmed_siblings.get(&r.device_id) == Some(&r.identity);
            if !trusted && waiting {
                self.siblings.remove(&r.device_id);
                continue;
            }
            if !trusted {
                self.siblings.remove(&r.device_id);
                if self.flagged_devices.insert(r.device_id.clone()) {
                    self.notices.push(SecurityNotice {
                        kind: "unverified_device".into(),
                        user_id: local.user_id.clone(),
                        device_id: r.device_id.clone(),
                        at_ms: now_ms(),
                        was_verified: false,
                    });
                }
            }
        }
        for device_id in &restored_siblings {
            // It restored from a backup that may be older than what we know: send it the set
            // and the removals until it acknowledges (that confirms its siblings, audit M2).
            self.acct.sibling_sync.insert(device_id.clone(), (0, now_ms() as i64));
            self.notices.push(SecurityNotice { kind: "account_restored".into(), user_id: local.user_id.clone(), device_id: device_id.clone(), at_ms: now_ms(), was_verified: false });
        }
        newly.extend(restored_siblings);
        let restored_now: HashSet<String> = self.notices.iter().filter(|n| n.kind == "account_restored").map(|n| n.device_id.clone()).collect();
        for device_id in newly.iter().filter(|d| !restored_now.contains(*d)) {
            self.notices.push(SecurityNotice {
                kind: "device_linked".into(),
                user_id: local.user_id.clone(),
                device_id: device_id.clone(),
                at_ms: now_ms(),
                was_verified: false,
            });
        }
        // Share the verified set with every sibling: a newly linked device cannot verify, from
        // signatures alone, the ones linked before its linker — and the others learn of the
        // newcomer at once instead of on their next directory check. Each sibling is re-sent
        // the set until it acknowledges it (`sync_siblings`).
        if !newly.is_empty() {
            let now = now_ms() as i64;
            for device in self.siblings.keys() {
                self.acct.sibling_sync.entry(device.clone()).or_insert((0, now));
            }
        }
        self.sync_siblings().await;
        Ok(())
    }

    // ---- sealed sender plumbing ----

    /// The sealed-sender trust root for this server, pinned on first use. It is accepted only with
    /// a valid signature from the server's instance key — the invite-pinned one when the app set
    /// it, otherwise the key the server presents (trust on first use, then pinned).
    async fn ensure_trust_root(&mut self) -> Result<Vec<u8>, EngineError> {
        if let Some(root) = &self.trust_root {
            return Ok(root.clone());
        }
        let v = self.sealed_api.get("/api/e2ee/trust-root").await?;
        let field = |k: &str| -> Result<Vec<u8>, EngineError> {
            B64.decode(v[k].as_str().ok_or(EngineError::Protocol("trust root response"))?).map_err(|_| EngineError::Protocol("trust root response"))
        };
        let root = field("trust_root_public")?;
        let signature = field("signature")?;
        let presented = field("server_public")?;
        let instance_key = match &self.pinned_instance_key {
            Some(pinned) if pinned != &presented => return Err(EngineError::Protocol("server identity does not match the pinned key")),
            Some(pinned) => pinned.clone(),
            None => presented,
        };
        if !certs::verify_root_binding(&instance_key, &root, &signature) {
            return Err(EngineError::Protocol("sealed-sender trust root is not signed by the server identity"));
        }
        self.pinned_instance_key = Some(instance_key);
        self.trust_root = Some(root.clone());
        Ok(root)
    }

    /// Our sender certificate, refreshed when close to expiry. Checked against the pinned trust
    /// root and our own address + identity before use.
    async fn ensure_cert(&mut self) -> Result<Vec<u8>, EngineError> {
        let now = now_ms();
        if let Some((cert, expires)) = &self.cert {
            if *expires > now + CERT_REFRESH_MARGIN_MS {
                return Ok(cert.clone());
            }
        }
        let local = self.local()?;
        let root = self.ensure_trust_root().await?;
        self.ensure_bound().await?;
        let v = self.api.post("/api/e2ee/certificates", serde_json::json!({ "device_id": local.device_id })).await.map_err(|e| self.fatal(e.into()))?;
        let cert = B64
            .decode(v["certificate"].as_str().ok_or(EngineError::Protocol("certificate response"))?)
            .map_err(|_| EngineError::Protocol("certificate response"))?;
        let info = certs::validate(&cert, &root, now)?;
        if info.sender != local || info.identity_key != self.store.identity_key() {
            return Err(EngineError::Protocol("server issued a certificate for a different identity"));
        }
        self.cert = Some((cert.clone(), info.expires_ms));
        Ok(cert)
    }

    /// Parse a `[{user_id?, device_id, delivery_key, identity_key, linked_by?, link_sig?}]` array:
    /// remember delivery keys, fold each listed contact into [`trust::ContactTrust`], and return
    /// our own account's rows plus — for every other user — ONLY the chain-verified devices. A
    /// device the server lists without a valid link chain is never returned, so nothing built on
    /// this (DM fan-out, sender-key / space-key / voice-key hand-offs) can reach it.
    fn ingest_devices(&mut self, default_user: Option<&str>, arr: &serde_json::Value) -> Vec<(DeviceAddress, Vec<u8>)> {
        let mut out = Vec::new();
        let mut rekeyed: Vec<DeviceAddress> = Vec::new();
        let mut by_user: BTreeMap<String, Vec<trust::DirRow>> = BTreeMap::new();
        for d in arr.as_array().into_iter().flatten().take(MAX_SERVER_ARRAY) {
            let Some(user) = d["user_id"].as_str().or(default_user) else { continue };
            let Some(device) = d["device_id"].as_str() else { continue };
            let Some(delivery) = d["delivery_key"].as_str().and_then(|s| B64.decode(s).ok()) else { continue };
            let Some(identity) = d["identity_key"].as_str().and_then(|s| B64.decode(s).ok()) else { continue };
            let addr = DeviceAddress::new(user, device);
            let Ok(name) = addr.name() else { continue };
            self.peer_delivery.insert(name, delivery);
            if self.user_id.as_deref() == Some(user) {
                out.push((addr, identity)); // own devices: the sibling set decides (send_content)
                continue;
            }
            // A contact's device that moved to another install (`device_rekeyed`).
            if d["generation"].as_i64().is_some_and(|g| self.note_peer_generation(user, device, g)) {
                rekeyed.push(addr.clone());
            }
            by_user.entry(user.to_string()).or_default().push(trust::DirRow {
                device: device.to_string(),
                identity,
                link: d["linked_by"].as_str().map(str::to_string).zip(d["link_sig"].as_str().and_then(|s| B64.decode(s).ok())),
            });
        }
        // A per-user listing that came back empty still says something: no device is left.
        if let Some(user) = default_user.filter(|u| self.user_id.as_deref() != Some(*u)) {
            by_user.entry(user.to_string()).or_default();
        }
        for (user, rows) in by_user {
            self.update_contact(&user, &rows);
            for peer in rekeyed.iter().filter(|p| p.user_id == user) {
                self.install_replaced(peer);
            }
            for r in rows {
                let addr = DeviceAddress::new(user.clone(), r.device);
                if self.contact_device_trusted(&addr) {
                    out.push((addr, r.identity));
                }
            }
        }
        out
    }

    /// Every registered device of `user_id` with the identity key the directory lists for it.
    async fn fetch_devices(&mut self, user_id: &str) -> Result<Vec<(DeviceAddress, Vec<u8>)>, EngineError> {
        let v = self.api.get(&format!("/api/e2ee/users/{}/devices", enc(user_id))).await?;
        // Before the listing is folded in: erase claims the server's record now corroborates.
        // Only THIS account's claims, against this account's record.
        self.confirm_erase_claims(user_id, &v["devices"], &v["erased"], false);
        Ok(self.ingest_devices(Some(user_id), &v["devices"]))
    }

    /// Every device of every member of `server_id`. Fails (rather than returning an empty list) on
    /// a malformed response: callers decide who may hold a key from this, so it must fail closed.
    async fn fetch_member_devices(&mut self, server_id: &str) -> Result<Vec<DeviceAddress>, EngineError> {
        let v = self.api.get(&format!("/api/e2ee/member-devices?server_id={}", enc(server_id))).await?;
        if !v["devices"].is_array() {
            return Err(EngineError::Protocol("no member devices"));
        }
        Ok(self.ingest_devices(None, &v["devices"]).into_iter().map(|(d, _)| d).collect())
    }

    /// Make sure we hold a usable session to `peer` and know its delivery key, fetching its prekey
    /// bundle (PQXDH) if not. Enforces the identity policy: a changed key for a peer the user had
    /// verified blocks ([`EngineError::IdentityChanged`]); for an unverified peer the new key is
    /// accepted and a "safety number changed" notice is queued.
    async fn ensure_session(&mut self, peer: &DeviceAddress) -> Result<(), EngineError> {
        let local = self.local()?;
        let name = peer.name()?;
        // The key THIS device holds for the peer (a vouched sibling, a chain-verified contact
        // device). A session counts only if it is with exactly that key: one that got into the
        // store any other way — a state written before receives were pinned, say — is retired
        // here and rebuilt from a bundle, which is checked against the same pin below.
        let Some(pin) = self.pinned_identity(peer) else {
            return Err(if peer.user_id == local.user_id { EngineError::Protocol("own device is not a verified sibling") } else { EngineError::IdentityChanged(peer.user_id.clone()) });
        };
        self.reconcile_identity(peer, &pin);
        if self.store.has_session(peer) && !self.store.has_session_with(peer, &pin) {
            let _ = self.store.archive_session(peer);
        }
        if self.store.has_session(peer) && self.peer_delivery.contains_key(&name) {
            return Ok(());
        }
        if self.store.has_session(peer) {
            // Session exists (they initiated) but we never learned their delivery key.
            self.fetch_devices(&peer.user_id).await?;
            if self.peer_delivery.contains_key(&name) {
                return Ok(());
            }
            return Err(EngineError::NoSession(name));
        }
        let v = self
            .api
            .post(
                "/api/e2ee/prekey-bundle",
                serde_json::json!({ "protocol_version": PROTOCOL_VERSION, "user_id": peer.user_id, "device_id": peer.device_id }),
            )
            .await?;
        let bytes = |val: &serde_json::Value| -> Result<Vec<u8>, EngineError> {
            B64.decode(val.as_str().ok_or(EngineError::Protocol("bundle field missing"))?).map_err(|_| EngineError::Protocol("bundle field not base64"))
        };
        let id = |val: &serde_json::Value| -> Result<u32, EngineError> {
            val.as_u64().and_then(|n| u32::try_from(n).ok()).ok_or(EngineError::Protocol("bundle id"))
        };
        let bundle = PreKeyBundleData {
            registration_id: id(&v["registration_id"])?,
            identity_key: bytes(&v["identity_key"])?,
            signed_pre_key: SignedPreKeyUpload {
                id: id(&v["signed_prekey"]["id"])?,
                public: bytes(&v["signed_prekey"]["public"])?,
                signature: bytes(&v["signed_prekey"]["signature"])?,
            },
            kyber_pre_key: KyberPreKeyUpload {
                id: id(&v["kyber_prekey"]["id"])?,
                public: bytes(&v["kyber_prekey"]["public"])?,
                signature: bytes(&v["kyber_prekey"]["signature"])?,
            },
            pre_key: match &v["one_time_prekey"] {
                serde_json::Value::Null => None,
                k => Some(PreKeyUpload { id: id(&k["id"])?, public: bytes(&k["public"])? }),
            },
        };
        // One of our own devices: the directory must serve exactly the identity key that was vouched
        // for by a link signature, or nothing is sent to it.
        if peer.user_id == local.user_id && self.siblings.get(&peer.device_id) != Some(&bundle.identity_key) {
            return Err(EngineError::Protocol("own device is not a verified sibling"));
        }
        // A contact's device: the directory must serve exactly the identity key that is pinned or
        // chain-verified for it. Anything else is a key the server (or someone in the middle)
        // substituted, and nothing is sent to it.
        if peer.user_id != local.user_id && self.contact_identity(peer) != Some(&bundle.identity_key) {
            return Err(EngineError::IdentityChanged(peer.user_id.clone()));
        }
        if bundle.identity_key != pin {
            return Err(EngineError::IdentityChanged(peer.user_id.clone()));
        }
        if self.store.known_identity(peer).is_none() {
            self.note_legacy_peer(peer);
        }
        self.store.process_bundle(&local, peer, &bundle)?;
        self.peer_delivery.insert(name, bytes(&v["delivery_key"])?);
        Ok(())
    }

    /// The identity key this device holds for `peer` from its OWN trust decisions: the vouched
    /// key of a sibling device, or the pinned / chain-verified key of a contact's live device.
    /// Never what a certificate, a bundle or a session says. Everything pairwise — what is
    /// received from `peer`, what is sent to it — is bound to this key.
    fn pinned_identity(&self, peer: &DeviceAddress) -> Option<Vec<u8>> {
        if self.user_id.as_deref() == Some(peer.user_id.as_str()) {
            self.siblings.get(&peer.device_id).cloned()
        } else {
            self.contact_identity(peer).cloned()
        }
    }

    /// Bring the libsignal store's record for `peer` in line with the pin: if it has another
    /// key on record, that key and the session made with it are retired (and the user is told).
    /// The pin is the authority; the store's record only ever follows it.
    fn reconcile_identity(&mut self, peer: &DeviceAddress, pin: &[u8]) {
        if self.store.known_identity(peer).is_some_and(|(k, _)| k != pin) {
            let _ = self.store.accept_identity(peer, pin);
            self.collect_identity_changes();
            self.forget_holder(peer);
        }
    }

    /// Seal one encoded payload for `peer`: `(envelope, peer's delivery key)`.
    async fn seal_for(&mut self, peer: &DeviceAddress, payload: &[u8]) -> Result<(Vec<u8>, Vec<u8>), EngineError> {
        self.ensure_session(peer).await?;
        let cert = self.ensure_cert().await?;
        // Checked again at the moment of encryption, inside the store: the key on record and
        // the session must both be for the key pinned for this device.
        let pin = self.pinned_identity(peer).ok_or_else(|| EngineError::IdentityChanged(peer.user_id.clone()))?;
        let envelope = self.store.sealed_encrypt(peer, &pin, &cert, payload)?;
        let delivery = self.peer_delivery.get(&peer.name()?).cloned().ok_or(EngineError::Protocol("no delivery key"))?;
        Ok((envelope, delivery))
    }

    /// Seal `content` for each target device and deposit the envelopes in ONE credential-less
    /// request. Per-device failures don't fail the batch; returns the devices actually reached.
    /// Errors only when nothing could be delivered and a hard error (e.g. a blocked identity
    /// change) explains why.
    async fn send_content(&mut self, targets: &[DeviceAddress], content: &Content) -> Result<Vec<DeviceAddress>, EngineError> {
        self.send_content_with(targets, content, None).await
    }

    /// [`Self::send_content`], persisting `row` (an outgoing message) together with the engine
    /// state before anything leaves.
    async fn send_content_with(&mut self, targets: &[DeviceAddress], content: &Content, row: Option<&OutgoingRow>) -> Result<Vec<DeviceAddress>, EngineError> {
        let local = self.local()?;
        // THE INVARIANT: a send that reaches no recipient device is an error, never `Ok` —
        // here, under every pairwise send there is. No device to send to at all: an error.
        // A device that may not be sent to (not vouched for, or of a verified contact whose
        // devices changed): `IdentityChanged`, below. Nothing accepted by any mailbox: an
        // error, at the end. The one `Ok` with nobody reached is a sync copy addressed only to
        // our OWN other devices none of which is a verified sibling yet — those are copies,
        // not recipients.
        if targets.is_empty() {
            return Err(EngineError::Protocol(NO_RECIPIENT));
        }
        // A direct-message payload for a GROUP conversation goes out wrapped with the group's
        // members, so "this is a group, of these people" is inside the ciphertext.
        let payload = match self.group_wrapped(&local, content)? {
            Some(wrapped) => wrapped.encode()?,
            None => content.encode()?,
        };
        let mut todo: Vec<(DeviceAddress, serde_json::Value)> = Vec::new();
        let mut first_err = None;
        for peer in targets {
            if peer == &local || todo.iter().any(|(p, _)| p == peer) {
                continue;
            }
            // Our own account's devices get traffic only once verified (link signature chain).
            if peer.user_id == local.user_id && !self.siblings.contains_key(&peer.device_id) {
                continue;
            }
            // A contact's device gets traffic only if it is chain-verified — and nothing goes to
            // any device of a VERIFIED contact whose device set changed until the user has
            // verified them again. This is the last gate before encryption; every hand-off
            // (DMs, sender keys, space keys, voice keys) passes through it.
            if peer.user_id != local.user_id && (self.contact_blocked(&peer.user_id) || !self.contact_device_trusted(peer)) {
                first_err.get_or_insert(EngineError::IdentityChanged(peer.user_id.clone()));
                continue;
            }
            match self.seal_for(peer, &payload).await {
                Ok((envelope, delivery)) => {
                    // So it can be asked for again by the hash of exactly these bytes.
                    self.remember_envelope(&envelope, content, peer);
                    todo.push((
                        peer.clone(),
                        serde_json::json!({
                            "user_id": peer.user_id,
                            "device_id": peer.device_id,
                            "delivery_key": B64.encode(delivery),
                            "envelope": B64.encode(envelope),
                        }),
                    ));
                }
                Err(e) => {
                    first_err.get_or_insert(e);
                }
            }
        }
        if todo.is_empty() {
            return match first_err {
                Some(e) => Err(e),
                None => Ok(Vec::new()),
            };
        }
        // The ratchets have advanced. That state (and the message, if this is one) goes to disk
        // BEFORE the envelopes leave: a crash after this point re-sends at worst; a crash before
        // it has sent nothing a restored state could contradict.
        self.checkpoint(row)?;
        let mut delivered = Vec::new();
        // A mailbox that is momentarily full or rate-limited answers "busy": try those again,
        // a little later each time, before giving up on them for this call.
        for wait in [None, Some(400), Some(1200), Some(3000)] {
            if let Some(ms) = wait {
                tokio::time::sleep(Duration::from_millis(ms)).await;
            }
            let batch: Vec<&serde_json::Value> = todo.iter().map(|(_, m)| m).collect();
            let resp = match self.sealed_api.post("/api/e2ee/sealed/send", serde_json::json!({ "messages": batch })).await {
                Ok(resp) => resp,
                Err(e) if wait.is_none() => return Err(e.into()),
                Err(_) => break,
            };
            let mut busy = Vec::new();
            let mut gone: Vec<(DeviceAddress, serde_json::Value)> = Vec::new();
            for ((peer, sent), r) in std::mem::take(&mut todo).into_iter().zip(resp["results"].as_array().into_iter().flatten()) {
                match r["status"].as_str() {
                    Some("ok") => delivered.push(peer),
                    // Unknown device or stale delivery key (the peer rotated it, e.g. after
                    // blocking someone). Forget the key; retry once below with a fresh one.
                    Some("gone") => {
                        if let Ok(name) = peer.name() {
                            self.peer_delivery.remove(&name);
                        }
                        gone.push((peer, sent));
                    }
                    Some("busy") => busy.push((peer, sent)),
                    _ => {}
                }
            }
            if !gone.is_empty() {
                let users: BTreeSet<String> = gone.iter().map(|(p, _)| p.user_id.clone()).collect();
                for user in users {
                    // A refusal here (we were blocked, or no longer share a server) simply leaves
                    // the device without a delivery key, so it is skipped.
                    let _ = self.fetch_devices(&user).await;
                }
                let mut retry = Vec::new();
                for (peer, mut sent) in gone {
                    if let Some(key) = peer.name().ok().and_then(|n| self.peer_delivery.get(&n)) {
                        sent["delivery_key"] = serde_json::json!(B64.encode(key));
                        retry.push((peer, sent));
                    }
                }
                if !retry.is_empty() {
                    let batch: Vec<&serde_json::Value> = retry.iter().map(|(_, m)| m).collect();
                    if let Ok(resp) = self.sealed_api.post("/api/e2ee/sealed/send", serde_json::json!({ "messages": batch })).await {
                        for ((peer, sent), r) in retry.into_iter().zip(resp["results"].as_array().into_iter().flatten()) {
                            match r["status"].as_str() {
                                Some("ok") => delivered.push(peer),
                                Some("busy") => busy.push((peer, sent)),
                                _ => {}
                            }
                        }
                    }
                }
            }
            if busy.is_empty() {
                break;
            }
            todo = busy;
        }
        if delivered.is_empty() {
            return Err(first_err.unwrap_or(EngineError::Protocol(NO_RECIPIENT)));
        }
        Ok(delivered)
    }

    // ---- sealed mailbox ----

    /// Fetch one page of this device's sealed mailbox, decrypt and act on every envelope, and
    /// remember their ids in `pending_acks`. Does NOT acknowledge: the caller persists the engine
    /// state first, then calls [`Engine::ack_inbox`] — so a crash can only cause a redelivery
    /// (rejected as a duplicate), never a lost message.
    pub async fn sync_inbox(&mut self) -> Result<InboxOutcome, EngineError> {
        let local = self.local()?;
        let root = self.ensure_trust_root().await?;
        // This session must be this device's (and this install its current one) before the
        // server lets it near the mailbox. A refusal here is final and typed.
        self.ensure_bound().await?;
        // Know our verified siblings before deciding what an "own device" message may do.
        let _ = self.refresh_siblings(false).await;
        let resp = self.api.get(&format!("/api/e2ee/sealed/inbox?device_id={}", enc(&local.device_id))).await.map_err(|e| self.fatal(e.into()))?;
        let mut outcome = InboxOutcome { more: resp["more"].as_bool().unwrap_or(false), ..Default::default() };
        let mut repairs: Vec<DeviceAddress> = Vec::new();
        let mut undecryptable: Vec<(DeviceAddress, Vec<u8>, i64)> = Vec::new();
        let now = now_ms();
        for e in resp["envelopes"].as_array().into_iter().flatten().take(MAX_SERVER_ARRAY) {
            let Some(id) = e["id"].as_str() else { continue };
            if self.pending_acks.iter().any(|p| p == id) {
                continue;
            }
            self.pending_acks.push(id.to_string());
            outcome.processed += 1;
            let Some(bytes) = e["envelope"].as_str().and_then(|s| B64.decode(s).ok()) else { continue };
            if bytes.len() > MAX_WIRE_ENVELOPE {
                continue;
            }
            let received_at = e["created_at"].as_i64().unwrap_or(now as i64);
            if let Some(sender) = self.receive_envelope(&local, &root, now, &bytes, received_at).await {
                if undecryptable.len() < 200 {
                    undecryptable.push((sender.clone(), bytes, received_at));
                }
                if !repairs.contains(&sender) {
                    repairs.push(sender);
                }
            }
        }
        self.collect_identity_changes();
        for peer in repairs {
            self.repair_session(&peer).await;
        }
        // On the repaired sessions: show a placeholder and ask for each one again.
        for (sender, envelope, received_at) in undecryptable {
            if !self.blocked.contains(&sender.user_id) {
                self.ask_envelope_again(&sender, &envelope, received_at).await;
            }
        }
        // Many peers set sessions up on our last-resort key: replace it (and the signed prekey)
        // now rather than at the weekly rotation, so its replay memory starts over.
        if self.store.last_resort_pressure() {
            let _ = self.maintain_keys().await;
        }
        outcome.provisioned = self.fulfill_provisions().await;
        if self.acct.announce_pending {
            self.announce_restore().await;
        }
        self.sync_siblings().await;
        self.retry_deliveries(false).await;
        Ok(outcome)
    }

    /// Open, check and act on one sealed envelope. Returns the sender when a message from a
    /// device we TRUST (certificate and session both under the key pinned for it) failed to
    /// decrypt — the only failure that calls for a session repair.
    ///
    /// The order is the point. The outer layer is opened and the certificate validated first,
    /// which changes nothing. The certificate is the server's statement, so before the inner
    /// message is given to libsignal the key it carries must be the key THIS device holds for
    /// that sender. A certificate naming a known device under another key — which only the
    /// certificate issuer can produce — is dropped right there: no session is started or
    /// replaced, no identity is recorded, no prekey is used, nothing is re-keyed, and the user
    /// is told.
    async fn receive_envelope(&mut self, local: &DeviceAddress, root: &[u8], now: u64, bytes: &[u8], received_at: i64) -> Option<DeviceAddress> {
        // An envelope already read for the held queue is spent, whoever its sender is by now.
        let envelope_hash: [u8; 32] = sha2::Sha256::digest(bytes).into();
        if self.peeked.contains(&envelope_hash) {
            return None;
        }
        let opened = self.store.sealed_open(local, root, now, bytes).ok()?;
        let sender = opened.sender.clone();
        let own = sender.user_id == local.user_id;
        let mut pin = self.pinned_identity(&sender);
        if pin.as_ref() != Some(&opened.identity_key) && self.dir_refreshed.get(&sender.user_id).is_none_or(|t| t.elapsed() >= DIRECTORY_RECHECK) {
            // Not a device we hold this key for. Our picture may just be old (a newly linked
            // device, a contact never seen before): look once, then decide.
            self.dir_refreshed.insert(sender.user_id.clone(), Instant::now());
            let _ = if own { self.refresh_siblings(true).await } else { self.fetch_devices(&sender.user_id).await.map(|_| ()) };
            pin = self.pinned_identity(&sender);
        }
        let Some(pin) = pin else {
            // Listed for a contact but vouched for by nobody: what it says is read WITHOUT
            // accepting it (no session, no identity is kept) and held until the user decides.
            // Anything else — an own-account device no sibling vouched for, a device that is
            // not listed at all — is dropped unread.
            let listed = self.contacts.get(&sender.user_id).and_then(|c| c.unvouched.get(&sender.device_id));
            if !own && listed == Some(&opened.identity_key) && !self.blocked.contains(&sender.user_id) {
                if let Ok(plaintext) = self.store.sealed_peek(local, &opened) {
                    if Content::decode(&plaintext).is_some() {
                        // Remembered by hash: this envelope is never read again, by this path
                        // or (once its sender is accepted) by the ordinary one.
                        if self.peeked.len() >= MAX_PEEKED {
                            self.peeked.pop_front();
                        }
                        self.peeked.push_back(envelope_hash);
                        self.hold_inbound(sender, &plaintext, received_at);
                    }
                }
            }
            return None;
        };
        if opened.identity_key != pin {
            self.note_identity_reject(&sender);
            return None;
        }
        // A store written before receives were pinned may still hold another key (and a
        // session with it) for this device: retire both, or the real device could never be
        // heard again.
        self.reconcile_identity(&sender, &pin);
        match self.store.sealed_decrypt_opened(local, &opened, &pin) {
            Ok(m) => {
                self.note_legacy_peer(&m.sender);
                // They started a NEW session over one we already had: their side was lost
                // (a restore, a reinstall). An implicit session reset — whatever we handed
                // them over the old one, sender keys above all, goes out again. Safe to act
                // on: the new session is with the pinned key, so it is theirs.
                if m.session_replaced {
                    self.forget_holder(&m.sender);
                }
                self.handle_content(local, m.sender, &m.plaintext, received_at).await;
                None
            }
            Err(SealedError { sender: Some(sender), error }) if !matches!(error, CryptoError::Duplicate | CryptoError::SelfSend | CryptoError::UntrustedIdentity(_)) => {
                // Someone we blocked gets no reply of any kind, not even a session reset.
                (!self.blocked.contains(&sender.user_id)).then_some(sender)
            }
            Err(_) => None,
        }
    }

    /// An envelope arrived under a certificate that names a device we know, with a key that is
    /// not the one we hold for it. Only whoever issues certificates can make one. Nothing was
    /// accepted and what we send still goes to the key we hold; the user is told (at most once
    /// an hour per device), with whether they had verified that contact.
    fn note_identity_reject(&mut self, sender: &DeviceAddress) {
        let Ok(name) = sender.name() else { return };
        if self.identity_rejects.get(&name).is_some_and(|t| t.elapsed() < IDENTITY_REJECT_NOTICE) {
            return;
        }
        if self.identity_rejects.len() >= 4096 {
            self.identity_rejects.retain(|_, t| t.elapsed() < IDENTITY_REJECT_NOTICE);
        }
        self.identity_rejects.insert(name, Instant::now());
        let was_verified = self.contacts.get(&sender.user_id).is_some_and(|c| c.verified.is_some());
        self.notices.push(SecurityNotice {
            kind: "identity_changed".into(),
            user_id: sender.user_id.clone(),
            device_id: sender.device_id.clone(),
            at_ms: now_ms(),
            was_verified,
        });
    }

    /// Acknowledge (delete server-side) every envelope processed so far. Call after persisting.
    pub async fn ack_inbox(&mut self) -> Result<(), EngineError> {
        if self.pending_acks.is_empty() {
            return Ok(());
        }
        let device_id = self.local()?.device_id;
        for chunk in self.pending_acks.clone().chunks(500) {
            self.api.post("/api/e2ee/sealed/ack", serde_json::json!({ "device_id": device_id, "ids": chunk })).await?;
        }
        self.pending_acks.clear();
        Ok(())
    }

    /// Drain the whole mailbox (sync + ack until empty). For callers that do not persist state
    /// between the two steps (tests, tools); apps use `sync_inbox` → persist → `ack_inbox`.
    pub async fn poll_inbox(&mut self) -> Result<InboxOutcome, EngineError> {
        let mut total = InboxOutcome::default();
        for _ in 0..50 {
            let o = self.sync_inbox().await?;
            self.ack_inbox().await?;
            total.processed += o.processed;
            total.provisioned += o.provisioned;
            if !o.more {
                break;
            }
        }
        Ok(total)
    }

    /// A message from `peer` failed to decrypt on our session with them (lost or diverged state —
    /// e.g. they restored from a backup). Archive the session and start a fresh one, like Signal's
    /// automatic session reset. Throttled per peer.
    async fn repair_session(&mut self, peer: &DeviceAddress) {
        let Ok(name) = peer.name() else { return };
        if self.repaired.get(&name).is_some_and(|t| t.elapsed() < REPAIR_INTERVAL) {
            return;
        }
        self.repaired.insert(name, Instant::now());
        if !self.contacts.contains_key(&peer.user_id) {
            let _ = self.fetch_devices(&peer.user_id).await;
        }
        let _ = self.store.archive_session(peer);
        let _ = self.send_content(std::slice::from_ref(peer), &Content::SessionReset).await;
        // Whatever sender keys we gave that device are gone with its old state.
        self.forget_holder(peer);
    }

    /// Make room for one more received distribution from `sender_user`: at the per-sender cap
    /// that sender's oldest one goes; at the global cap the oldest of all goes. Never refuses —
    /// a flood can only push out the flooder's own keys (or, at the global cap, the stalest).
    fn make_room_for_recv_key(&mut self, sender_user: &str) {
        // Ids received before this build have no recorded order: treat them as the oldest.
        if self.recv_order.len() < self.recv_keys.len() {
            let known: HashSet<&String> = self.recv_order.iter().collect();
            let mut missing: Vec<String> = self.recv_keys.keys().filter(|k| !known.contains(k)).cloned().collect();
            missing.sort();
            for id in missing.into_iter().rev() {
                self.recv_order.push_front(id);
            }
        }
        let of_sender = self.recv_keys.values().filter(|r| r.sender.user_id == sender_user).count();
        let victim = if of_sender >= MAX_RECV_KEYS_PER_SENDER {
            self.recv_order.iter().position(|id| self.recv_keys.get(id).is_some_and(|r| r.sender.user_id == sender_user))
        } else if self.recv_keys.len() >= MAX_RECV_KEYS {
            Some(0)
        } else {
            None
        };
        if let Some(id) = victim.and_then(|i| self.recv_order.remove(i)) {
            if let Some(r) = self.recv_keys.remove(&id) {
                if let Ok(uuid) = id.parse::<Uuid>() {
                    self.store.delete_sender_key(&r.sender, uuid);
                }
            }
        }
    }

    /// Is `user_id` someone THIS device accepts as a member of `server_id` — on its own roster,
    /// never on the server's list?
    fn accepted_member(&self, server_id: &str, user_id: &str) -> bool {
        self.user_id.as_deref() == Some(user_id) || self.rosters.get(server_id).is_some_and(|r| r.members.contains(user_id))
    }

    /// May `user_id` speak in `channel_id`? Only as an accepted member of the server the
    /// channel belongs to. Someone not on the roster yet may have been approved since we last
    /// looked: the signed approvals are read once more before refusing. Fails closed — an
    /// unknown channel, or a roster that cannot be established, accepts nobody.
    async fn accepted_speaker(&mut self, channel_id: &str, user_id: &str) -> bool {
        let Ok(server_id) = self.channel_server(channel_id).await else { return false };
        if self.ensure_roster(&server_id).await.is_err() {
            return false;
        }
        if self.accepted_member(&server_id, user_id) {
            return true;
        }
        self.reconfirm_owner(&server_id).await;
        if let Ok(v) = self.api.get(&format!("/api/servers/{}/member-approvals", enc(&server_id))).await {
            self.apply_approvals(&server_id, &v["approvals"]);
        }
        self.accepted_member(&server_id, user_id)
    }

    fn forget_holder(&mut self, peer: &DeviceAddress) {
        for key in self.send_keys.values_mut() {
            key.holders.remove(peer);
        }
        for call in &mut self.voice {
            call.sent_to.remove(peer);
        }
    }

    /// Participants of a DM conversation per the server's listing (cached).
    async fn conversation_participants(&mut self, conversation_id: &str) -> Vec<String> {
        if !self.dm_participants.contains_key(conversation_id) {
            if let Ok(list) = self.api.get("/api/dms").await {
                for c in list["conversations"].as_array().into_iter().flatten().take(MAX_SERVER_ARRAY) {
                    if let Some(id) = c["conversation_id"].as_str() {
                        let users = c["participants"].as_array().into_iter().flatten().filter_map(|u| u.as_str().map(str::to_string)).collect();
                        self.dm_participants.insert(id.to_string(), users);
                    }
                }
            }
        }
        self.dm_participants.get(conversation_id).cloned().unwrap_or_default()
    }

    /// Act on one decrypted sealed payload. `sender` is authenticated (certificate + session).
    async fn handle_content(&mut self, local: &DeviceAddress, sender: DeviceAddress, plaintext: &[u8], received_at: i64) {
        let Some(content) = Content::decode(plaintext) else { return };
        // The group marker: a wrapped direct-message payload is a group message of the members
        // it names; a bare one is a 1:1 message. `in_conversation` holds each to that.
        let (content, group) = match content {
            Content::Grouped { members, inner } => match Content::decode(&inner) {
                Some(inner) if inner.dm_conversation().is_some() && members.len() <= content::MAX_GROUP_DM => (inner, Some(members)),
                _ => return,
            },
            other => (other, None),
        };
        self.dm_group_claim = group;
        if self.blocked.contains(&sender.user_id) {
            return; // blocked: nothing they send is read, stored, or acted on
        }
        let from_own_account = sender.user_id == local.user_id;
        if from_own_account && !self.siblings.contains_key(&sender.device_id) {
            // The server lists it under our account, but none of our devices vouched for it. Check
            // once more (it may just have been linked), then refuse: no synced DMs, no space keys,
            // no provisioning, no sender keys.
            let _ = self.refresh_siblings(true).await;
            if !self.siblings.contains_key(&sender.device_id) {
                return;
            }
        }
        // The server issues sender certificates, so "this came from <my account>:<device>" is only
        // as good as the identity key behind the session. It must be the key that was vouched for.
        if from_own_account && self.store.known_identity(&sender).map(|(k, _)| k) != self.siblings.get(&sender.device_id).cloned() {
            return;
        }
        let from_own_device = from_own_account;
        if !from_own_account {
            // Another account's device: accepted only if it is chain-verified for that account
            // AND the session it spoke on is with the identity key we hold for it. The server
            // issues sender certificates and lists devices; neither makes a device theirs.
            let authentic = |e: &Engine| e.contact_identity(&sender).is_some_and(|k| e.store.known_identity(&sender).is_some_and(|(known, _)| &known == k));
            if !authentic(self) && self.dir_refreshed.get(&sender.user_id).is_none_or(|t| t.elapsed() >= DIRECTORY_RECHECK) {
                self.dir_refreshed.insert(sender.user_id.clone(), Instant::now());
                let _ = self.fetch_devices(&sender.user_id).await;
            }
            if !authentic(self) {
                // Listed but not vouched for: keep it until the user decides (a notice was
                // raised). Not listed at all (a removed device still holding a certificate, or
                // a made-up one): dropped.
                if self.contacts.get(&sender.user_id).is_some_and(|c| c.unvouched.contains_key(&sender.device_id)) {
                    self.hold_inbound(sender, plaintext, received_at);
                }
                return;
            }
        }
        match content {
            Content::Chat { conversation_id, message_id, text, sent_at, sync_peer } => {
                self.file_chat(local, sender, from_own_device, conversation_id, message_id, text, sent_at, sync_peer, received_at).await;
            }
            Content::ChatResend { retry_id, conversation_id, message_id, text, sent_at, sync_peer, reply_to } => {
                // Only what we asked this very device for. It takes the placeholder's place.
                let Some(ask) = self.answered(&format!("env:{retry_id}"), &sender) else { return };
                if let Some(scope) = ask.scope {
                    self.acct.retry_events.push(RetryEvent::Resolved { scope, id: format!("retry:{retry_id}") });
                }
                match reply_to {
                    None => self.file_chat(local, sender, from_own_device, conversation_id, message_id, text, sent_at, sync_peer, ask.at_ms).await,
                    Some(reply_to) => {
                        let kind = content::DmOpKind::Reply { text, sent_at, reply_to };
                        self.handle_dm_op(local, sender, from_own_device, conversation_id, message_id, sync_peer, kind, ask.at_ms).await;
                    }
                }
            }
            Content::RetryRequest { channel_id, ids } => self.on_retry_request(local, &sender, channel_id, ids).await,
            Content::RetryNone { channel_id, ids, lost } => self.on_retry_none(&sender, channel_id, ids, lost),
            Content::ChannelResend { channel_id, messages } => self.on_channel_resend(&sender, channel_id, messages),
            Content::SiblingsAck => {
                if from_own_device {
                    self.acct.sibling_sync.remove(&sender.device_id);
                }
            }
            Content::AccountSync { account_key } => {
                if from_own_device {
                    self.adopt_account_key(account_key);
                }
            }
            Content::SelfErased => {
                // Only a CLAIM. The device that says so is, at this moment, still registered —
                // a live device could say it to make its identity re-admittable later and
                // slip past a removal. It counts only once the SERVER's record agrees: that
                // identity is no longer a registered device and is recorded as self-erased
                // (`confirm_erase_claims`, on the next directory read). Until then: nothing.
                if let Some((identity, _)) = self.store.known_identity(&sender) {
                    self.claim_self_erase(&sender.user_id, identity);
                }
            }
            Content::Tombstones { identities } => {
                if from_own_device {
                    // Our own account's removals (from a verified sibling).
                    for identity in identities.into_iter().take(1024) {
                        self.tombstone(identity);
                    }
                } else {
                    // A contact's device telling us which of THEIR devices they removed: those
                    // identities are never re-admitted here either, whatever they claimed.
                    let vouched: Vec<Vec<u8>> = self.contacts.get(&sender.user_id).map(|c| c.vouched.values().cloned().collect()).unwrap_or_default();
                    for identity in identities.into_iter().take(1024).filter(|i| vouched.contains(i)) {
                        self.tombstone_contact_identity(&sender.user_id, identity);
                    }
                }
            }
            Content::SenderKey { channel_id, skdm } => {
                // Who may SPEAK in a channel is decided where who may READ it is: by the
                // roster this device keeps for the channel's server. A sender key from anyone
                // else — a ghost account the server made up, a member who was removed — is
                // not bound, so nothing they write there can ever be shown. Checked before
                // the distribution is processed: a refused key leaves nothing in the store.
                if channel_id.is_empty() || channel_id.len() > 128 {
                    return;
                }
                if !from_own_device && !self.accepted_speaker(&channel_id, &sender.user_id).await {
                    return;
                }
                // A distribution id is bound once (to one sender and one channel) and can
                // never be re-pointed — looked at before anything is stored under it.
                let Ok(claimed) = SignalStore::distribution_id_of(&skdm) else { return };
                if self.recv_keys.contains_key(&claimed.to_string()) {
                    return;
                }
                let Ok(id) = self.store.process_distribution(&sender, &skdm) else { return };
                let id = id.to_string();
                self.make_room_for_recv_key(&sender.user_id);
                // From here on, what this user writes in this channel is ours to read.
                self.acct.first_key_at.entry(format!("channel:{channel_id}|{}", sender.user_id)).or_insert(received_at);
                self.recv_keys.insert(id.clone(), RecvKey { scope: format!("channel:{channel_id}"), sender });
                self.recv_order.push_back(id);
            }
            Content::SpaceKey { server_id, key } => {
                // Accepted only from the host we recorded when joining, or from one of our OWN
                // devices (a sibling linking us in) — and only for a server we hold no key for.
                // (A pin of unknown origin does not count; try to re-confirm it first.)
                if !from_own_device {
                    self.reconfirm_owner(&server_id).await;
                }
                let from_expected_host = self.trusted_owner(&server_id) == Some(&sender.user_id);
                if (from_expected_host || from_own_device) && !self.spaces.contains_key(&server_id) {
                    self.spaces.insert(server_id, key);
                }
            }
            Content::ProvisionRequest { server_id } => {
                if !self.provisioned.contains(&format!("{server_id}|{}", sender.user_id)) {
                    self.prov_queue.push((sender, server_id));
                }
            }
            Content::VoiceKey { channel_id, call_id, index, key } => {
                if key.len() != 32 || index >= VOICE_KEYRING || call_id.len() > 128 || channel_id.len() > 128 {
                    return;
                }
                // Only for a call THIS device is in. A key for any other call id never creates a
                // call entry (which used to evict the live one once eight bogus ids arrived); it
                // waits briefly in a small per-sender buffer in case we are just joining.
                match self.voice.iter_mut().find(|c| c.channel_id == channel_id && c.call_id == call_id) {
                    Some(call) => {
                        call.peers.entry(sender.user_id).or_default().insert(index, key);
                    }
                    None => {
                        self.pending_voice.retain(|p| p.5.elapsed() < PENDING_VOICE_TTL);
                        let of_sender: Vec<usize> =
                            self.pending_voice.iter().enumerate().filter(|(_, p)| p.0 == sender.user_id).map(|(i, _)| i).collect();
                        if of_sender.len() >= MAX_PENDING_VOICE_PER_SENDER {
                            self.pending_voice.remove(of_sender[0]);
                        }
                        if self.pending_voice.len() >= MAX_PENDING_VOICE {
                            self.pending_voice.remove(0);
                        }
                        self.pending_voice.push((sender.user_id, channel_id, call_id, index, key, Instant::now()));
                    }
                }
            }
            Content::OwnerPins { pins } => {
                // Only a verified sibling of our own account may hand us a trust anchor (and it
                // only sends pins of known provenance); a trusted pin of ours is never replaced.
                if from_own_device {
                    self.accept_sibling_pins(pins);
                }
            }
            Content::DmReply { conversation_id, message_id, text, sent_at, reply_to, sync_peer } => {
                let kind = content::DmOpKind::Reply { text, sent_at, reply_to };
                self.handle_dm_op(local, sender, from_own_device, conversation_id, message_id, sync_peer, kind, received_at).await;
            }
            Content::DmEdit { conversation_id, message_id, text, sync_peer } => {
                self.handle_dm_op(local, sender, from_own_device, conversation_id, message_id, sync_peer, content::DmOpKind::Edit { text }, received_at).await;
            }
            Content::DmDelete { conversation_id, message_id, sync_peer } => {
                self.handle_dm_op(local, sender, from_own_device, conversation_id, message_id, sync_peer, content::DmOpKind::Delete, received_at).await;
            }
            Content::DmReaction { conversation_id, message_id, emoji, remove, sync_peer } => {
                let kind = content::DmOpKind::Reaction { emoji, remove };
                self.handle_dm_op(local, sender, from_own_device, conversation_id, message_id, sync_peer, kind, received_at).await;
            }
            Content::Report { report } => self.handle_report(&sender, report, received_at),
            Content::ChannelClear { server_id, channel_id, cleared_at } => self.on_channel_clear(&sender, from_own_device, server_id, channel_id, cleared_at, received_at).await,
            Content::ChannelDelete { server_id, channel_id, message_id } => self.on_channel_delete(&sender, from_own_device, server_id, channel_id, message_id).await,
            // Unwrapped above; a wrapper inside a wrapper is not a message.
            Content::Grouped { .. } => {}
            Content::SessionReset => {
                self.forget_holder(&sender);
                // One of our own devices starting over (a restore): what it restored may be
                // older than what the account knows now. It is sent the sibling set, the
                // removals and the owner pins again, until it says it has them.
                if from_own_device {
                    self.acct.sibling_sync.insert(sender.device_id.clone(), (0, now_ms() as i64));
                } else if !self.acct.tombstones.is_empty() {
                    // A contact starting over may have restored an old picture of OUR devices
                    // (audit M2): tell it again which of them were removed, so a removed one is
                    // not taken back there on the strength of a stale backup.
                    let identities = self.acct.tombstones.clone();
                    let _ = self.send_content(std::slice::from_ref(&sender), &Content::Tombstones { identities }).await;
                }
            }
            Content::Siblings { devices } => {
                // Only an already-verified sibling may extend our sibling set.
                if from_own_device {
                    // Tell it the set arrived (it re-sends until it hears so).
                    let _ = self.send_content(std::slice::from_ref(&sender), &Content::SiblingsAck).await;
                    for (device_id, identity) in devices.into_iter().take(16) {
                        // (Never a device that was removed, whoever still lists it.)
                        if device_id != local.device_id && !self.siblings.contains_key(&device_id) && !self.own_tombstoned(&identity) {
                            // (A restored sibling still unconfirmed is confirmed by this — the
                            // set of a verified sibling, audit M2.)
                            let confirmed = self.unconfirmed_siblings.remove(&device_id).is_some_and(|k| k == identity);
                            self.siblings.insert(device_id.clone(), identity);
                            if confirmed {
                                continue;
                            }
                            self.notices.push(SecurityNotice {
                                kind: "device_linked".into(),
                                user_id: local.user_id.clone(),
                                device_id,
                                at_ms: now_ms(),
                                was_verified: false,
                            });
                        }
                    }
                }
            }
        }
    }

    /// File one authenticated direct message (or a sibling's synced copy of one we sent).
    #[allow(clippy::too_many_arguments)]
    async fn file_chat(
        &mut self,
        local: &DeviceAddress,
        sender: DeviceAddress,
        from_own_device: bool,
        conversation_id: String,
        message_id: String,
        text: String,
        sent_at: i64,
        sync_peer: Option<String>,
        received_at: i64,
    ) {
        // What a peer wrote is a message, whatever it starts with: a body dressed up as one of
        // the core's own rows (a system notice, a "couldn't decrypt" stand-in) loses the
        // control character that would make it look like one.
        let text = crate::cache::neutralize_reserved(&text).to_string();
        if message_id.is_empty() || text.len() > MAX_TEXT || self.inbox_dms.len() >= MAX_BUFFERED_DMS {
            return;
        }
        // The conversation id is the sender's claim; only file the message there if the
        // conversation really is between us and that sender (for a sibling-synced copy:
        // between us and the named peer) — by this device's own binding once it has one.
        let counterpart = if from_own_device { sync_peer } else { Some(sender.user_id.clone()) };
        let Some(counterpart) = counterpart else { return };
        if !self.in_conversation(local, &conversation_id, &counterpart).await {
            return;
        }
        // A conversation is ordered by when things ARRIVED: the sender's clock is the sender's
        // claim (it could file a message anywhere in the past), the mailbox's arrival time is
        // not theirs to choose. The claimed time rides along and is shown beside it.
        let now = now_ms() as i64;
        self.inbox_dms.push(InboundDm {
            conversation_id,
            message_id,
            author_id: if from_own_device { SELF_AUTHOR.to_string() } else { sender.user_id },
            text,
            created_at: received_at.min(now),
            peer_user_id: counterpart,
            sent_at: Some(sent_at.min(now)),
        });
    }

    // ---- direct messages ----

    /// Look up a user by username → (user_id, a device_id). The device id is only a hint: sends
    /// always fan out to every device of the user.
    pub async fn find_user(&self, username: &str) -> Result<(String, String), EngineError> {
        let resp = self.api.get(&format!("/api/users/lookup?username={}", enc(username))).await?;
        let user_id = resp["user_id"].as_str().ok_or(EngineError::Protocol("user not found"))?.to_string();
        let device_id = resp["device_id"].as_str().ok_or(EngineError::Protocol("user has no device yet"))?.to_string();
        Ok((user_id, device_id))
    }

    /// Create or reuse a 1:1 DM conversation with `peer_user_id`; returns its id. (The conversation
    /// record is routing metadata; message content never touches it.)
    pub async fn open_dm(&mut self, peer_user_id: &str) -> Result<String, EngineError> {
        let resp = self.api.post("/api/dms", serde_json::json!({ "participant_ids": [peer_user_id] })).await?;
        let id = resp["conversation_id"].as_str().map(str::to_string).ok_or(EngineError::Protocol("no conversation_id"))?;
        self.dm_participants.remove(&id);
        Ok(id)
    }

    /// Send `text` to `peer`'s user: sealed-sender encrypted separately to every device of that
    /// user, plus a synced copy to each of our own other devices. Returns the (client-generated)
    /// message id. Fails if no device of the peer could be reached.
    ///
    /// Delivery is per DEVICE: the message counts as sent once one of the peer's devices has
    /// it, and every device that did not take it (unreachable session, a full mailbox) is owed
    /// it and retried on its own schedule ([`Engine::retry_deliveries`]) — it is not forgotten
    /// because another device accepted.
    pub async fn send_dm(&mut self, conversation_id: &str, peer: &PeerId, text: &str) -> Result<String, EngineError> {
        let message_id = skwod_crypto::new_distribution_id().to_string();
        self.send_dm_as(conversation_id, std::slice::from_ref(&peer.user_id), &message_id, text, None).await?;
        Ok(message_id)
    }

    /// Take every buffered inbound DM (all conversations).
    pub fn take_dms(&mut self) -> Vec<InboundDm> {
        std::mem::take(&mut self.inbox_dms)
    }

    /// Sync the mailbox and return the inbound messages of one conversation (chronological),
    /// leaving other conversations' messages buffered for [`Engine::take_dms`].
    pub async fn fetch_inbound_dm(&mut self, conversation_id: &str, _peer: &PeerId, _my_user_id: &str) -> Result<Vec<InboundMessage>, EngineError> {
        self.sync_inbox().await?;
        let (mine, rest): (Vec<InboundDm>, Vec<InboundDm>) =
            std::mem::take(&mut self.inbox_dms).into_iter().partition(|m| m.conversation_id == conversation_id);
        self.inbox_dms = rest;
        Ok(mine
            .into_iter()
            .map(|m| InboundMessage {
                message_id: m.message_id,
                author_id: m.author_id,
                text: m.text,
                created_at: m.created_at,
                reply_to_id: None,
                is_edited: false,
                deleted: false,
                undecryptable: false,
            })
            .collect())
    }

    // ---- channels (Sender Keys) ----

    fn send_key_id(&self, scope: &str) -> Option<Uuid> {
        self.send_keys.get(scope).map(|k| Uuid::from_bytes(k.distribution_id))
    }

    /// Create (or rotate) our sender key for `scope`. Rotating mints a NEW distribution id and key
    /// (libsignal keeps no link to the old chain), deletes the old key so it can never be used to
    /// send again, and resets the holder set: the fresh key has been handed to nobody.
    pub fn create_group_session(&mut self, scope: &str) -> Result<(), EngineError> {
        self.refuse_if_passive()?;
        let local = self.local()?;
        if let Some(old) = self.send_keys.remove(scope) {
            self.store.delete_sender_key(&local, Uuid::from_bytes(old.distribution_id));
        }
        let id = skwod_crypto::new_distribution_id();
        self.store.create_distribution(&local, id)?;
        self.send_keys.insert(scope.to_string(), SendKey { distribution_id: *id.as_bytes(), holders: BTreeSet::new() });
        self.stale_scopes.remove(scope);
        Ok(())
    }

    fn ensure_send_key(&mut self, scope: &str) -> Result<Uuid, EngineError> {
        if !self.send_keys.contains_key(scope) {
            self.create_group_session(scope)?;
        }
        self.send_key_id(scope).ok_or_else(|| EngineError::NoSession(scope.to_string()))
    }

    /// Record that `user_id` was removed from `server_id` (the server's `member_removed` event, a
    /// member-list diff, or local knowledge of a kick/ban/leave). Every scope of ours in that
    /// server whose current key any of their devices holds is marked stale, so the next membership
    /// check rotates it, and we stop accepting their sender keys for that server's channels.
    pub fn member_removed(&mut self, server_id: &str, user_id: &str) {
        self.roster_remove(server_id, user_id);
        // They also hold our mailbox delivery key (every member is handed it): replace it.
        self.delivery_key_exposed();
        for (scope, key) in &self.send_keys {
            let in_server = scope
                .strip_prefix("channel:")
                .and_then(|c| self.channel_servers.get(c))
                // Unknown channel → assume it may belong to this server (over-rotating is safe).
                .is_none_or(|s| s == server_id);
            if in_server && key.holders.iter().any(|d| d.user_id == user_id) {
                self.stale_scopes.insert(scope.clone());
            }
        }
        let scopes: HashSet<String> =
            self.channel_servers.iter().filter(|(_, s)| s.as_str() == server_id).map(|(c, _)| format!("channel:{c}")).collect();
        let dropped: Vec<(String, RecvKey)> = self
            .recv_keys
            .iter()
            .filter(|(_, r)| r.sender.user_id == user_id && scopes.contains(&r.scope))
            .map(|(id, r)| (id.clone(), r.clone()))
            .collect();
        for (id, r) in dropped {
            self.recv_keys.remove(&id);
            self.recv_order.retain(|o| o != &id);
            if let Ok(uuid) = id.parse::<Uuid>() {
                self.store.delete_sender_key(&r.sender, uuid);
            }
        }
    }

    /// Does our current sender key for `scope` need rotating before the next send?
    pub fn group_key_stale(&self, scope: &str) -> bool {
        self.send_keys.contains_key(scope) && self.stale_scopes.contains(scope)
    }

    /// Whether our sender key for `scope` must rotate given the live member devices: yes when any
    /// device holding the CURRENT key is no longer a member device (its user was kicked, banned or
    /// left — or that device was removed from their account), or a removal was reported.
    fn membership_rotation_needed(&self, scope: &str, devices: &BTreeSet<DeviceAddress>) -> bool {
        match self.send_keys.get(scope) {
            None => false, // no key ⇒ nothing distributed ⇒ nothing to protect
            Some(key) => self.stale_scopes.contains(scope) || key.holders.iter().any(|d| !devices.contains(d)),
        }
    }

    /// Enforce the membership boundary on our sender key for one channel and make sure **every
    /// device of every current member** holds it:
    ///
    /// 1. fetch the live member-device list (a failed fetch is an error — never encrypt under a key
    ///    we could not vouch for);
    /// 2. if the current key reached anyone no longer on that list, rotate it;
    /// 3. hand the current key to every listed device that does not hold it yet — including the
    ///    other devices of a member we already keyed, and our own other devices.
    ///
    /// Returns whether a rotation happened. Per-device hand-off failures are non-fatal (they are
    /// retried on the next call); that device simply is not recorded as a holder.
    async fn sync_channel_key(&mut self, channel_id: &str, server_id: &str) -> Result<bool, EngineError> {
        let local = self.local()?;
        let scope = format!("channel:{channel_id}");
        let _ = self.refresh_siblings(false).await;
        let devices: BTreeSet<DeviceAddress> = self
            .fetch_member_devices(server_id)
            .await?
            .into_iter()
            .filter(|d| d != &local)
            // Of our own account's devices, only verified siblings count as members.
            .filter(|d| d.user_id != local.user_id || self.siblings.contains_key(&d.device_id))
            .collect();
        // Members whose devices held our key and are gone: stop accepting THEIR keys here too.
        // (Computed against what the SERVER lists; who may receive the key is decided below.)
        let current_users: HashSet<&str> = devices.iter().map(|d| d.user_id.as_str()).collect();
        let gone_users: BTreeSet<String> = self
            .send_keys
            .get(&scope)
            .into_iter()
            .flat_map(|k| k.holders.iter())
            .filter(|d| !current_users.contains(d.user_id.as_str()) && d.user_id != local.user_id)
            .map(|d| d.user_id.clone())
            .collect();
        // "No devices listed" is not always "no longer a member": a block (in either direction)
        // hides two members' devices from each other while both stay in the server. Such a
        // member gets no key from us for as long as that lasts (the rotation below) — but is not
        // struck off the roster, or an unblock would leave the two unable to read each other
        // until someone approved a join that never happened. Only someone the member list no
        // longer names is removed. (If that list cannot be read, assume removed, as before.)
        if !gone_users.is_empty() {
            let still_members: HashSet<String> = self.list_members(server_id).await.map(|m| m.into_iter().map(|(id, _)| id).collect()).unwrap_or_default();
            for user in gone_users {
                if !still_members.contains(&user) {
                    self.member_removed(server_id, &user);
                }
            }
        }
        let rotated = self.membership_rotation_needed(&scope, &devices);
        if rotated {
            self.create_group_session(&scope)?;
        }
        let id = self.ensure_send_key(&scope)?;
        let holders = self.send_keys.get(&scope).map(|k| k.holders.clone()).unwrap_or_default();
        // The server's member list is a claim. Our key goes only to members this device accepts
        // (baseline, or a signed approval from someone already accepted) and only once their
        // arrival — or their new device — has been shown in this channel.
        let admitted = self.admit(server_id, &scope, devices.into_iter().collect()).await;
        let need: Vec<DeviceAddress> = admitted.into_iter().filter(|d| !holders.contains(d)).collect();
        if !need.is_empty() {
            let skdm = self.store.create_distribution(&local, id)?;
            let content = Content::SenderKey { channel_id: channel_id.to_string(), skdm };
            if let Ok(delivered) = self.send_content(&need, &content).await {
                let now = now_ms() as i64;
                for device in &delivered {
                    if let Ok(name) = device.name() {
                        self.acct.keyed_at.entry(format!("{scope}|{name}")).or_insert(now);
                    }
                }
                if let Some(key) = self.send_keys.get_mut(&scope) {
                    key.holders.extend(delivered);
                }
            }
        }
        Ok(rotated)
    }

    /// Which server a channel belongs to. Usually already known (channel lists populate the map);
    /// otherwise look through the servers we belong to. Errors if the channel is in none of them —
    /// callers must not send into a channel whose membership they cannot check.
    async fn channel_server(&mut self, channel_id: &str) -> Result<String, EngineError> {
        if let Some(s) = self.channel_servers.get(channel_id) {
            return Ok(s.clone());
        }
        let resp = self.api.get("/api/servers").await?;
        let servers: Vec<String> =
            resp["servers"].as_array().into_iter().flatten().take(MAX_SERVER_ARRAY).filter_map(|s| s["server_id"].as_str().map(str::to_string)).collect();
        for server_id in servers {
            let _ = self.list_channels(&server_id).await;
            if let Some(s) = self.channel_servers.get(channel_id) {
                return Ok(s.clone());
            }
        }
        Err(EngineError::Protocol("unknown channel"))
    }

    /// [`Self::sync_channel_key`] for whichever server the channel belongs to.
    async fn ensure_current_group_key(&mut self, channel_id: &str) -> Result<bool, EngineError> {
        let server_id = self.channel_server(channel_id).await?;
        self.sync_channel_key(channel_id, &server_id).await
    }

    /// Enforce the membership boundary on ONE channel and distribute our key to every member
    /// device. Call on channel open and periodically while it is active. Returns whether a rotation
    /// happened.
    pub async fn sync_channel_membership(&mut self, channel_id: &str, server_id: &str, _my_user_id: &str) -> Result<bool, EngineError> {
        if !self.bind_channel(channel_id, server_id) {
            return Err(EngineError::Protocol("that channel belongs to another space"));
        }
        self.sync_channel_key(channel_id, server_id).await
    }

    /// [`Self::sync_channel_membership`] across EVERY channel of a server. Call right after
    /// kicking/banning someone so all of the server's keys rotate at once.
    pub async fn sync_server_membership(&mut self, server_id: &str, _my_user_id: &str) -> Result<bool, EngineError> {
        let channels = self.list_channels(server_id).await?;
        let mut rotated = false;
        for ch in &channels {
            rotated |= self.sync_channel_key(&ch.channel_id, server_id).await?;
        }
        Ok(rotated)
    }

    /// Hand our channel sender key to a member — to **all** of that user's devices (the device id in
    /// `peer` is only a hint). Refuses a user who is not a member of the channel's server, and
    /// rotates first if the current key already reached someone since removed.
    pub async fn share_group_key(&mut self, channel_id: &str, peer: &PeerId) -> Result<(), EngineError> {
        let scope = format!("channel:{channel_id}");
        let server_id = self.channel_server(channel_id).await?;
        let devices = self.fetch_member_devices(&server_id).await?;
        if !devices.iter().any(|d| d.user_id == peer.user_id) {
            return Err(EngineError::Protocol("recipient is not a member of this space"));
        }
        self.sync_channel_key(channel_id, &server_id).await?;
        let reached = self.send_keys.get(&scope).is_some_and(|k| k.holders.iter().any(|d| d.user_id == peer.user_id));
        if reached {
            Ok(())
        } else {
            Err(EngineError::Protocol("could not reach any device of that member"))
        }
    }

    /// Encrypt `text` with our channel sender key and post it. Returns the message id.
    pub async fn send_channel_message(&mut self, channel_id: &str, text: &str) -> Result<String, EngineError> {
        self.send_channel_message_reply(channel_id, text, None).await
    }

    /// Seal one channel message: the text plus its own id, reply target and edit flag, all inside
    /// the sender-key plaintext, so none of that metadata is the server's to choose.
    fn channel_ciphertext(&mut self, channel_id: &str, message_id: &str, reply_to: Option<&str>, edited: bool, text: &str) -> Result<String, EngineError> {
        let local = self.local()?;
        let id = self.ensure_send_key(&format!("channel:{channel_id}"))?;
        let body = ChannelBody { id: message_id.to_string(), reply_to: reply_to.map(str::to_string), edited, text: text.to_string() };
        let plaintext = postcard::to_stdvec(&body).map_err(|_| EngineError::Serde)?;
        let mut wire = vec![CHANNEL_WIRE_V3];
        wire.extend(self.store.group_encrypt(&local, id, &plaintext)?);
        Ok(B64.encode(wire))
    }

    /// Send a channel message, optionally as a REPLY to `reply_to_id`. See
    /// [`Engine::send_channel_message_with`].
    pub async fn send_channel_message_reply(&mut self, channel_id: &str, text: &str, reply_to_id: Option<&str>) -> Result<String, EngineError> {
        self.send_channel_message_with(channel_id, text, reply_to_id, &[]).await
    }

    /// Send a channel message. The message id is chosen
    /// here (a fresh random UUID; the server must file the message under exactly it, and refuses
    /// a duplicate) and travels INSIDE the ciphertext together with the reply target; receivers
    /// check both, so the server can neither re-attach the ciphertext to another message nor
    /// point the reply somewhere else. (`reply_to_id` is still sent in the clear for the server's own
    /// bookkeeping; receivers ignore that copy.)
    ///
    /// `blob_ids` are the uploads this message's body refers to: the server links them to the
    /// message as it stores it, which is what lets the other members download them.
    pub async fn send_channel_message_with(&mut self, channel_id: &str, text: &str, reply_to_id: Option<&str>, blob_ids: &[String]) -> Result<String, EngineError> {
        let message_id = skwod_crypto::new_distribution_id().to_string();
        self.send_channel_message_as(channel_id, &message_id, text, reply_to_id, blob_ids).await?;
        Ok(message_id)
    }

    /// [`Engine::send_channel_message_with`] under a message id the CALLER chose, returning the
    /// SERVER's time for the message. Repeating a send under the same id is safe: the server
    /// files an author's id once and answers a repeat with the original's time — which is what
    /// lets a queued send be retried until an answer is seen (the core's outbox).
    pub async fn send_channel_message_as(&mut self, channel_id: &str, message_id: &str, text: &str, reply_to_id: Option<&str>, blob_ids: &[String]) -> Result<i64, EngineError> {
        self.unsent = None;
        if text.len() > MAX_TEXT {
            return Err(EngineError::TooLarge(TOO_LARGE));
        }
        if Uuid::parse_str(message_id).map(|u| u.hyphenated().to_string()).ok().as_deref() != Some(message_id) {
            return Err(EngineError::Protocol("bad message id"));
        }
        // Never encrypt under a key a removed member still holds: re-check the member devices and
        // rotate first if needed (fails the send if the list can't be fetched).
        self.ensure_bound().await?;
        self.ensure_current_group_key(channel_id).await?;
        let message_id = message_id.to_string();
        let ciphertext = self.channel_ciphertext(channel_id, &message_id, reply_to_id, false, text)?;
        if B64.decode(&ciphertext).map(|w| w.len()).unwrap_or(usize::MAX) > MAX_WIRE_ENVELOPE {
            return Err(EngineError::TooLarge(TOO_LARGE));
        }
        // Kept so a member whose device lost our sender key (a restore) can be sent it again;
        // and the sender-key chain that just advanced goes to disk, with the message, before
        // the ciphertext leaves.
        self.remember_channel_message(channel_id, &message_id, reply_to_id, false, text);
        // (Game state is filed apart from the conversation; see `Traffic`.)
        let scope = if Traffic::of(text).hidden { format!("aux:{channel_id}") } else { format!("channel:{channel_id}") };
        let row = OutgoingRow { scope, message_id: message_id.clone(), text: text.to_string(), created_at: now_ms() as i64, reply_to_id: reply_to_id.map(str::to_string) };
        self.checkpoint(Some(&row))?;
        // Nothing about WHAT this is goes to the server: a chat line, a like and a chess move
        // are the same opaque envelope there (see `Traffic`).
        let mut body = serde_json::json!({
            "message_id": message_id,
            "ciphertext": ciphertext,
            "author_device_id": self.device_id,
        });
        if let Some(r) = reply_to_id {
            body["reply_to_id"] = serde_json::json!(r);
        }
        if !blob_ids.is_empty() {
            body["blob_ids"] = serde_json::json!(blob_ids);
        }
        let resp = self.api.post(&format!("/api/channels/{}/messages", enc(channel_id)), body).await.map_err(|e| self.fatal(e.into()))?;
        let assigned = resp["message_id"].as_str().ok_or(EngineError::Protocol("no message_id"))?;
        if assigned != message_id {
            // The id is OURS to choose: it is inside the ciphertext, and receivers drop a
            // ciphertext served under any other id. A server that files the message under an id
            // of its own (one that predates client-chosen ids — or one that wants to pick the id,
            // perhaps an id that already exists) does not get the content re-sealed to match.
            // Withdraw the stray row and fail the send.
            let _ = self.api.delete(&format!("/api/messages/{}", enc(assigned))).await;
            return Err(EngineError::UpdateRequired(
                "this skwod's server has to be updated before this app can send messages here; ask the host to update it".into(),
            ));
        }
        self.unsent = None;
        Ok(resp["created_at"].as_i64().unwrap_or_else(|| now_ms() as i64))
    }

    /// Edit a channel message we authored: re-encrypt the new text with our current sender key,
    /// marked as an edit of exactly `message_id` inside the ciphertext, and PATCH it in place.
    /// `reply_to_id` is the message's existing reply target (it is re-stated, not changed).
    ///
    /// The edit is sealed under THIS device's sender key — which need not be the device that
    /// sent the original — so the server is told which device made it; readers decrypt the row
    /// as that device.
    pub async fn edit_channel_message(&mut self, channel_id: &str, message_id: &str, text: &str, reply_to_id: Option<&str>) -> Result<(), EngineError> {
        if text.len() > MAX_TEXT {
            return Err(EngineError::TooLarge(TOO_LARGE));
        }
        self.ensure_bound().await?;
        self.ensure_current_group_key(channel_id).await?; // same guarantee as a fresh send
        let ciphertext = self.channel_ciphertext(channel_id, message_id, reply_to_id, true, text)?;
        self.remember_channel_message(channel_id, message_id, reply_to_id, true, text);
        self.checkpoint(None)?;
        self.api
            .patch(&format!("/api/messages/{}", enc(message_id)), serde_json::json!({ "ciphertext": ciphertext, "author_device_id": self.device_id }))
            .await
            .map_err(|e| self.fatal(e.into()))?;
        Ok(())
    }

    /// Decrypt one channel message from `sender` in `scope`. The message's distribution id must be
    /// one that `sender` announced **for this scope**. Returns the text and, for a v3 message,
    /// the metadata the sender authenticated — the caller must compare it with the row it came in.
    ///
    /// The version byte in front is the server's claim (it is outside the ciphertext), so the
    /// plaintext decides (M2):
    ///
    /// (a) it is a [`ChannelBody`] — exactly, with nothing left over: a v3 message, also when
    ///     it was served labelled v2. Its id, reply target and edit flag are the sealed ones.
    /// (b) it is anything else under a v2 label: a build-42 message. Text only (`meta: None`).
    /// (c) …unless this sender device has been seen writing v3 here and its own signed counter
    ///     puts this body after that ([`V3Seen`]): refused with [`V2_AFTER_V3`].
    ///
    /// What a malicious server can still do with build-42 bodies: serve one this device has
    /// not opened yet (a sender key opens each message once) under any row — any message id,
    /// position or date — or leave it out. It cannot alter the text, show it twice, attach a
    /// reply or an edit marker to it, or do any of this to a v3 message.
    pub fn open_channel_message(&mut self, scope: &str, sender: &PeerId, wire: &[u8]) -> Result<ChannelPlaintext, EngineError> {
        let (version, body) = match wire.split_first() {
            Some((v @ (&CHANNEL_WIRE_V2 | &CHANNEL_WIRE_V3), rest)) if wire.len() <= MAX_WIRE_ENVELOPE => (*v, rest),
            _ => return Err(EngineError::Protocol("not a channel message")),
        };
        // Unauthenticated until the decryption below has checked the sender's signature over it.
        let (id, chain, iteration) = SignalStore::group_message_position(body)?;
        let dist = id.to_string();
        match self.recv_keys.get(&dist) {
            Some(r) if r.scope == scope && &r.sender == sender => {}
            _ => return Err(EngineError::NoSession(format!("{scope}|{}", sender.name()?))),
        }
        let plaintext = self.store.group_decrypt(sender, body)?.1;
        let mark = format!("{scope}|{}", sender.name()?);
        // Strict: the whole plaintext is one `ChannelBody`, or it is not one.
        if let Ok((body, [])) = postcard::take_from_bytes::<ChannelBody>(&plaintext) {
            self.note_v3(mark, scope, sender, &dist, chain, iteration);
            return Ok(ChannelPlaintext { text: body.text, meta: Some((body.id, body.reply_to, body.edited)) });
        }
        if version != CHANNEL_WIRE_V2 {
            return Err(EngineError::Protocol("malformed channel message"));
        }
        if let Some(seen) = self.b45.v3_seen.get(&mark) {
            let before_v3 = seen.legacy.get(&dist).is_some_and(|floors| floors.get(&chain).is_none_or(|first_v3| iteration < *first_v3));
            if !before_v3 {
                return Err(EngineError::Protocol(V2_AFTER_V3));
            }
        }
        Ok(ChannelPlaintext { text: String::from_utf8(plaintext).map_err(|_| EngineError::Protocol("message is not text"))?, meta: None })
    }

    /// `sender` sealed a v3 body in `scope` at `(dist, chain, iteration)` of its key schedule.
    fn note_v3(&mut self, mark: String, scope: &str, sender: &PeerId, dist: &str, chain: u32, iteration: u32) {
        if !self.b45.v3_seen.contains_key(&mark) {
            // The first one: what it had announced to us up to now is where build-42 bodies
            // of its may still turn up.
            let legacy = self.recv_keys.iter().filter(|(_, r)| r.scope == scope && &r.sender == sender).map(|(id, _)| (id.clone(), BTreeMap::new())).collect();
            self.b45.v3_seen.insert(mark.clone(), V3Seen { legacy });
        }
        if let Some(floors) = self.b45.v3_seen.get_mut(&mark).and_then(|seen| seen.legacy.get_mut(dist)) {
            let first_v3 = floors.entry(chain).or_insert(iteration);
            *first_v3 = (*first_v3).min(iteration);
        }
    }

    /// The build-45 section as persisted: bounded, and without what can no longer matter. A
    /// distribution whose key is gone can open nothing, so it is dropped from `legacy` — which
    /// only ever makes the rule stricter (a mark with no legacy distribution left refuses every
    /// build-42 body from that device). If there are still too many marks, those of senders we
    /// hold no key from at all in that channel go first.
    fn b45_for_export(&self) -> Build45Ext {
        let mut out = self.b45.clone();
        for seen in out.v3_seen.values_mut() {
            seen.legacy.retain(|dist, _| self.recv_keys.contains_key(dist));
        }
        if out.v3_seen.len() > MAX_V3_SEEN {
            let mut excess = out.v3_seen.len() - MAX_V3_SEEN;
            out.v3_seen.retain(|_, seen| {
                let drop = excess > 0 && seen.legacy.is_empty();
                excess -= usize::from(drop);
                !drop
            });
            while out.v3_seen.len() > MAX_V3_SEEN {
                out.v3_seen.pop_first();
            }
        }
        out.deferred_provisions.truncate(MAX_DEFERRED_PROVISIONS);
        out
    }

    /// [`Self::open_channel_message`], text only (no metadata check). For tools and tests.
    pub fn group_decrypt(&mut self, scope: &str, sender: &PeerId, wire: &[u8]) -> Result<Vec<u8>, EngineError> {
        Ok(self.open_channel_message(scope, sender, wire)?.text.into_bytes())
    }

    /// The reply target and edit flag to show for a decrypted message that the server served
    /// as row `mid` — or `None` to drop it.
    ///
    /// v3 (`meta` present): the id, reply target and edit flag are the SENDER's, from inside the
    /// ciphertext. A ciphertext served under any other message id is dropped: the server moved
    /// it, or replayed it into another slot (never shown as text instead).
    ///
    /// Build 42 (`meta` absent): the sender stated none of them, so there is no reply link and
    /// no edit marker. The row's own `reply_to_id` / `is_edited` are the server's word and are
    /// not used for ANY message — which is why this takes no row.
    fn row_metadata(mid: &str, meta: Option<(String, Option<String>, bool)>) -> Option<(Option<String>, bool)> {
        match meta {
            Some((id, reply_to, edited)) => (id == mid).then_some((reply_to, edited)),
            None => Some((None, false)),
        }
    }

    /// Fetch + decrypt the newest page of a channel (chronological). For tools and tests; apps
    /// go through [`Engine::channel_page`] with a cursor.
    pub async fn fetch_channel_messages(&mut self, channel_id: &str, my_user_id: &str) -> Result<Vec<InboundMessage>, EngineError> {
        // Pick up any sender keys that arrived since the last poll.
        let _ = self.sync_inbox().await;
        Ok(self.channel_page(channel_id, my_user_id, PageCursor::Before(i64::MAX)).await?.messages)
    }

    /// Fetch one page of a channel and decrypt what other devices wrote (oldest first within
    /// the page). Messages we cannot decrypt (no sender key yet, already consumed, pre-upgrade
    /// ciphertext) are skipped but still counted in `rows`, so a caller can keep paging.
    pub async fn channel_page(&mut self, channel_id: &str, my_user_id: &str, cursor: PageCursor) -> Result<ChannelPage, EngineError> {
        let scope = format!("channel:{channel_id}");
        let at = match cursor {
            PageCursor::Before(t) => format!("before={t}"),
            PageCursor::After(t) => format!("after={t}"),
        };
        let resp = self.api.get(&format!("/api/channels/{}/messages?limit={PAGE}&{at}", enc(channel_id))).await?;
        let mut msgs = resp["messages"].as_array().cloned().unwrap_or_default();
        msgs.truncate(MAX_SERVER_ARRAY);
        // Rows are shown only for authors this device accepts as members of the channel's
        // server (its own roster). Without a roster nothing can be attributed: fail closed.
        let server_id = self.channel_server(channel_id).await?;
        self.ensure_roster(&server_id).await?;
        // Decrypt in the order the messages were written: a sender key only ratchets forward.
        msgs.sort_by_key(|m| (m["created_at"].as_i64().unwrap_or_default(), m["updated_at"].as_i64().unwrap_or_default()));
        // `cleared_at` in the response is the SERVER saying the channel was cleared. It is not
        // passed on: nothing is purged on a server field. A clear reaches a device as a sealed
        // message from the pinned owner, checked against the confirmed placement of the
        // channel (`guard::on_channel_clear`, `take_channel_clears`).
        let mut page = ChannelPage { rows: msgs.len(), min_created_at: i64::MAX, cleared_at: None, ..Default::default() };
        // What we could not decrypt, per author device: asked for again after the loop.
        let mut missing: BTreeMap<DeviceAddress, Vec<String>> = BTreeMap::new();
        let reaction_key = self.channel_servers.get(channel_id).and_then(|sid| self.spaces.get(sid)).copied();
        for m in &msgs {
            let mid = m["message_id"].as_str().unwrap_or_default().to_string();
            page.max_updated_at = page.max_updated_at.max(m["updated_at"].as_i64().unwrap_or_default());
            page.min_created_at = page.min_created_at.min(m["created_at"].as_i64().unwrap_or(i64::MAX));
            page.ids.push(mid.clone());
            for r in m["reactions"].as_array().into_iter().flatten().take(MAX_SERVER_ARRAY) {
                let (Some(user_id), Some(emoji_hash)) = (r["user_id"].as_str(), r["emoji_hash"].as_str()) else { continue };
                // Only a reaction that opens for this message and this user is one; and only
                // an accepted member's.
                if !self.accepted_member(&server_id, user_id) {
                    continue;
                }
                let Some(emoji) = Self::open_reaction(reaction_key.as_ref(), &mid, user_id, emoji_hash, r["emoji_ciphertext"].as_str()) else { continue };
                page.reactions.push(Reaction { message_id: mid.clone(), user_id: user_id.to_string(), emoji_hash: emoji_hash.to_string(), emoji: Some(emoji) });
            }
            // Whatever the server serves under the name of someone who is not an accepted
            // member — a message, a tombstone — is not a row of this channel.
            if !m["author_id"].as_str().is_some_and(|author| self.accepted_member(&server_id, author)) {
                continue;
            }
            // A deleted message tombstones for EVERY device (including the author's other devices).
            if m["deleted_at"].as_i64().is_some() {
                page.messages.push(InboundMessage {
                    message_id: mid,
                    author_id: m["author_id"].as_str().unwrap_or_default().to_string(),
                    text: String::new(),
                    created_at: m["created_at"].as_i64().unwrap_or_default(),
                    reply_to_id: None,
                    is_edited: false,
                    deleted: true,
                    undecryptable: false,
                });
                continue;
            }
            let Some(author) = m["author_id"].as_str() else { continue };
            let Some(device) = m["author_device_id"].as_str() else { continue };
            // Skip only what THIS device sealed (rendered from the local cache already). A sibling
            // device's messages — and a sibling's EDIT of a message this device sent: the row
            // then names the editing device — are decrypted and shown.
            if author == my_user_id && Some(device) == self.device_id.as_deref() {
                // …unless it was sealed under this device id on ANOTHER install: the device
                // was restored here after it was written (moved to a new phone and back, or
                // restored from a backup older than the message). This cache never held it and
                // the keys it was sealed with are gone, so nobody can be asked for it again.
                // It is not silently missing either: a placeholder, final. The cache keeps
                // what it already holds (this install's own rows), so only the gap gets one.
                let created_at = m["created_at"].as_i64().unwrap_or_default();
                if !mid.is_empty() && self.acct.restored_at.is_some_and(|at| created_at <= at) {
                    let mut row = Self::channel_placeholder(&mid, author, created_at);
                    row.text = undecryptable_body(author, true);
                    page.messages.push(row);
                }
                continue;
            }
            let Some(bytes) = m["ciphertext"].as_str().and_then(|ct| B64.decode(ct).ok()) else { continue };
            let peer = DeviceAddress::new(author, device);
            let pt = match self.open_channel_message(&scope, &peer, &bytes) {
                Ok(pt) => pt,
                // A current-protocol message we hold no usable key for (we were restored, the
                // key never reached us, the chain moved on). It is not silently missing: a
                // placeholder takes its place and its author's device is asked to send it again.
                // (Not a replay of one we already read, not something written before we were
                // let in — see `should_ask_again` — and not a build-42 body refused because
                // its sender had already moved to v3: that one is final.)
                Err(e)
                    if matches!(bytes.first(), Some(&CHANNEL_WIRE_V2 | &CHANNEL_WIRE_V3))
                        && !mid.is_empty()
                        && !self.blocked.contains(author)
                        && !matches!(&e, EngineError::Protocol(why) if *why == V2_AFTER_V3)
                        && !matches!(&e, EngineError::Crypto(why) if why == "duplicate message")
                        && self.should_ask_again(&scope, author, m["created_at"].as_i64().unwrap_or_default()) =>
                {
                    page.messages.push(Self::channel_placeholder(&mid, author, m["created_at"].as_i64().unwrap_or_default()));
                    missing.entry(peer).or_default().push(mid);
                    continue;
                }
                Err(_) => continue,
            };
            let Some((reply_to_id, is_edited)) = Self::row_metadata(&mid, pt.meta) else { continue };
            page.messages.push(InboundMessage {
                message_id: mid,
                author_id: author.to_string(),
                // What a member wrote is a message, whatever it starts with.
                text: crate::cache::neutralize_reserved(&pt.text).to_string(),
                created_at: m["created_at"].as_i64().unwrap_or_default(),
                reply_to_id,
                is_edited,
                deleted: false,
                undecryptable: false,
            });
        }
        if !missing.is_empty() {
            self.ask_channel_again(channel_id, missing).await;
        }
        Ok(page)
    }

    /// Every 1:1 DM conversation this ACCOUNT is in, as the server lists them — including ones
    /// started on another of our devices, or by the other person, that this device never opened.
    pub async fn list_dms(&mut self) -> Result<Vec<DmConversation>, EngineError> {
        let me = self.account_user_id().await?;
        let list = self.api.get("/api/dms").await?;
        let mut out = Vec::new();
        for c in list["conversations"].as_array().into_iter().flatten().take(MAX_SERVER_ARRAY) {
            let Some(id) = c["conversation_id"].as_str() else { continue };
            let users: Vec<String> = c["participants"].as_array().into_iter().flatten().filter_map(|u| u.as_str().map(str::to_string)).collect();
            self.dm_participants.insert(id.to_string(), users.clone());
            if c["is_group"].as_bool() == Some(true) || users.len() != 2 {
                continue;
            }
            let Some(peer) = users.iter().find(|u| **u != me) else { continue };
            if self.blocked.contains(peer) {
                continue;
            }
            let name = c["participant_names"][peer.as_str()].as_str().unwrap_or_default().to_string();
            out.push(DmConversation { conversation_id: id.to_string(), peer_user_id: peer.clone(), peer_username: name });
        }
        Ok(out)
    }

    /// Calls ringing for this account right now on this server: `(channel_id, server_id, from
    /// user, ring_id, expires_at ms)`. What a device woken by a call push asks every one of its
    /// servers, to find the room that is actually ringing.
    pub async fn pending_rings(&self) -> Result<Vec<(String, String, String, String, i64)>, EngineError> {
        let v = self.api.get("/api/rings").await?;
        Ok(v["rings"]
            .as_array()
            .into_iter()
            .flatten()
            .take(MAX_SERVER_ARRAY)
            .filter_map(|r| {
                Some((
                    r["channel_id"].as_str()?.to_string(),
                    r["server_id"].as_str()?.to_string(),
                    r["from"].as_str()?.to_string(),
                    r["ring_id"].as_str().unwrap_or_default().to_string(),
                    r["expires_at"].as_i64().unwrap_or_default(),
                ))
            })
            .collect())
    }

    // ---- spaces (encrypted metadata) + provisioning ----

    /// AEAD-seal a channel/space name under a space key: `b64(nonce || ciphertext)`.
    fn seal_name(key: &[u8; 32], name: &str) -> String {
        B64.encode(aead::seal(key, b"skwod/space-name", name.as_bytes()))
    }

    /// Open a sealed name with a space key. Returns None on any failure (unknown key / tampering).
    fn open_name(key: &[u8; 32], sealed_b64: &str) -> Option<String> {
        String::from_utf8(aead::open(key, b"skwod/space-name", &B64.decode(sealed_b64).ok()?)?).ok()
    }

    /// Decrypt a channel/space name for a space we hold the key for.
    pub fn decrypt_name(&self, server_id: &str, sealed_b64: &str) -> Option<String> {
        self.spaces.get(server_id).and_then(|k| Self::open_name(k, sealed_b64))
    }

    async fn create_channel_of(&mut self, server_id: &str, key: &[u8; 32], name: &str, kind: &str) -> Result<String, EngineError> {
        self.create_channel_for(server_id, key, name, kind, None).await
    }

    async fn create_channel_for(&mut self, server_id: &str, key: &[u8; 32], name: &str, kind: &str, purpose: Option<&str>) -> Result<String, EngineError> {
        let mut body = serde_json::json!({ "name_ciphertext": Self::seal_name(key, name), "type": kind });
        if let Some(p) = purpose {
            body["purpose"] = serde_json::json!(p);
        }
        let chan = self.api.post(&format!("/api/servers/{}/channels", enc(server_id)), body).await?;
        let channel_id = chan["channel_id"].as_str().ok_or(EngineError::Protocol("no channel_id"))?.to_string();
        self.confirm_channel(&channel_id, server_id);
        self.ensure_send_key(&format!("channel:{channel_id}"))?;
        Ok(channel_id)
    }

    /// Create a real E2EE space: a server plus a default text channel, both with encrypted names,
    /// plus an invite code. We also mint our own sender key for the channel.
    pub async fn create_space(&mut self, name: &str, channel_name: &str) -> Result<SpaceHandle, EngineError> {
        let sk: [u8; 32] = skwod_crypto::random_bytes();
        let server = self.api.post("/api/servers", serde_json::json!({ "name_ciphertext": Self::seal_name(&sk, name) })).await?;
        let server_id = server["server_id"].as_str().ok_or(EngineError::Protocol("no server_id"))?.to_string();
        let channel_id = self.create_channel_of(&server_id, &sk, channel_name, "text").await?;
        // The feed has a home of its own from the start (see `feed_channel`). An older server
        // that does not know the purpose refuses the field's value or ignores it; either way
        // the space exists and the fallback applies.
        let _ = self.create_channel_for(&server_id, &sk, "feed", "text", Some("feed")).await;
        // A code invite (default) needs host approval — for the creator's own first shareable link
        // we want an auto-join token so a friend can get in with just the code.
        let invite = self.api.post(&format!("/api/servers/{}/invites", enc(&server_id)), serde_json::json!({ "kind": "token" })).await?;
        let invite_code = invite["code"].as_str().ok_or(EngineError::Protocol("no invite code"))?.to_string();
        self.spaces.insert(server_id.clone(), sk);
        // We created it: we are its owner and, so far, its only member.
        if let Some(me) = self.user_id.clone() {
            self.pin_owner(&server_id, &me, trust::OwnerSource::Created);
            self.rosters.entry(server_id.clone()).or_default().members.insert(me);
        }
        Ok(SpaceHandle { server_id, channel_id, invite_code, space_key_hex: hex::encode(sk) })
    }

    /// Add a channel to an existing server we hold the space key for. Returns the channel id.
    pub async fn create_channel(&mut self, server_id: &str, name: &str) -> Result<String, EngineError> {
        let sk = *self.spaces.get(server_id).ok_or(EngineError::Protocol("no space key for server"))?;
        self.create_channel_of(server_id, &sk, name, "text").await
    }

    /// The ONE channel this server's feed (posts, stories, likes, comments) lives in — the same
    /// answer on every device and for every member:
    ///
    /// 1. the channel the server marks `purpose = feed` (hidden from channel lists);
    /// 2. a server created before that existed has none: whoever may manage channels (the
    ///    owner) creates it here, once;
    /// 3. until the owner's app has done that, everyone uses the lowest-position text channel
    ///    (the server's stable order) — not "whichever channel this device happened to list
    ///    first".
    pub async fn feed_channel(&mut self, server_id: &str) -> Result<String, EngineError> {
        let channels = self.list_channels(server_id).await?;
        if let Some(c) = channels.iter().find(|c| c.purpose.as_deref() == Some("feed")) {
            return Ok(c.channel_id.clone());
        }
        if let Some(sk) = self.spaces.get(server_id).copied() {
            if let Ok(id) = self.create_channel_for(server_id, &sk, "feed", "text", Some("feed")).await {
                // Only trust it if the server really made it THE feed channel (an old server
                // ignores the field and has just made an ordinary channel: remove that again).
                let now = self.list_channels(server_id).await?;
                if now.iter().any(|c| c.channel_id == id && c.purpose.as_deref() == Some("feed")) {
                    return Ok(id);
                }
                let _ = self.api.delete(&format!("/api/channels/{}", enc(&id))).await;
            }
        }
        channels.into_iter().find(|c| c.kind == "text").map(|c| c.channel_id).ok_or(EngineError::Protocol("this skwod has no text channel"))
    }

    /// Resolve (or create) this server's voice channel and return its id.
    pub async fn ensure_voice_channel(&mut self, server_id: &str, name: &str) -> Result<String, EngineError> {
        if let Some(ch) = self.list_channels(server_id).await?.into_iter().find(|c| c.kind == "voice") {
            return Ok(ch.channel_id);
        }
        let sk = *self.spaces.get(server_id).ok_or(EngineError::Protocol("no space key for server"))?;
        self.create_channel_of(server_id, &sk, name, "voice").await
    }

    /// Join a space via an invite code + its space key (hex), for a known channel. Returns whether
    /// the join is pending host approval.
    pub async fn join_space(&mut self, invite_code: &str, space_key_hex: &str, channel_id: &str) -> Result<JoinOutcome, EngineError> {
        let bytes = hex::decode(space_key_hex).map_err(|_| EngineError::Protocol("bad space key hex"))?;
        let sk: [u8; 32] = bytes.as_slice().try_into().map_err(|_| EngineError::Protocol("space key must be 32 bytes"))?;
        let resp = self.api.post(&format!("/api/invites/{}/accept", enc(invite_code)), serde_json::json!({})).await?;
        let outcome = Self::parse_join_outcome(&resp)?;
        self.apply_join(&outcome, Some(sk))?;
        self.confirm_channel(channel_id, &outcome.server_id);
        Ok(outcome)
    }

    /// Join a space with ONLY an invite code. Channel keys + names arrive
    /// automatically once the host provisions us over sealed sessions.
    pub async fn join_by_code(&mut self, invite_code: &str) -> Result<JoinOutcome, EngineError> {
        let resp = self.api.post(&format!("/api/invites/{}/accept", enc(invite_code)), serde_json::json!({})).await?;
        let outcome = Self::parse_join_outcome(&resp)?;
        self.apply_join(&outcome, None)?;
        Ok(outcome)
    }

    /// Take what an invite-accept response says into our trust state. The response is the
    /// server's: it names the space and its host, and the first time we hear of a space that is
    /// what we pin (the join is the user's own act). It can never CHANGE what is already there:
    ///
    /// - a space whose owner is pinned keeps that owner. A response naming anyone else for it —
    ///   any invite, accepted on a host that then answers with the id of a space we are already
    ///   in — is refused, and the user is told (`"owner_change_refused"`: `user_id` = who the
    ///   server named, `device_id` = the server id);
    /// - a space key we hold is never replaced.
    ///
    /// Changing either takes the user's explicit decision ([`Engine::forget_space`]).
    fn apply_join(&mut self, outcome: &JoinOutcome, space_key: Option<[u8; 32]>) -> Result<(), EngineError> {
        let server_id = &outcome.server_id;
        if server_id.is_empty() || server_id.len() > 128 || outcome.host_user_id.as_ref().is_some_and(|h| h.is_empty() || h.len() > 128) {
            return Err(EngineError::Protocol("join response"));
        }
        if let (Some(pinned), Some(named)) = (self.expected_provisioner.get(server_id), &outcome.host_user_id) {
            if pinned != named {
                let named = named.clone();
                self.notices.push(SecurityNotice { kind: "owner_change_refused".into(), user_id: named, device_id: server_id.clone(), at_ms: now_ms(), was_verified: false });
                return Err(EngineError::Protocol("this invite names a different owner for a space you are already in"));
            }
        }
        if let Some(sk) = space_key {
            // Held from the start (so names can be read once approved) — unless one is held.
            self.spaces.entry(server_id.clone()).or_insert(sk);
        }
        // Record the authorized host so a later space key is only accepted from them. A pin we
        // already trust stays as it is, with the source it has.
        if let Some(host) = &outcome.host_user_id {
            if self.trusted_owner(server_id).is_none() {
                self.pin_owner(server_id, host, trust::OwnerSource::Invite);
            }
        }
        Ok(())
    }

    /// The user's explicit decision to drop everything this device trusts about one space: its
    /// pinned owner, its key, its roster and the sender keys of its channels. For a space they
    /// have left, or one whose ownership really changed and that they choose to join afresh —
    /// the next join pins whatever that join names. Nothing the server sends leads here.
    pub fn forget_space(&mut self, server_id: &str) {
        self.expected_provisioner.remove(server_id);
        self.owner_sources.remove(server_id);
        self.claimed_owners.remove(server_id);
        self.spaces.remove(server_id);
        self.rosters.remove(server_id);
        let channels: Vec<String> = self.channel_servers.iter().filter(|(_, s)| s.as_str() == server_id).map(|(c, _)| format!("channel:{c}")).collect();
        self.channel_servers.retain(|_, s| s != server_id);
        self.guard.channel_servers.retain(|_, s| s != server_id);
        let placed = &self.channel_servers;
        self.listed_channels.retain(|c| placed.contains_key(c));
        for scope in channels {
            if let (Some(key), Ok(local)) = (self.send_keys.remove(&scope), self.local()) {
                self.store.delete_sender_key(&local, Uuid::from_bytes(key.distribution_id));
            }
            let dropped: Vec<String> = self.recv_keys.iter().filter(|(_, r)| r.scope == scope).map(|(id, _)| id.clone()).collect();
            for id in dropped {
                if let (Some(r), Ok(uuid)) = (self.recv_keys.remove(&id), id.parse::<Uuid>()) {
                    self.store.delete_sender_key(&r.sender, uuid);
                }
                self.recv_order.retain(|o| o != &id);
            }
        }
    }

    /// List all channels in a server we're a member of, decrypting each name with the space key we
    /// hold (name is None until a key arrives).
    pub async fn list_channels(&mut self, server_id: &str) -> Result<Vec<ChannelMeta>, EngineError> {
        let resp = self.api.get(&format!("/api/servers/{}/channels", enc(server_id))).await?;
        let arr = resp["channels"].as_array().cloned().unwrap_or_default();
        // A listing places channels this device has not placed yet. It never MOVES one: a
        // channel id listed here that we hold under another server is refused (and left out of
        // what is returned), so listing it under a server someone else owns gives that owner
        // nothing.
        let mut foreign: HashSet<String> = HashSet::new();
        for c in arr.iter().take(MAX_SERVER_ARRAY) {
            if let Some(id) = c["channel_id"].as_str() {
                if !self.bind_channel(id, server_id) {
                    foreign.insert(id.to_string());
                }
            }
        }
        Ok(arr
            .into_iter()
            .take(MAX_SERVER_ARRAY)
            .filter_map(|c| {
                let channel_id = c["channel_id"].as_str().filter(|id| !foreign.contains(*id))?.to_string();
                let name = c["name_ciphertext"].as_str().and_then(|ct| self.decrypt_name(server_id, ct));
                let kind = c["type"].as_str().unwrap_or("text").to_string();
                let purpose = c["purpose"].as_str().map(str::to_string);
                Some(ChannelMeta { channel_id, name, kind, purpose })
            })
            .collect())
    }

    /// Ask the host of `server_id` to provision us (after a token/username auto-join, where the
    /// host has no approval step to hang provisioning off). Sent to every device of the host.
    pub async fn request_provision(&mut self, server_id: &str, host: &PeerId) -> Result<(), EngineError> {
        // We are about to ask `host` for this server's key, so `host` is who we expect it from.
        // A device that lost everything (an account reset) has no pin left, and without one the
        // answer would be dropped and the server would never come back. But WHO the host is
        // came from the server's listing, and that alone must not become a trust anchor: the
        // pin is recorded with no provenance (`legacy-unknown`, authorizing nothing) and only
        // counts once the instance — under the key we pinned — attests that same owner.
        if self.trusted_owner(server_id).is_none() && host.user_id != self.user_id.clone().unwrap_or_default() {
            self.expected_provisioner.entry(server_id.to_string()).or_insert_with(|| host.user_id.clone());
            self.owner_rechecked.remove(server_id);
            self.reconfirm_owner(server_id).await;
        }
        let devices: Vec<DeviceAddress> = self.fetch_devices(&host.user_id).await?.into_iter().map(|(d, _)| d).collect();
        self.send_content(&devices, &Content::ProvisionRequest { server_id: server_id.to_string() }).await?;
        Ok(())
    }

    /// Inbox sync entry point for the app's timer: process the sealed mailbox (installing relayed
    /// keys, buffering DMs, fulfilling members' provision requests) and keep our prekeys stocked.
    /// Returns how many members were newly provisioned this pass.
    pub async fn process_control_inbox(&mut self, _my_user_id: &str) -> Result<u32, EngineError> {
        let outcome = self.sync_inbox().await?;
        let _ = self.maintain_keys().await;
        Ok(outcome.provisioned)
    }

    /// Put this engine in notification-extension mode, for good (there is no way back: the
    /// extension's process never becomes the app). docs/PUSH.md: the extension "never registers
    /// a device or creates keys". A passive engine still reads its mailbox, decrypts, answers
    /// "send it again" requests and acknowledges — and it:
    ///
    /// - never registers, refills one-time prekeys, rotates the signed prekey or the delivery
    ///   key, or uploads any key ([`Engine::maintain_keys`] does nothing);
    /// - never mints or rotates a sender key (`create_group_session` refuses, so nothing that
    ///   would hand a NEW key out can run);
    /// - never binds a session for an install that has no install secret yet (it would have
    ///   to make one);
    /// - fulfils no provision request: those are kept, persisted, for the app
    ///   ([`Build45Ext::deferred_provisions`]).
    ///
    /// Enforced where the keys are made, not at the call sites, so every entry point the
    /// extension uses (`process_control_inbox`, the channel and DM fetches, which all sync the
    /// mailbox first) is covered.
    pub fn set_passive(&mut self) {
        self.passive = true;
    }

    /// [`Engine::set_passive`], then the mailbox sync. What the notification extension calls
    /// instead of [`Engine::process_control_inbox`].
    pub async fn process_inbox_passive(&mut self) -> Result<(), EngineError> {
        self.set_passive();
        self.sync_inbox().await?;
        Ok(())
    }

    fn refuse_if_passive(&self) -> Result<(), EngineError> {
        if self.passive {
            return Err(EngineError::Protocol("the notification extension creates no keys"));
        }
        Ok(())
    }

    /// Fulfill queued provision requests — for users this device ALREADY accepts as members of
    /// that server, and nobody else.
    ///
    /// A provision request is just a message from a user the server says is a member. It is
    /// never, by itself, a reason to sign an approval or hand over a key: a malicious server can
    /// insert a ghost user and have it ask. So this function never signs anything. A requester
    /// who is not in our roster (and a server we keep no roster for yet is a server where nobody
    /// is accepted) is left held and surfaced to the user as a join request
    /// (`"join_request"` notice); only an explicit action — [`Engine::approve_join_request`] /
    /// [`Engine::approve_member`] — admits them, after which [`Engine::provision_member`] runs.
    async fn fulfill_provisions(&mut self) -> u32 {
        if self.passive {
            // Handing a member the keys can mint or rotate a sender key: the app's job. Kept
            // in the persisted state (the envelope that asked is acknowledged and gone).
            for request in std::mem::take(&mut self.prov_queue) {
                if !self.b45.deferred_provisions.contains(&request) && self.b45.deferred_provisions.len() < MAX_DEFERRED_PROVISIONS {
                    self.b45.deferred_provisions.push(request);
                }
            }
            return 0;
        }
        let mut queued = std::mem::take(&mut self.b45.deferred_provisions);
        queued.append(&mut self.prov_queue);
        let mut count = 0;
        for (peer, server_id) in queued {
            let key = format!("{server_id}|{}", peer.user_id);
            if self.provisioned.contains(&key) || !self.spaces.contains_key(&server_id) {
                continue;
            }
            let accepted = self.rosters.get(&server_id).is_some_and(|r| r.members.contains(&peer.user_id));
            if !accepted {
                self.note_join_request(&server_id, &peer.user_id);
                continue;
            }
            if !self.is_member(&server_id, &peer.user_id).await.unwrap_or(false) {
                continue; // not (or no longer) a member per the server — don't hand over keys.
            }
            if self.provision_accepted(&server_id, &peer).await.is_ok() {
                self.provisioned.insert(key);
                count += 1;
            }
        }
        count
    }

    /// Provision a member the user just admitted: sends the space key (to decrypt names) to every
    /// trusted device of that user, then hands our sender key for every channel to every member
    /// device that lacks it. The host's app calls this right after approving a join request
    /// ([`Engine::approve_join_request`]), and for our own other devices. Idempotent.
    ///
    /// It does NOT approve anyone: a user this device does not already accept as a member of
    /// `server_id` is refused. Approval is a separate, explicit step.
    pub async fn provision_member(&mut self, server_id: &str, peer: &PeerId) -> Result<(), EngineError> {
        let own = self.user_id.as_deref() == Some(peer.user_id.as_str());
        if !own && !self.rosters.get(server_id).is_some_and(|r| r.members.contains(&peer.user_id)) {
            return Err(EngineError::Protocol("that user has not been approved as a member of this space"));
        }
        self.provision_accepted(server_id, peer).await
    }

    async fn provision_accepted(&mut self, server_id: &str, peer: &PeerId) -> Result<(), EngineError> {
        let sk = *self.spaces.get(server_id).ok_or(EngineError::NoSession(format!("space:{server_id}")))?;
        let devices: Vec<DeviceAddress> = self.fetch_devices(&peer.user_id).await?.into_iter().map(|(d, _)| d).collect();
        self.send_content(&devices, &Content::SpaceKey { server_id: server_id.to_string(), key: sk }).await?;
        for ch in self.list_channels(server_id).await? {
            self.sync_channel_key(&ch.channel_id, server_id).await?;
        }
        Ok(())
    }

    // ---- voice ----

    /// Fetch a LiveKit room-access token for a voice channel: `(token, room, url)`.
    pub async fn voice_token(&self, channel_id: &str) -> Result<(String, String, Option<String>), EngineError> {
        let resp = self.api.post(&format!("/api/channels/{}/voice-token", enc(channel_id)), serde_json::json!({})).await?;
        let token = resp["token"].as_str().ok_or(EngineError::Protocol("no voice token"))?.to_string();
        let room = resp["room"].as_str().unwrap_or_default().to_string();
        let url = resp["url"].as_str().map(str::to_string);
        Ok((token, room, url))
    }

    fn voice_call(&mut self, channel_id: &str, call_id: &str) -> &mut VoiceCall {
        if let Some(i) = self.voice.iter().position(|c| c.channel_id == channel_id && c.call_id == call_id) {
            return &mut self.voice[i];
        }
        if self.voice.len() >= MAX_VOICE_CALLS {
            self.voice.remove(0);
        }
        // Keys that reached us just before we joined this call.
        let mut peers: BTreeMap<String, BTreeMap<u32, Vec<u8>>> = BTreeMap::new();
        self.pending_voice.retain(|p| p.5.elapsed() < PENDING_VOICE_TTL);
        let (mine, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut self.pending_voice).into_iter().partition(|p| p.1 == channel_id && p.2 == call_id);
        self.pending_voice = rest;
        for (user, _, _, index, key, _) in mine {
            peers.entry(user).or_default().insert(index, key);
        }
        self.voice.push(VoiceCall {
            channel_id: channel_id.to_string(),
            call_id: call_id.to_string(),
            own_key: skwod_crypto::random_bytes::<32>().to_vec(),
            own_index: 0,
            sent_to: BTreeSet::new(),
            audience: BTreeSet::new(),
            peers,
        });
        self.voice.last_mut().expect("just pushed")
    }

    /// Voice/video E2EE keys for one call, as `(user_id, 32-byte key, key_index)`, own key LAST.
    ///
    /// Each device generates a **random** media key per call (`call_id` = the LiveKit room session
    /// id) and sends it — over sealed libsignal sessions only — to the devices of the users in
    /// `participants` (intersected with the server's current members). Nothing is derived from
    /// long-lived keys and the server never sees a key.
    ///
    /// **Rotation:** when someone our current key was sent to is no longer in `participants` (they
    /// left the call) or no longer a member (kicked mid-call), a fresh key is generated at the next
    /// key index and sent only to those who remain, so a leaver cannot decrypt anything after.
    ///
    /// `participants = None` means "every current member of the server" (no leave detection).
    /// An empty result means E2EE could not be set up — the caller MUST NOT join (ADR-007).
    pub async fn voice_sync(
        &mut self,
        channel_id: &str,
        my_user_id: &str,
        call_id: &str,
        participants: Option<&[String]>,
    ) -> Result<Vec<(String, Vec<u8>, u32)>, EngineError> {
        let local = self.local()?;
        let server_id = self.channel_server(channel_id).await?;
        let _ = self.sync_inbox().await;
        let members = self.fetch_member_devices(&server_id).await?;
        let allowed: Option<HashSet<&str>> = participants.map(|p| p.iter().map(String::as_str).collect());
        let targets: Vec<DeviceAddress> = members
            .into_iter()
            .filter(|d| d != &local && d.user_id != local.user_id)
            .filter(|d| allowed.as_ref().is_none_or(|a| a.contains(d.user_id.as_str())))
            .collect();
        // Same membership gate as channel keys: accepted members, arrival shown in the channel.
        let targets = self.admit(&server_id, &format!("channel:{channel_id}"), targets).await;
        let target_users: BTreeSet<String> = targets.iter().map(|d| d.user_id.clone()).collect();

        let call = self.voice_call(channel_id, call_id);
        if call.audience.iter().any(|u| !target_users.contains(u)) {
            call.own_key = skwod_crypto::random_bytes::<32>().to_vec();
            call.own_index = (call.own_index + 1) % VOICE_KEYRING;
            call.sent_to.clear();
            call.audience.clear();
        }
        let need: Vec<DeviceAddress> = targets.into_iter().filter(|d| !call.sent_to.contains(d)).collect();
        let content =
            Content::VoiceKey { channel_id: channel_id.to_string(), call_id: call_id.to_string(), index: call.own_index, key: call.own_key.clone() };
        if !need.is_empty() {
            if let Ok(delivered) = self.send_content(&need, &content).await {
                let call = self.voice_call(channel_id, call_id);
                call.audience.extend(delivered.iter().map(|d| d.user_id.clone()));
                call.sent_to.extend(delivered);
            }
        }
        let call = self.voice_call(channel_id, call_id);
        let mut out = Vec::new();
        for (user, keys) in &call.peers {
            if user == my_user_id || !target_users.contains(user) {
                continue; // only keys of people actually in this call with us
            }
            for (index, key) in keys {
                out.push((user.clone(), key.clone(), *index));
            }
        }
        out.push((my_user_id.to_string(), call.own_key.clone(), call.own_index));
        Ok(out)
    }

    /// Pre-join check: can this device do voice E2EE for `channel_id` at all (registered, knows
    /// the channel's server, can obtain a sender certificate)? The caller refuses to join when
    /// false (ADR-007).
    pub async fn voice_ready(&mut self, channel_id: &str) -> bool {
        self.local().is_ok() && self.channel_server(channel_id).await.is_ok() && self.ensure_cert().await.is_ok()
    }
}

/// Hooks for the integration tests (simulating what only a malicious server could otherwise do).
#[doc(hidden)]
impl Engine {
    /// Pretend `identity_key` is the key on record for `peer`.
    pub fn test_force_known_identity(&mut self, peer: &DeviceAddress, identity_key: &[u8]) {
        let _ = self.store.accept_identity(peer, identity_key);
    }

    /// Pretend `identity_key` is the key this device holds (pinned / chain-verified) for `peer`.
    pub fn test_force_contact_identity(&mut self, peer: &DeviceAddress, identity_key: &[u8]) {
        if let Some(c) = self.contacts.get_mut(&peer.user_id) {
            c.vouched.insert(peer.device_id.clone(), identity_key.to_vec());
        }
    }

    /// Drop the session with `peer` so the next send must fetch a bundle.
    pub fn test_drop_session(&mut self, peer: &DeviceAddress) {
        let _ = self.store.archive_session(peer);
        if let Ok(name) = peer.name() {
            self.peer_delivery.remove(&name);
        }
    }
}

#[cfg(test)]
mod tests;
