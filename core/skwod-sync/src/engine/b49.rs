//! Build 49: server names bound to their server and version, and the sealed channel between our
//! OWN devices ("sibling state") that carries what a newly linked device is missing: the contact
//! verifications (merged here, under the rules below) and app state the apps merge themselves
//! (the contact book, the avatar cache). docs/SECURITY.md → "Sibling sync" lists the rules.

use std::collections::BTreeMap;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use skwod_crypto::{aead, DeviceAddress};

use super::{now_ms, rest::checked_server_name, Content, Engine, EngineError, SecurityNotice};

/// Tag of the build-49 section in a persisted engine state.
pub(super) const SECTION_BUILD49: u8 = 0xB9;

/// The kinds of app state a sibling may hand over (anything else is dropped). Their formats,
/// the same on every platform (the apps must agree; the core never reads them):
/// - `contacts.v1`: a JSON object, user id → `{"name": String, "level": "unverified" |
///   "known" | "verified", "known": Bool?}`.
/// - `avatars.v1`: a JSON array of `{"key": String, "img": base64 String or absent/empty for a
///   clear, "ts": Int}`.
pub const SIBLING_KINDS: [&str; 2] = ["contacts.v1", "avatars.v1"];
/// One app payload, at most (it travels in a sealed envelope of its own, under the 256 KiB
/// receive cap).
pub const MAX_SIBLING_BODY: usize = 120 * 1024;
/// App payloads kept until the app takes them.
const MAX_SIBLING_INBOX: usize = 64;
/// Shares to our siblings per window, and the window.
const SIBLING_SENDS_PER_WINDOW: u32 = 24;
const SIBLING_WINDOW_MS: i64 = 10 * 60 * 1000;
/// A sibling's "send me your state" is answered at most this often.
const SIBLING_REQUEST_GAP_MS: i64 = 10 * 60 * 1000;
/// Encoded bytes in one snapshot envelope, at most (well under the 256 KiB receive cap); a
/// larger snapshot is split by size, never truncated.
pub(super) const SNAPSHOT_CHUNK_BYTES: usize = 100 * 1024;
/// Snapshot envelopes per share, at most (a bound on one share: about 3 MiB of identities).
const MAX_SNAPSHOT_CHUNKS: usize = 32;
/// Contacts remembered per sibling snapshot (and per received envelope).
const MAX_SNAPSHOT_USERS: usize = 8000;
/// Identity keys per contact in a snapshot, at most.
const MAX_KEYS_PER_CONTACT: usize = 32;
/// Contacts remembered as "verified on my other device, not pinned here yet".
const MAX_PENDING_VERIFIED: usize = 2000;
/// A v2 server name dated further ahead than this is refused (it would lock the name).
pub(super) const NAME_VERSION_SKEW_MS: u64 = 10 * 60 * 1000;
/// Version of the sibling-state message.
pub(super) const SIBLING_STATE_V1: u8 = 1;

/// AAD of a renamed server's name: bound to the server, so the host cannot move a name between
/// servers that share a key, or show one server's name on another.
fn server_name_aad(server_id: &str) -> Vec<u8> {
    format!("skwod/server-name-v2|{server_id}").into_bytes()
}

/// What a v2 server name seals: a version that only goes up (the host cannot roll a rename
/// back by serving an older ciphertext), the name, and who renamed it.
#[derive(Serialize, Deserialize)]
struct ServerNameV2 {
    version: u64,
    name: String,
    by: String,
}

/// App state handed over by one of our own devices, until the app takes it.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct SiblingPayload {
    pub from_device: String,
    pub kind: String,
    pub body: Vec<u8>,
    /// Contacts that sibling's snapshot vouches for and that agree with this device (or that
    /// this device has not pinned): the ONLY users a payload entry may be applied for.
    pub vouched_users: Vec<String>,
    /// Contacts that sibling holds under other keys than this device: skipped.
    pub mismatched_users: Vec<String>,
}

/// The sibling device a piece of state came from, as it was when it arrived. Anything from a
/// device that is no longer a sibling under that identity (removed, re-keyed, tombstoned) is
/// dropped when it would be used.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub(super) struct Source {
    pub device: String,
    pub identity: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub(super) struct PendingVerified {
    pub set: Vec<Vec<u8>>,
    pub verified_at: i64,
    pub source: Source,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub(super) struct InboxEntry {
    pub payload: SiblingPayload,
    pub source: Source,
}

/// A sibling's identity snapshot (user → the identity set it holds), assembled from its
/// snapshot envelopes.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(super) struct Snapshot {
    pub identity: Vec<u8>,
    /// The share it was assembled from: a newer share starts over, an older one is dropped.
    pub share: u64,
    /// Envelopes in this share, and the indexes received so far.
    pub total: u16,
    pub received: std::collections::BTreeSet<u16>,
    pub users: BTreeMap<String, Vec<Vec<u8>>>,
}

impl Snapshot {
    /// Every envelope of the share arrived.
    pub fn complete(&self) -> bool {
        self.total > 0 && self.received.len() == self.total as usize
    }
}

/// When this device's verification of a contact was cleared.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub(super) struct Cleared {
    pub at: i64,
    /// The user un-verified them here: no sibling's verification is ever merged for them again
    /// (until the user verifies them here). False: cleared by accepting a changed device set —
    /// only a verification made after that counts.
    pub explicit: bool,
}

#[derive(Default, Serialize, Deserialize)]
pub(super) struct Build49State {
    /// Server id → the highest name version this device has accepted.
    pub name_versions: BTreeMap<String, u64>,
    /// User id → a sibling's verification for a contact this device has not pinned yet.
    pub pending_verified: BTreeMap<String, PendingVerified>,
    pub inbox: Vec<InboxEntry>,
    /// Sibling device → its identity snapshot.
    pub snapshots: BTreeMap<String, Snapshot>,
    /// User id → when this device (or a merge) verified them.
    pub verified_at: BTreeMap<String, i64>,
    /// User id → when this device's verification of them was cleared.
    pub cleared: BTreeMap<String, Cleared>,
    /// Shares in the current window: (window start, count).
    pub sends: (i64, u32),
    /// Sibling device → when we last answered its request.
    pub answered: BTreeMap<String, i64>,
    /// The last share id this device used (monotonic), and the last contacts share (what an
    /// avatar payload relies on).
    pub last_share: u64,
    pub last_contacts_share: u64,
}

/// (user, identity set) per contact.
pub(super) type IdentityList = Vec<(String, Vec<Vec<u8>>)>;
/// (user, verified identity set, verified at) per contact.
pub(super) type VerifiedList = Vec<(String, Vec<Vec<u8>>, i64)>;

impl Engine {
    // ---- server names (v2) ----

    /// Seal a new name for `server_id`, versioned above anything this device has seen.
    /// Returns the sealed name and its version; nothing is stored — the version counts only once
    /// the host took the rename (`note_server_name_version`), so a failed rename never makes this
    /// device refuse the name that is still live.
    pub(super) fn seal_server_name_v2(&self, key: &[u8; 32], server_id: &str, name: &str, by: &str) -> Result<(String, u64), EngineError> {
        let seen = self.b49.name_versions.get(server_id).copied().unwrap_or(0);
        let version = now_ms().max(seen.saturating_add(1));
        let plain = postcard::to_stdvec(&ServerNameV2 { version, name: name.to_string(), by: by.to_string() }).map_err(|_| EngineError::Serde)?;
        Ok((B64.encode(aead::seal(key, &server_name_aad(server_id), &plain)), version))
    }

    /// The host took a rename sealed at `version`: never accept an older name again.
    pub(super) fn note_server_name_version(&mut self, server_id: &str, version: u64) {
        let stored = self.b49.name_versions.entry(server_id.to_string()).or_insert(0);
        *stored = (*stored).max(version);
    }

    /// Open a server's name as the host serves it. A v2 name must be for THIS server, not
    /// older than the newest one accepted here, and not dated in the future (a version far
    /// ahead would lock the name for good); a name from before renames existed (the AAD every
    /// build used at creation) is taken only while no v2 name has been seen for it. Every name
    /// goes through `checked_server_name`, the rule renames are held to.
    pub(super) fn open_server_name(&mut self, server_id: &str, sealed_b64: &str) -> Option<String> {
        let key = *self.spaces.get(server_id)?;
        let bytes = B64.decode(sealed_b64).ok()?;
        if let Some(plain) = aead::open(&key, &server_name_aad(server_id), &bytes) {
            let v2: ServerNameV2 = postcard::from_bytes(&plain).ok()?;
            let seen = self.b49.name_versions.get(server_id).copied().unwrap_or(0);
            if v2.version < seen || v2.version > now_ms().saturating_add(NAME_VERSION_SKEW_MS) {
                return None;
            }
            let name = checked_server_name(&v2.name).ok()?;
            let stored = self.b49.name_versions.entry(server_id.to_string()).or_insert(0);
            *stored = (*stored).max(v2.version);
            return Some(name);
        }
        if self.b49.name_versions.contains_key(server_id) {
            return None;
        }
        let legacy = self.decrypt_name(server_id, sealed_b64)?;
        checked_server_name(&legacy).ok()
    }

    // ---- verification bookkeeping (called from `trust.rs`) ----

    /// `set_verified` / `accept_identity_change` changed a contact's verification here.
    pub(super) fn note_verification_change(&mut self, user: &str, verified: bool, explicit: bool) {
        let now = now_ms() as i64;
        if verified {
            self.b49.verified_at.insert(user.to_string(), now);
            self.b49.cleared.remove(user);
        } else {
            self.b49.verified_at.remove(user);
            let explicit = explicit || self.b49.cleared.get(user).is_some_and(|c| c.explicit);
            self.b49.cleared.insert(user.to_string(), Cleared { at: now, explicit });
            self.b49.pending_verified.remove(user);
        }
    }

    // ---- the sibling channel ----

    fn sibling_targets(&self) -> Result<Vec<DeviceAddress>, EngineError> {
        let local = self.local()?;
        Ok(self.siblings.keys().filter(|d| **d != local.device_id).map(|d| DeviceAddress::new(local.user_id.clone(), d.clone())).collect())
    }

    /// Is `source` still one of our verified devices, under that identity, and not removed?
    fn source_current(&self, source: &Source) -> bool {
        self.siblings.get(&source.device) == Some(&source.identity) && !self.own_tombstoned(&source.identity)
    }

    /// Count one share against the window; false when the window is full.
    pub(super) fn take_sibling_send(&mut self) -> bool {
        let now = now_ms() as i64;
        let (start, count) = self.b49.sends;
        if now - start >= SIBLING_WINDOW_MS {
            self.b49.sends = (now, 1);
            return true;
        }
        if count >= SIBLING_SENDS_PER_WINDOW {
            return false;
        }
        self.b49.sends = (start, count + 1);
        true
    }

    /// The contacts this device verified (for exactly the devices they have now, with when),
    /// and every pinned contact's live identity set.
    pub(super) fn trust_snapshot(&self) -> (VerifiedList, IdentityList) {
        let mut verified = Vec::new();
        let mut identities = Vec::new();
        for (user, c) in self.contacts.iter().take(MAX_SNAPSHOT_USERS) {
            let live = c.live_identities();
            if live.is_empty() || live.len() > MAX_KEYS_PER_CONTACT {
                continue;
            }
            if c.is_verified() {
                verified.push((user.clone(), live.clone(), self.b49.verified_at.get(user).copied().unwrap_or(0)));
            }
            identities.push((user.clone(), live));
        }
        (verified, identities)
    }

    /// Hand app state (`kind`, `body`) to every verified device of our own account, sealed like
    /// any message (the host relays ciphertext it cannot tell from a chat message). With the
    /// contact book, this device's identity snapshot and verifications go first, split over as
    /// many envelopes as they need. Returns how many devices it went to.
    pub async fn share_with_siblings(&mut self, kind: &str, body: Vec<u8>) -> Result<u32, EngineError> {
        if !SIBLING_KINDS.contains(&kind) {
            return Err(EngineError::Protocol("unknown sibling state kind"));
        }
        if body.len() > MAX_SIBLING_BODY {
            return Err(EngineError::TooLarge("That is too much to hand to your other devices at once."));
        }
        let targets = self.sibling_targets()?;
        if targets.is_empty() {
            return Ok(0);
        }
        if !self.take_sibling_send() {
            return Err(EngineError::TooLarge("Your other devices were just sent this — try again in a few minutes."));
        }
        let share = if kind == "contacts.v1" {
            // A new share, above every one this device used (persisted with the state).
            let share = now_ms().max(self.b49.last_share.saturating_add(1));
            self.b49.last_share = share;
            self.b49.last_contacts_share = share;
            let mut chunks = snapshot_chunks(self.trust_snapshot());
            // An empty snapshot is still one envelope: it resets the receiver's.
            if chunks.is_empty() { chunks.push((Vec::new(), Vec::new())); }
            let total = chunks.len() as u16;
            for (i, (verified, identities)) in chunks.into_iter().enumerate() {
                self.send_content(&targets, &Content::SiblingState { v: SIBLING_STATE_V1, share, chunk: (i as u16, total), verified, identities, app: Vec::new() }).await?;
            }
            share
        } else {
            // Avatars rely on the last contacts share's snapshot.
            self.b49.last_contacts_share
        };
        let content = Content::SiblingState { v: SIBLING_STATE_V1, share, chunk: (0, 0), verified: Vec::new(), identities: Vec::new(), app: vec![(kind.to_string(), body)] };
        let sent = self.send_content(&targets, &content).await?;
        Ok(sent.len() as u32)
    }

    /// Ask our other devices to send their state (a newly linked device does, once linked).
    pub async fn request_sibling_state(&mut self) -> Result<u32, EngineError> {
        let targets = self.sibling_targets()?;
        if targets.is_empty() || !self.take_sibling_send() {
            return Ok(0);
        }
        Ok(self.send_content(&targets, &Content::SiblingStateRequest).await?.len() as u32)
    }

    /// App state our siblings handed over since the last call — only what came from a device
    /// that is still one of ours under the same identity.
    pub fn take_sibling_payloads(&mut self) -> Vec<SiblingPayload> {
        self.purge_stale_sibling_state();
        std::mem::take(&mut self.b49.inbox).into_iter().map(|e| e.payload).collect()
    }

    /// Drop everything that came from a device that is no longer a sibling under that identity.
    pub(super) fn purge_stale_sibling_state(&mut self) {
        let inbox = std::mem::take(&mut self.b49.inbox);
        self.b49.inbox = inbox.into_iter().filter(|e| self.source_current(&e.source)).collect();
        let pending = std::mem::take(&mut self.b49.pending_verified);
        self.b49.pending_verified = pending.into_iter().filter(|(_, p)| self.source_current(&p.source)).collect();
        let snapshots = std::mem::take(&mut self.b49.snapshots);
        self.b49.snapshots = snapshots
            .into_iter()
            .filter(|(d, s)| self.source_current(&Source { device: d.clone(), identity: s.identity.clone() }))
            .collect();
    }

    /// `SiblingStateRequest` from `sender` (already checked to be our own verified device):
    /// the app is told (`"sibling_state_requested"`) at most once per gap per device.
    pub(super) fn on_sibling_request(&mut self, sender: &DeviceAddress) {
        let now = now_ms() as i64;
        if self.b49.answered.get(&sender.device_id).is_some_and(|at| now - at < SIBLING_REQUEST_GAP_MS) {
            return;
        }
        self.b49.answered.retain(|d, _| self.siblings.contains_key(d));
        self.b49.answered.insert(sender.device_id.clone(), now);
        let user_id = self.local().map(|l| l.user_id).unwrap_or_default();
        self.notices.push(SecurityNotice { kind: "sibling_state_requested".into(), user_id, device_id: sender.device_id.clone(), at_ms: now_ms(), was_verified: false });
    }

    /// `SiblingState` from `sender`, which the caller has checked is one of our own verified
    /// devices (sealed-sender identity = the sibling key we verified through the link chain).
    #[allow(clippy::too_many_arguments)] // the fields of one `Content::SiblingState`
    pub(super) fn on_sibling_state(&mut self, sender: &DeviceAddress, v: u8, share: u64, chunk: (u16, u16), verified: VerifiedList, identities: IdentityList, app: Vec<(String, Vec<u8>)>) {
        if v != SIBLING_STATE_V1 {
            return;
        }
        let Some(identity) = self.siblings.get(&sender.device_id).cloned() else { return };
        let source = Source { device: sender.device_id.clone(), identity: identity.clone() };
        if !self.source_current(&source) {
            return;
        }
        if app.is_empty() {
            // A snapshot envelope: (index, total) of ONE share. A newer share (or a new identity
            // for that device) starts over — even an empty one; an older share is dropped whole.
            let (index, total) = chunk;
            if total == 0 || index >= total || total as usize > MAX_SNAPSHOT_CHUNKS {
                return;
            }
            let snap = self.b49.snapshots.entry(sender.device_id.clone()).or_default();
            if snap.identity == identity && share < snap.share {
                return;
            }
            if snap.identity != identity || share > snap.share || snap.total != total {
                *snap = Snapshot { identity: identity.clone(), share, total, ..Default::default() };
            }
            snap.received.insert(index);
            for (user, set) in identities.into_iter().take(MAX_SNAPSHOT_USERS) {
                if snap.users.len() >= MAX_SNAPSHOT_USERS && !snap.users.contains_key(&user) {
                    break;
                }
                let set = sorted(&set);
                if !set.is_empty() && set.len() <= MAX_KEYS_PER_CONTACT && user.len() <= 128 {
                    snap.users.insert(user, set);
                }
            }
            for (user, set, at) in verified.into_iter().take(MAX_SNAPSHOT_USERS) {
                self.merge_sibling_verified(&user, set, at, &source);
            }
            return;
        }
        // Who a payload may speak for: users in that sibling's snapshot of EXACTLY the share the
        // payload relies on, complete, from the same identity — whose set agrees with ours (or
        // whom this device has not pinned). Otherwise nobody (fail closed).
        let (mut vouched, mut mismatched) = (Vec::new(), Vec::new());
        if let Some(snap) = self.b49.snapshots.get(&sender.device_id).filter(|s| s.identity == identity && s.share == share && s.complete()) {
            for (user, set) in &snap.users {
                match self.contacts.get(user).map(|c| c.live_identities()).filter(|l| !l.is_empty()) {
                    Some(mine) if &mine != set => mismatched.push(user.clone()),
                    _ => vouched.push(user.clone()),
                }
            }
        }
        for (kind, body) in app.into_iter().take(SIBLING_KINDS.len()) {
            if !SIBLING_KINDS.contains(&kind.as_str()) || body.len() > MAX_SIBLING_BODY {
                continue;
            }
            if self.b49.inbox.len() >= MAX_SIBLING_INBOX {
                self.b49.inbox.remove(0);
            }
            let payload = SiblingPayload { from_device: sender.device_id.clone(), kind, body, vouched_users: vouched.clone(), mismatched_users: mismatched.clone() };
            self.b49.inbox.push(InboxEntry { payload, source: source.clone() });
        }
    }

    /// May a sibling's verification made at `at` count, given what this device did?
    fn verification_allowed(&self, user: &str, at: i64) -> bool {
        match self.b49.cleared.get(user) {
            None => true,
            Some(c) => !c.explicit && at > c.at,
        }
    }

    /// Merge one "verified" from a sibling. Never downgrades or replaces a verification made
    /// here, never overrides a hold (an unvouched device), never revives a verification this
    /// device cleared (`verification_allowed`), and never pins a key. For exactly the device set
    /// this device holds, the contact becomes verified. For a DIFFERENT set, the sibling's
    /// verification stands as a hold: an `identity_changed` notice, and nothing is sent to that
    /// contact until the user verifies again here. A contact not pinned here yet is remembered.
    /// True when it agrees with what this device has.
    pub(super) fn merge_sibling_verified(&mut self, user: &str, set: Vec<Vec<u8>>, at: i64, source: &Source) -> bool {
        let set = sorted(&set);
        if set.is_empty() || set.len() > MAX_KEYS_PER_CONTACT || user.len() > 128 || !self.verification_allowed(user, at) {
            return false;
        }
        let live = self.contacts.get(user).map(|c| c.live_identities()).unwrap_or_default();
        if live.is_empty() {
            if self.b49.pending_verified.len() >= MAX_PENDING_VERIFIED && !self.b49.pending_verified.contains_key(user) {
                return false;
            }
            self.b49.pending_verified.insert(user.to_string(), PendingVerified { set, verified_at: at, source: source.clone() });
            return true;
        }
        self.settle_sibling_verification(user, set, at)
    }

    /// Apply a sibling's verification of `set` to a contact this device holds devices for.
    fn settle_sibling_verification(&mut self, user: &str, set: Vec<Vec<u8>>, at: i64) -> bool {
        let Some(c) = self.contacts.get_mut(user) else { return false };
        if let Some(ours) = &c.verified {
            return ours == &set;
        }
        if !c.unvouched.is_empty() {
            return false;
        }
        let agrees = c.live_identities() == set;
        c.verified = Some(set);
        self.b49.verified_at.insert(user.to_string(), at);
        if !agrees {
            // Verified elsewhere for other devices than the ones this device holds: held, like
            // any verified contact whose devices changed, until the user verifies again.
            let user_id = user.to_string();
            self.notices.push(SecurityNotice { kind: "identity_changed".into(), user_id, device_id: String::new(), at_ms: now_ms(), was_verified: true });
        }
        agrees
    }

    /// After `user`'s devices were (re)read: a sibling's verification waiting for them takes
    /// effect — if the sibling is still ours and nothing here cleared it since.
    pub(super) fn apply_pending_verified(&mut self, user: &str) {
        let Some(p) = self.b49.pending_verified.get(user).cloned() else { return };
        if !self.source_current(&p.source) || !self.verification_allowed(user, p.verified_at) {
            self.b49.pending_verified.remove(user);
            return;
        }
        if self.contacts.get(user).is_none_or(|c| c.live_identities().is_empty()) {
            return;
        }
        self.b49.pending_verified.remove(user);
        self.settle_sibling_verification(user, p.set, p.verified_at);
    }

    pub(super) fn b49_export(&self) -> Vec<u8> {
        postcard::to_stdvec(&self.b49).expect("engine state serialization is infallible")
    }

    pub(super) fn b49_import(body: Option<&[u8]>) -> Build49State {
        let mut s: Build49State = body.and_then(|b| postcard::from_bytes(b).ok()).unwrap_or_default();
        s.inbox.truncate(MAX_SIBLING_INBOX);
        s
    }
}

/// A snapshot split into envelopes of at most `SNAPSHOT_CHUNK_BYTES` encoded bytes (each with
/// the verifications of its own contacts), so none can exceed the receive cap however many
/// devices a contact has. At most `MAX_SNAPSHOT_CHUNKS` envelopes.
pub(super) fn snapshot_chunks((verified, identities): (VerifiedList, IdentityList)) -> Vec<(VerifiedList, IdentityList)> {
    let verified_by: BTreeMap<&String, &(String, Vec<Vec<u8>>, i64)> = verified.iter().map(|v| (&v.0, v)).collect();
    // Postcard size of one entry, generously: lengths, the user id, every key (twice when the
    // contact is also in the verified list), the timestamp.
    let cost = |user: &String, set: &Vec<Vec<u8>>| -> usize {
        let keys: usize = set.iter().map(|k| k.len() + 5).sum();
        let mut n = user.len() + 10 + keys;
        if verified_by.contains_key(user) { n += user.len() + 20 + keys; }
        n
    };
    let mut out: Vec<(VerifiedList, IdentityList)> = Vec::new();
    let (mut v, mut ids, mut size) = (Vec::new(), Vec::new(), 64usize);
    for (user, set) in identities {
        let c = cost(&user, &set);
        if !ids.is_empty() && size + c > SNAPSHOT_CHUNK_BYTES {
            out.push((std::mem::take(&mut v), std::mem::take(&mut ids)));
            size = 64;
            if out.len() == MAX_SNAPSHOT_CHUNKS { return out; }
        }
        if let Some(entry) = verified_by.get(&user) { v.push((*entry).clone()); }
        ids.push((user, set));
        size += c;
    }
    if !ids.is_empty() && out.len() < MAX_SNAPSHOT_CHUNKS { out.push((v, ids)); }
    out
}

fn sorted(set: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut s: Vec<Vec<u8>> = set.iter().take(MAX_KEYS_PER_CONTACT + 1).cloned().collect();
    s.sort();
    s.dedup();
    s
}
