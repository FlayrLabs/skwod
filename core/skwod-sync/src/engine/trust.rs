//! Who the engine trusts with keys — decided on this device, never by the server's lists.
//!
//! Two layers, both persisted in the engine state:
//!
//! 1. **Contact devices** ([`ContactTrust`]). The first time a user is seen, the devices the
//!    directory lists for them are pinned (trust on first use of the *account*). From then on a
//!    device counts only if a **link signature** chains it back to a pinned device — the same
//!    signatures an account's own devices verify for each other. Traffic goes to, and is accepted
//!    from, chain-verified devices only; a listed device with no valid chain is *held* and
//!    reported. Verification ("safety number") is per account, over the sorted device-identity
//!    set: when a verified contact's set changes, or a device of theirs is unvouched, every send
//!    to them is blocked until the user checks again.
//!
//! 2. **Server rosters** ([`Roster`]). For each server, the users this device accepts as members.
//!    The first look at a server takes the listed members as the baseline; after that, a user the
//!    server lists is only accepted with a **member approval** signed by the device of someone
//!    already accepted there (or the pinned owner). Keys for a channel go to a newly accepted
//!    user or a newly linked device only once a visible "joined (approved by …)" / "added a
//!    device" event has been written into that channel. A user the server merely inserts stays
//!    held and flagged.
//!
//! This is the interim for ADR-012 (docs/DECISIONS.md): a member-signed membership log replaces
//! [`Roster`] and the approval records without changing the callers ([`Engine::admit`]).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use skwod_crypto::DeviceAddress;

use super::{enc, now_ms, Engine, EngineError, SecurityNotice, MAX_SERVER_ARRAY};

/// Inbound payloads from not-yet-verified contact devices kept until the user decides.
const MAX_HELD_INBOUND: usize = 200;
const MAX_HELD_PER_USER: usize = 50;
/// How far in the future an approval may be dated (clock skew).
const APPROVAL_SKEW_MS: i64 = 10 * 60 * 1000;

/// What this device knows about one other account's devices.
#[derive(Clone, Default, Serialize, Deserialize)]
pub(super) struct ContactTrust {
    /// Every device identity ever accepted for this user (device id → identity key): pinned at
    /// first sight, or vouched for by a link signature from a device already in here. Devices that
    /// were later removed stay on record (so the same device id can never be re-pointed at
    /// another key) but they are RETIRED: an entry that is not in `live` was seen removed, and
    /// from then on it neither vouches for a new device nor comes back by being listed again
    /// (`Engine::update_contact`).
    pub vouched: BTreeMap<String, Vec<u8>>,
    /// Accepted devices the directory currently lists — the only ones traffic goes to or is
    /// accepted from.
    pub live: BTreeSet<String>,
    /// Listed devices with no valid chain (device id → identity key). Held.
    pub unvouched: BTreeMap<String, Vec<u8>>,
    /// The device-identity set (sorted) the user verified the account safety number for.
    pub verified: Option<Vec<Vec<u8>>>,
}

impl ContactTrust {
    /// What "Accept" would take on: a fingerprint (hex SHA-256) of the live devices with their
    /// keys and of every listed device nobody vouched for, with its key (audit L2). The banner
    /// shows the state this is computed from; accepting names it, so a tap accepts exactly what
    /// was on screen — never a device the server listed in between.
    pub fn accept_fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut parts: Vec<&[u8]> = vec![b"skwod-accept-v1"];
        let live: Vec<(&String, &Vec<u8>)> = self.live.iter().filter_map(|d| self.vouched.get(d).map(|k| (d, k))).collect();
        let count = (live.len() as u32).to_be_bytes();
        parts.push(&count);
        for (d, k) in &live {
            parts.push(d.as_bytes());
            parts.push(k);
        }
        for (d, k) in &self.unvouched {
            parts.push(d.as_bytes());
            parts.push(k);
        }
        hex::encode(Sha256::digest(skwod_crypto::link::op_payload(&parts)))
    }

    /// Sorted identity keys of the live devices: what the account safety number covers.
    pub fn live_identities(&self) -> Vec<Vec<u8>> {
        let mut keys: Vec<Vec<u8>> = self.live.iter().filter_map(|d| self.vouched.get(d).cloned()).collect();
        keys.sort();
        keys
    }

    /// A verified contact whose device set is no longer the one that was verified, or who has a
    /// device nobody vouched for: nothing is sent until the user verifies again.
    pub fn blocked(&self) -> bool {
        match &self.verified {
            Some(set) => set != &self.live_identities() || !self.unvouched.is_empty(),
            None => false,
        }
    }

    pub fn is_verified(&self) -> bool {
        self.verified.is_some() && !self.blocked()
    }
}

/// One directory row.
pub(super) struct DirRow {
    pub device: String,
    pub identity: Vec<u8>,
    pub link: Option<(String, Vec<u8>)>,
}

/// The users this device accepts as members of one server.
#[derive(Clone, Default, Serialize, Deserialize)]
pub(super) struct Roster {
    pub members: BTreeSet<String>,
    /// Per scope (`channel:<id>`): devices whose arrival has been shown there and that may
    /// therefore hold our key for it.
    pub cleared: BTreeMap<String, BTreeSet<DeviceAddress>>,
    /// When we saw a user removed (unix ms). An approval must be newer to re-admit them.
    pub removed_at: BTreeMap<String, i64>,
    /// Listed users with no acceptable approval, already flagged.
    pub held: BTreeSet<String>,
    /// Who approved whom (member → approver), for the "approved by" line.
    pub approved_by: BTreeMap<String, String>,
}

/// A membership event the UI must show as a persistent row in `scope`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemEvent {
    /// - `"member_joined"`: `user_id` joined (approved by `by_user_id`, when known).
    /// - `"device_added"`: `user_id` linked device `device_id`.
    /// - `"member_held"`: the server lists `user_id` but nobody we trust approved them. They get
    ///   no keys until someone does (`Engine::approve_member`).
    pub kind: String,
    /// `"channel:<id>"`.
    pub scope: String,
    pub user_id: String,
    pub device_id: String,
    pub by_user_id: Option<String>,
    pub at_ms: u64,
}

/// Writes a [`SystemEvent`] where the user will see it (the message cache); `true` once it is
/// durably there. Installed by the application; keys follow the event, never precede it.
pub type EventSink = Box<dyn Fn(&SystemEvent) -> bool + Send + Sync>;

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct HeldInbound {
    pub sender: DeviceAddress,
    pub plaintext: Vec<u8>,
    pub received_at: i64,
}

/// Where a pinned server owner came from. A pin WITHOUT a recorded source — every pin written
/// before sources existed (build 42, a restored key backup) — is `legacy-unknown`: it authorizes
/// nothing and is never passed on until it is re-confirmed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum OwnerSource {
    /// We created the space on this device.
    Created,
    /// The host named by the join we made (invite accept).
    Invite,
    /// A verified sibling device of our own account told us (`OwnerPins`).
    Sibling,
    /// A legacy pin re-confirmed by an attestation signed with the pinned instance key.
    InstanceSigned,
}

/// Engine state added after build 42. Serialized AFTER the original `EngineState` (postcard is
/// not self-describing, so that struct can never grow), behind a version byte.
#[derive(Default, Serialize, Deserialize)]
pub(super) struct EngineExt {
    pub contacts: BTreeMap<String, ContactTrust>,
    pub rosters: BTreeMap<String, Roster>,
    pub events: Vec<SystemEvent>,
    pub held_inbound: Vec<HeldInbound>,
    /// Received distribution ids, oldest first (eviction order for `recv_keys`).
    pub recv_order: VecDeque<String>,
    /// Provenance of each owner pin (server id → source). No entry = `legacy-unknown`.
    pub owner_sources: BTreeMap<String, OwnerSource>,
}

pub(super) const EXT_VERSION: u8 = 1;

impl Engine {
    fn notice(&mut self, kind: &str, user_id: &str, device_id: &str, was_verified: bool) {
        self.notices.push(SecurityNotice {
            kind: kind.into(),
            user_id: user_id.to_string(),
            device_id: device_id.to_string(),
            at_ms: now_ms(),
            was_verified,
        });
    }

    // ---- contact devices ----

    /// Fold one directory listing of `user`'s devices into what we trust about them.
    pub(super) fn update_contact(&mut self, user: &str, rows: &[DirRow]) {
        let first = !self.contacts.contains_key(user);
        let mut c = self.contacts.remove(user).unwrap_or_default();
        let was_blocked = c.blocked();
        if first {
            // First sight of this account: pin what the directory lists (trust on first use).
            for r in rows {
                c.vouched.insert(r.device.clone(), r.identity.clone());
            }
            // Carry over the per-device "verified" marks of build 42 — only if every listed
            // device had one; a partly verified account must be verified again as a whole.
            let all_verified = !rows.is_empty()
                && rows.iter().all(|r| self.store.known_identity(&DeviceAddress::new(user, r.device.as_str())).is_some_and(|(k, v)| v && k == r.identity));
            if all_verified {
                let mut set: Vec<Vec<u8>> = rows.iter().map(|r| r.identity.clone()).collect();
                set.sort();
                c.verified = Some(set);
            }
        }
        // Who may vouch (M5). Only a device that is one of theirs NOW: one this very listing
        // names and this pass has accepted (`live`, below). A device that is absent from the
        // listing is treated exactly like one we were told was removed — it vouches for
        // nobody, in the listing where it first goes missing as much as in any later one.
        // Otherwise whoever holds a discarded device's key (a thief, or the old phone's next
        // owner) needs only the server's help to add devices to the account: the server drops
        // the old row and lists a new one "linked by" it, in one listing. The cost is to an
        // honest replacement seen late: "old phone links the new one and is then removed",
        // observed only after the removal, leaves the new phone HELD (flagged as unvouched)
        // until another of the contact's live devices links it or the user verifies the
        // contact again. A removal the contact's own devices told us about
        // (`contact_tombstones`) retires the key at once, whatever the server goes on listing.
        // (`was_live` still decides whether an already-accepted device stays accepted.)
        let was_live: BTreeSet<String> = if first { rows.iter().map(|r| r.device.clone()).collect() } else { c.live.clone() };
        let removed_by_owner = |identity: &Vec<u8>| self.acct.contact_tombstones.get(user).is_some_and(|set| set.contains(identity));
        let mut live = BTreeSet::new();
        let mut newly = Vec::new();
        loop {
            let mut progressed = false;
            for r in rows {
                if live.contains(&r.device) {
                    continue;
                }
                match c.vouched.get(&r.device) {
                    // Still listed since we last looked — or a self-erased device restored
                    // under its own row, which the server's record corroborates.
                    Some(k) if k == &r.identity && !removed_by_owner(&r.identity) && (was_live.contains(&r.device) || self.may_readmit_contact_identity(user, &r.identity)) => {
                        live.insert(r.device.clone());
                        progressed = true;
                    }
                    // A device we saw removed, listed again: not accepted on the server's
                    // word. It is held and flagged like any other unvouched device.
                    Some(k) if k == &r.identity => {}
                    // A device id we accepted under another identity key: not that device.
                    Some(_) => {}
                    None => {
                        let Some((linker, sig)) = &r.link else {
                            // No link, but an identity key we already accepted for this user
                            // under another device row — AND that device told us it was
                            // erasing itself: the same device, restored. (A device its owner
                            // REMOVED never said so; its key coming back is not accepted — it
                            // stays unvouched and is flagged.)
                            if c.vouched.values().any(|k| k == &r.identity) && self.may_readmit_contact_identity(user, &r.identity) {
                                c.vouched.insert(r.device.clone(), r.identity.clone());
                                live.insert(r.device.clone());
                                newly.push(r.device.clone());
                                progressed = true;
                            }
                            continue;
                        };
                        let Some(linker_identity) = c.vouched.get(linker) else { continue };
                        if !live.contains(linker) || removed_by_owner(linker_identity) {
                            continue; // a device that is gone (or retired) vouches for nobody
                        }
                        if skwod_crypto::link::verify_link(linker_identity, user, &r.identity, sig) {
                            c.vouched.insert(r.device.clone(), r.identity.clone());
                            live.insert(r.device.clone());
                            newly.push(r.device.clone());
                            progressed = true;
                        }
                    }
                }
            }
            if !progressed {
                break;
            }
        }
        let unvouched: BTreeMap<String, Vec<u8>> =
            rows.iter().filter(|r| !live.contains(&r.device)).map(|r| (r.device.clone(), r.identity.clone())).collect();
        let fresh_unvouched: Vec<String> = unvouched.keys().filter(|d| !c.unvouched.contains_key(*d)).cloned().collect();
        // What is held from an unvouched device was read under the key listed for it THEN. If
        // that key is no longer the one listed (changed, or the device is gone or accepted
        // through a link), the held text is not that device's to have delivered later.
        let stale: Vec<String> = c.unvouched.iter().filter(|(d, k)| unvouched.get(*d) != Some(*k)).map(|(d, _)| d.clone()).collect();
        if !stale.is_empty() {
            self.held_inbound.retain(|h| !(h.sender.user_id == user && stale.contains(&h.sender.device_id)));
        }
        // Devices we accepted that the directory no longer lists: removed from the account.
        let departed: Vec<String> = c.live.iter().filter(|d| !live.contains(*d)).cloned().collect();
        c.live = live;
        c.unvouched = unvouched;
        let (verified, blocked) = (c.verified.is_some(), c.blocked());
        self.contacts.insert(user.to_string(), c);
        for device in departed {
            // Drop its receive keys, rotate what it held of ours, stop owing it anything.
            self.device_gone(&DeviceAddress::new(user, device));
        }
        for device in newly {
            self.notice("new_device", user, &device, false);
        }
        for device in fresh_unvouched {
            self.notice("unverified_contact_device", user, &device, verified);
        }
        if !was_blocked && blocked {
            self.notice("identity_changed", user, "", true);
        }
        // A verification one of our other devices made for exactly these devices (build 49).
        self.apply_pending_verified(user);
    }

    /// Is `peer` a chain-verified, currently listed device of a contact?
    pub(super) fn contact_device_trusted(&self, peer: &DeviceAddress) -> bool {
        self.contacts.get(&peer.user_id).is_some_and(|c| c.live.contains(&peer.device_id) && c.vouched.contains_key(&peer.device_id))
    }

    /// The identity key we accept for a contact device, if it is trusted.
    pub(super) fn contact_identity(&self, peer: &DeviceAddress) -> Option<&Vec<u8>> {
        let c = self.contacts.get(&peer.user_id)?;
        c.live.contains(&peer.device_id).then(|| c.vouched.get(&peer.device_id)).flatten()
    }

    /// Sends to this user are blocked until the user verifies them again.
    pub(super) fn contact_blocked(&self, user_id: &str) -> bool {
        self.contacts.get(user_id).is_some_and(ContactTrust::blocked)
    }

    /// What the UI needs to explain where a contact stands, without sending anything:
    /// `(verified, sends_held, live devices, unvouched devices)`. `sends_held` is the state in
    /// which a send fails with `IdentityChanged`.
    pub fn contact_status(&self, user_id: &str) -> (bool, bool, u32, u32) {
        match self.contacts.get(user_id) {
            Some(c) => (c.is_verified(), c.blocked(), c.live.len() as u32, c.unvouched.len() as u32),
            None => (false, false, 0, 0),
        }
    }

    /// The fingerprint of the device set "Accept" would take on for `user_id`, as things stand
    /// here (`ContactTrust::accept_fingerprint`). Shown with the banner; passed back to
    /// [`Engine::accept_identity_change`].
    pub fn accept_fingerprint(&self, user_id: &str) -> String {
        self.contacts.get(user_id).map(ContactTrust::accept_fingerprint).unwrap_or_default()
    }

    /// Keep an inbound payload from a device that is listed but not vouched for.
    pub(super) fn hold_inbound(&mut self, sender: DeviceAddress, plaintext: &[u8], received_at: i64) {
        // The same payload from the same device is held once, however often it arrives.
        if self.held_inbound.iter().any(|h| h.sender == sender && h.plaintext == plaintext) {
            return;
        }
        let of_user = self.held_inbound.iter().filter(|h| h.sender.user_id == sender.user_id).count();
        if of_user >= MAX_HELD_PER_USER {
            if let Some(i) = self.held_inbound.iter().position(|h| h.sender.user_id == sender.user_id) {
                self.held_inbound.remove(i);
            }
        }
        if self.held_inbound.len() >= MAX_HELD_INBOUND {
            self.held_inbound.remove(0);
        }
        self.held_inbound.push(HeldInbound { sender, plaintext: plaintext.to_vec(), received_at });
    }

    /// The user compared `displayed` — the safety number that was on their screen — with the
    /// contact and it matched: mark the account verified, but ONLY for the device set that number
    /// covers. The directory is read again and the number recomputed here; if it is no longer
    /// `displayed` (a device was added or removed, on either side, between showing the number
    /// and confirming it) nothing is marked and `IdentityChanged` is returned — the app shows
    /// the new number and the user compares again. Fails closed when the directory cannot be
    /// read: a verification is never recorded against a set we could not re-check.
    pub async fn verify_contact(&mut self, user_id: &str, displayed: &str) -> Result<(), EngineError> {
        let peer = DeviceAddress::new(user_id, "");
        self.fetch_devices(user_id).await?;
        let (ours, theirs) = self.account_fingerprints(user_id).await?;
        let current = if ours <= theirs { format!("{ours}{theirs}") } else { format!("{theirs}{ours}") };
        if !skwod_crypto::link::same_safety_number(displayed, &current) {
            return Err(EngineError::IdentityChanged(user_id.to_string()));
        }
        self.set_verified(&peer, true)
    }

    /// The two halves of the account safety number with `user_id`: `(ours, theirs)`.
    pub(super) async fn account_fingerprints(&mut self, user_id: &str) -> Result<(String, String), EngineError> {
        let local = self.local()?;
        if user_id == local.user_id {
            return Err(EngineError::Protocol("no safety number with yourself"));
        }
        let _ = self.refresh_siblings(false).await;
        if !self.contacts.contains_key(user_id) {
            self.fetch_devices(user_id).await?;
        }
        let theirs = self.contacts.get(user_id).map(ContactTrust::live_identities).unwrap_or_default();
        let mut ours: Vec<Vec<u8>> = self.siblings.values().cloned().collect();
        ours.push(self.store.identity_key());
        skwod_crypto::link::account_fingerprints(&local.user_id, &ours, user_id, &theirs).ok_or(EngineError::Protocol("that user has no verified device"))
    }

    /// `user_id`'s half of the account safety number WITHOUT trusting anything: `&self`, so it
    /// cannot pin. For an account this device already holds devices for, that is the pinned
    /// fingerprint (`true`). For one never seen, it is computed from what the directory lists
    /// right now and is only the server's claim (`false`) — fit to show, labelled as
    /// unverified, next to a stranger in a list. Listing people must never be what makes this
    /// device trust their keys: a server could get a ghost's keys pinned just by showing it.
    /// Pinning happens when the user acts (lets them in, messages them, verifies them).
    pub async fn peek_contact_fingerprint(&self, user_id: &str) -> Result<(String, bool), EngineError> {
        let local = self.local()?;
        if user_id == local.user_id {
            return Err(EngineError::Protocol("no safety number with yourself"));
        }
        let mut ours: Vec<Vec<u8>> = self.siblings.values().cloned().collect();
        ours.push(self.store.identity_key());
        let pinned = self.contacts.get(user_id).map(ContactTrust::live_identities).filter(|ids| !ids.is_empty());
        let (theirs, known) = match pinned {
            Some(ids) => (ids, true),
            None => {
                let v = self.api.get(&format!("/api/e2ee/users/{}/devices", enc(user_id))).await?;
                let ids: Vec<Vec<u8>> = v["devices"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .take(MAX_SERVER_ARRAY)
                    .filter_map(|d| d["identity_key"].as_str().and_then(|k| B64.decode(k).ok()))
                    .collect();
                (ids, false)
            }
        };
        let (_, theirs) = skwod_crypto::link::account_fingerprints(&local.user_id, &ours, user_id, &theirs).ok_or(EngineError::Protocol("that user has no device"))?;
        Ok((theirs, known))
    }

    /// `user_id`'s half of the account safety number (see `SkwodClient::account_fingerprint`).
    pub async fn contact_fingerprint(&mut self, user_id: &str) -> Result<String, EngineError> {
        Ok(self.account_fingerprints(user_id).await?.1)
    }

    /// The payload of the safety-number QR code THIS device shows for `user_id` (directional:
    /// see `skwod_crypto::link::safety_qr_payload`).
    pub async fn safety_qr(&mut self, user_id: &str) -> Result<String, EngineError> {
        let (ours, theirs) = self.account_fingerprints(user_id).await?;
        Ok(skwod_crypto::link::safety_qr_payload(&ours, &theirs))
    }

    /// Check a code scanned from `user_id`'s screen. `Ok(None)`: not a safety code. `Ok(Some(n))`
    /// with `n` = the 60-digit number it corresponds to when it MATCHES (pass it to
    /// [`Engine::verify_contact`]); `Err(IdentityChanged)` when it is a safety code that does not
    /// match — someone may be in the middle, or it is this device's own code.
    pub async fn check_safety_qr(&mut self, user_id: &str, scanned: &str) -> Result<Option<String>, EngineError> {
        let (ours, theirs) = self.account_fingerprints(user_id).await?;
        match skwod_crypto::link::safety_qr_matches(scanned, &ours, &theirs) {
            None => Ok(None),
            Some(false) => Err(EngineError::IdentityChanged(user_id.to_string())),
            Some(true) => Ok(Some(if ours <= theirs { format!("{ours}{theirs}") } else { format!("{theirs}{ours}") })),
        }
    }

    /// Mark (or unmark) a contact **account** verified for exactly the devices we currently
    /// accept for them. Refused while any of their devices is unvouched (accept or reject that
    /// first). NOT bound to what the user looked at: apps go through [`Engine::verify_contact`];
    /// this is the primitive under it (and what unmarking uses).
    pub fn set_verified(&mut self, peer: &DeviceAddress, verified: bool) -> Result<(), EngineError> {
        let c = self.contacts.get_mut(&peer.user_id).ok_or(EngineError::Protocol("unknown contact"))?;
        if !verified {
            c.verified = None;
            // The user un-verified them here: no sibling's verification revives it (build 49).
            self.note_verification_change(&peer.user_id, false, true);
            return Ok(());
        }
        if !c.unvouched.is_empty() || c.live.is_empty() {
            return Err(EngineError::IdentityChanged(peer.user_id.clone()));
        }
        c.verified = Some(c.live_identities());
        self.note_verification_change(&peer.user_id, true, false);
        Ok(())
    }

    /// Whether the user verified this contact for exactly the devices they have now.
    pub fn is_verified(&self, peer: &DeviceAddress) -> bool {
        self.contacts.get(&peer.user_id).is_some_and(ContactTrust::is_verified)
    }

    /// The contact has unvouched devices or (for a verified contact) a changed device set, and
    /// the user chose to continue: accept the devices the banner SHOWED as theirs. `shown` is
    /// the [`Engine::accept_fingerprint`] the banner was drawn with; the directory is read again
    /// and, if what would be accepted is no longer exactly that set (a device added, removed or
    /// re-keyed in between), nothing is accepted and `IdentityChanged` is returned — the app
    /// shows the banner again for the new set (audit L2). The verified mark is cleared until
    /// they compare the safety number again. Anything held from those devices is then delivered.
    pub async fn accept_identity_change(&mut self, peer: &DeviceAddress, shown: &str) -> Result<(), EngineError> {
        let local = self.local()?;
        self.fetch_devices(&peer.user_id).await?;
        let c = self.contacts.get_mut(&peer.user_id).ok_or(EngineError::Protocol("unknown contact"))?;
        let now = c.accept_fingerprint();
        if shown != now {
            return Err(EngineError::IdentityChanged(peer.user_id.clone()));
        }
        let accepted: Vec<(String, Vec<u8>)> = std::mem::take(&mut c.unvouched).into_iter().collect();
        for (device, identity) in &accepted {
            c.vouched.insert(device.clone(), identity.clone());
            c.live.insert(device.clone());
        }
        c.verified = None;
        // Only a verification made after this counts from a sibling (build 49).
        self.note_verification_change(&peer.user_id, false, false);
        for (device, identity) in &accepted {
            let addr = DeviceAddress::new(peer.user_id.clone(), device.clone());
            // The user's decision is what puts this key on record (nothing a message carried
            // did); a session with any other key is retired with it.
            let _ = self.store.accept_identity(&addr, identity);
        }
        self.collect_identity_changes();
        let (mine, rest): (Vec<HeldInbound>, Vec<HeldInbound>) =
            std::mem::take(&mut self.held_inbound).into_iter().partition(|h| h.sender.user_id == peer.user_id);
        self.held_inbound = rest;
        for h in mine {
            self.handle_content(&local, h.sender, &h.plaintext, h.received_at).await;
        }
        Ok(())
    }

    /// The 60-digit **account** safety number with `peer`'s user: one number per pair of
    /// accounts, over each side's sorted device-identity set (ours: this device + verified
    /// siblings; theirs: their chain-verified devices). Both sides compute the same value.
    pub async fn safety_number(&mut self, _my_user_id: &str, peer: &DeviceAddress) -> Result<String, EngineError> {
        let (ours, theirs) = self.account_fingerprints(&peer.user_id).await?;
        Ok(if ours <= theirs { format!("{ours}{theirs}") } else { format!("{theirs}{ours}") })
    }

    // ---- server rosters ----

    /// The identity key an approval by `user`:`device` must verify under — only a device we
    /// currently trust for that user (ourselves, a verified sibling, a chain-verified contact
    /// device of a contact who is not blocked).
    fn approver_identity(&self, user: &str, device: &str) -> Option<Vec<u8>> {
        if self.user_id.as_deref() == Some(user) {
            return if self.device_id.as_deref() == Some(device) { Some(self.store.identity_key()) } else { self.siblings.get(device).cloned() };
        }
        let c = self.contacts.get(user)?;
        if c.blocked() || !c.live.contains(device) {
            return None;
        }
        c.vouched.get(device).cloned()
    }

    /// Accept the users in `approvals` (the server's `member-approvals` list) into `server_id`'s
    /// roster — each only if the approval is signed by a trusted device of the pinned owner or of
    /// someone already accepted there, and is newer than the user's last removal.
    pub(super) fn apply_approvals(&mut self, server_id: &str, approvals: &serde_json::Value) {
        let owner = self.trusted_owner(server_id).cloned();
        let now = now_ms() as i64;
        loop {
            let mut progressed = false;
            for a in approvals.as_array().into_iter().flatten().take(MAX_SERVER_ARRAY) {
                let (Some(user), Some(approver), Some(device), Some(ts), Some(sig)) = (
                    a["user_id"].as_str(),
                    a["approver_user_id"].as_str(),
                    a["approver_device_id"].as_str(),
                    a["ts"].as_i64(),
                    a["signature"].as_str().and_then(|s| B64.decode(s).ok()),
                ) else {
                    continue;
                };
                let Some(roster) = self.rosters.get(server_id) else { return };
                if roster.members.contains(user) || approver == user {
                    continue;
                }
                if ts <= roster.removed_at.get(user).copied().unwrap_or(0) || ts > now + APPROVAL_SKEW_MS {
                    continue;
                }
                if owner.as_deref() != Some(approver) && !roster.members.contains(approver) {
                    continue;
                }
                let Some(identity) = self.approver_identity(approver, device) else { continue };
                if !skwod_crypto::link::verify_member_approval(&identity, server_id, user, approver, ts, &sig) {
                    continue;
                }
                if let Some(roster) = self.rosters.get_mut(server_id) {
                    roster.members.insert(user.to_string());
                    roster.held.remove(user);
                    roster.approved_by.insert(user.to_string(), approver.to_string());
                    progressed = true;
                }
            }
            if !progressed {
                break;
            }
        }
    }

    /// Show an event where the user will see it. With a sink (the app's message cache) the event
    /// must be durably written before this returns true; without one (tools, tests) it is queued
    /// for [`Engine::take_system_events`].
    fn show_event(&mut self, event: SystemEvent) -> bool {
        match &self.event_sink {
            Some(sink) => sink(&event),
            None => {
                self.events.push(event);
                true
            }
        }
    }

    /// Of `devices` (members' devices per the server), the ones that may hold our key for `scope`
    /// right now. Pure given the engine state; [`Engine::admit`] fetches approvals first.
    pub(super) fn clear_devices(&mut self, server_id: &str, scope: &str, devices: Vec<DeviceAddress>) -> Vec<DeviceAddress> {
        let local_user = self.user_id.clone().unwrap_or_default();
        let Some(mut roster) = self.rosters.remove(server_id) else { return Vec::new() };
        let first_scope = !roster.cleared.contains_key(scope);
        let mut cleared = roster.cleared.remove(scope).unwrap_or_default();
        let seen_users: BTreeSet<String> = cleared.iter().map(|d| d.user_id.clone()).collect();
        let mut joined_now: BTreeSet<String> = BTreeSet::new();
        let mut out = Vec::new();
        let event = |kind: &str, d: &DeviceAddress, by: Option<String>| SystemEvent {
            kind: kind.into(),
            scope: scope.to_string(),
            user_id: d.user_id.clone(),
            device_id: if kind == "device_added" { d.device_id.clone() } else { String::new() },
            by_user_id: by,
            at_ms: now_ms(),
        };
        for d in devices {
            if d.user_id == local_user {
                out.push(d); // our own devices are governed by the sibling set
                continue;
            }
            if !roster.members.contains(&d.user_id) {
                // Listed by the server, approved by nobody we trust: no keys, and say so once.
                if roster.held.insert(d.user_id.clone()) {
                    self.show_event(event("member_held", &d, None));
                }
                continue;
            }
            // The first time we key a channel, its accepted members are the baseline.
            if first_scope || cleared.contains(&d) || joined_now.contains(&d.user_id) {
                cleared.insert(d.clone());
                out.push(d);
                continue;
            }
            let shown = if seen_users.contains(&d.user_id) {
                self.show_event(event("device_added", &d, None))
            } else {
                let by = roster.approved_by.get(&d.user_id).cloned();
                let shown = self.show_event(event("member_joined", &d, by));
                if shown {
                    joined_now.insert(d.user_id.clone());
                }
                shown
            };
            // No visible event, no key: retried on the next sync.
            if shown {
                cleared.insert(d.clone());
                out.push(d);
            }
        }
        roster.cleared.insert(scope.to_string(), cleared);
        self.rosters.insert(server_id.to_string(), roster);
        out
    }

    /// The membership gate for key distribution: which of `devices` (what the server says the
    /// members' devices are) may receive our key for `scope` in `server_id`.
    pub(super) async fn admit(&mut self, server_id: &str, scope: &str, devices: Vec<DeviceAddress>) -> Vec<DeviceAddress> {
        let local_user = self.user_id.clone().unwrap_or_default();
        let users: BTreeSet<String> = devices.iter().filter(|d| d.user_id != local_user).map(|d| d.user_id.clone()).collect();
        if !self.rosters.contains_key(server_id) {
            // First look at this server from this device (we just joined, or this is the first
            // build that keeps a roster): the members listed now are the baseline.
            let mut roster = Roster { members: users.clone(), ..Roster::default() };
            roster.members.insert(local_user);
            self.baseline_without_requests(server_id, &mut roster);
            self.rosters.insert(server_id.to_string(), roster);
        }
        let unknown = users.iter().any(|u| !self.rosters[server_id].members.contains(u));
        if unknown {
            self.reconfirm_owner(server_id).await;
            if let Ok(v) = self.api.get(&format!("/api/servers/{}/member-approvals", enc(server_id))).await {
                self.apply_approvals(server_id, &v["approvals"]);
            }
        }
        self.clear_devices(server_id, scope, devices)
    }

    /// Make sure we keep a roster for `server_id`, taking the members the server lists NOW as
    /// the baseline if this is our first look (see [`Engine::admit`]).
    pub(super) async fn ensure_roster(&mut self, server_id: &str) -> Result<(), EngineError> {
        if self.rosters.contains_key(server_id) {
            return Ok(());
        }
        let devices = self.fetch_member_devices(server_id).await?;
        let mut roster = Roster { members: devices.into_iter().map(|d| d.user_id).collect(), ..Roster::default() };
        roster.members.extend(self.user_id.clone());
        self.baseline_without_requests(server_id, &mut roster);
        self.rosters.insert(server_id.to_string(), roster);
        Ok(())
    }

    /// A user who asked to be provisioned before we had a roster is not part of the baseline:
    /// they stay held until someone approves them.
    fn baseline_without_requests(&mut self, server_id: &str, roster: &mut Roster) {
        let pending: Vec<(String, String)> = self.join_requests.iter().filter(|(s, _)| s == server_id).cloned().collect();
        for key in pending {
            roster.members.remove(&key.1);
            roster.held.insert(key.1.clone());
            self.join_requests.remove(&key);
        }
    }

    /// A user this device does not accept in `server_id` asked to be provisioned. Nothing is
    /// signed or sent; the user is flagged as held and the app is told once, so the owner can
    /// decide (`"join_request"` notice: `user_id` = the requester, `device_id` = the SERVER id).
    pub(super) fn note_join_request(&mut self, server_id: &str, user_id: &str) {
        // No roster yet (we have not baselined this server): remember the request so the
        // baseline, when it is taken, leaves this user OUT instead of grandfathering them in.
        let fresh = match self.rosters.get_mut(server_id) {
            Some(roster) => roster.held.insert(user_id.to_string()),
            None => self.join_requests.insert((server_id.to_string(), user_id.to_string())),
        };
        if fresh {
            self.notice("join_request", user_id, server_id, false);
        }
    }

    /// Approve `user_id` as a member of `server_id`: sign the approval with this device's
    /// identity key, publish it for the other members to verify, and accept the user here.
    ///
    /// This is the ONLY place an approval is signed, and it is reached only from an explicit
    /// user action — approving a join request, or tapping "Let in" on a member shown as held.
    /// Nothing the server or another user sends ever leads here on its own.
    pub async fn approve_member(&mut self, server_id: &str, user_id: &str) -> Result<(), EngineError> {
        let local = self.local()?;
        if user_id == local.user_id {
            return Ok(());
        }
        self.ensure_roster(server_id).await?;
        let ts = now_ms() as i64;
        let signature = self.store.sign_member_approval(server_id, user_id, &local.user_id, ts)?;
        // Best-effort: a server that drops the record only keeps the newcomer held for others.
        let _ = self
            .api
            .post(
                &format!("/api/servers/{}/member-approvals", enc(server_id)),
                serde_json::json!({ "user_id": user_id, "approver_device_id": local.device_id, "ts": ts, "signature": B64.encode(signature) }),
            )
            .await;
        if let Some(roster) = self.rosters.get_mut(server_id) {
            roster.members.insert(user_id.to_string());
            roster.held.remove(user_id);
            roster.approved_by.insert(user_id.to_string(), local.user_id);
        }
        Ok(())
    }

    /// Users the server lists in `server_id` that this device is holding (no trusted approval).
    pub fn held_members(&self, server_id: &str) -> Vec<String> {
        self.rosters.get(server_id).map(|r| r.held.iter().cloned().collect()).unwrap_or_default()
    }

    /// Forget a removed member: they need a fresh approval (newer than now) to come back, and
    /// their devices must be shown again before they get a key.
    pub(super) fn roster_remove(&mut self, server_id: &str, user_id: &str) {
        if let Some(roster) = self.rosters.get_mut(server_id) {
            roster.members.remove(user_id);
            roster.held.remove(user_id);
            roster.approved_by.remove(user_id);
            roster.removed_at.insert(user_id.to_string(), now_ms() as i64);
            for devices in roster.cleared.values_mut() {
                devices.retain(|d| d.user_id != user_id);
            }
        }
    }

    /// Pin `owner` as the owner of `server_id`, recording where the pin came from.
    pub(super) fn pin_owner(&mut self, server_id: &str, owner: &str, source: OwnerSource) {
        self.expected_provisioner.insert(server_id.to_string(), owner.to_string());
        self.owner_sources.insert(server_id.to_string(), source);
    }

    /// The pinned owner of `server_id` — only if the pin has a known, trustworthy source. A
    /// `legacy-unknown` pin is not returned: it must not authorize a space key or an approval.
    pub(super) fn trusted_owner(&self, server_id: &str) -> Option<&String> {
        self.owner_sources.get(server_id).and(self.expected_provisioner.get(server_id))
    }

    /// The owner pins a sibling device may be told about: trusted ones only. A `legacy-unknown`
    /// pin is never propagated (it would arrive looking as trustworthy as any other).
    pub(super) fn owner_pins_to_share(&self) -> Vec<(String, String)> {
        self.expected_provisioner
            .iter()
            .filter(|(server, _)| self.owner_sources.contains_key(*server))
            .map(|(s, o)| (s.clone(), o.clone()))
            .take(MAX_SERVER_ARRAY)
            .collect()
    }

    /// A verified sibling told us its owner pins. Each is taken only where we hold no TRUSTED pin
    /// (a trusted pin is never replaced; a `legacy-unknown` one gives way to the sibling's).
    pub(super) fn accept_sibling_pins(&mut self, pins: Vec<(String, String)>) {
        for (server_id, owner) in pins.into_iter().take(MAX_SERVER_ARRAY) {
            if server_id.len() <= 128 && owner.len() <= 128 && self.trusted_owner(&server_id).is_none() {
                self.pin_owner(&server_id, &owner, OwnerSource::Sibling);
            }
        }
    }

    /// Re-confirm a `legacy-unknown` pin from an owner attestation (`{owner_id, signature}`)
    /// signed by the PINNED instance key. It only ever confirms the owner already pinned: an
    /// attestation naming anyone else changes nothing. Returns whether the pin is now trusted.
    pub(super) fn apply_owner_attestation(&mut self, server_id: &str, attestation: &serde_json::Value) -> bool {
        if self.trusted_owner(server_id).is_some() {
            return true;
        }
        let (Some(pinned_owner), Some(instance_key)) = (self.expected_provisioner.get(server_id).cloned(), self.pinned_instance_key.clone()) else {
            return false;
        };
        let (Some(owner), Some(sig)) = (attestation["owner_id"].as_str(), attestation["signature"].as_str().and_then(|s| B64.decode(s).ok())) else {
            return false;
        };
        if owner != pinned_owner || !skwod_crypto::instance::verify_owner_attestation(&instance_key, server_id, owner, &sig) {
            return false;
        }
        self.owner_sources.insert(server_id.to_string(), OwnerSource::InstanceSigned);
        true
    }

    /// Try (at most once a minute per server) to re-confirm a `legacy-unknown` owner pin.
    pub(super) async fn reconfirm_owner(&mut self, server_id: &str) {
        if self.trusted_owner(server_id).is_some() || !self.expected_provisioner.contains_key(server_id) {
            return;
        }
        if self.owner_rechecked.get(server_id).is_some_and(|t| t.elapsed() < std::time::Duration::from_secs(60)) {
            return;
        }
        self.owner_rechecked.insert(server_id.to_string(), std::time::Instant::now());
        if let Ok(v) = self.api.get(&format!("/api/servers/{}/owner-attestation", enc(server_id))).await {
            self.apply_owner_attestation(server_id, &v);
        }
    }

    /// The owner of `server_id` as this device has it PINNED from a trustworthy source, or
    /// `None`: our own create flow, the join we made, a verified sibling device (`OwnerPins`),
    /// or a pre-provenance pin re-confirmed by the pinned instance key. It is the trust anchor
    /// for space keys and member approvals, so nothing the server merely *lists* is ever written
    /// into it, and a pin of unknown origin does not count.
    pub async fn space_owner(&mut self, server_id: &str) -> Option<String> {
        self.reconfirm_owner(server_id).await;
        self.trusted_owner(server_id).cloned()
    }

    /// The account that owns the INSTANCE (the host), as attested by the pinned instance key
    /// (`GET /api/instance/owner-attestation`), or `None` when no instance key is pinned, the
    /// server has none, or the signature does not hold. This is the instance's own word about
    /// itself: good for instance-level cosmetics (the skwod icon), never for keys or approvals.
    /// The caller pins the first answer (see `SkwodClient::instance_owner`).
    pub async fn attested_instance_owner(&mut self) -> Option<String> {
        let instance_key = self.pinned_instance_key.clone()?;
        let v = self.api.get("/api/instance/owner-attestation").await.ok()?;
        check_instance_owner(&instance_key, &v)
    }

    /// Record what the SERVER says the owners of our servers are (`GET /api/servers`). Display
    /// only: kept apart from the pinned owners, and never read by space-key acceptance, approval
    /// verification or anything else that decides trust.
    pub(super) fn note_claimed_owners(&mut self, servers: &serde_json::Value) {
        for s in servers.as_array().into_iter().flatten().take(MAX_SERVER_ARRAY) {
            if let (Some(id), Some(owner)) = (s["server_id"].as_str(), s["owner_id"].as_str()) {
                self.claimed_owners.insert(id.to_string(), owner.to_string());
            }
        }
    }

    /// Who the server CLAIMS owns `server_id` — for labels only (e.g. a crown in a member list).
    /// Never a basis for trusting anything that user says or signs.
    pub async fn space_owner_claimed(&mut self, server_id: &str) -> Option<String> {
        if !self.claimed_owners.contains_key(server_id) {
            if let Ok(resp) = self.api.get("/api/servers").await {
                self.note_claimed_owners(&resp["servers"]);
            }
        }
        self.claimed_owners.get(server_id).cloned()
    }

    /// Drain membership events that had no sink to go to (see [`EventSink`]).
    pub fn take_system_events(&mut self) -> Vec<SystemEvent> {
        std::mem::take(&mut self.events)
    }

    /// Install the sink that shows membership events (the app's encrypted message cache).
    pub fn set_event_sink(&mut self, sink: EventSink) {
        // Anything queued before the sink existed goes through it now.
        let queued = std::mem::take(&mut self.events);
        self.events = queued.into_iter().filter(|e| !sink(e)).collect();
        self.event_sink = Some(sink);
    }

    /// The DM conversation (if any) this account has with `user_id` — where a notice about that
    /// contact belongs.
    pub async fn dm_conversation_with(&mut self, user_id: &str) -> Option<String> {
        let find = |e: &Engine| {
            e.dm_participants.iter().find(|(_, users)| users.len() <= 2 && users.iter().any(|u| u == user_id)).map(|(id, _)| id.clone())
        };
        if let Some(id) = find(self) {
            return Some(id);
        }
        self.dm_participants.clear();
        let _ = self.conversation_participants("").await;
        find(self)
    }
}

/// Validate an instance-owner attestation (`{owner_id, signature}`) against the pinned key.
pub(super) fn check_instance_owner(instance_key: &[u8], attestation: &serde_json::Value) -> Option<String> {
    let owner = attestation["owner_id"].as_str().filter(|o| !o.is_empty() && o.len() <= 128)?;
    let sig = attestation["signature"].as_str().and_then(|s| B64.decode(s).ok())?;
    skwod_crypto::instance::verify_instance_owner(instance_key, owner, &sig).then(|| owner.to_string())
}
