//! State this device keeps so the server cannot rewrite what it already decided (build 45):
//! which people a direct conversation is with, which channel clears were really ordered by
//! someone entitled to, and the newest key backup this install has seen.
//!
//! Persisted as one tagged, skippable section of the engine state ([`SECTION_GUARD`]).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::Ordering;

use serde::{Deserialize, Serialize};
use skwod_crypto::DeviceAddress;

use super::{accounts, now_ms, Content, Engine, EngineError, SecurityNotice, MAX_SERVER_ARRAY};

/// Engine-state section tag.
pub(super) const SECTION_GUARD: u8 = 0xE2;
/// Key-backup section tag (in the backup blob's tail): the backup's sequence number.
pub(super) const SECTION_BACKUP_SEQ: u8 = 0xE3;

/// Conversations a binding is kept for. Past this no NEW conversation is accepted (existing
/// ones go on working): refusing is the safe side of a bound.
const MAX_BOUND_CONVERSATIONS: usize = 50_000;
/// People one conversation can be bound to.
const MAX_BOUND_PEERS: usize = 64;
/// How far ahead of our clock a clear time may be (the server's clock, which message times use).
const CLEAR_SKEW_MS: i64 = 10 * 60 * 1000;
/// Authenticated clears waiting for the application.
const MAX_PENDING_CLEARS: usize = 1_000;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct GuardState {
    /// Direct conversation id → the people (never us) it is with, fixed the first time the
    /// conversation is used. A message is only ever filed in a conversation from someone in
    /// its set, whatever the server lists as its participants later.
    pub dm_peers: BTreeMap<String, BTreeSet<String>>,
    /// Channel clears ordered by the pinned owner of the channel's server (or by one of our own
    /// devices) and not yet taken by the application: `(channel id, cleared at, unix ms)`.
    pub channel_clears: Vec<(String, i64)>,
    /// The highest key-backup sequence number this install has uploaded or restored.
    pub backup_seq: u64,
    /// Channel-message deletions that arrived over a sealed session and were not yet taken by
    /// the application.
    pub channel_deletes: Vec<ChannelDelete>,
    /// Channel id → the server it belongs to, CONFIRMED by something the user did on this device
    /// (see `confirm_channel`). Never written by a server listing, never evicted, never moved.
    /// Who may clear a channel or delete in it is decided by the pinned owner and roster of
    /// THIS server — so where a channel belongs must not be the server's to say.
    pub channel_servers: BTreeMap<String, String>,
}

/// "Delete this channel message", as an authenticated device said it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelDelete {
    pub channel_id: String,
    pub message_id: String,
    /// The account that said so ([`super::SELF_AUTHOR`] for one of our own devices). Unless
    /// `by_owner`, the application applies it only to a message THIS account wrote.
    pub by_user_id: String,
    /// It came from the owner this device has pinned for the channel's server (who may delete
    /// anyone's message there).
    pub by_owner: bool,
}

impl Engine {
    // ---- direct conversations ----

    /// Is `conversation_id` bound to (all of) `peers`? Binds it to exactly them when it has no
    /// binding yet. `false`: it is bound to other people — or the table is full.
    pub(super) fn bind_conversation(&mut self, conversation_id: &str, peers: &BTreeSet<String>) -> bool {
        if let Some(bound) = self.guard.dm_peers.get(conversation_id) {
            return !peers.is_empty() && peers.is_subset(bound);
        }
        if peers.is_empty() || peers.len() > MAX_BOUND_PEERS || conversation_id.is_empty() || conversation_id.len() > 128 || self.guard.dm_peers.len() >= MAX_BOUND_CONVERSATIONS {
            return false;
        }
        self.guard.dm_peers.insert(conversation_id.to_string(), peers.clone());
        true
    }

    /// The wrapped form of a direct-message payload for a GROUP conversation (one bound to more
    /// than one other person), or `None` when `content` goes out as it is.
    pub(super) fn group_wrapped(&self, local: &DeviceAddress, content: &Content) -> Result<Option<Content>, EngineError> {
        let Some(bound) = content.dm_conversation().and_then(|c| self.guard.dm_peers.get(c)).filter(|b| b.len() > 1) else { return Ok(None) };
        let mut members: Vec<String> = bound.iter().cloned().collect();
        members.push(local.user_id.clone());
        members.sort();
        members.dedup();
        Ok(Some(Content::Grouped { members, inner: content.encode()? }))
    }

    /// Is `conversation_id` a group conversation? `Some(true)` / `Some(false)` once it has been
    /// used on this device — from then on that is fixed, and it came from inside a sealed
    /// message or from the user's own send, not from the server's `is_group`. `None`: never
    /// used here.
    pub fn conversation_is_group(&self, conversation_id: &str) -> Option<bool> {
        self.guard.dm_peers.get(conversation_id).map(|b| b.len() > 1)
    }

    /// The people `conversation_id` is bound to, if it has been used.
    pub(super) fn conversation_binding(&self, conversation_id: &str) -> Option<&BTreeSet<String>> {
        self.guard.dm_peers.get(conversation_id)
    }

    // ---- where a channel belongs ----
    //
    // Two tiers. A CONFIRMED placement comes from an act of the user that NAMES the server —
    // creating the channel in it, joining through an invite to it, opening the channel from
    // its list ([`Engine::confirm_channel`]). Writing, deleting or clearing in a channel
    // confirms nothing: those only know the channel id, and promoting "wherever the server
    // currently lists it" would hand the choice back to the server. It is persisted, never evicted, never moved, and is the
    // only kind that lets a clear or a deletion through. A LISTED placement is what a server
    // listing said about a channel nothing is confirmed for: kept in memory only, at most
    // `MAX_SERVER_ARRAY` per server with the least recently listed going first, good for
    // routing and nothing else. A listing never confirms anything, so no amount of listed
    // junk can fill, or push anything out of, the confirmed table.

    /// The user acted on `channel_id` as a channel of `server_id`: confirm that placement. A
    /// listed placement elsewhere gives way to it; a CONFIRMED one in another server does not —
    /// `false`, nothing changes, and the user is told once (`"channel_remap_refused"`:
    /// `user_id` = the server it is confirmed in, `device_id` = the channel). Only
    /// [`Engine::forget_space`] removes a confirmed placement.
    pub fn confirm_channel(&mut self, channel_id: &str, server_id: &str) -> bool {
        if channel_id.is_empty() || channel_id.len() > 128 || server_id.is_empty() || server_id.len() > 128 {
            return false;
        }
        match self.guard.channel_servers.get(channel_id) {
            Some(bound) if bound == server_id => true,
            Some(bound) => {
                let bound = bound.clone();
                self.note_remap(channel_id, bound);
                false
            }
            None => {
                self.listed_channels.retain(|c| c != channel_id);
                self.guard.channel_servers.insert(channel_id.to_string(), server_id.to_string());
                self.channel_servers.insert(channel_id.to_string(), server_id.to_string());
                true
            }
        }
    }

    /// The server `channel_id` is CONFIRMED in on this device, if any.
    pub(super) fn confirmed_server(&self, channel_id: &str) -> Option<String> {
        self.guard.channel_servers.get(channel_id).cloned()
    }

    /// A server LISTING names `channel_id` under `server_id`. Places it if nothing is placed
    /// for it (listed tier: in memory, bounded per server, least recently listed evicted) and
    /// never moves anything: `false` when the channel is placed — confirmed or listed — under
    /// another server (reported only when that placement is a confirmed one).
    pub(super) fn bind_channel(&mut self, channel_id: &str, server_id: &str) -> bool {
        if channel_id.is_empty() || channel_id.len() > 128 || server_id.is_empty() || server_id.len() > 128 {
            return false;
        }
        match self.channel_servers.get(channel_id) {
            Some(placed) if placed == server_id => {
                // Still listed: it is the most recently listed one again.
                if let Some(at) = self.listed_channels.iter().position(|c| c == channel_id) {
                    self.listed_channels.remove(at);
                    self.listed_channels.push_back(channel_id.to_string());
                }
                true
            }
            Some(placed) => {
                if self.guard.channel_servers.contains_key(channel_id) {
                    let placed = placed.clone();
                    self.note_remap(channel_id, placed);
                }
                false
            }
            None => {
                // Make room among THIS server's listed placements only.
                let of_server: Vec<usize> =
                    self.listed_channels.iter().enumerate().filter(|(_, c)| self.channel_servers.get(*c).is_some_and(|s| s == server_id)).map(|(i, _)| i).collect();
                if of_server.len() >= MAX_SERVER_ARRAY {
                    if let Some(evicted) = self.listed_channels.remove(of_server[0]) {
                        self.channel_servers.remove(&evicted);
                    }
                }
                self.channel_servers.insert(channel_id.to_string(), server_id.to_string());
                self.listed_channels.push_back(channel_id.to_string());
                true
            }
        }
    }

    fn note_remap(&mut self, channel_id: &str, bound: String) {
        if self.flagged_devices.insert(format!("remap:{channel_id}")) {
            self.notices.push(SecurityNotice { kind: "channel_remap_refused".into(), user_id: bound, device_id: channel_id.to_string(), at_ms: now_ms(), was_verified: false });
        }
    }

    /// Does this device hold a CONFIRMED placement of `channel_id` in exactly `server_id`? The
    /// only thing a clear or a deletion is ever checked against.
    pub(super) fn channel_bound_to(&self, channel_id: &str, server_id: &str) -> bool {
        self.guard.channel_servers.get(channel_id).is_some_and(|s| s == server_id)
    }

    // ---- channel clears ----

    /// Tell every member device (and our own other devices) that WE cleared `channel_id`, over
    /// the sealed sessions. This — not the server's `cleared_at` — is what makes their devices
    /// drop what they cached.
    ///
    /// Only for a channel this device has placed in `server_id`: a channel id the server lists
    /// under that server but that we hold under another is not ours to clear there.
    pub(super) async fn announce_clear(&mut self, server_id: &str, channel_id: &str) {
        // Never confirmed here by anything a listing said: acting in a channel does not turn
        // the server's placement of it into ours.
        if !self.channel_bound_to(channel_id, server_id) {
            return;
        }
        // The time the SERVER recorded (message times are its clock), read back and bounded
        // by ours; our own clock when it cannot be read.
        let now = now_ms() as i64;
        let recorded = match self.api.get(&format!("/api/channels/{}/messages?limit=1&before={}", super::enc(channel_id), i64::MAX)).await {
            Ok(v) => v["cleared_at"].as_i64(),
            Err(_) => None,
        };
        let cleared_at = recorded.filter(|at| *at > 0 && *at <= now + CLEAR_SKEW_MS).unwrap_or(now);
        let Ok(devices) = self.fetch_member_devices(server_id).await else { return };
        let content = Content::ChannelClear { server_id: server_id.to_string(), channel_id: channel_id.to_string(), cleared_at };
        for chunk in devices.chunks(100) {
            let _ = self.send_content(chunk, &content).await;
        }
    }

    /// A sealed "this channel was cleared" arrived from an authenticated device. It names the
    /// server it speaks for, inside the ciphertext, and counts only if
    /// - THIS device has the channel placed in exactly that server (its own stored placement:
    ///   no placement, or another server, is a refusal — nothing is looked up), and
    /// - the sender is one of our own devices or the owner this device has pinned for it.
    ///
    /// So the owner of one server cannot clear a channel of another, wherever the host lists
    /// that channel today. The time is bounded by the present.
    pub(super) async fn on_channel_clear(&mut self, sender: &DeviceAddress, from_own_device: bool, server_id: String, channel_id: String, cleared_at: i64, received_at: i64) {
        if !self.channel_bound_to(&channel_id, &server_id) {
            return;
        }
        if !from_own_device {
            self.reconfirm_owner(&server_id).await;
            if self.trusted_owner(&server_id) != Some(&sender.user_id) {
                return;
            }
        }
        let _ = received_at; // the server's stamp on the envelope: not a bound worth having
        let cleared_at = cleared_at.min(now_ms() as i64 + CLEAR_SKEW_MS);
        if cleared_at <= 0 || self.guard.channel_clears.iter().any(|(c, at)| c == &channel_id && *at >= cleared_at) {
            return;
        }
        if self.guard.channel_clears.len() >= MAX_PENDING_CLEARS {
            self.guard.channel_clears.remove(0);
        }
        self.guard.channel_clears.push((channel_id, cleared_at));
    }

    /// Tell every member device (and our own other devices) that we deleted `message_id`.
    pub(super) async fn announce_delete(&mut self, channel_id: &str, message_id: &str) {
        // Routing only (who to tell): the placement may be a listed one. An author's deletion
        // rests on the author, not on where the channel is placed.
        let Some(server_id) = self.channel_servers.get(channel_id).cloned() else { return };
        let Ok(devices) = self.fetch_member_devices(&server_id).await else { return };
        let content = Content::ChannelDelete { server_id: server_id.clone(), channel_id: channel_id.to_string(), message_id: message_id.to_string() };
        for chunk in devices.chunks(100) {
            let _ = self.send_content(chunk, &content).await;
        }
    }

    /// A sealed "I deleted this channel message" arrived from an authenticated device. Whose
    /// message it may delete is decided where the message is (the application's cache): the
    /// sender's own, or anyone's if the sender is the pinned owner of the channel's server.
    ///
    /// An AUTHOR's deletion needs nothing from the server's side of things: the sender is
    /// authenticated, and the application applies it only to a message that sender wrote in
    /// that channel — so where the channel belongs does not come into it. The OWNER's wider
    /// right (anyone's message) does depend on the server, and is granted like a clear: only
    /// when this device has the channel confirmed in exactly the server the message names and
    /// the sender is the owner pinned for it.
    pub(super) async fn on_channel_delete(&mut self, sender: &DeviceAddress, from_own_device: bool, server_id: String, channel_id: String, message_id: String) {
        if message_id.is_empty() || message_id.len() > 128 || channel_id.is_empty() || channel_id.len() > 128 {
            return;
        }
        let placed = self.channel_bound_to(&channel_id, &server_id);
        if placed {
            self.reconfirm_owner(&server_id).await;
        }
        let by_owner = placed && !from_own_device && self.trusted_owner(&server_id).is_some_and(|o| o == &sender.user_id);
        if self.guard.channel_deletes.len() >= MAX_PENDING_CLEARS {
            self.guard.channel_deletes.remove(0);
        }
        let by_user_id = if from_own_device { super::SELF_AUTHOR.to_string() } else { sender.user_id.clone() };
        self.guard.channel_deletes.push(ChannelDelete { channel_id, message_id, by_user_id, by_owner });
    }

    /// Take the authenticated channel-message deletions that arrived. A tombstone the SERVER
    /// serves for a message this device can already read is not grounds to delete it.
    pub fn take_channel_deletes(&mut self) -> Vec<ChannelDelete> {
        std::mem::take(&mut self.guard.channel_deletes)
    }

    /// Take the authenticated channel clears that arrived: `(channel id, cleared at)`. The
    /// application drops what it cached for each channel from before that time. A `cleared_at`
    /// the SERVER reports (a page, a realtime event) is never grounds to delete anything.
    pub fn take_channel_clears(&mut self) -> Vec<(String, i64)> {
        std::mem::take(&mut self.guard.channel_clears)
    }

    // ---- key backups ----

    /// The sequence number for a backup written now: above every one this install has seen.
    pub(super) fn next_backup_seq(&self) -> u64 {
        let seq = now_ms().max(self.guard.backup_seq + 1);
        self.exported_backup_seq.store(seq, Ordering::Relaxed);
        seq
    }

    /// The backup exported last reached the server: remember its sequence number.
    pub(super) fn backup_uploaded(&mut self) {
        self.guard.backup_seq = self.guard.backup_seq.max(self.exported_backup_seq.load(Ordering::Relaxed));
    }

    /// The sequence number a backup blob's tail carries (0: written before build 45).
    pub(super) fn backup_seq_of(tail: &[u8]) -> u64 {
        accounts::read_sections(tail)
            .unwrap_or_default()
            .into_iter()
            .find(|(t, _)| *t == SECTION_BACKUP_SEQ)
            .and_then(|(_, body)| postcard::from_bytes::<u64>(body).ok())
            .unwrap_or(0)
    }

    /// Refuse to restore a backup OLDER than one this install has already uploaded or restored:
    /// the server is serving a stale blob (it still opens under the same recovery key), and
    /// taking it would bring back the sibling set and contact trust from before whatever
    /// happened since — a device removal above all.
    pub(super) fn check_backup_fresh(&self, tail: &[u8]) -> Result<u64, EngineError> {
        let seq = Self::backup_seq_of(tail);
        if seq < self.guard.backup_seq {
            return Err(EngineError::Protocol("this backup is older than one this device has already seen"));
        }
        Ok(seq)
    }

    /// Cap what a section read from disk can hold (it is ours, but bounded all the same).
    pub(super) fn bound_guard(mut guard: GuardState) -> GuardState {
        guard.channel_clears.truncate(MAX_PENDING_CLEARS);
        guard.channel_deletes.truncate(MAX_PENDING_CLEARS);
        while guard.dm_peers.len() > MAX_BOUND_CONVERSATIONS.max(MAX_SERVER_ARRAY) {
            guard.dm_peers.pop_last();
        }
        guard
    }
}
