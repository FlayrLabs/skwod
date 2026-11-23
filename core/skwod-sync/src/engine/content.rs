//! Build 44 "content": direct-message parity (edit, delete for everyone, reactions, replies,
//! small groups) and abuse reports sealed to the instance owner.
//!
//! Everything here travels as a sealed `Content` variant over the pairwise libsignal sessions —
//! the same road as a plain DM — so the server learns nothing new: an edit, a reaction and a
//! report are the same opaque envelope as a message. What is new is decided on the RECEIVING
//! device, after decryption, under two rules:
//!
//! - an operation names a conversation; it is only accepted when that conversation really is
//!   between us and its sender (the check a plain DM already gets);
//! - an edit or a delete only ever touches a message its SENDER wrote. The engine cannot see the
//!   message store, so it hands the operation on with the authenticated author and the core
//!   applies it through a cache rule that refuses to modify another author's row.
//!
//! State added here is serialized in a tagged section of its own after `trust::EngineExt` (see
//! `Engine::export_state` and `accounts::write_section`): postcard structs can never grow.

use serde::{Deserialize, Serialize};

use super::*;

/// The most people in a group DM (pairwise fan-out: every message is sealed once per device).
pub const MAX_GROUP_DM: usize = 10;
const MAX_BUFFERED_OPS: usize = 5_000;
const MAX_BUFFERED_REPORTS: usize = 500;
const MAX_REACTION: usize = 64;
/// The most of a reported message a reporter may reveal.
pub const MAX_REPORT_EXCERPT: usize = 8 * 1024;

/// What a decrypted DM operation does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DmOpKind {
    /// A message that quotes another one (`reply_to`); otherwise exactly a plain DM.
    Reply { text: String, sent_at: i64, reply_to: String },
    /// New text for a message its author wrote.
    Edit { text: String },
    /// The author removed the message for everyone.
    Delete,
    /// The sender reacted to (or took a reaction off) a message.
    Reaction { emoji: String, remove: bool },
}

/// A decrypted, authenticated DM operation waiting for the core to apply it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DmOp {
    pub conversation_id: String,
    pub message_id: String,
    /// Who did it: the sender's user id, or [`SELF_AUTHOR`] for a copy from one of our devices.
    pub author_id: String,
    /// The other party (for a group: the sender, or for our own copy any other member).
    pub peer_user_id: String,
    pub kind: DmOpKind,
    pub received_at: i64,
}

/// An abuse report that reached this device because this account owns the instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundReport {
    /// The server's id for the report (matches the metadata row in its queue), or empty.
    pub report_id: String,
    /// Authenticated: the account whose device sealed this.
    pub reporter_user_id: String,
    pub subject_user_id: Option<String>,
    pub server_id: Option<String>,
    pub category: String,
    /// What the reporter wrote.
    pub note: Option<String>,
    /// The reported message, as the reporter chose to reveal it. This is the reporter's CLAIM
    /// about what was said: nothing here proves the subject wrote it.
    pub excerpt: Option<String>,
    pub received_at: i64,
    /// Where the reported message is, as the reporter says: the channel and the message id.
    /// A CLAIM like the excerpt — the owner's device looks the message up itself before it
    /// acts on it. Sealed to the owner only; the server's queue never gets either.
    pub channel_id: Option<String>,
    pub message_id: Option<String>,
}

/// Engine state added in build 44b (its own section; see the module docs).
#[derive(Default, Serialize, Deserialize)]
pub(super) struct ContentExt {
    pub dm_ops: Vec<DmOp>,
    pub reports: Vec<InboundReport>,
}

/// The state section [`ContentExt`] is written in (`accounts::write_section`).
pub(super) const SECTION_CONTENT: u8 = 0xC1;

/// A direct message as it travels: a plain `Chat`, or a `DmReply` when it quotes another.
pub(super) fn dm_message(conversation_id: &str, message_id: &str, text: &str, sent_at: i64, reply_to: Option<&str>, sync_peer: Option<String>) -> Content {
    let (conversation_id, message_id, text) = (conversation_id.to_string(), message_id.to_string(), text.to_string());
    match reply_to {
        None => Content::Chat { conversation_id, message_id, text, sent_at, sync_peer },
        Some(r) => Content::DmReply { conversation_id, message_id, text, sent_at, reply_to: r.to_string(), sync_peer },
    }
}

impl Engine {
    /// Is `conversation_id` really a conversation between us and `counterpart`?
    ///
    /// Decided by this device's own binding once the conversation has been used: the people it
    /// is with were fixed then, and the server's participant list is not asked again — listing
    /// someone else in a 1:1 does not let them write into it. A conversation with no binding
    /// yet is checked against the server's list once, and bound to the people it names.
    pub(super) async fn in_conversation(&mut self, local: &DeviceAddress, conversation_id: &str, counterpart: &str) -> bool {
        // What the SENDER sealed: a group of these members (a wrapped payload), or a 1:1 (bare).
        let claimed: Option<BTreeSet<String>> = match self.dm_group_claim.clone() {
            Some(members) => {
                let set: BTreeSet<String> = members.into_iter().collect();
                if set.len() < 3 || set.len() > MAX_GROUP_DM || !set.contains(&local.user_id) || !set.contains(counterpart) || counterpart == local.user_id {
                    return false;
                }
                Some(set.into_iter().filter(|u| u != &local.user_id).collect())
            }
            None => None,
        };
        let one = || std::iter::once(counterpart.to_string()).collect::<BTreeSet<String>>();
        if let Some(bound) = self.conversation_binding(conversation_id) {
            // A group message only in the group it names, in full; a 1:1 message only in a 1:1.
            return match &claimed {
                Some(peers) => bound == peers,
                None => bound.len() == 1 && bound.contains(counterpart),
            };
        }
        // First use here: the server's list must agree with what the sender sealed — both that
        // these are the people, and that it is (or is not) a group.
        let expected: BTreeSet<String> = claimed.unwrap_or_else(one);
        let agrees = |p: &[String]| p.contains(&local.user_id) && p.iter().filter(|u| *u != &local.user_id).cloned().collect::<BTreeSet<String>>() == expected;
        let mut participants = self.conversation_participants(conversation_id).await;
        if !agrees(&participants) {
            // Opened after our list was cached: look once more.
            self.dm_participants.remove(conversation_id);
            participants = self.conversation_participants(conversation_id).await;
        }
        agrees(&participants) && self.bind_conversation(conversation_id, &expected)
    }

    /// Accept one decrypted DM operation (the sender is already authenticated and not blocked).
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn handle_dm_op(
        &mut self,
        local: &DeviceAddress,
        sender: DeviceAddress,
        from_own_device: bool,
        conversation_id: String,
        message_id: String,
        sync_peer: Option<String>,
        kind: DmOpKind,
        received_at: i64,
    ) {
        if message_id.is_empty() || message_id.len() > 128 || self.dm_ops.len() >= MAX_BUFFERED_OPS {
            return;
        }
        match &kind {
            DmOpKind::Reply { text, reply_to, .. } if text.len() > MAX_TEXT || reply_to.is_empty() || reply_to.len() > 128 => return,
            DmOpKind::Edit { text } if text.len() > MAX_TEXT => return,
            DmOpKind::Reaction { emoji, .. } if emoji.is_empty() || emoji.len() > MAX_REACTION => return,
            _ => {}
        }
        let counterpart = if from_own_device { sync_peer } else { Some(sender.user_id.clone()) };
        let Some(counterpart) = counterpart else { return };
        if !self.in_conversation(local, &conversation_id, &counterpart).await {
            return;
        }
        // Clamp a sender-chosen timestamp to "not in the future", like a plain DM — and what a
        // peer wrote is a message, whatever it starts with (`cache::neutralize_reserved`).
        let plain = |text: String| crate::cache::neutralize_reserved(&text).to_string();
        let kind = match kind {
            DmOpKind::Reply { text, sent_at, reply_to } => DmOpKind::Reply { text: plain(text), sent_at: sent_at.min(received_at.max(now_ms() as i64)), reply_to },
            DmOpKind::Edit { text } => DmOpKind::Edit { text: plain(text) },
            other => other,
        };
        self.dm_ops.push(DmOp {
            conversation_id,
            message_id,
            author_id: if from_own_device { SELF_AUTHOR.to_string() } else { sender.user_id },
            peer_user_id: counterpart,
            kind,
            received_at,
        });
    }

    /// Take every buffered DM operation.
    pub fn take_dm_ops(&mut self) -> Vec<DmOp> {
        std::mem::take(&mut self.dm_ops)
    }

    /// Take every abuse report that reached this (instance owner's) device.
    pub fn take_reports(&mut self) -> Vec<InboundReport> {
        std::mem::take(&mut self.reports)
    }

    pub(super) fn handle_report(&mut self, sender: &DeviceAddress, mut report: InboundReport, received_at: i64) {
        let too_long = |s: &Option<String>, max: usize| s.as_ref().is_some_and(|s| s.len() > max);
        if self.reports.len() >= MAX_BUFFERED_REPORTS
            || report.category.len() > 64
            || too_long(&report.note, MAX_REPORT_EXCERPT)
            || too_long(&report.excerpt, MAX_REPORT_EXCERPT)
            || too_long(&report.channel_id, 64)
            || too_long(&report.message_id, 64)
        {
            return;
        }
        // The reporter is whoever sealed it — never a field of the payload.
        report.reporter_user_id = sender.user_id.clone();
        report.received_at = received_at;
        self.reports.push(report);
    }

    /// The devices a DM to `peer_user` goes to, with the same refusals as a plain DM: nothing is
    /// sent to a verified contact whose devices changed until the user has looked.
    async fn dm_targets(&mut self, local: &DeviceAddress, peer_user: &str) -> Result<Vec<DeviceAddress>, EngineError> {
        let devices: Vec<DeviceAddress> = self.fetch_devices(peer_user).await?.into_iter().map(|(d, _)| d).collect();
        if peer_user != local.user_id {
            let c = self.contacts.get(peer_user);
            if self.contact_blocked(peer_user) || (devices.is_empty() && c.is_some_and(|c| !c.unvouched.is_empty())) {
                return Err(EngineError::IdentityChanged(peer_user.to_string()));
            }
        }
        if devices.is_empty() {
            return Err(EngineError::Protocol("recipient has no registered device"));
        }
        Ok(devices)
    }

    /// Seal `content(sync_peer)` to every device of every one of `peers`, then (best-effort) a
    /// copy to our own other devices naming `peers[0]` as the conversation's other party.
    /// Succeeds when at least one device of EVERY peer took it.
    pub(super) async fn dm_fanout(&mut self, peers: &[String], content: impl Fn(Option<String>) -> Content) -> Result<(), EngineError> {
        let local = self.local()?;
        let peers: Vec<&String> = peers.iter().filter(|p| **p != local.user_id).collect();
        let Some(first) = peers.first().map(|p| p.to_string()) else {
            return Err(EngineError::Protocol("a direct message needs someone to go to"));
        };
        // Resolve everyone before sending to anyone: a group message must not reach half a group.
        let mut all = Vec::new();
        for p in &peers {
            all.push(self.dm_targets(&local, p).await?);
        }
        let outbound = content(None);
        for devices in &all {
            self.send_content(devices, &outbound).await?;
        }
        if let Ok(own) = self.fetch_devices(&local.user_id).await {
            let own: Vec<DeviceAddress> = own.into_iter().map(|(d, _)| d).filter(|d| d != &local).collect();
            if !own.is_empty() {
                let _ = self.send_content(&own, &content(Some(first))).await;
            }
        }
        Ok(())
    }

    /// Send a DM under a message id the CALLER chose (so a queued send can be repeated: a
    /// receiver files an id once), optionally as a reply. `peers` is who the user addressed —
    /// one person, or the members of a group — never a list taken from the server.
    pub async fn send_dm_as(&mut self, conversation_id: &str, peers: &[String], message_id: &str, text: &str, reply_to: Option<&str>) -> Result<(), EngineError> {
        if text.len() > MAX_TEXT {
            return Err(EngineError::TooLarge(TOO_LARGE));
        }
        if message_id.is_empty() || message_id.len() > 128 {
            return Err(EngineError::Protocol("bad message id"));
        }
        let sent_at = now_ms() as i64;
        self.unsent = None;
        let local = self.local()?;
        let peers: Vec<&String> = peers.iter().filter(|p| **p != local.user_id).collect();
        let Some(first) = peers.first().map(|p| p.to_string()) else {
            return Err(EngineError::Protocol("a direct message needs someone to go to"));
        };
        // Who the USER addressed is who this conversation is with, from its first use on; a
        // conversation already bound to other people is not written into.
        let addressed: std::collections::BTreeSet<String> = peers.iter().map(|p| p.to_string()).collect();
        if !self.bind_conversation(conversation_id, &addressed) {
            return Err(EngineError::Protocol("that conversation is with someone else"));
        }
        // Resolve everyone before sending to anyone: a group message must not reach half a group.
        let mut all = Vec::new();
        for p in &peers {
            all.push(self.dm_targets(&local, p).await?);
        }
        let content = |sync_peer: Option<String>| dm_message(conversation_id, message_id, text, sent_at, reply_to, sync_peer);
        // Kept to send again from (a device that could not decrypt it, one that missed it).
        self.remember_dm(message_id, conversation_id, &first, text, sent_at, reply_to);
        // The plaintext row goes to disk in the same transaction as the advanced ratchets,
        // before anything leaves (a row the outbox already wrote is left as it is).
        let row = OutgoingRow {
            scope: format!("dm:{conversation_id}"),
            message_id: message_id.to_string(),
            text: text.to_string(),
            created_at: sent_at,
            reply_to_id: reply_to.map(str::to_string),
        };
        // Delivery is per DEVICE: the send succeeds once a device of EVERY peer has it, and each
        // device that did not take it is owed it and retried on its own schedule
        // (`retry_deliveries`).
        let outbound = content(None);
        let mut row = Some(&row);
        for devices in all {
            let delivered = self.send_content_with(&devices, &outbound, row.take()).await?;
            self.owe_deliveries(message_id, devices.into_iter().filter(|d| !delivered.contains(d) && d != &local));
        }
        self.unsent = None;
        // A copy to our own other devices so the conversation shows up there too — each of
        // them owed it like any recipient device.
        let own: Vec<DeviceAddress> = self.siblings.keys().map(|d| DeviceAddress::new(local.user_id.clone(), d.clone())).collect();
        if !own.is_empty() {
            let reached = self.send_content(&own, &content(Some(first))).await.unwrap_or_default();
            self.owe_deliveries(message_id, own.into_iter().filter(|d| !reached.contains(d)));
        }
        Ok(())
    }

    /// Edit a DM we wrote, on every device of everyone in the conversation and on our own.
    pub async fn edit_dm(&mut self, conversation_id: &str, peers: &[String], message_id: &str, text: &str) -> Result<(), EngineError> {
        if text.len() > MAX_TEXT {
            return Err(EngineError::TooLarge(TOO_LARGE));
        }
        let (cid, mid, text) = (conversation_id.to_string(), message_id.to_string(), text.to_string());
        self.dm_fanout(peers, |sync_peer| Content::DmEdit { conversation_id: cid.clone(), message_id: mid.clone(), text: text.clone(), sync_peer }).await
    }

    /// Delete a DM we wrote, for everyone.
    pub async fn delete_dm(&mut self, conversation_id: &str, peers: &[String], message_id: &str) -> Result<(), EngineError> {
        let (cid, mid) = (conversation_id.to_string(), message_id.to_string());
        self.dm_fanout(peers, |sync_peer| Content::DmDelete { conversation_id: cid.clone(), message_id: mid.clone(), sync_peer }).await
    }

    /// React to a DM (or take the reaction off).
    pub async fn react_dm(&mut self, conversation_id: &str, peers: &[String], message_id: &str, emoji: &str, remove: bool) -> Result<(), EngineError> {
        if emoji.is_empty() || emoji.len() > MAX_REACTION {
            return Err(EngineError::Protocol("bad reaction"));
        }
        let (cid, mid, emoji) = (conversation_id.to_string(), message_id.to_string(), emoji.to_string());
        self.dm_fanout(peers, |sync_peer| Content::DmReaction { conversation_id: cid.clone(), message_id: mid.clone(), emoji: emoji.clone(), remove, sync_peer }).await
    }

    /// Open a group DM with `member_user_ids` (2–9 other people). Returns the conversation id.
    pub async fn open_group_dm(&mut self, member_user_ids: &[String]) -> Result<String, EngineError> {
        let me = self.account_user_id().await?;
        let others: BTreeSet<&String> = member_user_ids.iter().filter(|u| **u != me).collect();
        if others.len() < 2 || others.len() + 1 > MAX_GROUP_DM {
            return Err(EngineError::Protocol("a group chat needs 3 to 10 people"));
        }
        let resp = self.api.post("/api/dms", serde_json::json!({ "participant_ids": others })).await?;
        let id = resp["conversation_id"].as_str().map(str::to_string).ok_or(EngineError::Protocol("no conversation_id"))?;
        self.dm_participants.remove(&id);
        Ok(id)
    }

    /// Every group conversation this account is in: `(conversation id, the other members)`,
    /// as the server lists them. Groups with a member this account blocked are left out.
    pub async fn list_group_dms(&mut self) -> Result<Vec<(String, Vec<String>)>, EngineError> {
        let me = self.account_user_id().await?;
        let list = self.api.get("/api/dms").await?;
        let mut out = Vec::new();
        for c in list["conversations"].as_array().into_iter().flatten().take(MAX_SERVER_ARRAY) {
            let Some(id) = c["conversation_id"].as_str() else { continue };
            let users: Vec<String> = c["participants"].as_array().into_iter().flatten().filter_map(|u| u.as_str().map(str::to_string)).collect();
            self.dm_participants.insert(id.to_string(), users.clone());
            if users.len() < 3 || users.len() > MAX_GROUP_DM || !users.contains(&me) {
                continue;
            }
            let others: Vec<String> = users.into_iter().filter(|u| *u != me).collect();
            if others.iter().any(|u| self.blocked.contains(u)) {
                continue;
            }
            out.push((id.to_string(), others));
        }
        Ok(out)
    }

    /// The members of a group DM as the SERVER lists them — for display and for the app to
    /// compare with the people the user chose; sends go only to whom the app names.
    pub async fn group_dm_members(&mut self, conversation_id: &str) -> Vec<String> {
        self.dm_participants.remove(conversation_id);
        self.conversation_participants(conversation_id).await
    }

    /// File an abuse report. The server's queue gets the METADATA only (who reported whom, the
    /// category) — its operator is who acts on it. What the reporter wrote and the message they
    /// chose to reveal are sealed to the instance owner's own devices, like a DM, so they are
    /// readable by that person and by nobody who merely has the database.
    ///
    /// `owner` is the instance owner as this device has verified it (`None`: unknown, or it is
    /// us). Without one, a note still reaches the server's queue in plaintext — the pre-44
    /// behaviour — but a message excerpt is never sent that way. Returns
    /// `(report id, whether the sealed part was delivered)`.
    #[allow(clippy::too_many_arguments)]
    pub async fn report(
        &mut self,
        owner: Option<&str>,
        category: &str,
        note: Option<&str>,
        excerpt: Option<&str>,
        subject_user_id: Option<&str>,
        server_id: Option<&str>,
        message_ref: Option<(&str, &str)>,
    ) -> Result<(String, bool), EngineError> {
        if excerpt.is_some_and(|e| e.len() > MAX_REPORT_EXCERPT) || note.is_some_and(|n| n.len() > MAX_REPORT_EXCERPT) {
            return Err(EngineError::TooLarge("That report is too long. Shorten the note or the quoted message."));
        }
        let me = self.account_user_id().await?;
        let owner = owner.filter(|o| *o != me);
        // Plaintext to the server only when there is no owner to seal it to.
        let body = if owner.is_some() { None } else { note };
        let report_id = self.report_abuse(category, body, subject_user_id, server_id).await?;
        let Some(owner) = owner else { return Ok((report_id, false)) };
        let report = InboundReport {
            report_id: report_id.clone(),
            reporter_user_id: String::new(),
            subject_user_id: subject_user_id.map(str::to_string),
            server_id: server_id.map(str::to_string),
            category: category.to_string(),
            note: note.map(str::to_string),
            excerpt: excerpt.map(str::to_string),
            received_at: 0,
            channel_id: message_ref.map(|(c, _)| c.to_string()),
            message_id: message_ref.map(|(_, m)| m.to_string()),
        };
        let local = self.local()?;
        let sealed = match self.dm_targets(&local, owner).await {
            Ok(devices) => self.send_content(&devices, &Content::Report { report }).await.is_ok(),
            Err(_) => false,
        };
        Ok((report_id, sealed))
    }

    /// The users this device drops everything from (see `block_user`), without the network.
    pub fn blocked_users(&self) -> Vec<String> {
        self.blocked.iter().cloned().collect()
    }
}
