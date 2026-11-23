//! Build 44 "content": blocks that hide everywhere, reports with feedback, direct-message
//! parity (edit / delete / react / reply / small groups), channel clears that reach every
//! device, and stories that end.
//!
//! The FFI surface added here is documented in `docs/FFI-CHANGES.md` ("Build 44b").

use std::collections::BTreeMap;

use skwod_sync::cache::CachedMessage;
use skwod_sync::{DmOpKind, Reaction, SELF_AUTHOR};

use crate::{now_ms, BlockInfo, CoreError, DmEvent, Message, MessageReaction, SkwodClient, REACTIONS_PREFIX};

const CLEARED_PREFIX: &str = "cleared-at:";
const CLOCK_KEY: &str = "server-clock-offset";
/// How far past this device's clock a clear may reach (message times are the server's clock).
const CLEAR_SKEW_MS: i64 = 10 * 60 * 1000;
const REPORTS_KEY: &str = "reports-inbox";
const MAX_KEPT_REPORTS: usize = 500;

/// What filing a report did.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ReportReceipt {
    /// The server's id for the report. Show "Report sent" once this is back.
    pub report_id: String,
    /// The note and the quoted message were sealed to the skwod's owner (only they can read
    /// them). `false`: there is no verified owner to seal to (or it is this account) — then a
    /// note went to the server's report queue as text and a quoted message was NOT sent.
    pub sealed_to_owner: bool,
}

/// A report that reached this device because this account owns the skwod.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AbuseReport {
    pub report_id: String,
    /// Authenticated: the account that sent it.
    pub reporter_user_id: String,
    pub subject_user_id: Option<String>,
    pub server_id: Option<String>,
    pub category: String,
    pub note: Option<String>,
    /// The reported message as the REPORTER chose to reveal it — their claim of what was said.
    pub excerpt: Option<String>,
    pub received_at: i64,
    /// Where the reported message is, as the reporter says (a claim, like `excerpt`): look the
    /// message up with `cached_message("channel:<channel_id>", message_id)` before acting on
    /// it. `None` for a report about a person, a DM, or one filed without a message.
    pub channel_id: Option<String>,
    pub message_id: Option<String>,
}

/// A group direct conversation as the server lists it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct GroupDm {
    pub conversation_id: String,
    /// Everyone in it except this account — the SERVER's list. Show it; before the first send
    /// the app passes the people the user actually chose.
    pub member_user_ids: Vec<String>,
}

impl AbuseReport {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "report_id": self.report_id, "reporter_user_id": self.reporter_user_id, "subject_user_id": self.subject_user_id,
            "server_id": self.server_id, "category": self.category, "note": self.note, "excerpt": self.excerpt, "received_at": self.received_at,
            "channel_id": self.channel_id, "message_id": self.message_id,
        })
    }

    fn from_json(v: &serde_json::Value) -> Option<Self> {
        let s = |k: &str| v[k].as_str().map(str::to_string);
        Some(AbuseReport {
            report_id: s("report_id")?,
            reporter_user_id: s("reporter_user_id")?,
            subject_user_id: s("subject_user_id"),
            server_id: s("server_id"),
            category: s("category")?,
            note: s("note"),
            excerpt: s("excerpt"),
            received_at: v["received_at"].as_i64().unwrap_or_default(),
            channel_id: s("channel_id"),
            message_id: s("message_id"),
        })
    }
}

fn dm_scope(conversation_id: &str) -> String {
    format!("dm:{conversation_id}")
}

impl SkwodClient {
    fn load_reports(&self) -> Vec<AbuseReport> {
        self.kv(REPORTS_KEY)
            .and_then(|j| serde_json::from_str::<serde_json::Value>(&j).ok())
            .and_then(|v| v.as_array().map(|a| a.iter().filter_map(AbuseReport::from_json).collect()))
            .unwrap_or_default()
    }

    fn save_reports(&self, reports: &[AbuseReport]) {
        self.kv_put(REPORTS_KEY, &serde_json::Value::Array(reports.iter().map(AbuseReport::to_json).collect()).to_string());
    }

    pub(crate) fn me(&self) -> Option<String> {
        self.self_user.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub(crate) fn with_cache<T>(&self, f: impl FnOnce(&skwod_sync::Cache) -> T) -> Option<T> {
        self.cache.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(f)
    }

    // ---- server time ----

    /// Remember how far this device's clock is from the server's, from a time the server just
    /// stamped on something we sent.
    pub(crate) fn note_server_time(&self, server_ms: i64) {
        self.kv_put(CLOCK_KEY, &(server_ms - now_ms()).to_string());
    }

    /// The server's "now", as best this device knows it (its own clock until it has sent once).
    pub(crate) fn server_now(&self) -> i64 {
        now_ms() + self.kv(CLOCK_KEY).and_then(|v| v.parse::<i64>().ok()).unwrap_or(0)
    }

    // ---- channel clear ----

    /// A channel-message deletion that arrived over a sealed session: tombstone the message
    /// where this device holds it — only if the device that said so may delete it (its author,
    /// or the pinned owner of the server), and never a row the core wrote.
    pub(crate) fn apply_channel_delete(&self, d: &skwod_sync::ChannelDelete) {
        let me = self.self_user.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let author = (!d.by_owner).then_some(d.by_user_id.as_str());
        let at = self.server_now();
        self.with_cache(|cache| {
            for scope in [format!("channel:{}", d.channel_id), format!("aux:{}", d.channel_id)] {
                let _ = cache.tombstone_message(&scope, &d.message_id, author, me.as_deref(), at);
            }
        });
    }

    /// The channel was cleared at `cleared_at` (server time) by someone this device accepts a
    /// clear from — the caller's business: our own action, or a sealed message from the pinned
    /// owner or one of our own devices, never the server's word. Purge the messages cached from
    /// before it — chat, game state, reactions, queued sends — once per clear. The time is
    /// bounded by the present (a clear cannot reach into the future), and the rows the core
    /// itself wrote about membership and security stay.
    pub(crate) fn apply_channel_clear(&self, channel_id: &str, cleared_at: i64) {
        let cleared_at = cleared_at.min(now_ms() + CLEAR_SKEW_MS);
        if cleared_at <= 0 {
            return;
        }
        let key = format!("{CLEARED_PREFIX}{channel_id}");
        if self.kv(&key).and_then(|v| v.parse::<i64>().ok()).is_some_and(|seen| seen >= cleared_at) {
            return;
        }
        self.with_cache(|cache| {
            for scope in [format!("channel:{channel_id}"), format!("aux:{channel_id}")] {
                let _ = cache.clear_scope_before(&scope, cleared_at);
            }
            // Reactions hang off messages that are gone.
            let _ = cache.kv_set(&format!("{REACTIONS_PREFIX}{channel_id}"), "{}");
            let _ = cache.kv_set(&key, &cleared_at.to_string());
        });
    }

    // ---- direct-message operations ----

    fn dm_reactions_map(&self, conversation_id: &str) -> BTreeMap<String, Vec<Reaction>> {
        self.kv(&format!("{REACTIONS_PREFIX}dm:{conversation_id}")).and_then(|j| serde_json::from_str(&j).ok()).unwrap_or_default()
    }

    /// Record (or take away) `user`'s `emoji` on a DM. One row per (user, emoji).
    fn set_dm_reaction(&self, conversation_id: &str, message_id: &str, user: &str, emoji: &str, remove: bool) {
        let mut all = self.dm_reactions_map(conversation_id);
        let rows = all.entry(message_id.to_string()).or_default();
        rows.retain(|r| !(r.user_id == user && r.emoji.as_deref() == Some(emoji)));
        if !remove && rows.len() < 200 {
            rows.push(Reaction { message_id: message_id.to_string(), user_id: user.to_string(), emoji_hash: emoji.to_string(), emoji: Some(emoji.to_string()) });
        }
        if rows.is_empty() {
            all.remove(message_id);
        }
        if let Ok(json) = serde_json::to_string(&all) {
            self.kv_put(&format!("{REACTIONS_PREFIX}dm:{conversation_id}"), &json);
        }
    }

    /// A deleted message takes its reactions with it.
    fn drop_dm_reactions(&self, conversation_id: &str, message_id: &str) {
        let mut all = self.dm_reactions_map(conversation_id);
        if all.remove(message_id).is_some() {
            if let Ok(json) = serde_json::to_string(&all) {
                self.kv_put(&format!("{REACTIONS_PREFIX}dm:{conversation_id}"), &json);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn push_dm_event(&self, kind: &str, conversation_id: &str, peer_user_id: &str, message_id: &str, from_self: bool, text: &str, created_at: i64) {
        let mut events = self.dm_events.lock().unwrap_or_else(|e| e.into_inner());
        if events.len() < 5_000 {
            events.push(DmEvent {
                kind: kind.into(),
                conversation_id: conversation_id.into(),
                peer_user_id: peer_user_id.into(),
                message_id: message_id.into(),
                from_self,
                text: text.into(),
                created_at,
                is_group: false, // filled in when the events are taken
            });
        }
    }

    /// Apply the DM operations the engine decrypted, and file the reports it received.
    ///
    /// The rule that matters: an edit or a delete changes a message only when the operation's
    /// AUTHENTICATED sender is that message's author (`Cache::revise_message`), and never
    /// creates one. A reaction is recorded under its sender's id and can only remove that
    /// sender's own.
    pub(crate) async fn apply_dm_ops(&self) {
        let (ops, reports) = {
            let mut engine = self.engine.lock().await;
            (engine.take_dm_ops(), engine.take_reports())
        };
        let me = self.me();
        for op in ops {
            let scope = dm_scope(&op.conversation_id);
            let from_self = op.author_id == SELF_AUTHOR;
            match op.kind {
                DmOpKind::Reply { text, sent_at, reply_to } => {
                    let row = CachedMessage {
                        message_id: op.message_id.clone(),
                        scope,
                        author_id: Some(op.author_id.clone()),
                        content: Some(text.clone()),
                        reply_to_id: Some(reply_to),
                        is_edited: false,
                        is_pinned: false,
                        deleted_at: None,
                        created_at: sent_at,
                        updated_at: sent_at,
                        kind: skwod_sync::cache::KIND_PLAIN,
                    };
                    if self.with_cache(|c| c.insert_message_if_absent(&row).unwrap_or(false)).unwrap_or(true) {
                        self.push_dm_event("message", &op.conversation_id, &op.peer_user_id, &op.message_id, from_self, &text, sent_at);
                    }
                }
                DmOpKind::Edit { text } => {
                    let changed = self.with_cache(|c| c.revise_message(&scope, &op.message_id, &op.author_id, me.as_deref(), Some(&text), op.received_at).unwrap_or(false));
                    if changed == Some(true) {
                        self.push_dm_event("edit", &op.conversation_id, &op.peer_user_id, &op.message_id, from_self, &text, op.received_at);
                    }
                }
                DmOpKind::Delete => {
                    let changed = self.with_cache(|c| c.revise_message(&scope, &op.message_id, &op.author_id, me.as_deref(), None, op.received_at).unwrap_or(false));
                    if changed == Some(true) {
                        self.drop_dm_reactions(&op.conversation_id, &op.message_id);
                        self.push_dm_event("delete", &op.conversation_id, &op.peer_user_id, &op.message_id, from_self, "", op.received_at);
                    }
                }
                DmOpKind::Reaction { emoji, remove } => {
                    // Only on a message this device holds in THAT conversation.
                    let known = self.with_cache(|c| c.message(&scope, &op.message_id).ok().flatten().is_some_and(|m| m.deleted_at.is_none())).unwrap_or(false);
                    let who = if from_self { me.clone() } else { Some(op.author_id.clone()) };
                    if let (true, Some(who)) = (known, who) {
                        self.set_dm_reaction(&op.conversation_id, &op.message_id, &who, &emoji, remove);
                        self.push_dm_event("reaction", &op.conversation_id, &op.peer_user_id, &op.message_id, from_self, &emoji, op.received_at);
                    }
                }
            }
        }
        if !reports.is_empty() {
            let mut kept = self.load_reports();
            for r in reports {
                if kept.iter().any(|k| !r.report_id.is_empty() && k.report_id == r.report_id && k.reporter_user_id == r.reporter_user_id) {
                    continue;
                }
                kept.push(AbuseReport {
                    report_id: r.report_id,
                    reporter_user_id: r.reporter_user_id,
                    subject_user_id: r.subject_user_id,
                    server_id: r.server_id,
                    category: r.category,
                    note: r.note,
                    excerpt: r.excerpt,
                    received_at: r.received_at,
                    channel_id: r.channel_id,
                    message_id: r.message_id,
                });
            }
            let excess = kept.len().saturating_sub(MAX_KEPT_REPORTS);
            kept.drain(..excess);
            self.save_reports(&kept);
        }
    }

    /// File our own DM in the cache (a plain message or a reply).
    pub(crate) fn store_own_dm(&self, conversation_id: &str, message_id: &str, text: &str, reply_to_id: Option<&str>, created_at: i64) {
        let row = CachedMessage {
            message_id: message_id.to_string(),
            scope: dm_scope(conversation_id),
            author_id: Some(SELF_AUTHOR.to_string()),
            content: Some(text.to_string()),
            reply_to_id: reply_to_id.map(str::to_string),
            is_edited: false,
            is_pinned: false,
            deleted_at: None,
            created_at,
            updated_at: created_at,
            kind: skwod_sync::cache::KIND_PLAIN,
        };
        self.with_cache(|c| c.insert_message_if_absent(&row));
    }

    /// Our own edit / delete / reaction, applied to this device's copy.
    pub(crate) fn apply_own_dm_edit(&self, conversation_id: &str, message_id: &str, text: Option<&str>) -> bool {
        let me = self.me();
        let changed = self.with_cache(|c| c.revise_message(&dm_scope(conversation_id), message_id, SELF_AUTHOR, me.as_deref(), text, now_ms()).unwrap_or(false)).unwrap_or(false);
        if changed && text.is_none() {
            self.drop_dm_reactions(conversation_id, message_id);
        }
        changed
    }

    pub(crate) fn apply_own_dm_reaction(&self, conversation_id: &str, message_id: &str, emoji: &str, remove: bool) {
        if let Some(me) = self.me() {
            self.set_dm_reaction(conversation_id, message_id, &me, emoji, remove);
        }
    }

    /// Is `message_id` a message of ours in this conversation (so we may edit or delete it)?
    pub(crate) fn own_dm(&self, conversation_id: &str, message_id: &str) -> bool {
        let me = self.me();
        self.with_cache(|c| {
            c.message(&dm_scope(conversation_id), message_id)
                .ok()
                .flatten()
                .is_some_and(|m| m.deleted_at.is_none() && (m.author_id.as_deref() == Some(SELF_AUTHOR) || (m.author_id.is_some() && m.author_id == me)))
        })
        .unwrap_or(false)
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl SkwodClient {
    // ---- blocks ----

    /// Bring the block list up to date from the server (a block made on another of this
    /// account's devices takes effect here) and return it. Call at launch and on reconnect.
    /// Everything read through this client is filtered by it from then on.
    pub async fn refresh_blocks(&self) -> Result<Vec<BlockInfo>, CoreError> {
        let rows = self.engine.lock().await.list_blocks().await;
        self.persist().await;
        Ok(rows?.into_iter().map(|(user_id, username)| BlockInfo { user_id, username }).collect())
    }

    /// The users this account has blocked, as this device knows it — no network. For the
    /// places the core does not read for the app: realtime `message` notifications, presence,
    /// typing, member lists.
    pub fn blocked_user_ids(&self) -> Vec<String> {
        self.blocked.lock().unwrap_or_else(|e| e.into_inner()).iter().cloned().collect()
    }

    /// Is `user_id` blocked by this account (no network)?
    pub fn is_blocked(&self, user_id: String) -> bool {
        self.blocked.lock().unwrap_or_else(|e| e.into_inner()).contains(&user_id)
    }

    // ---- reports ----

    /// Report a person, or a message of theirs, to whoever runs this skwod.
    ///
    /// `note` is what the reporter wrote; `message_text` is the reported message IF the
    /// reporter chose to include it (ask them — it reveals a message the host could not
    /// otherwise read). Both are sealed to the skwod owner's devices, end to end; the server's
    /// own report queue receives only who reported whom and the category. Throws when the
    /// report could not be filed at all; on success show a confirmation.
    pub async fn report_message(
        &self,
        category: String,
        note: Option<String>,
        message_text: Option<String>,
        subject_user_id: Option<String>,
        server_id: Option<String>,
    ) -> Result<ReportReceipt, CoreError> {
        self.report_message_at(category, note, message_text, subject_user_id, server_id, None, None).await
    }

    /// `report_message` for a CHANNEL message, also telling the owner where it is
    /// (`channel_id`, `message_id`) so the reports inbox can offer "Remove message". Both go
    /// only into the part sealed to the owner — the server's queue is told neither. Pass them
    /// together or not at all.
    #[allow(clippy::too_many_arguments)]
    pub async fn report_message_at(
        &self,
        category: String,
        note: Option<String>,
        message_text: Option<String>,
        subject_user_id: Option<String>,
        server_id: Option<String>,
        channel_id: Option<String>,
        message_id: Option<String>,
    ) -> Result<ReportReceipt, CoreError> {
        let message_ref = channel_id.as_deref().zip(message_id.as_deref()).filter(|(c, m)| !c.is_empty() && !m.is_empty() && c.len() <= 64 && m.len() <= 64);
        // Whoever runs the skwod: the instance's owner as attested under the pinned instance
        // key; failing that (an instance nobody claimed), the pinned owner of the space the
        // report is about. Never a name the server merely lists.
        let mut owner = self.instance_owner().await;
        if owner.is_none() {
            if let Some(server_id) = &server_id {
                owner = self.space_owner(server_id.clone()).await;
            }
        }
        let trim = |s: Option<String>| s.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        let excerpt = trim(message_text).map(|s| {
            let mut end = s.len().min(skwod_sync::MAX_REPORT_EXCERPT);
            while !s.is_char_boundary(end) {
                end -= 1;
            }
            s[..end].to_string()
        });
        let result = self
            .engine
            .lock()
            .await
            .report(owner.as_deref(), &category, trim(note).as_deref(), excerpt.as_deref(), subject_user_id.as_deref(), server_id.as_deref(), message_ref)
            .await;
        self.persist().await;
        let (report_id, sealed_to_owner) = result?;
        Ok(ReportReceipt { report_id, sealed_to_owner })
    }

    /// Reports sealed to this account as the skwod's owner, oldest first. Empty for everyone
    /// else. (They arrive with the mailbox: `sync_dms`.)
    pub async fn received_reports(&self) -> Vec<AbuseReport> {
        self.load_reports()
    }

    /// Remove a report from this device's list once it has been dealt with.
    pub async fn dismiss_report(&self, report_id: String, reporter_user_id: String) {
        let mut kept = self.load_reports();
        kept.retain(|r| !(r.report_id == report_id && r.reporter_user_id == reporter_user_id));
        self.save_reports(&kept);
    }

    // ---- direct messages: reply, edit, delete, react ----

    /// Send a DM as a reply to `reply_to_id` (a message of this conversation). Like `send_dm`
    /// otherwise. `peer_user_ids`: the other person — or, for a group, the people in it.
    pub async fn reply_dm(&self, conversation_id: String, peer_user_ids: Vec<String>, text: String, reply_to_id: String) -> Result<String, CoreError> {
        let id = skwod_crypto::new_distribution_id().to_string();
        let result = self.engine.lock().await.send_dm_as(&conversation_id, &peer_user_ids, &id, &text, Some(&reply_to_id)).await;
        self.drop_unsent().await;
        self.persist().await;
        result?;
        self.store_own_dm(&conversation_id, &id, &text, Some(&reply_to_id), now_ms());
        Ok(id)
    }

    /// Edit a DM this account sent. It changes on every device of everyone in the conversation
    /// and on this account's other devices. Fails with `Invalid` for a message that is not ours.
    pub async fn edit_dm(&self, conversation_id: String, peer_user_ids: Vec<String>, message_id: String, text: String) -> Result<(), CoreError> {
        if !self.own_dm(&conversation_id, &message_id) {
            return Err(CoreError::Invalid { detail: "You can only edit your own messages.".into() });
        }
        let result = self.engine.lock().await.edit_dm(&conversation_id, &peer_user_ids, &message_id, &text).await;
        self.persist().await;
        result?;
        self.apply_own_dm_edit(&conversation_id, &message_id, Some(&text));
        Ok(())
    }

    /// Delete a DM this account sent, for everyone.
    pub async fn delete_dm(&self, conversation_id: String, peer_user_ids: Vec<String>, message_id: String) -> Result<(), CoreError> {
        if !self.own_dm(&conversation_id, &message_id) {
            return Err(CoreError::Invalid { detail: "You can only delete your own messages.".into() });
        }
        let result = self.engine.lock().await.delete_dm(&conversation_id, &peer_user_ids, &message_id).await;
        self.persist().await;
        result?;
        self.apply_own_dm_edit(&conversation_id, &message_id, None);
        Ok(())
    }

    /// React to a DM with `emoji`, or (`remove`) take that reaction off.
    pub async fn react_dm(&self, conversation_id: String, peer_user_ids: Vec<String>, message_id: String, emoji: String, remove: bool) -> Result<(), CoreError> {
        let result = self.engine.lock().await.react_dm(&conversation_id, &peer_user_ids, &message_id, &emoji, remove).await;
        self.persist().await;
        result?;
        self.apply_own_dm_reaction(&conversation_id, &message_id, &emoji, remove);
        Ok(())
    }

    /// Every reaction in a DM conversation, from this device's cache (`emoji` is always set;
    /// `user_id` is the reactor's real id, also for this account).
    pub async fn dm_reactions(&self, conversation_id: String) -> Vec<MessageReaction> {
        let blocked = self.blocked.lock().unwrap_or_else(|e| e.into_inner()).clone();
        self.dm_reactions_map(&conversation_id)
            .into_values()
            .flatten()
            .filter(|r| !blocked.contains(&r.user_id))
            .map(|r| MessageReaction { message_id: r.message_id, user_id: r.user_id, emoji_hash: r.emoji_hash, emoji: r.emoji })
            .collect()
    }

    // ---- group direct messages ----

    /// Start a group chat with 2–9 other people (3–10 with this account). Every message is
    /// sealed separately to every device of every member — no shared group key.
    pub async fn open_group_dm(&self, member_user_ids: Vec<String>) -> Result<String, CoreError> {
        Ok(self.engine.lock().await.open_group_dm(&member_user_ids).await?)
    }

    /// The group conversations this account is in, as the server lists them.
    pub async fn list_group_dms(&self) -> Result<Vec<GroupDm>, CoreError> {
        let rows = self.engine.lock().await.list_group_dms().await?;
        Ok(rows.into_iter().map(|(conversation_id, member_user_ids)| GroupDm { conversation_id, member_user_ids }).collect())
    }

    /// Send to a group conversation (or to one person: `send_dm` with an explicit recipient
    /// list). Returns the message id.
    pub async fn send_group_dm(&self, conversation_id: String, member_user_ids: Vec<String>, text: String) -> Result<String, CoreError> {
        let id = skwod_crypto::new_distribution_id().to_string();
        let result = self.engine.lock().await.send_dm_as(&conversation_id, &member_user_ids, &id, &text, None).await;
        self.drop_unsent().await;
        self.persist().await;
        result?;
        self.store_own_dm(&conversation_id, &id, &text, None, now_ms());
        Ok(id)
    }

    // ---- channel clear ----

    /// The realtime `channel_cleared` event arrived for `channel_id`. The event is the
    /// SERVER's, so by itself it deletes nothing (build 45): it is only a hint that a sealed
    /// "I cleared this channel" from the owner may be waiting, so the mailbox is read now. If
    /// one is there, this device's cache of the channel is emptied up to the time it names;
    /// if not, nothing changes. `cleared_at` is ignored and kept for source compatibility.
    pub async fn channel_cleared(&self, channel_id: String, cleared_at: Option<i64>) {
        let _ = (channel_id, cleared_at);
        let _ = self.engine.lock().await.sync_inbox().await;
        self.store_inbound_dms().await;
        self.persist().await;
    }

    // ---- stories ----

    /// The server's current time (ms) as this device estimates it. Compare `created_at` values
    /// against THIS, not the device clock.
    pub async fn server_now_ms(&self) -> i64 {
        self.server_now()
    }

    /// End the stories of `channel_id` that are older than `ttl_ms`. A story is a message whose
    /// body starts with `story_tag`; its age is the SERVER's `created_at` against the server's
    /// clock — never a time the sender wrote into it. Other people's expired stories are
    /// removed from this device's cache; this account's own are deleted for everyone (queued,
    /// so it also works offline). Returns how many ended. Call when the feed opens and on a
    /// slow timer.
    pub async fn expire_stories(&self, channel_id: String, story_tag: String, ttl_ms: i64) -> u32 {
        if story_tag.is_empty() || ttl_ms <= 0 {
            return 0;
        }
        let scope = format!("channel:{channel_id}");
        let cutoff = self.server_now() - ttl_ms;
        let me = self.me();
        let rows = self.with_cache(|c| c.messages(&scope, cutoff + 1, 5_000).unwrap_or_default()).unwrap_or_default();
        let mut ended = 0;
        for m in rows {
            if m.deleted_at.is_some() || !m.content.as_deref().is_some_and(|c| c.starts_with(&story_tag)) {
                continue;
            }
            ended += 1;
            let mine = m.author_id.as_deref() == Some(SELF_AUTHOR) || (m.author_id.is_some() && m.author_id == me);
            if mine {
                // Tombstone it on the server (and its media with it); other members' devices
                // drop it on their next sync even if their own clocks disagree.
                let _ = self.queue_channel_delete(channel_id.clone(), m.message_id).await;
            } else {
                self.with_cache(|c| c.remove_message(&scope, &m.message_id));
            }
        }
        if ended > 0 {
            let _ = self.flush_outbox().await;
        }
        ended
    }

    /// One cached message (`None` when this device does not hold it).
    pub async fn cached_message(&self, scope: String, message_id: String) -> Option<Message> {
        self.with_cache(|c| c.message(&scope, &message_id).ok().flatten()).flatten().map(Message::from)
    }
}
