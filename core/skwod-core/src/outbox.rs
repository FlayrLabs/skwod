//! The outbox: nothing a person sends is lost because the network was not there.
//!
//! Every user-initiated write — a chat line, a feed post, a story, a comment, a game move, a
//! forward (all of them channel messages), an edit, a delete, a reaction, and their DM
//! counterparts — can be QUEUED instead of sent. Queueing is local and instant: the operation
//! is written to the encrypted cache, an own message appears in history at once, and
//! `flush_outbox` delivers the queue whenever it can (call it after queueing, on reconnect, at
//! launch and on a slow timer).
//!
//! **Exactly once.** A message's id is chosen here, before the first attempt, and is the same
//! on every retry. For a channel message the server files an author's id once and answers a
//! repeat with the original's answer (`messages.rs`, `resent`); for a DM the receiving device
//! files an id once (`insert_message_if_absent`). So "the request went out but the answer was
//! lost" — the case an outbox exists for — is retried without a duplicate.
//!
//! **Order.** Operations of one conversation are delivered in the order they were queued: while
//! one is waiting for the network, the ones behind it in the same conversation wait too. One
//! that FAILED for good (refused by the server, too large, …) steps aside — it is shown as
//! failed with the reason and the user retries or discards it — and does not hold the rest up.
//!
//! **States.** `sending` (queued or being retried) and `failed` (needs the user). A delivered
//! operation simply leaves the queue.

use skwod_sync::cache::OutboxItem;
use skwod_sync::{ClientError, EngineError, SELF_AUTHOR};

use crate::{now_ms, CoreError, SkwodClient};

const MAX_QUEUED: usize = 2_000;
/// Non-network errors get this many tries before the operation is marked failed (a sender key
/// that has not arrived yet, a device list mid-change).
const SOFT_TRIES: u32 = 3;
const MAX_BACKOFF_MS: i64 = 5 * 60 * 1000;

/// A queued operation, for the UI.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PendingSend {
    /// The queue entry (pass to `retry_send` / `discard_send`).
    pub local_id: String,
    /// `channel:<id>` or `dm:<id>`.
    pub scope: String,
    /// The message this operation sends or changes — match it against history rows.
    pub message_id: String,
    /// `send`, `edit`, `delete` or `reaction`.
    pub kind: String,
    /// `sending` or `failed`.
    pub state: String,
    /// For `failed`: a sentence to show.
    pub error: Option<String>,
    pub attempts: u32,
    pub created_at: i64,
}

/// What a flush did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, uniffi::Record)]
pub struct OutboxReport {
    /// Delivered by this flush.
    pub sent: u32,
    /// Still waiting (no network, or behind something that is).
    pub pending: u32,
    /// Need the user (`retry_send` / `discard_send`).
    pub failed: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Op {
    ChannelSend { text: String, reply_to_id: Option<String>, blob_ids: Vec<String>, uploads: Vec<String> },
    ChannelEdit { text: String },
    ChannelDelete,
    ChannelReaction { emoji: String, remove: bool },
    DmSend { peers: Vec<String>, text: String, reply_to_id: Option<String>, uploads: Vec<String> },
    DmEdit { peers: Vec<String>, text: String },
    DmDelete { peers: Vec<String> },
    DmReaction { peers: Vec<String>, emoji: String, remove: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    pub local_id: String,
    /// `channel:<id>` / `dm:<id>`.
    pub scope: String,
    pub message_id: String,
    pub op: Op,
    pub failed: bool,
    pub attempts: u32,
    pub error: Option<String>,
    /// Not before this time (ms).
    pub next_at: i64,
    pub created_at: i64,
}

fn strings(v: &serde_json::Value) -> Vec<String> {
    v.as_array().into_iter().flatten().filter_map(|s| s.as_str().map(str::to_string)).collect()
}

impl Entry {
    fn kind(&self) -> &'static str {
        match self.op {
            Op::ChannelSend { .. } | Op::DmSend { .. } => "send",
            Op::ChannelEdit { .. } | Op::DmEdit { .. } => "edit",
            Op::ChannelDelete | Op::DmDelete { .. } => "delete",
            Op::ChannelReaction { .. } | Op::DmReaction { .. } => "reaction",
        }
    }

    fn target(&self) -> &str {
        self.scope.split_once(':').map(|(_, id)| id).unwrap_or_default()
    }

    fn to_item(&self) -> OutboxItem {
        let (kind, mut body) = match &self.op {
            Op::ChannelSend { text, reply_to_id, blob_ids, uploads } => {
                ("channel_send", serde_json::json!({ "text": text, "reply_to_id": reply_to_id, "blob_ids": blob_ids, "uploads": uploads }))
            }
            Op::ChannelEdit { text } => ("channel_edit", serde_json::json!({ "text": text })),
            Op::ChannelDelete => ("channel_delete", serde_json::json!({})),
            Op::ChannelReaction { emoji, remove } => ("channel_reaction", serde_json::json!({ "emoji": emoji, "remove": remove })),
            Op::DmSend { peers, text, reply_to_id, uploads } => ("dm_send", serde_json::json!({ "peers": peers, "text": text, "reply_to_id": reply_to_id, "uploads": uploads })),
            Op::DmEdit { peers, text } => ("dm_edit", serde_json::json!({ "peers": peers, "text": text })),
            Op::DmDelete { peers } => ("dm_delete", serde_json::json!({ "peers": peers })),
            Op::DmReaction { peers, emoji, remove } => ("dm_reaction", serde_json::json!({ "peers": peers, "emoji": emoji, "remove": remove })),
        };
        body["kind"] = kind.into();
        body["message_id"] = self.message_id.clone().into();
        body["failed"] = self.failed.into();
        body["attempts"] = self.attempts.into();
        body["error"] = self.error.clone().into();
        body["next_at"] = self.next_at.into();
        OutboxItem { local_id: self.local_id.clone(), scope: self.scope.clone(), content: body.to_string(), reply_to_id: None, created_at: self.created_at }
    }

    fn from_item(item: &OutboxItem) -> Option<Entry> {
        let v: serde_json::Value = serde_json::from_str(&item.content).ok()?;
        let s = |k: &str| v[k].as_str().map(str::to_string);
        let text = || s("text").unwrap_or_default();
        let peers = || strings(&v["peers"]);
        let emoji = || s("emoji").unwrap_or_default();
        let remove = v["remove"].as_bool().unwrap_or(false);
        let op = match v["kind"].as_str()? {
            "channel_send" => Op::ChannelSend { text: text(), reply_to_id: s("reply_to_id"), blob_ids: strings(&v["blob_ids"]), uploads: strings(&v["uploads"]) },
            "channel_edit" => Op::ChannelEdit { text: text() },
            "channel_delete" => Op::ChannelDelete,
            "channel_reaction" => Op::ChannelReaction { emoji: emoji(), remove },
            "dm_send" => Op::DmSend { peers: peers(), text: text(), reply_to_id: s("reply_to_id"), uploads: strings(&v["uploads"]) },
            "dm_edit" => Op::DmEdit { peers: peers(), text: text() },
            "dm_delete" => Op::DmDelete { peers: peers() },
            "dm_reaction" => Op::DmReaction { peers: peers(), emoji: emoji(), remove },
            _ => return None,
        };
        Some(Entry {
            local_id: item.local_id.clone(),
            scope: item.scope.clone(),
            message_id: s("message_id")?,
            op,
            failed: v["failed"].as_bool().unwrap_or(false),
            attempts: v["attempts"].as_u64().unwrap_or(0) as u32,
            error: s("error"),
            next_at: v["next_at"].as_i64().unwrap_or(0),
            created_at: item.created_at,
        })
    }
}

/// What a failed attempt means for the entry.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// The network or the server was not there: keep trying, however long it takes.
    Wait,
    /// Might pass on another try (keys in flight); becomes `Fatal` after [`SOFT_TRIES`].
    Soft(String),
    /// It will not go through as it is: show the sentence, let the user decide.
    Fatal(String),
    /// The thing is already as asked (deleting what is gone): done.
    Done,
}

fn server_sentence(body: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(body).ok().and_then(|v| v["error"].as_str().map(str::to_string)).filter(|s| !s.is_empty())
}

pub(crate) fn judge(kind: &str, e: &EngineError) -> Verdict {
    match e {
        EngineError::Client(ClientError::Transport(_)) => Verdict::Wait,
        EngineError::Client(ClientError::Status { status, body }) => match *status {
            // Not signed in right now, rate-limited, or the server is having a moment.
            // The host's disk is full: that will not clear by retrying in a minute.
            413 | 507 => Verdict::Fatal(server_sentence(body).unwrap_or_else(|| "That is too big to send.".into())),
            401 | 408 | 425 | 429 | 500..=599 => Verdict::Wait,
            404 if kind == "delete" => Verdict::Done,
            404 => Verdict::Fatal("That message or conversation no longer exists.".into()),
            403 => Verdict::Fatal(server_sentence(body).filter(|s| s.contains(' ')).unwrap_or_else(|| "You are not allowed to do that here.".into())),
            409 => Verdict::Fatal("That message could not be sent (its id is taken). Discard it and send it again.".into()),
            _ => Verdict::Fatal(server_sentence(body).unwrap_or_else(|| format!("The server refused it ({status})."))),
        },
        EngineError::Client(ClientError::Shape) => Verdict::Soft("The server answered in a way this app did not understand.".into()),
        EngineError::TooLarge(s) => Verdict::Fatal((*s).to_string()),
        EngineError::UpdateRequired(s) => Verdict::Fatal(s.clone()),
        EngineError::IdentityChanged(_) => Verdict::Fatal("Their safety number changed. Check it, then send again.".into()),
        other => Verdict::Soft(format!("Couldn't send: {other}")),
    }
}

fn backoff_ms(attempts: u32) -> i64 {
    (2_000i64 << attempts.min(8)).min(MAX_BACKOFF_MS)
}

impl SkwodClient {
    pub(crate) fn outbox_all(&self) -> Vec<Entry> {
        self.with_cache(|c| c.outbox_pending().unwrap_or_default()).unwrap_or_default().iter().filter_map(Entry::from_item).collect()
    }

    fn outbox_save(&self, e: &Entry) {
        let item = e.to_item();
        self.with_cache(|c| c.outbox_update(&item.local_id, &item.content));
    }

    fn outbox_drop(&self, local_id: &str) {
        self.with_cache(|c| c.outbox_remove(local_id));
    }

    fn enqueue(&self, scope: String, message_id: String, op: Op) -> Result<Entry, CoreError> {
        let entry = Entry {
            local_id: skwod_crypto::new_distribution_id().to_string(),
            scope,
            message_id,
            op,
            failed: false,
            attempts: 0,
            error: None,
            next_at: 0,
            created_at: next_queued_ms(),
        };
        let stored = self.with_cache(|c| {
            if c.outbox_pending().map(|p| p.len()).unwrap_or(0) >= MAX_QUEUED {
                return Err(CoreError::Invalid { detail: "Too many messages are waiting to be sent. Connect to the internet and try again.".into() });
            }
            c.outbox_enqueue(&entry.to_item()).map_err(CoreError::from)
        });
        match stored {
            Some(Ok(())) => Ok(entry),
            Some(Err(e)) => Err(e),
            // A queue that is not on disk is not a queue.
            None => Err(CoreError::Invalid { detail: "Sending is not ready yet. Try again in a moment.".into() }),
        }
    }

    fn message_scope(channel_id: &str, text: &str) -> String {
        if skwod_sync::Traffic::of(text).hidden {
            format!("aux:{channel_id}")
        } else {
            format!("channel:{channel_id}")
        }
    }

    /// Run one entry. `Ok(())` = delivered.
    async fn deliver(&self, e: &Entry) -> Result<(), EngineError> {
        let target = e.target().to_string();
        match &e.op {
            Op::ChannelSend { text, reply_to_id, blob_ids, uploads } => {
                // Attachments first: each resumes from wherever its upload stopped.
                let (text, mut blobs) = self.resolve_uploads(text, uploads).await?;
                blobs.extend(blob_ids.iter().cloned());
                // (The row is the outbox's own, written when the send was queued: it stays whether
                // or not this attempt succeeds, so the engine's "unsent" marker is just cleared.)
                let sent = {
                    let mut engine = self.engine.lock().await;
                    let sent = engine.send_channel_message_as(&target, &e.message_id, &text, reply_to_id.as_deref(), &blobs).await;
                    engine.take_unsent();
                    sent
                };
                let created_at = sent?;
                self.note_server_time(created_at);
                let scope = Self::message_scope(&target, &text);
                self.with_cache(|c| {
                    if !uploads.is_empty() {
                        // The row was cached with upload placeholders; it now names real blobs.
                        let _ = c.replace_message_text(&scope, &e.message_id, &text);
                    }
                    let _ = c.set_message_time(&scope, &e.message_id, created_at);
                });
                self.forget_uploads(uploads);
                Ok(())
            }
            Op::ChannelEdit { text } => {
                let reply_to = self.with_cache(|c| c.message(&format!("channel:{target}"), &e.message_id).ok().flatten()).flatten().and_then(|m| m.reply_to_id);
                self.engine.lock().await.edit_channel_message(&target, &e.message_id, text, reply_to.as_deref()).await
            }
            Op::ChannelDelete => self.engine.lock().await.delete_channel_message(&target, &e.message_id).await,
            Op::ChannelReaction { emoji, remove } => {
                let mut engine = self.engine.lock().await;
                if *remove {
                    engine.remove_reaction(&target, &e.message_id, emoji).await
                } else {
                    engine.add_reaction(&target, &e.message_id, emoji).await
                }
            }
            Op::DmSend { peers, text, reply_to_id, uploads } => {
                let (text, _) = self.resolve_uploads(text, uploads).await?;
                let sent = {
                    let mut engine = self.engine.lock().await;
                    let sent = engine.send_dm_as(&target, peers, &e.message_id, &text, reply_to_id.as_deref()).await;
                    engine.take_unsent();
                    sent
                };
                sent?;
                if !uploads.is_empty() {
                    self.with_cache(|c| c.replace_message_text(&e.scope, &e.message_id, &text));
                }
                self.forget_uploads(uploads);
                Ok(())
            }
            Op::DmEdit { peers, text } => self.engine.lock().await.edit_dm(&target, peers, &e.message_id, text).await,
            Op::DmDelete { peers } => self.engine.lock().await.delete_dm(&target, peers, &e.message_id).await,
            Op::DmReaction { peers, emoji, remove } => self.engine.lock().await.react_dm(&target, peers, &e.message_id, emoji, *remove).await,
        }
    }

    /// Undo what queueing showed optimistically (the user discarded the operation).
    fn undo_optimistic(&self, e: &Entry) {
        match &e.op {
            Op::ChannelSend { text, uploads, .. } => {
                self.with_cache(|c| c.remove_message(&Self::message_scope(e.target(), text), &e.message_id));
                self.abandon_uploads(uploads);
            }
            Op::DmSend { uploads, .. } => {
                self.with_cache(|c| c.remove_message(&e.scope, &e.message_id));
                self.abandon_uploads(uploads);
            }
            Op::DmReaction { emoji, remove, .. } => self.apply_own_dm_reaction(e.target(), &e.message_id, emoji, !*remove),
            // An edit or delete that never went out: the next sync restores what the server
            // holds for channels; for DMs the local change stands until then.
            _ => {}
        }
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl SkwodClient {
    /// Queue a channel message — chat, a feed post, a story, a comment, a game move, a forward:
    /// whatever `text` encodes. It is in this device's history at once (as sent by `__me__`)
    /// and reaches the server when it can. Returns the message id. Follow with `flush_outbox`.
    ///
    /// `blob_ids`: attachments already uploaded. `upload_ids`: attachments prepared with
    /// `prepare_upload` and not uploaded yet — `text` refers to each by its
    /// `placeholder_blob_id`, which is replaced by the real blob id when the upload finishes.
    pub async fn queue_channel_message(
        &self,
        channel_id: String,
        text: String,
        reply_to_id: Option<String>,
        blob_ids: Vec<String>,
        upload_ids: Vec<String>,
    ) -> Result<String, CoreError> {
        if text.len() > skwod_sync::MAX_TEXT {
            return Err(CoreError::Invalid { detail: "That message is too big to send. Shorten it, or send the photo or file as an attachment.".into() });
        }
        let id = skwod_crypto::new_distribution_id().to_string();
        let entry = self.enqueue(
            format!("channel:{channel_id}"),
            id.clone(),
            Op::ChannelSend { text: text.clone(), reply_to_id: reply_to_id.clone(), blob_ids, uploads: upload_ids },
        )?;
        self.store_meta(&Self::message_scope(&channel_id, &text), &id, SELF_AUTHOR, Some(&text), entry.created_at, reply_to_id.as_deref(), false, false);
        Ok(id)
    }

    /// Queue an edit of a channel message this account wrote (shown at once).
    pub async fn queue_channel_edit(&self, channel_id: String, message_id: String, text: String) -> Result<(), CoreError> {
        if text.len() > skwod_sync::MAX_TEXT {
            return Err(CoreError::Invalid { detail: "That message is too big to send.".into() });
        }
        let scope = format!("channel:{channel_id}");
        // Still waiting to go out itself: change what will be sent instead of queueing an edit.
        if let Some(mut pending) = self.outbox_all().into_iter().find(|e| e.message_id == message_id && matches!(e.op, Op::ChannelSend { .. })) {
            if let Op::ChannelSend { text: queued, .. } = &mut pending.op {
                *queued = text.clone();
            }
            pending.failed = false;
            pending.next_at = 0;
            self.outbox_save(&pending);
            self.with_cache(|c| c.replace_message_text(&scope, &message_id, &text));
            return Ok(());
        }
        self.enqueue(scope.clone(), message_id.clone(), Op::ChannelEdit { text: text.clone() })?;
        self.store_meta(&scope, &message_id, SELF_AUTHOR, Some(&text), now_ms(), None, true, false);
        Ok(())
    }

    /// Queue the deletion of a channel message (a chat line, a post, a story, a comment) this
    /// account wrote; it is shown as removed at once.
    pub async fn queue_channel_delete(&self, channel_id: String, message_id: String) -> Result<(), CoreError> {
        let scope = format!("channel:{channel_id}");
        // Never sent: just take it back.
        let queued: Vec<Entry> = self.outbox_all().into_iter().filter(|e| e.message_id == message_id && e.scope == scope).collect();
        if let Some(send) = queued.iter().find(|e| matches!(e.op, Op::ChannelSend { .. }) && e.attempts == 0) {
            for e in &queued {
                self.outbox_drop(&e.local_id);
            }
            self.undo_optimistic(send);
            return Ok(());
        }
        self.enqueue(scope.clone(), message_id.clone(), Op::ChannelDelete)?;
        // Tombstone it where this device holds it (chat or game state).
        let aux = format!("aux:{channel_id}");
        let in_aux = self.with_cache(|c| c.message(&aux, &message_id).ok().flatten().is_some()).unwrap_or(false);
        self.store_meta(if in_aux { &aux } else { &scope }, &message_id, SELF_AUTHOR, None, now_ms(), None, false, true);
        Ok(())
    }

    /// Queue adding (or removing) this account's `emoji` reaction on a channel message.
    pub async fn queue_reaction(&self, channel_id: String, message_id: String, emoji: String, remove: bool) -> Result<(), CoreError> {
        self.enqueue(format!("channel:{channel_id}"), message_id, Op::ChannelReaction { emoji, remove })?;
        Ok(())
    }

    /// Queue a direct message (optionally a reply). `peer_user_ids`: the other person, or the
    /// members of a group. Returns the message id.
    pub async fn queue_dm(
        &self,
        conversation_id: String,
        peer_user_ids: Vec<String>,
        text: String,
        reply_to_id: Option<String>,
        upload_ids: Vec<String>,
    ) -> Result<String, CoreError> {
        if text.len() > skwod_sync::MAX_TEXT {
            return Err(CoreError::Invalid { detail: "That message is too big to send. Shorten it, or send the photo or file as an attachment.".into() });
        }
        let id = skwod_crypto::new_distribution_id().to_string();
        let entry = self.enqueue(
            format!("dm:{conversation_id}"),
            id.clone(),
            Op::DmSend { peers: peer_user_ids, text: text.clone(), reply_to_id: reply_to_id.clone(), uploads: upload_ids },
        )?;
        self.store_own_dm(&conversation_id, &id, &text, reply_to_id.as_deref(), entry.created_at);
        Ok(id)
    }

    /// Queue an edit of a DM this account sent.
    pub async fn queue_dm_edit(&self, conversation_id: String, peer_user_ids: Vec<String>, message_id: String, text: String) -> Result<(), CoreError> {
        if !self.own_dm(&conversation_id, &message_id) {
            return Err(CoreError::Invalid { detail: "You can only edit your own messages.".into() });
        }
        self.enqueue(format!("dm:{conversation_id}"), message_id.clone(), Op::DmEdit { peers: peer_user_ids, text: text.clone() })?;
        self.apply_own_dm_edit(&conversation_id, &message_id, Some(&text));
        Ok(())
    }

    /// Queue deleting, for everyone, a DM this account sent.
    pub async fn queue_dm_delete(&self, conversation_id: String, peer_user_ids: Vec<String>, message_id: String) -> Result<(), CoreError> {
        if !self.own_dm(&conversation_id, &message_id) {
            return Err(CoreError::Invalid { detail: "You can only delete your own messages.".into() });
        }
        self.enqueue(format!("dm:{conversation_id}"), message_id.clone(), Op::DmDelete { peers: peer_user_ids })?;
        self.apply_own_dm_edit(&conversation_id, &message_id, None);
        Ok(())
    }

    /// Queue a reaction on a DM (or its removal).
    pub async fn queue_dm_reaction(&self, conversation_id: String, peer_user_ids: Vec<String>, message_id: String, emoji: String, remove: bool) -> Result<(), CoreError> {
        self.enqueue(format!("dm:{conversation_id}"), message_id.clone(), Op::DmReaction { peers: peer_user_ids, emoji: emoji.clone(), remove })?;
        self.apply_own_dm_reaction(&conversation_id, &message_id, &emoji, remove);
        Ok(())
    }

    /// Deliver what is queued, oldest first, as far as the network allows. Safe to call often
    /// and from several places at once (one flush runs at a time; a second call waits for it
    /// and then finds little to do).
    pub async fn flush_outbox(&self) -> OutboxReport {
        let _gate = self.outbox_gate.lock().await;
        let mut report = OutboxReport::default();
        // Conversations with something still waiting: everything behind it waits too.
        let mut held: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut offline = false;
        for mut e in self.outbox_all() {
            if e.failed {
                report.failed += 1;
                continue;
            }
            if offline || held.contains(&e.scope) || e.next_at > now_ms() {
                held.insert(e.scope.clone());
                report.pending += 1;
                continue;
            }
            let result = self.deliver(&e).await;
            match result.as_ref().map_err(|err| judge(e.kind(), err)) {
                Ok(()) | Err(Verdict::Done) => {
                    self.outbox_drop(&e.local_id);
                    report.sent += 1;
                }
                Err(verdict) => {
                    e.attempts += 1;
                    let fatal = match verdict {
                        Verdict::Fatal(s) => Some(s),
                        Verdict::Soft(s) if e.attempts >= SOFT_TRIES => Some(s),
                        Verdict::Soft(s) => {
                            e.error = Some(s);
                            None
                        }
                        Verdict::Wait => {
                            // No point knocking again for every other entry right now.
                            offline = true;
                            None
                        }
                        Verdict::Done => None,
                    };
                    match fatal {
                        Some(sentence) => {
                            e.failed = true;
                            e.error = Some(sentence);
                            report.failed += 1;
                        }
                        None => {
                            // The network being away is not the entry's fault: retry soon.
                            e.next_at = if offline { 0 } else { now_ms() + backoff_ms(e.attempts) };
                            held.insert(e.scope.clone());
                            report.pending += 1;
                        }
                    }
                    self.outbox_save(&e);
                }
            }
        }
        self.persist().await;
        report
    }

    /// What is queued — for one scope (`channel:<id>` / `dm:<id>`) or, with `None`, everything.
    /// Overlay it on history: a row whose id has a `send` here is "Sending…" or, when `failed`,
    /// "Not sent" with `error` and Retry / Discard.
    pub async fn pending_sends(&self, scope: Option<String>) -> Vec<PendingSend> {
        self.outbox_all()
            .into_iter()
            .filter(|e| scope.as_ref().is_none_or(|s| &e.scope == s))
            .map(|e| PendingSend {
                kind: e.kind().to_string(),
                state: if e.failed { "failed" } else { "sending" }.to_string(),
                local_id: e.local_id,
                scope: e.scope,
                message_id: e.message_id,
                error: e.error,
                attempts: e.attempts,
                created_at: e.created_at,
            })
            .collect()
    }

    /// Put a failed operation back in line (then `flush_outbox`).
    pub async fn retry_send(&self, local_id: String) {
        if let Some(mut e) = self.outbox_all().into_iter().find(|e| e.local_id == local_id) {
            e.failed = false;
            e.attempts = 0;
            e.error = None;
            e.next_at = 0;
            self.outbox_save(&e);
        }
    }

    /// Give up on a queued operation. A message that was never sent disappears from history.
    pub async fn discard_send(&self, local_id: String) {
        if let Some(e) = self.outbox_all().into_iter().find(|e| e.local_id == local_id) {
            self.outbox_drop(&e.local_id);
            self.undo_optimistic(&e);
        }
    }
}


/// The time a queued item is filed under: the clock, but never the same millisecond twice, so
/// messages queued in quick succession keep the order they were written in (history sorts by
/// time, then by id — and ids are random).
fn next_queued_ms() -> i64 {
    use std::sync::atomic::{AtomicI64, Ordering};
    static LAST: AtomicI64 = AtomicI64::new(0);
    let now = now_ms();
    let mut prev = LAST.load(Ordering::Relaxed);
    loop {
        let next = now.max(prev + 1);
        match LAST.compare_exchange_weak(prev, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return next,
            Err(p) => prev = p,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(status: u16, body: &str) -> EngineError {
        EngineError::Client(ClientError::Status { status, body: body.to_string() })
    }

    #[test]
    fn entries_survive_the_trip_through_the_cache() {
        let ops = vec![
            Op::ChannelSend { text: "hi".into(), reply_to_id: Some("r".into()), blob_ids: vec!["b".into()], uploads: vec!["u".into()] },
            Op::ChannelEdit { text: "new".into() },
            Op::ChannelDelete,
            Op::ChannelReaction { emoji: "👍".into(), remove: true },
            Op::DmSend { peers: vec!["p1".into(), "p2".into()], text: "yo".into(), reply_to_id: None, uploads: vec![] },
            Op::DmEdit { peers: vec!["p".into()], text: "t".into() },
            Op::DmDelete { peers: vec!["p".into()] },
            Op::DmReaction { peers: vec!["p".into()], emoji: "❤️".into(), remove: false },
        ];
        for (i, op) in ops.into_iter().enumerate() {
            let e = Entry {
                local_id: format!("l{i}"),
                scope: "channel:c".into(),
                message_id: format!("m{i}"),
                op,
                failed: i % 2 == 0,
                attempts: i as u32,
                error: (i % 3 == 0).then(|| "why".to_string()),
                next_at: 5,
                created_at: 9,
            };
            assert_eq!(Entry::from_item(&e.to_item()), Some(e));
        }
        let junk = OutboxItem { local_id: "x".into(), scope: "channel:c".into(), content: "plain text from an older build".into(), reply_to_id: None, created_at: 1 };
        assert_eq!(Entry::from_item(&junk), None, "an entry this build cannot read is skipped, not sent as garbage");
    }

    #[test]
    fn a_missing_network_waits_and_a_refusal_fails_with_a_sentence() {
        assert_eq!(judge("send", &EngineError::Client(ClientError::Transport("connection refused".into()))), Verdict::Wait);
        for s in [401, 429, 500, 502, 503] {
            assert_eq!(judge("send", &status(s, "")), Verdict::Wait, "{s}");
        }
        assert_eq!(judge("delete", &status(404, "")), Verdict::Done, "deleting what is gone is done");
        assert!(matches!(judge("edit", &status(404, "")), Verdict::Fatal(_)));
        assert_eq!(judge("send", &status(413, r#"{"error":"you have used all of your attachment storage"}"#)), Verdict::Fatal("you have used all of your attachment storage".into()));
        assert_eq!(judge("send", &status(403, r#"{"error":"forbidden"}"#)), Verdict::Fatal("You are not allowed to do that here.".into()));
        assert!(matches!(judge("send", &EngineError::TooLarge("too big")), Verdict::Fatal(s) if s == "too big"));
        assert!(matches!(judge("send", &EngineError::IdentityChanged("u".into())), Verdict::Fatal(_)));
        assert!(matches!(judge("send", &EngineError::Protocol("no space key for server")), Verdict::Soft(_)));
        assert!(backoff_ms(0) == 2_000 && backoff_ms(3) == 16_000 && backoff_ms(30) == MAX_BACKOFF_MS);
    }
}
