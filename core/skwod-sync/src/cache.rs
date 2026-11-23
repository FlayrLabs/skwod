//! Encrypted local cache — the on-device store behind every native client.
//!
//! The whole SQLite file is SQLCipher-encrypted under a 32-byte key held by the platform key
//! store (Secure Enclave / StrongBox gated). Inside it, message CONTENT is stored decrypted —
//! that's the point of a local cache — so the database key is the only thing standing between
//! a stolen device image and the plaintext. Never write cache contents elsewhere.
//!
//! Tables: kv (engine state), profiles, servers, channels, conversations, messages,
//! outbox (optimistic sends awaiting server ack), sessions (serialized ratchet / sender-key
//! state, opaque blobs owned by the engine).

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("wrong cache key or corrupt database")]
    BadKey,
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

/// v1: `messages.message_id` was a global primary key. v2: the key is `(scope, message_id)`, so an
/// id chosen by one conversation's sender can never address a row of another conversation.
const SCHEMA_VERSION: i64 = 2;

/// Rebuild a v1 `messages` table under the `(scope, message_id)` key. Every v1 row is kept (ids
/// were globally unique there, so no two rows can collide under the wider key).
const MIGRATE_MESSAGES_V2: &str = "
BEGIN;
CREATE TABLE messages_v2 (
  message_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  author_id TEXT,
  content TEXT,
  reply_to_id TEXT,
  is_edited INTEGER NOT NULL DEFAULT 0,
  is_pinned INTEGER NOT NULL DEFAULT 0,
  deleted_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (scope, message_id)
);
INSERT INTO messages_v2 (message_id, scope, author_id, content, reply_to_id, is_edited, is_pinned, deleted_at, created_at, updated_at)
  SELECT message_id, scope, author_id, content, reply_to_id, is_edited, is_pinned, deleted_at, created_at, updated_at FROM messages;
DROP TABLE messages;
ALTER TABLE messages_v2 RENAME TO messages;
COMMIT;
";

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS kv (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS profiles (
  user_id TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  display_name TEXT,
  status TEXT,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS servers (
  server_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  owner_id TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS channels (
  channel_id TEXT PRIMARY KEY,
  server_id TEXT NOT NULL,
  name TEXT NOT NULL,
  kind TEXT NOT NULL,
  position INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS conversations (
  conversation_id TEXT PRIMARY KEY,
  is_group INTEGER NOT NULL,
  name TEXT,
  participants TEXT NOT NULL,     -- JSON array of user ids
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
  message_id TEXT NOT NULL,
  scope TEXT NOT NULL,            -- 'channel:<id>' or 'dm:<id>'
  author_id TEXT,
  content TEXT,                   -- decrypted plaintext (NULL for tombstones)
  reply_to_id TEXT,
  is_edited INTEGER NOT NULL DEFAULT 0,
  is_pinned INTEGER NOT NULL DEFAULT 0,
  deleted_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  kind INTEGER NOT NULL DEFAULT 0, -- 0 = a message; 1 / 2 = a row the CORE wrote (see KIND_*)
  PRIMARY KEY (scope, message_id)
);
CREATE INDEX IF NOT EXISTS idx_messages_scope ON messages(scope, created_at);
CREATE TABLE IF NOT EXISTS outbox (
  local_id TEXT PRIMARY KEY,
  scope TEXT NOT NULL,
  content TEXT NOT NULL,
  reply_to_id TEXT,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sent (
  key TEXT PRIMARY KEY,           -- engine-defined: 'dm:<id>' / 'ch:<channel>:<id>' / 'env:<hash>'
  value BLOB NOT NULL,            -- what was sent, to send it again (pruned after ~30 days)
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sent_created ON sent(created_at);
CREATE TABLE IF NOT EXISTS sessions (
  session_id TEXT PRIMARY KEY,    -- engine-defined, e.g. 'dr:<user>:<device>' / 'sk:<scope>:<sender>'
  state BLOB NOT NULL,            -- serialized ratchet/sender-key state (engine-owned format)
  updated_at INTEGER NOT NULL
);
";

/// A cached (already decrypted) message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedMessage {
    pub message_id: String,
    pub scope: String,
    pub author_id: Option<String>,
    pub content: Option<String>,
    pub reply_to_id: Option<String>,
    pub is_edited: bool,
    pub is_pinned: bool,
    pub deleted_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
    /// What wrote this row ([`KIND_PLAIN`] for every message). Read back from the cache; on
    /// the way in it is honoured only by [`Cache::insert_core_row`] — every other writer
    /// stores a plain message whatever this says.
    pub kind: u8,
}

/// A message: something a person (this account or a peer) sent.
pub const KIND_PLAIN: u8 = 0;
/// A security / membership notice the core wrote into the conversation.
pub const KIND_SYSTEM: u8 = 1;
/// The core's stand-in for a message this device could not decrypt.
pub const KIND_UNDECRYPTABLE: u8 = 2;

/// Body prefixes only the core may write. What a row IS is its `kind` column, never its text —
/// but the apps of builds ≤ 43 told a system row by this text, and nothing a peer sends should
/// even look like one: a message body that starts with one of these is stored with its leading
/// control character removed, so it reads as the plain text it is.
const RESERVED_PREFIXES: [&str; 2] = [crate::SYSTEM_TAG, crate::UNDECRYPTABLE_TAG];

/// `text` as a MESSAGE may carry it: unchanged, unless it starts with a prefix reserved for
/// rows the core writes — then without the control character that makes it one.
pub fn neutralize_reserved(text: &str) -> &str {
    if RESERVED_PREFIXES.iter().any(|p| text.starts_with(p)) {
        &text[1..]
    } else {
        text
    }
}

/// An optimistic send waiting for the server's ack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxItem {
    pub local_id: String,
    pub scope: String,
    pub content: String,
    pub reply_to_id: Option<String>,
    pub created_at: i64,
}

pub struct Cache {
    conn: Connection,
}

impl Cache {
    /// Open (creating if needed) the encrypted cache at `path` under `key`.
    /// A wrong key surfaces as [`CacheError::BadKey`], not garbage reads.
    pub fn open(path: &Path, key: &[u8; 32]) -> Result<Self, CacheError> {
        let conn = Connection::open(path)?;
        // Keying must happen before any other statement touches the file.
        conn.pragma_update(None, "key", format!("x'{}'", hex::encode(key)))?;
        // Probe: with the wrong key this fails ("file is not a database").
        let probe: Result<i64, _> = conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0));
        if probe.is_err() {
            return Err(CacheError::BadKey);
        }
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        let has_messages: bool =
            conn.query_row("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'messages'", [], |r| r.get::<_, i64>(0))? > 0;
        if has_messages && version < 2 {
            if let Err(e) = conn.execute_batch(MIGRATE_MESSAGES_V2) {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(e.into());
            }
        }
        conn.execute_batch(SCHEMA)?;
        // Additive columns are added where missing rather than by schema version, so two
        // builds that each add one do not have to agree on a number.
        let has_sent_at: bool = conn.query_row("SELECT count(*) FROM pragma_table_info('messages') WHERE name = 'sent_at'", [], |r| r.get::<_, i64>(0))? > 0;
        if !has_sent_at {
            // When the SENDER says a direct message was sent (`created_at` is when it arrived).
            conn.execute_batch("ALTER TABLE messages ADD COLUMN sent_at INTEGER")?;
        }
        let has_kind: bool = conn.query_row("SELECT count(*) FROM pragma_table_info('messages') WHERE name = 'kind'", [], |r| r.get::<_, i64>(0))? > 0;
        if !has_kind {
            // What wrote the row. Until now a system row was told by its author and text; the
            // ones already here (written by the core of an earlier build, which never filed a
            // peer's message under the reserved author) are marked once.
            conn.execute_batch("ALTER TABLE messages ADD COLUMN kind INTEGER NOT NULL DEFAULT 0")?;
            conn.execute(
                "UPDATE messages SET kind = ?1 WHERE author_id = ?2 AND substr(content, 1, length(?3)) = ?3",
                params![KIND_SYSTEM as i64, crate::SYSTEM_AUTHOR, crate::SYSTEM_TAG],
            )?;
        }
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        Ok(Self { conn })
    }

    // ---- kv ----

    pub fn kv_set(&self, key: &str, value: &str) -> Result<(), CacheError> {
        self.conn.execute(
            "INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn kv_get(&self, key: &str) -> Result<Option<String>, CacheError> {
        Ok(self.conn.query_row("SELECT value FROM kv WHERE key = ?", params![key], |r| r.get(0)).optional()?)
    }

    /// Tests only: make every kv read and write FAIL (the table is gone), as a damaged file would.
    #[doc(hidden)]
    pub fn break_kv_for_test(&self) {
        self.conn.execute_batch("DROP TABLE kv").expect("drop kv");
    }

    /// Tests only: make this file look like one written before rows had a `kind`.
    #[doc(hidden)]
    pub fn downgrade_for_test(&self) {
        self.conn.execute_batch("ALTER TABLE messages DROP COLUMN kind").expect("drop column");
    }

    // ---- messages ----

    /// Insert a message, or update the row with the same id **in the same scope by the same
    /// author**. A row is addressed by `(scope, message_id)`; an existing row is only modified when
    /// the incoming author is the stored author, so nobody can rewrite someone else's message by
    /// reusing its id. Returns whether a row was inserted or updated.
    pub fn upsert_message(&self, m: &CachedMessage) -> Result<bool, CacheError> {
        self.upsert_message_as(m, None)
    }

    /// [`Self::upsert_message`] where `self_user` is this account's user id: this account's own
    /// messages are stored under either that id (a sibling device's send, or a server tombstone) or
    /// the [`crate::SELF_AUTHOR`] sentinel (this device's send), and the two count as one author.
    ///
    /// Always a plain MESSAGE: a reserved body prefix is neutralized, the reserved system author
    /// is refused, and a row this replaces (a placeholder its author sent again) becomes a
    /// plain message too.
    pub fn upsert_message_as(&self, m: &CachedMessage, self_user: Option<&str>) -> Result<bool, CacheError> {
        if m.author_id.as_deref() == Some(crate::SYSTEM_AUTHOR) {
            return Ok(false);
        }
        let me = self_user.unwrap_or(crate::SELF_AUTHOR);
        let changed = self.conn.execute(
            "INSERT INTO messages (message_id, scope, author_id, content, reply_to_id, is_edited, is_pinned, deleted_at, created_at, updated_at, kind)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 0)
             ON CONFLICT (scope, message_id) DO UPDATE SET content = excluded.content, is_edited = excluded.is_edited,
                 is_pinned = excluded.is_pinned, deleted_at = excluded.deleted_at, updated_at = excluded.updated_at,
                 reply_to_id = COALESCE(messages.reply_to_id, excluded.reply_to_id), kind = 0
             WHERE messages.author_id IS excluded.author_id
                OR (messages.author_id IN (?11, ?12) AND excluded.author_id IN (?11, ?12))",
            params![
                m.message_id,
                m.scope,
                m.author_id,
                m.content.as_deref().map(neutralize_reserved),
                m.reply_to_id,
                m.is_edited as i64,
                m.is_pinned as i64,
                m.deleted_at,
                m.created_at,
                m.updated_at,
                crate::SELF_AUTHOR,
                me
            ],
        )?;
        Ok(changed > 0)
    }

    /// Insert a message only if `(scope, message_id)` is not already present; an existing row is
    /// never touched. Used for direct messages, whose ids are chosen by the sender and which have
    /// no edit path. Returns whether the row was inserted. Always a plain MESSAGE (see
    /// [`Self::upsert_message_as`]).
    pub fn insert_message_if_absent(&self, m: &CachedMessage) -> Result<bool, CacheError> {
        if m.author_id.as_deref() == Some(crate::SYSTEM_AUTHOR) {
            return Ok(false);
        }
        self.insert_row(m, KIND_PLAIN, m.content.as_deref().map(neutralize_reserved))
    }

    /// Insert a row the CORE itself made — a system notice ([`KIND_SYSTEM`]) or the stand-in
    /// for a message that could not be decrypted ([`KIND_UNDECRYPTABLE`]) — unless
    /// `(scope, message_id)` exists already (an existing row, of any kind, is never touched).
    /// This and [`Self::set_core_content`] are the only writers of a non-plain row: nothing a
    /// peer sends reaches them.
    pub fn insert_core_row(&self, m: &CachedMessage) -> Result<bool, CacheError> {
        if m.kind == KIND_PLAIN {
            return self.insert_message_if_absent(m);
        }
        self.insert_row(m, m.kind, m.content.as_deref())
    }

    fn insert_row(&self, m: &CachedMessage, kind: u8, content: Option<&str>) -> Result<bool, CacheError> {
        let changed = self.conn.execute(
            "INSERT OR IGNORE INTO messages (message_id, scope, author_id, content, reply_to_id, is_edited, is_pinned, deleted_at, created_at, updated_at, kind)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                m.message_id,
                m.scope,
                m.author_id,
                content,
                m.reply_to_id,
                m.is_edited as i64,
                m.is_pinned as i64,
                m.deleted_at,
                m.created_at,
                m.updated_at,
                kind as i64
            ],
        )?;
        Ok(changed > 0)
    }

    /// One message, if cached.
    pub fn message(&self, scope: &str, message_id: &str) -> Result<Option<CachedMessage>, CacheError> {
        Ok(self
            .conn
            .query_row(
                "SELECT message_id, scope, author_id, content, reply_to_id, is_edited, is_pinned, deleted_at, created_at, updated_at, kind
                 FROM messages WHERE scope = ? AND message_id = ?",
                params![scope, message_id],
                |r| {
                    Ok(CachedMessage {
                        message_id: r.get(0)?,
                        scope: r.get(1)?,
                        author_id: r.get(2)?,
                        content: r.get(3)?,
                        reply_to_id: r.get(4)?,
                        is_edited: r.get::<_, i64>(5)? == 1,
                        is_pinned: r.get::<_, i64>(6)? == 1,
                        deleted_at: r.get(7)?,
                        created_at: r.get(8)?,
                        updated_at: r.get(9)?,
                        kind: r.get::<_, i64>(10)? as u8,
                    })
                },
            )
            .optional()?)
    }

    /// Remove one message (a placeholder that was answered; a send that did not go out).
    /// Tombstone an EXISTING message (never a row the core wrote, never inserting one): its
    /// content goes and it is marked deleted at `at`. With `author` it applies only to a row by
    /// that author (`self_user` as in [`Self::upsert_message_as`]); without, to whoever wrote
    /// it. Returns whether a row changed.
    pub fn tombstone_message(&self, scope: &str, message_id: &str, author: Option<&str>, self_user: Option<&str>, at: i64) -> Result<bool, CacheError> {
        let me = self_user.unwrap_or(crate::SELF_AUTHOR);
        let changed = match author {
            None => self.conn.execute(
                "UPDATE messages SET content = NULL, deleted_at = ?3, updated_at = ?3 WHERE scope = ?1 AND message_id = ?2 AND kind = 0 AND deleted_at IS NULL",
                params![scope, message_id, at],
            )?,
            Some(author) => self.conn.execute(
                "UPDATE messages SET content = NULL, deleted_at = ?3, updated_at = ?3 WHERE scope = ?1 AND message_id = ?2 AND kind = 0 AND deleted_at IS NULL
                 AND (author_id IS ?4 OR (author_id IN (?5, ?6) AND ?4 IN (?5, ?6)))",
                params![scope, message_id, at, author, crate::SELF_AUTHOR, me],
            )?,
        };
        Ok(changed > 0)
    }

    pub fn delete_message(&self, scope: &str, message_id: &str) -> Result<(), CacheError> {
        self.conn.execute("DELETE FROM messages WHERE scope = ? AND message_id = ?", params![scope, message_id])?;
        Ok(())
    }

    /// Replace the content of an existing row, whoever its author is recorded as. For rows this
    /// device wrote itself (a placeholder's wording); never for content that came off the wire.
    pub fn set_content(&self, scope: &str, message_id: &str, content: &str) -> Result<(), CacheError> {
        self.conn.execute(
            "UPDATE messages SET content = ? WHERE scope = ? AND message_id = ? AND kind = 0",
            params![neutralize_reserved(content), scope, message_id],
        )?;
        Ok(())
    }

    /// New content for a row the core made (`kind` is not plain) — and only for such a row.
    pub fn set_core_content(&self, scope: &str, message_id: &str, kind: u8, content: &str) -> Result<(), CacheError> {
        self.conn.execute(
            "UPDATE messages SET content = ? WHERE scope = ? AND message_id = ? AND kind = ? AND kind != 0",
            params![content, scope, message_id, kind as i64],
        )?;
        Ok(())
    }

    /// When the sender says a message was sent (direct messages; `created_at` is the arrival).
    pub fn set_sent_at(&self, scope: &str, message_id: &str, sent_at: i64) -> Result<(), CacheError> {
        self.conn.execute("UPDATE messages SET sent_at = ? WHERE scope = ? AND message_id = ?", params![sent_at, scope, message_id])?;
        Ok(())
    }

    pub fn sent_at(&self, scope: &str, message_id: &str) -> Option<i64> {
        self.conn.query_row("SELECT sent_at FROM messages WHERE scope = ? AND message_id = ?", params![scope, message_id], |r| r.get(0)).ok().flatten()
    }

    /// Write the engine state and (if there is one) an outgoing message in ONE transaction:
    /// the ratchet that sealed a message is never on disk without the message, nor the message
    /// without the ratchet.
    pub fn persist_send(&self, session_id: &str, state: &[u8], row: Option<&CachedMessage>) -> Result<(), CacheError> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| {
            self.session_put(session_id, state, 0)?;
            if let Some(m) = row {
                self.insert_message_if_absent(m)?;
            }
            Ok::<_, CacheError>(())
        })();
        match result {
            Ok(()) => Ok(self.conn.execute_batch("COMMIT")?),
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    // ---- sent store (what the engine can send again) ----

    pub fn sent_put(&self, key: &str, value: &[u8], at_ms: i64) -> Result<(), CacheError> {
        self.conn.execute(
            "INSERT INTO sent (key, value, created_at) VALUES (?, ?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value, created_at = excluded.created_at",
            params![key, value, at_ms],
        )?;
        Ok(())
    }

    pub fn sent_get(&self, key: &str) -> Result<Option<Vec<u8>>, CacheError> {
        Ok(self.conn.query_row("SELECT value FROM sent WHERE key = ?", params![key], |r| r.get(0)).optional()?)
    }

    pub fn sent_prune(&self, before_ms: i64) -> Result<(), CacheError> {
        self.conn.execute("DELETE FROM sent WHERE created_at < ?", params![before_ms])?;
        Ok(())
    }

    /// Newest-first page of messages in a scope, strictly older than `before` (ms).
    pub fn messages(&self, scope: &str, before: i64, limit: usize) -> Result<Vec<CachedMessage>, CacheError> {
        let mut stmt = self.conn.prepare(
            "SELECT message_id, scope, author_id, content, reply_to_id, is_edited, is_pinned, deleted_at, created_at, updated_at, kind
             FROM messages WHERE scope = ? AND created_at < ?
             ORDER BY created_at DESC, message_id DESC LIMIT ?",
        )?;
        let rows = stmt.query_map(params![scope, before, limit as i64], |r| {
            Ok(CachedMessage {
                message_id: r.get(0)?,
                scope: r.get(1)?,
                author_id: r.get(2)?,
                content: r.get(3)?,
                reply_to_id: r.get(4)?,
                is_edited: r.get::<_, i64>(5)? == 1,
                is_pinned: r.get::<_, i64>(6)? == 1,
                deleted_at: r.get(7)?,
                created_at: r.get(8)?,
                updated_at: r.get(9)?,
                kind: r.get::<_, i64>(10)? as u8,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Newest message timestamp in a scope (backfill cursor); 0 when empty.
    pub fn latest_message_ts(&self, scope: &str) -> Result<i64, CacheError> {
        Ok(self
            .conn
            .query_row("SELECT COALESCE(MAX(created_at), 0) FROM messages WHERE scope = ?", params![scope], |r| {
                r.get(0)
            })?)
    }

    // ---- outbox (optimistic writes) ----

    pub fn outbox_enqueue(&self, item: &OutboxItem) -> Result<(), CacheError> {
        self.conn.execute(
            "INSERT INTO outbox (local_id, scope, content, reply_to_id, created_at) VALUES (?, ?, ?, ?, ?)",
            params![item.local_id, item.scope, item.content, item.reply_to_id, item.created_at],
        )?;
        Ok(())
    }

    pub fn outbox_pending(&self) -> Result<Vec<OutboxItem>, CacheError> {
        let mut stmt = self
            .conn
            .prepare("SELECT local_id, scope, content, reply_to_id, created_at FROM outbox ORDER BY created_at")?;
        let rows = stmt.query_map([], |r| {
            Ok(OutboxItem {
                local_id: r.get(0)?,
                scope: r.get(1)?,
                content: r.get(2)?,
                reply_to_id: r.get(3)?,
                created_at: r.get(4)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Replace a queued item's content (its state, attempts, last error), keeping its place.
    pub fn outbox_update(&self, local_id: &str, content: &str) -> Result<(), CacheError> {
        self.conn.execute("UPDATE outbox SET content = ? WHERE local_id = ?", params![content, local_id])?;
        Ok(())
    }

    /// File a message under the SERVER's time for it (own sends are first cached under the
    /// local clock, which no other member's ordering shares).
    pub fn set_message_time(&self, scope: &str, message_id: &str, created_at: i64) -> Result<(), CacheError> {
        self.conn.execute("UPDATE messages SET created_at = ?, updated_at = MAX(updated_at, ?) WHERE scope = ? AND message_id = ?", params![created_at, created_at, scope, message_id])?;
        Ok(())
    }

    /// Change the text of an EXISTING message (or tombstone it, `content = None`) — only when
    /// `author` wrote it. Never inserts: an edit of a message this device does not hold, or of
    /// someone else's, changes nothing. `self_user` as in [`Self::upsert_message_as`]. Returns
    /// whether a row changed.
    pub fn revise_message(&self, scope: &str, message_id: &str, author: &str, self_user: Option<&str>, content: Option<&str>, at: i64) -> Result<bool, CacheError> {
        let me = self_user.unwrap_or(crate::SELF_AUTHOR);
        let changed = self.conn.execute(
            "UPDATE messages SET content = ?1, is_edited = CASE WHEN ?1 IS NULL THEN is_edited ELSE 1 END,
                    deleted_at = CASE WHEN ?1 IS NULL THEN ?2 ELSE deleted_at END, updated_at = ?2
             WHERE scope = ?3 AND message_id = ?4 AND deleted_at IS NULL
               AND kind = 0
               AND (author_id IS ?5 OR (author_id IN (?6, ?7) AND ?5 IN (?6, ?7)))",
            params![content.map(neutralize_reserved), at, scope, message_id, author, crate::SELF_AUTHOR, me],
        )?;
        Ok(changed > 0)
    }

    /// Swap the text of a message that has not been delivered yet (a queued send whose
    /// attachment placeholders were just resolved, or that was reworded while waiting). Not an
    /// edit: nobody has seen another version.
    pub fn replace_message_text(&self, scope: &str, message_id: &str, content: &str) -> Result<(), CacheError> {
        self.conn.execute(
            "UPDATE messages SET content = ? WHERE scope = ? AND message_id = ? AND deleted_at IS NULL AND kind = 0",
            params![neutralize_reserved(content), scope, message_id],
        )?;
        Ok(())
    }

    /// Remove one message outright (an expired story: nothing is left to show as "removed").
    pub fn remove_message(&self, scope: &str, message_id: &str) -> Result<(), CacheError> {
        self.conn.execute("DELETE FROM messages WHERE scope = ? AND message_id = ?", params![scope, message_id])?;
        Ok(())
    }

    /// Drop every cached message of `scope` written at or before `cutoff` — the channel was
    /// cleared then. Messages (and queued sends) from after the clear stay.
    ///
    /// Rows the CORE wrote about membership and security (system rows) are never part of a
    /// clear: whoever may clear a channel's messages may not thereby erase the record of who
    /// was let in or whose keys changed.
    pub fn clear_scope_before(&self, scope: &str, cutoff: i64) -> Result<usize, CacheError> {
        let n = self.conn.execute("DELETE FROM messages WHERE scope = ? AND created_at <= ? AND kind != ?", params![scope, cutoff, KIND_SYSTEM as i64])?;
        self.conn.execute("DELETE FROM outbox WHERE scope = ? AND created_at <= ?", params![scope, cutoff])?;
        Ok(n)
    }

    /// Ack: the server accepted the send — drop it from the outbox.
    pub fn outbox_remove(&self, local_id: &str) -> Result<(), CacheError> {
        self.conn.execute("DELETE FROM outbox WHERE local_id = ?", params![local_id])?;
        Ok(())
    }

    /// Drop every cached message and any queued outbox item for a scope ('channel:<id>' / 'dm:<id>').
    /// Used after a server-side "clear channel/server" so the local view empties at once, not just on
    /// the next sync.
    pub fn clear_scope(&self, scope: &str) -> Result<(), CacheError> {
        self.conn.execute("DELETE FROM messages WHERE scope = ?", params![scope])?;
        self.conn.execute("DELETE FROM outbox WHERE scope = ?", params![scope])?;
        Ok(())
    }

    // ---- structure ----

    pub fn upsert_server(&self, server_id: &str, name: &str, owner_id: &str, updated_at: i64) -> Result<(), CacheError> {
        self.conn.execute(
            "INSERT INTO servers (server_id, name, owner_id, updated_at) VALUES (?, ?, ?, ?)
             ON CONFLICT (server_id) DO UPDATE SET name = excluded.name, owner_id = excluded.owner_id, updated_at = excluded.updated_at",
            params![server_id, name, owner_id, updated_at],
        )?;
        Ok(())
    }

    pub fn upsert_channel(
        &self,
        channel_id: &str,
        server_id: &str,
        name: &str,
        kind: &str,
        position: i64,
        updated_at: i64,
    ) -> Result<(), CacheError> {
        self.conn.execute(
            "INSERT INTO channels (channel_id, server_id, name, kind, position, updated_at) VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT (channel_id) DO UPDATE SET name = excluded.name, kind = excluded.kind,
                 position = excluded.position, updated_at = excluded.updated_at",
            params![channel_id, server_id, name, kind, position, updated_at],
        )?;
        Ok(())
    }

    /// (channel_id, name, kind, position) for a server, in display order.
    pub fn channels(&self, server_id: &str) -> Result<Vec<(String, String, String, i64)>, CacheError> {
        let mut stmt = self.conn.prepare(
            "SELECT channel_id, name, kind, position FROM channels WHERE server_id = ? ORDER BY position, channel_id",
        )?;
        let rows = stmt.query_map(params![server_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    // ---- sessions (opaque engine-owned state) ----

    pub fn session_put(&self, session_id: &str, state: &[u8], updated_at: i64) -> Result<(), CacheError> {
        self.conn.execute(
            "INSERT INTO sessions (session_id, state, updated_at) VALUES (?, ?, ?)
             ON CONFLICT (session_id) DO UPDATE SET state = excluded.state, updated_at = excluded.updated_at",
            params![session_id, state, updated_at],
        )?;
        Ok(())
    }

    pub fn session_get(&self, session_id: &str) -> Result<Option<Vec<u8>>, CacheError> {
        Ok(self
            .conn
            .query_row("SELECT state FROM sessions WHERE session_id = ?", params![session_id], |r| r.get(0))
            .optional()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn msg(id: &str, scope: &str, ts: i64) -> CachedMessage {
        CachedMessage {
            message_id: id.to_string(),
            scope: scope.to_string(),
            author_id: Some("alice".to_string()),
            content: Some(format!("content-{id}")),
            reply_to_id: None,
            is_edited: false,
            is_pinned: false,
            deleted_at: None,
            created_at: ts,
            updated_at: ts,
            kind: KIND_PLAIN,
        }
    }

    /// Engine M1: a clear removes messages from before it and nothing else — not what came
    /// after, and never the rows the core wrote about membership and security. A deletion
    /// tombstones an existing message of the author who asked (or anyone's, for the owner),
    /// never a core row, and never creates a row.
    #[test]
    fn clears_spare_system_rows_and_deletions_need_the_author() {
        let dir = tempfile::tempdir().unwrap();
        let c = Cache::open(&dir.path().join("cache.db"), &key(3)).unwrap();
        c.upsert_message(&msg("old", "channel:c", 100)).unwrap();
        c.upsert_message(&msg("new", "channel:c", 300)).unwrap();
        let notice = CachedMessage { author_id: Some(crate::SYSTEM_AUTHOR.to_string()), kind: KIND_SYSTEM, ..msg("sys:joined", "channel:c", 50) };
        assert!(c.insert_core_row(&notice).unwrap());
        assert_eq!(c.clear_scope_before("channel:c", 200).unwrap(), 1);
        let left: Vec<String> = c.messages("channel:c", i64::MAX, 10).unwrap().into_iter().map(|m| m.message_id).collect();
        assert!(left.contains(&"new".to_string()) && left.contains(&"sys:joined".to_string()) && !left.contains(&"old".to_string()), "{left:?}");

        // Someone who is not the author cannot delete alice's message; alice can; the owner can.
        assert!(!c.tombstone_message("channel:c", "new", Some("mallory"), Some("me"), 400).unwrap());
        assert_eq!(c.message("channel:c", "new").unwrap().unwrap().content.as_deref(), Some("content-new"));
        assert!(c.tombstone_message("channel:c", "new", Some("alice"), Some("me"), 400).unwrap());
        let gone = c.message("channel:c", "new").unwrap().unwrap();
        assert!(gone.content.is_none() && gone.deleted_at == Some(400));
        c.upsert_message(&msg("other", "channel:c", 500)).unwrap();
        assert!(c.tombstone_message("channel:c", "other", None, Some("me"), 600).unwrap(), "the owner's deletion");
        // Our own message, stored under the self sentinel, deleted from another of our devices.
        c.upsert_message(&CachedMessage { author_id: Some(crate::SELF_AUTHOR.to_string()), ..msg("mine", "channel:c", 700) }).unwrap();
        assert!(c.tombstone_message("channel:c", "mine", Some(crate::SELF_AUTHOR), Some("me"), 800).unwrap());
        // Never a core row, and never a row that is not there.
        assert!(!c.tombstone_message("channel:c", "sys:joined", None, Some("me"), 900).unwrap());
        assert!(!c.tombstone_message("channel:c", "never-seen", None, Some("me"), 900).unwrap());
        assert!(c.message("channel:c", "never-seen").unwrap().is_none());
    }

    #[test]
    fn roundtrip_and_persistence_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        {
            let c = Cache::open(&path, &key(7)).unwrap();
            c.kv_set("device_id", "dev-1").unwrap();
            c.upsert_message(&msg("m1", "channel:c1", 100)).unwrap();
            c.upsert_message(&msg("m2", "channel:c1", 200)).unwrap();
            c.upsert_server("s1", "My Server", "alice", 1).unwrap();
            c.upsert_channel("c1", "s1", "general", "text", 0, 1).unwrap();
            c.session_put("dr:bob:dev1", b"opaque-ratchet-state", 1).unwrap();
        }
        let c = Cache::open(&path, &key(7)).unwrap();
        assert_eq!(c.kv_get("device_id").unwrap().as_deref(), Some("dev-1"));
        let msgs = c.messages("channel:c1", i64::MAX, 10).unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].message_id, "m2", "newest first");
        assert_eq!(c.latest_message_ts("channel:c1").unwrap(), 200);
        assert_eq!(c.channels("s1").unwrap()[0].1, "general");
        assert_eq!(c.session_get("dr:bob:dev1").unwrap().as_deref(), Some(&b"opaque-ratchet-state"[..]));
    }

    #[test]
    fn a_send_is_persisted_whole_or_not_at_all_and_the_sent_store_prunes() {
        let dir = tempfile::tempdir().unwrap();
        let c = Cache::open(&dir.path().join("cache.db"), &key(8)).unwrap();
        c.persist_send("engine-state", b"ratchet-1", Some(&msg("m1", "dm:x", 10))).unwrap();
        assert_eq!(c.session_get("engine-state").unwrap().as_deref(), Some(&b"ratchet-1"[..]));
        assert_eq!(c.message("dm:x", "m1").unwrap().unwrap().content.as_deref(), Some("content-m1"));
        c.set_sent_at("dm:x", "m1", 7).unwrap();
        assert_eq!(c.sent_at("dm:x", "m1"), Some(7));
        c.delete_message("dm:x", "m1").unwrap();
        assert!(c.message("dm:x", "m1").unwrap().is_none());

        c.sent_put("dm:old", b"old", 100).unwrap();
        c.sent_put("dm:new", b"new", 900).unwrap();
        c.sent_prune(500).unwrap();
        assert_eq!((c.sent_get("dm:old").unwrap(), c.sent_get("dm:new").unwrap().as_deref()), (None, Some(&b"new"[..])));
    }

    #[test]
    fn wrong_key_is_rejected_not_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        Cache::open(&path, &key(1)).unwrap().kv_set("secret", "value").unwrap();
        match Cache::open(&path, &key(2)) {
            Err(CacheError::BadKey) => {}
            Err(other) => panic!("expected BadKey, got {other:?}"),
            Ok(_) => panic!("wrong key must not open the cache"),
        }
        // Original key still works.
        assert_eq!(Cache::open(&path, &key(1)).unwrap().kv_get("secret").unwrap().as_deref(), Some("value"));
    }

    #[test]
    fn file_on_disk_is_not_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        let c = Cache::open(&path, &key(9)).unwrap();
        c.upsert_message(&msg("m1", "dm:x", 1)).unwrap();
        drop(c);
        let raw = std::fs::read(&path).unwrap();
        assert!(!raw.windows(10).any(|w| w == b"content-m1"), "plaintext leaked to disk");
        assert!(!raw.starts_with(b"SQLite format 3"), "file is not encrypted");
    }

    #[test]
    fn outbox_lifecycle_and_message_pagination() {
        let dir = tempfile::tempdir().unwrap();
        let c = Cache::open(&dir.path().join("cache.db"), &key(3)).unwrap();
        c.outbox_enqueue(&OutboxItem {
            local_id: "l1".into(),
            scope: "channel:c1".into(),
            content: "optimistic".into(),
            reply_to_id: None,
            created_at: 5,
        })
        .unwrap();
        assert_eq!(c.outbox_pending().unwrap().len(), 1);
        c.outbox_remove("l1").unwrap();
        assert!(c.outbox_pending().unwrap().is_empty());

        for i in 0..10 {
            c.upsert_message(&msg(&format!("m{i}"), "channel:c1", i)).unwrap();
        }
        let page1 = c.messages("channel:c1", i64::MAX, 4).unwrap();
        assert_eq!(page1.len(), 4);
        assert_eq!(page1[0].message_id, "m9");
        let page2 = c.messages("channel:c1", page1.last().unwrap().created_at, 4).unwrap();
        assert_eq!(page2[0].message_id, "m5");
        // Edit propagates via upsert.
        let mut edited = msg("m9", "channel:c1", 9);
        edited.content = Some("edited".into());
        edited.is_edited = true;
        c.upsert_message(&edited).unwrap();
        let top = &c.messages("channel:c1", i64::MAX, 1).unwrap()[0];
        assert_eq!(top.content.as_deref(), Some("edited"));
        assert!(top.is_edited);
    }

    fn by(id: &str, scope: &str, author: &str, text: &str) -> CachedMessage {
        CachedMessage { author_id: Some(author.into()), content: Some(text.into()), ..msg(id, scope, 1) }
    }

    fn content(c: &Cache, scope: &str, id: &str) -> Option<String> {
        c.messages(scope, i64::MAX, 100).unwrap().into_iter().find(|m| m.message_id == id).and_then(|m| m.content)
    }

    /// H2: a DM peer picks the id of a message cached in ANOTHER scope (or by another author) and
    /// sends a `Chat` with it. Before the fix `message_id` was a global key and the upsert
    /// overwrote the victim row's content.
    #[test]
    fn reused_message_id_cannot_rewrite_another_scope_or_author() {
        let dir = tempfile::tempdir().unwrap();
        let c = Cache::open(&dir.path().join("cache.db"), &key(4)).unwrap();
        c.upsert_message(&by("m1", "channel:general", "alice", "the real announcement")).unwrap();
        c.upsert_message(&by("d1", "dm:alice-me", "alice", "alice's real dm")).unwrap();

        // Mallory (a DM peer) reuses the channel message's id in her own DM with us.
        assert!(c.insert_message_if_absent(&by("m1", "dm:mallory-me", "mallory", "forged")).unwrap());
        assert_eq!(content(&c, "channel:general", "m1").as_deref(), Some("the real announcement"));
        assert_eq!(content(&c, "dm:mallory-me", "m1").as_deref(), Some("forged"), "it lands in her own scope only");

        // Same scope, same id, different author (two members of a channel): no overwrite.
        assert!(!c.upsert_message(&by("m1", "channel:general", "mallory", "forged")).unwrap());
        assert_eq!(content(&c, "channel:general", "m1").as_deref(), Some("the real announcement"));

        // A DM is never updated in place, even by its own author replaying the id.
        assert!(!c.insert_message_if_absent(&by("d1", "dm:alice-me", "alice", "rewritten")).unwrap());
        assert_eq!(content(&c, "dm:alice-me", "d1").as_deref(), Some("alice's real dm"));

        // The author's own edit still applies.
        assert!(c.upsert_message(&by("m1", "channel:general", "alice", "edited by alice")).unwrap());
        assert_eq!(content(&c, "channel:general", "m1").as_deref(), Some("edited by alice"));
    }

    /// This account's messages are stored as `__me__` (this device) or its user id (a sibling
    /// device / a server tombstone); the two are one author.
    #[test]
    fn own_messages_match_under_either_author_form() {
        let dir = tempfile::tempdir().unwrap();
        let c = Cache::open(&dir.path().join("cache.db"), &key(5)).unwrap();
        c.upsert_message(&by("m1", "channel:c", crate::SELF_AUTHOR, "mine")).unwrap();
        let mut tomb = by("m1", "channel:c", "my-user", "");
        tomb.content = None;
        tomb.deleted_at = Some(9);
        assert!(!c.upsert_message(&tomb).unwrap(), "without knowing who we are, a different author is refused");
        assert!(c.upsert_message_as(&tomb, Some("my-user")).unwrap());
        assert!(c.messages("channel:c", i64::MAX, 1).unwrap()[0].deleted_at.is_some());
        assert!(!c.upsert_message_as(&by("m1", "channel:c", "someone-else", "x"), Some("my-user")).unwrap());
    }

    /// A build-42 cache (global `message_id` key, user_version 1) is rebuilt in place with every row
    /// intact, and the wider key then applies.
    #[test]
    fn v1_cache_migrates_to_scoped_message_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.pragma_update(None, "key", format!("x'{}'", hex::encode(key(6)))).unwrap();
            conn.execute_batch(
                "CREATE TABLE messages (
                   message_id TEXT PRIMARY KEY, scope TEXT NOT NULL, author_id TEXT, content TEXT, reply_to_id TEXT,
                   is_edited INTEGER NOT NULL DEFAULT 0, is_pinned INTEGER NOT NULL DEFAULT 0, deleted_at INTEGER,
                   created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
                 CREATE INDEX idx_messages_scope ON messages(scope, created_at);
                 INSERT INTO messages VALUES ('m1','channel:c','alice','one','r0',1,0,NULL,10,11);
                 INSERT INTO messages VALUES ('m2','dm:d','bob',NULL,NULL,0,0,20,20,20);
                 PRAGMA user_version = 1;",
            )
            .unwrap();
        }
        for _ in 0..2 {
            // Twice: the migration must not run (or fail) again on the next launch.
            let c = Cache::open(&path, &key(6)).unwrap();
            let m1 = &c.messages("channel:c", i64::MAX, 10).unwrap()[0];
            assert_eq!((m1.content.as_deref(), m1.reply_to_id.as_deref(), m1.is_edited, m1.updated_at), (Some("one"), Some("r0"), true, 11));
            assert_eq!(c.messages("dm:d", i64::MAX, 10).unwrap()[0].deleted_at, Some(20));
        }
        let c = Cache::open(&path, &key(6)).unwrap();
        assert!(c.insert_message_if_absent(&by("m1", "dm:other", "mallory", "forged")).unwrap());
        assert_eq!(content(&c, "channel:c", "m1").as_deref(), Some("one"));
    }
}
