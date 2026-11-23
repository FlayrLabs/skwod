-- Build 45 security audit.

-- Which invite an account signed up with. A signup uses the invite up (`join.rs`): at most
-- `max_uses` accounts per invite, and only a few of them may sit unadmitted at once.
CREATE TABLE invite_signups (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  invite_id TEXT NOT NULL REFERENCES invites(id) ON DELETE CASCADE,
  created_at BIGINT NOT NULL
);
CREATE INDEX idx_invite_signups_invite ON invite_signups(invite_id);
-- How many accounts the invite has created. Claimed with one conditional UPDATE, which also
-- serialises concurrent signups on the same invite (row lock on Postgres, the writer lock on
-- SQLite) while the unadmitted ones are counted. (No backfill: `invite_signups` starts empty.)
ALTER TABLE invites ADD COLUMN signup_count BIGINT NOT NULL DEFAULT 0;

-- Capability-bound wakes (docs/PUSH.md): the device registers with the push gateway itself and
-- hands this server only the opaque, revocable credential it got back. A row has EITHER a
-- credential (and empty token columns) or, from a build <= 45, the raw tokens.
ALTER TABLE push_registrations ADD COLUMN wake_credential TEXT;

-- Per-account stored-bytes accounting sums ciphertext lengths by author.
CREATE INDEX idx_dm_messages_author ON dm_messages(author_id);
