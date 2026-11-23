-- User-safety tooling: bans that actually stick, user blocks, and abuse reports.
--
-- Context: `BAN_MEMBERS` (bit 16) existed in the permission mask since day one but had no
-- enforcement — kick only deleted the membership row, so a kicked user could rejoin with any
-- valid invite. These tables make moderation real without weakening E2EE: every check keys on
-- public routing metadata (user ids) only; the server still can't read any content.

-- Server-level bans. A row here means the user is barred from (re)joining the server through
-- ANY join path (invite redemption, join-request approval) until unbanned.
CREATE TABLE server_bans (
  server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  -- Who issued the ban (kept for the admin audit trail; nulled if that account is deleted).
  banned_by TEXT REFERENCES profiles(id) ON DELETE SET NULL,
  -- Optional moderator note. Plaintext by design: it is the moderator's OWN words, never content.
  reason TEXT,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (server_id, user_id)
);
CREATE INDEX idx_server_bans_user ON server_bans(user_id);

-- User-to-user blocks (self-scoped, Signal-style). Enforced server-side on DM creation and DM
-- sends between the pair — the server needs only the two user ids, no plaintext.
CREATE TABLE user_blocks (
  blocker_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  blocked_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (blocker_id, blocked_id)
);
CREATE INDEX idx_user_blocks_blocked ON user_blocks(blocked_id);

-- Abuse reports: the operator's signal on an E2EE instance (the server cannot scan content).
-- `body` is the reporter's OWN plaintext description/excerpt they chose to include when filing
-- (Signal-style user-initiated disclosure) — nothing is decrypted server-side.
CREATE TABLE abuse_reports (
  id TEXT PRIMARY KEY,
  reporter_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  subject_user_id TEXT REFERENCES profiles(id) ON DELETE SET NULL,
  server_id TEXT REFERENCES servers(id) ON DELETE SET NULL,
  category TEXT NOT NULL,
  body TEXT,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved')),
  created_at INTEGER NOT NULL
);
CREATE INDEX idx_abuse_reports_status ON abuse_reports(status, created_at);
