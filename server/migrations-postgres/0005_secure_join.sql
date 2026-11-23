-- Secure join (security-first): two host-controlled ways in, so "anyone can't just join".
--
-- 1. Auto-approve invites — the host vouches up front, so the joiner is admitted immediately:
--      * kind='token'    : a one-time link/QR; any username may redeem it once.
--      * kind='username' : reserved for a specific username; only that name auto-joins.
-- 2. Approval-required invites — a shareable code (kind='code'). Redeeming it does NOT join;
--    it files a join request the host must approve. Lowest trust, so a human gates it.
--
-- The existing `admin_setup_code` (from `skwod init`) authorizes ACCOUNT creation (join.rs); this
-- layer authorizes SERVER/community membership.

ALTER TABLE invites ADD COLUMN kind TEXT NOT NULL DEFAULT 'code'
  CHECK (kind IN ('code', 'token', 'username'));
-- For kind='username': the reserved username this invite auto-approves.
ALTER TABLE invites ADD COLUMN reserved_username TEXT;
-- Whether redeeming this invite requires host approval. Default true for 'code', the migration
-- backfills false for token/username at creation time in code.
ALTER TABLE invites ADD COLUMN requires_approval BIGINT NOT NULL DEFAULT 1
  CHECK (requires_approval IN (0, 1));

-- Pending membership requests awaiting host approval.
CREATE TABLE join_requests (
  id TEXT PRIMARY KEY,
  server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  invite_id TEXT REFERENCES invites(id) ON DELETE SET NULL,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'approved', 'denied')),
  created_at BIGINT NOT NULL DEFAULT ((extract(epoch from now()) * 1000)::bigint),
  updated_at BIGINT NOT NULL DEFAULT ((extract(epoch from now()) * 1000)::bigint),
  UNIQUE (server_id, user_id)
);
CREATE INDEX idx_join_requests_server_status ON join_requests(server_id, status);
