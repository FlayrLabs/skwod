-- Signed member approvals (docs/DECISIONS.md ADR-012, interim for a member-signed membership log).
-- When an owner/admin's device admits a user to a server it signs "user U is a member of server S
-- as of ts" with its identity key. Clients hand channel / space / voice keys to a user they have
-- not seen in that server before only after verifying such a signature from someone they already
-- trust there. The server only stores and relays the records: it cannot forge one, and dropping
-- one merely keeps the newcomer held.
CREATE TABLE member_approvals (
  server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  approver_user_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  approver_device_id TEXT NOT NULL,
  ts BIGINT NOT NULL,                  -- signed timestamp (unix ms), chosen by the approver
  signature BYTEA NOT NULL,             -- XEdDSA by the approver device's identity key
  created_at BIGINT NOT NULL,
  PRIMARY KEY (server_id, user_id, approver_user_id)
);
