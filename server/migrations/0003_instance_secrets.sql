-- Instance-level secrets (server sealed-sender signing key, LiveKit creds later).
-- These are SERVER keys — never user private keys (those never reach the server).
CREATE TABLE instance_secrets (
  name TEXT PRIMARY KEY,
  value BLOB NOT NULL,
  created_at INTEGER NOT NULL
);

-- Key-transparency chain-fork detection: two appends claiming the same predecessor
-- (per user) must conflict, mirroring the original's 23505 → CHAIN_FORK behavior.
-- NULL previous_commitment (chain head) is enforced single-per-user in code.
CREATE UNIQUE INDEX idx_identity_log_chain
  ON identity_key_log(user_id, previous_commitment)
  WHERE previous_commitment IS NOT NULL;
