-- Build 45 security audit, second pass.

-- Instance-level bans (audit H-2). When the instance owner deletes an account AND bans it,
-- what could identify the same person coming back is remembered here — and nothing else is
-- (no address is ever stored): the username, and the identity keys of the devices the account
-- had. A signup under a banned name and a device registration with a banned identity key are
-- refused. The invite the account signed up with is revoked at the same time (`auth.rs`).
-- `kind` is 'username' or 'identity_key'.
CREATE TABLE instance_bans (
  kind TEXT NOT NULL,
  value BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (kind, value)
);
