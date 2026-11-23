-- Build 44a: accounts, devices and recovery.

-- A session knows which device it speaks for: set when that session registers the device,
-- restores it (rekey), or proves it with the device's identity key (`devices/:id/bind`).
-- Removing a device ends the sessions bound to it; a bound session may only act as its device.
ALTER TABLE sessions ADD COLUMN device_id TEXT;
CREATE INDEX idx_sessions_device ON sessions(user_id, device_id);

-- Bumped every time a device is re-keyed (a key-backup restore). An install that still holds
-- the previous generation is a superseded copy of the device: it is refused with 409 and stops,
-- instead of living on as a clone that shares the identity key.
ALTER TABLE user_devices ADD COLUMN generation INTEGER NOT NULL DEFAULT 0;

-- What the approving device hands the new one with its approval: its sibling set, the account
-- key (device names), space keys and owner pins — sealed under a key derived from the link code,
-- which the server never sees. Opaque here.
ALTER TABLE device_link_requests ADD COLUMN approval_bundle BLOB;

-- The generation of its device a session was bound at, recorded by the SERVER (never taken from
-- the client afterwards). A session whose recorded generation is not the device's current one
-- belongs to a superseded install and is refused on every device-scoped request.
ALTER TABLE sessions ADD COLUMN device_generation INTEGER;

-- SHA-256 of a secret only the CURRENT install of the device holds (set at register / rekey).
-- Binding a session needs the secret, so an install that merely shares the identity key — the
-- one a restore was made from — cannot bind at the new generation.
ALTER TABLE user_devices ADD COLUMN install_hash BLOB;

-- Devices that existed BEFORE install secrets. Only these may be used by a session that is not
-- bound yet (a client that predates binding), and only until the first current-protocol request
-- binds them — which records the install secret and clears the flag. A row created from now on
-- always has an install secret and is never flagged.
ALTER TABLE user_devices ADD COLUMN legacy_unbound INTEGER NOT NULL DEFAULT 0;
UPDATE user_devices SET legacy_unbound = 1;

-- A re-key asked for by an install that does not hold the device's current install secret: a
-- key-backup restore (or someone with a copy of the identity key). It waits here until another
-- current device approves it, the registration PIN is given, or the hold runs out — and every
-- current device of the account is told and can cancel it meanwhile. `install_hash` is
-- SHA-256 of the recovering install's secret: completing the recovery takes the SECRET, so
-- knowing (or guessing) the hash completes nothing.
CREATE TABLE device_recoveries (
  user_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL,
  install_hash BLOB NOT NULL,
  requested_at INTEGER NOT NULL,
  approved_by TEXT,
  -- Names THIS request to the devices that approve or refuse it (they sign it). Random, issued
  -- by the server; the install hash above is never handed out.
  nonce TEXT NOT NULL,
  PRIMARY KEY (user_id, device_id)
);

-- Sessions that existed BEFORE this migration. A legacy_unbound device row may be bound (once)
-- only by one of these: the install that was already signed in as that account when binding
-- arrived. A sign-in made afterwards cannot claim a legacy row; it goes through recovery.
ALTER TABLE sessions ADD COLUMN pre_migration INTEGER NOT NULL DEFAULT 0;
UPDATE sessions SET pre_migration = 1;

-- Recovery keys of an account, as an APPEND-ONLY history that neither a new backup nor
-- deleting the backup can erase — in two tables, so that WHETHER A KEY IS VALID is one fact in
-- one place:
--
--   backup_keys   one row per recovery key ever set: its verifier (the PUBLIC half of a key the
--                 client derives from the backup key, which only the recovery key unwraps), when
--                 it was set, and when and why it left force.
--   backup_blobs  the backup contents sealed under a key — every version, never rewritten.
--
-- A proof of the recovery key is judged ONLY by its `backup_keys` row. A blob has no validity of
-- its own: it is served to a restore only while its key is valid. So retiring a key retires
-- every version of the backup under it at once, and nothing about a blob can keep a key alive.
--
-- A key grants an IMMEDIATE restore while
--   set_at + hold <= now                                  (seasoned), and
--   retired_at IS NULL, or retired_at > now with retire_reason = 'replaced'   (in force / overlap).
-- `retire_reason` (see the rules in keydir.rs):
--   'replaced'    another key (or none) took its place by a backup write or delete. If it was
--                 seasoned it keeps restoring for one more hold period (the OVERLAP), once;
--                 if not, it is retired on the spot (retired_at = the moment it was replaced).
--   'consumed'    it was used for that one overlap restore. Over.
--   'cancelled'   a newer, unseasoned key that an overlap restore with the older key voided.
--   'compromised' the key may be known to someone else (a device was removed, an erased device
--                 was reported lost, the user said so). EVERY key still in force or in overlap
--                 is retired at that moment. Never served, never accepted, never brought back.
-- A key that has left force is never touched again.
CREATE TABLE backup_keys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  verifier BLOB NOT NULL,
  set_at INTEGER NOT NULL,
  replaced_at INTEGER,
  retired_at INTEGER,
  retire_reason TEXT
);
CREATE INDEX idx_backup_keys_user ON backup_keys(user_id, set_at);

CREATE TABLE backup_blobs (
  id TEXT PRIMARY KEY,
  key_id TEXT NOT NULL REFERENCES backup_keys(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  encrypted_blob BLOB NOT NULL,
  salt BLOB NOT NULL,
  version INTEGER NOT NULL,
  kdf_params TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX idx_backup_blobs_key ON backup_blobs(key_id, created_at);

-- Nonces for recovery-key proofs: issued to ONE session, answerable only by it, short-lived,
-- and consumed only by a valid signature — so nobody can burn the owner's challenge.
CREATE TABLE backup_auth_nonces (
  nonce TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  session_hash BLOB NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX idx_backup_auth_nonces_session ON backup_auth_nonces(session_hash, created_at);

-- Why a device left the account, by IDENTITY KEY (the row itself is gone): `self_erased` (it
-- unregistered itself — "Erase this device") or `removed` (another device of the account
-- removed it — lost, stolen, no longer trusted). A `removed` identity is never registered
-- again on this account except through a link approval by a current device: not by a reset,
-- not by a recovery-key restore. `removed` is permanent and is not downgraded.
CREATE TABLE device_tombstones (
  user_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  identity_key BLOB NOT NULL,
  device_id TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, identity_key)
);
