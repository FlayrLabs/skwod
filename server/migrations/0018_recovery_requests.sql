-- Audit L1: several restore requests for one device, one per requesting install, each with its
-- own hold. No filing replaces or voids another; every current device sees each one and
-- approves or cancels it individually; approving one ends the others. A request completes by
-- its hold only if it was never contested (`contested_at`: when a second request for the same
-- device was filed during its hold); a contested one needs an approval, the PIN or the
-- recovery key.
CREATE TABLE device_recoveries_new (
  user_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL,
  install_hash BLOB NOT NULL,
  requested_at INTEGER NOT NULL,
  approved_by TEXT,
  nonce TEXT NOT NULL,
  contested_at INTEGER,
  PRIMARY KEY (user_id, device_id, install_hash)
);
INSERT INTO device_recoveries_new (user_id, device_id, install_hash, requested_at, approved_by, nonce)
  SELECT user_id, device_id, install_hash, requested_at, approved_by, nonce FROM device_recoveries;
DROP TABLE device_recoveries;
ALTER TABLE device_recoveries_new RENAME TO device_recoveries;
CREATE UNIQUE INDEX device_recoveries_nonce ON device_recoveries (user_id, nonce);
-- One row per (account, device) that has had a restore request: every filing and every
-- approval first WRITES it, inside its transaction, so they are serialized per device (a row
-- lock on Postgres, the write lock on SQLite) and the cap and exclusivity checks are atomic.
CREATE TABLE device_recovery_locks (
  user_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL,
  bumped INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, device_id)
);
