-- Build 48, "Add a device" by QR. Kept apart from device_link_requests on purpose: nothing in
-- the typed-code link flow can list, approve or replace one of these rows.
--
-- The device showing the QR first registers its offer (device-signed): `device_pair_offers`.
-- A new device that has NOT signed in opens one request per REGISTERED offer (`offer_id`, from
-- the QR); anything else is answered the same way and stored nowhere. A second request for the same offer marks it `contested` and nothing is approved. The
-- account's existing device approves exactly the identity key whose emoji were confirmed; the
-- new device then claims ONE session by signing with that identity key (`claimed`).
CREATE TABLE device_pair_offers (
  offer_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL,
  username TEXT NOT NULL,
  expires_at BIGINT NOT NULL,
  created_at BIGINT NOT NULL
);

CREATE TABLE device_pair_requests (
  id TEXT PRIMARY KEY,
  offer_id TEXT NOT NULL UNIQUE,
  user_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  identity_key BLOB NOT NULL,
  proof BLOB NOT NULL,
  poll_hash BLOB NOT NULL,
  contested BIGINT NOT NULL DEFAULT 0,
  approver_device_id TEXT,
  approver_identity_key BLOB,
  link_sig BLOB,
  approval_mac BLOB,
  approval_bundle BLOB,
  claimed BIGINT NOT NULL DEFAULT 0,
  denied BIGINT NOT NULL DEFAULT 0,
  created_at BIGINT NOT NULL
);
CREATE INDEX idx_device_pair_requests_user ON device_pair_requests(user_id, created_at);
