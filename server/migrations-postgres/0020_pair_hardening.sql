-- Build 48 security review of "Add a device" by QR (see docs/SECURITY.md).
--
-- `device_pair_offers.consumed`: set once the offer has been approved, denied, contested or used
-- to register a device. No new request is ever opened for a consumed offer (a deleted row used to
-- let a later request for the same offer start afresh).
-- `device_pair_requests.nonce`: the existing device's commit-then-reveal nonce, released to the
-- new device only after the server holds its identity key and the existing device has seen it.
-- `device_pair_requests.registered`: the claimed session registered this key (the row is kept,
-- marked, instead of deleted).
-- `device_pair_requests.session_hash`: the session the claim issued, revoked if the request is
-- contested or expires before that session registers a device.
ALTER TABLE device_pair_offers ADD COLUMN consumed BIGINT NOT NULL DEFAULT 0;
ALTER TABLE device_pair_requests ADD COLUMN nonce BYTEA;
ALTER TABLE device_pair_requests ADD COLUMN registered BIGINT NOT NULL DEFAULT 0;
ALTER TABLE device_pair_requests ADD COLUMN session_hash BYTEA;
