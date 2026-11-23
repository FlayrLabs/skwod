-- E2EE protocol v2: Signal's libsignal (PQXDH + Double Ratchet/SPQR + Sender Keys + Sealed Sender).
--
-- Key material from protocol v1 (the in-house implementation shipped in builds 29-40) cannot be
-- converted, so every v1 device row and prekey is dropped here. Upgraded clients register a fresh
-- libsignal identity on first launch; v1 clients are refused with 426 "update required".
-- Accounts, sessions, servers, channels, memberships and stored ciphertext are untouched.

DROP TABLE one_time_prekeys;
DROP TABLE user_devices;
-- Server-side sender-key distribution rows recorded who shares which channel key with whom.
-- Distribution now travels only inside sealed-sender envelopes; the table is gone for good.
DROP TABLE sender_key_distributions;
-- Retry requests recorded "user A could not decrypt user B's message" in the clear.
DROP TABLE e2ee_retry_requests;

CREATE TABLE user_devices (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL,
  device_name_ciphertext BYTEA,
  protocol_version BIGINT NOT NULL,
  registration_id BIGINT NOT NULL,
  identity_key BYTEA NOT NULL,              -- libsignal IdentityKey (33 bytes, serialized)
  signed_prekey_id BIGINT NOT NULL,
  signed_prekey BYTEA NOT NULL,             -- libsignal EC public key
  signed_prekey_sig BYTEA NOT NULL,         -- XEdDSA(identity, signed_prekey)
  kyber_last_resort_id BIGINT NOT NULL,
  kyber_last_resort BYTEA NOT NULL,         -- Kyber-1024 public key (served when one-time keys run out)
  kyber_last_resort_sig BYTEA NOT NULL,
  -- Capability required to deposit a sealed-sender envelope for this device. Handed out only
  -- with a prekey bundle, i.e. to accounts allowed to start a session with this device.
  delivery_key BYTEA NOT NULL,
  -- Device linking: every device after an account's first must carry a signature from an existing
  -- device's identity key over its own identity key (NULL only for the first device, or after a
  -- full reset). The server refuses to register an unlinked extra device; siblings verify the
  -- signature themselves and do not rely on that refusal.
  linked_by TEXT,
  link_sig BYTEA,
  spk_timestamp BIGINT NOT NULL DEFAULT ((extract(epoch from now()) * 1000)::bigint),
  attested BIGINT NOT NULL DEFAULT 0,
  created_at BIGINT NOT NULL DEFAULT ((extract(epoch from now()) * 1000)::bigint),
  last_active_at BIGINT NOT NULL DEFAULT ((extract(epoch from now()) * 1000)::bigint),
  UNIQUE (user_id, device_id)
);
CREATE INDEX idx_user_devices_user ON user_devices(user_id);

-- One-time prekeys, EC and Kyber. Each is handed out at most once (atomic claim).
CREATE TABLE one_time_prekeys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('ec', 'kyber')),
  key_id BIGINT NOT NULL,
  public_key BYTEA NOT NULL,
  signature BYTEA,                          -- Kyber prekeys are signed by the identity key
  used BIGINT NOT NULL DEFAULT 0,
  created_at BIGINT NOT NULL DEFAULT ((extract(epoch from now()) * 1000)::bigint),
  UNIQUE (user_id, device_id, kind, key_id)
);
CREATE INDEX idx_one_time_prekeys_device ON one_time_prekeys(user_id, device_id, kind, used);

-- Per-device mailbox of sealed-sender envelopes. The server knows the RECIPIENT device (it has to
-- route) and nothing else: no sender column exists, and the deposit endpoint takes no credentials.
CREATE TABLE sealed_envelopes (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL,
  envelope BYTEA NOT NULL,
  seq BIGINT NOT NULL,                      -- arrival order (delivery is FIFO per device)
  created_at BIGINT NOT NULL
);
CREATE INDEX idx_sealed_envelopes_device ON sealed_envelopes(user_id, device_id, seq);

-- Pending device-link requests. Holds public values only: the new device's identity key, an HMAC
-- proof keyed by the link code (which never reaches the server), and — once an existing device
-- approves — that device's link signature and approval MAC.
CREATE TABLE device_link_requests (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  identity_key BYTEA NOT NULL,
  proof BYTEA NOT NULL,
  approver_device_id TEXT,
  approver_identity_key BYTEA,
  link_sig BYTEA,
  approval_mac BYTEA,
  created_at BIGINT NOT NULL
);
CREATE INDEX idx_device_link_requests_user ON device_link_requests(user_id, created_at);

-- Durable per-account E2EE record. A row exists from the moment an account registers its FIRST
-- device and is never removed by device deletion — so "this account has had a device" cannot be
-- undone by emptying user_devices. After that, a new device needs a link from a current device,
-- or a reset: with the registration-lock PIN, or after a waiting period during which any existing
-- device can cancel it.
CREATE TABLE e2ee_accounts (
  user_id TEXT PRIMARY KEY REFERENCES profiles(id) ON DELETE CASCADE,
  first_device_at BIGINT NOT NULL,
  reset_requested_at BIGINT,
  reset_identity_key BYTEA,
  -- When the registration-lock PIN was last set/changed. A PIN younger than the reset hold never
  -- lets a reset skip the hold (so a PIN cannot be planted and used at once).
  pin_set_at BIGINT
);

-- Device-operation proofs already accepted. Each signature is single-use: a row lives until the
-- proof's freshness window has passed, so a captured proof cannot be replayed inside it.
CREATE TABLE device_op_proofs (
  proof_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  expires_at BIGINT NOT NULL
);
