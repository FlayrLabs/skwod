-- Blind push gateway registrations (docs/SECURITY.md "Push"). One row per signed-in app install:
-- the APNs token(s) plus the gateway that install asked to be woken through. Tied to the SESSION
-- that registered it, so logout, session expiry and account deletion remove it by cascade; device
-- removal deletes it explicitly (push.rs). Nothing here names a sender, channel or message.
CREATE TABLE push_registrations (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  session_hash BLOB NOT NULL UNIQUE REFERENCES sessions(token_hash) ON DELETE CASCADE,
  device_id TEXT,                       -- optional: lets device removal target exactly this row
  gateway TEXT NOT NULL,                -- validated https origin (+ optional path prefix)
  apns_token TEXT NOT NULL,             -- hex
  voip_token TEXT,                      -- hex, PushKit; NULL = no call wakes
  topic TEXT NOT NULL,                  -- app bundle id
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX idx_push_registrations_user ON push_registrations(user_id);
