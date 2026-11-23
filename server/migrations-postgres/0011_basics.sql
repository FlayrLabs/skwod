-- Build 43 "broken basics".

-- Attachments. A DM attachment has no server-side message row to hang access on (DMs are sealed
-- mail), so its uploader registers the SHA-256 of a random download token; whoever presents the
-- token may fetch the ciphertext. The token itself travels only inside the E2EE descriptor.
ALTER TABLE blobs ADD COLUMN token_hash BYTEA;

-- Sessions slide on use. `origin_at` is when the user actually signed in: the absolute lifetime
-- is counted from it, and a rotated token inherits it.
ALTER TABLE sessions ADD COLUMN origin_at BIGINT NOT NULL DEFAULT 0;
UPDATE sessions SET origin_at = created_at;
-- 1 once the token was rotated away: it then only runs out a short grace period.
ALTER TABLE sessions ADD COLUMN superseded BIGINT NOT NULL DEFAULT 0;

-- One deterministic feed scope per server: a hidden channel with purpose = 'feed'.
ALTER TABLE channels ADD COLUMN purpose TEXT;
CREATE UNIQUE INDEX idx_channels_feed ON channels(server_id) WHERE purpose = 'feed';

-- The catch-up cursor (`?after=`) reads a channel by `updated_at`.
CREATE INDEX idx_messages_channel_updated ON messages(channel_id, updated_at);
CREATE INDEX idx_message_attachments_blob ON message_attachments(storage_path);

-- An opaque tag the DEVICE chose for this skwod when it registered for pushes (random, kept on
-- the device). It rides along with every wake so a phone signed in to several skwods can tell
-- which one woke it — without trusting what any of them says afterwards.
ALTER TABLE push_registrations ADD COLUMN wake_tag TEXT;
