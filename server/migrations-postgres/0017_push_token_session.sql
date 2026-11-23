-- Direct-push tokens (operators with their own APNs/FCM keys; `{ "token", "platform" }` on
-- /api/push/register) now belong to the SESSION that registered them, like gateway
-- registrations: logout, session expiry, device removal and account deletion remove them by
-- cascade, so a signed-out install is no longer woken.
--
-- Existing rows were stored unvalidated (any string, any number of them) and name no session;
-- they are dropped. An install that uses the direct route registers again when it next runs.
-- (Numbered 0017 at integration: 0015 and 0016 are the two audit migrations before it.)
DELETE FROM push_tokens;
ALTER TABLE push_tokens ADD COLUMN session_hash BYTEA REFERENCES sessions(token_hash) ON DELETE CASCADE;
