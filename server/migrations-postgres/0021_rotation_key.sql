-- Build 51: a rotation whose answer never reached the client (the app was suspended, the
-- connection dropped) can be asked for again (`auth::rotate`).
--
-- `sessions.rotation_key`: SHA-256 of a random key the client made and stored BEFORE it asked to
-- rotate this token. Within the old token's grace, and only with that key, it may rotate again.
-- `sessions.successor_hash`: the token the last rotation issued in this one's place.
-- `sessions.used`: this token has been presented (a successor that was is never replaced).
ALTER TABLE sessions ADD COLUMN rotation_key BYTEA;
ALTER TABLE sessions ADD COLUMN successor_hash BYTEA;
ALTER TABLE sessions ADD COLUMN used BIGINT NOT NULL DEFAULT 0;
