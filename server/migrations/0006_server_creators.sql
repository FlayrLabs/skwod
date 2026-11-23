-- Instance-level grant: which non-owner accounts may create servers inside this skwod.
-- The instance owner can always create servers; a row here grants a specific member the
-- same right. Absence of a row = that member cannot create servers (the default).
CREATE TABLE server_creators (
  user_id TEXT PRIMARY KEY REFERENCES profiles(id) ON DELETE CASCADE,
  granted_at INTEGER NOT NULL
);
