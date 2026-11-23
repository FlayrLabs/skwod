-- Blob upload sessions (TUS-style resumable). Bytes live at <data>/blobs/<id>; this table
-- tracks progress and ownership. Content is client-side encrypted before upload — the server
-- never sees plaintext or the per-file key (that travels in metadata_ciphertext on the
-- attachment row).
CREATE TABLE blobs (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  total_size INTEGER NOT NULL CHECK (total_size > 0),
  received_bytes INTEGER NOT NULL DEFAULT 0,
  complete INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX idx_blobs_owner ON blobs(owner_id);
