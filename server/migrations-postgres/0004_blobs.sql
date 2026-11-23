-- Blob upload sessions (TUS-style resumable). Bytes live at <data>/blobs/<id>; this table
-- tracks progress and ownership. Content is client-side encrypted before upload — the server
-- never sees plaintext or the per-file key (that travels in metadata_ciphertext on the
-- attachment row).
CREATE TABLE blobs (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  total_size BIGINT NOT NULL CHECK (total_size > 0),
  received_bytes BIGINT NOT NULL DEFAULT 0,
  complete BIGINT NOT NULL DEFAULT 0,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL
);

CREATE INDEX idx_blobs_owner ON blobs(owner_id);
