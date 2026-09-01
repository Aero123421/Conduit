CREATE TABLE IF NOT EXISTS owner_api_tokens (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES owner_principals(id),
  verifier_hash TEXT NOT NULL UNIQUE,
  label TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 128),
  status TEXT NOT NULL CHECK (status IN ('active','revoked','expired')),
  issued_from_session_id TEXT REFERENCES owner_sessions(id),
  created_at TEXT NOT NULL,
  last_used_at TEXT,
  expires_at TEXT NOT NULL,
  revoked_at TEXT
) STRICT;
CREATE INDEX IF NOT EXISTS owner_api_tokens_principal_status_idx ON owner_api_tokens(principal_id,status);
UPDATE schema_versions SET version=3,applied_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE component='control_plane' AND version < 3;
