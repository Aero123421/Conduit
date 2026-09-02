CREATE TABLE IF NOT EXISTS effect_idempotency_records (
  scope TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  payload_digest TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('reserved','completed','uncertain')),
  response_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  PRIMARY KEY(scope,idempotency_key)
) STRICT;
UPDATE schema_versions SET version=4,applied_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE component='control_plane' AND version < 4;
