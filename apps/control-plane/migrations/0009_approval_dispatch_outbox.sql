CREATE TABLE approval_dispatch_outbox (
  approval_id TEXT PRIMARY KEY REFERENCES approvals(id) ON DELETE RESTRICT,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
  message_id TEXT NOT NULL UNIQUE,
  payload_digest TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('pending','dispatching','offered','expired')),
  attempt_count INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TEXT NOT NULL,
  lease_token TEXT,
  lease_expires_at TEXT,
  last_error_code TEXT,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE INDEX approval_dispatch_due_idx
ON approval_dispatch_outbox(state, next_attempt_at, expires_at);

UPDATE schema_versions
SET version=9,applied_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
WHERE component='control_plane' AND version < 9;
