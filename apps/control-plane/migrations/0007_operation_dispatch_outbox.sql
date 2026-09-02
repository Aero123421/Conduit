CREATE TABLE operation_dispatch_outbox (
  operation_id TEXT PRIMARY KEY REFERENCES operation_journal(id),
  device_id TEXT NOT NULL REFERENCES devices(id),
  message_id TEXT NOT NULL UNIQUE,
  correlation_id TEXT NOT NULL,
  payload_digest TEXT NOT NULL CHECK (length(payload_digest) = 64),
  payload_json TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('pending','dispatching','offered','expired')),
  attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  next_attempt_at TEXT NOT NULL,
  lease_token TEXT,
  lease_expires_at TEXT,
  result_json TEXT,
  last_error_code TEXT,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE INDEX operation_dispatch_due_idx
ON operation_dispatch_outbox(state, next_attempt_at, expires_at);

UPDATE schema_versions
SET version=7,applied_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
WHERE component='control_plane' AND version=6;
