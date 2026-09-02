-- Board fanout is a separate Durable Object write. Keep durable D1 custody of
-- every Device-originated realtime projection until BoardRoom accepts it.
CREATE TABLE realtime_projection_outbox (
  event_id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
  session_id TEXT NOT NULL REFERENCES collaboration_sessions(id) ON DELETE RESTRICT,
  event_type TEXT NOT NULL,
  record_id TEXT NOT NULL,
  revision INTEGER NOT NULL CHECK (revision >= 1),
  event_json TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('pending','publishing','published')),
  attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  next_attempt_at TEXT NOT NULL,
  lease_token TEXT,
  lease_expires_at TEXT,
  last_error_code TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  published_at TEXT
) STRICT;

CREATE INDEX realtime_projection_due_idx
ON realtime_projection_outbox(device_id, state, next_attempt_at, lease_expires_at);

UPDATE schema_versions
SET version=12,applied_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
WHERE component='control_plane' AND version=11;
