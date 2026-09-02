ALTER TABLE oauth_clients ADD COLUMN source_hash TEXT;
ALTER TABLE oauth_clients ADD COLUMN expires_at TEXT;
CREATE INDEX oauth_clients_pending_expiry_idx ON oauth_clients(status,expires_at);
CREATE INDEX oauth_clients_source_pending_idx ON oauth_clients(source_hash,status,expires_at);

ALTER TABLE device_enrollments ADD COLUMN source_hash TEXT;
ALTER TABLE device_enrollments ADD COLUMN poll_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE device_enrollments ADD COLUMN next_poll_at TEXT;
CREATE INDEX device_enrollments_source_pending_idx ON device_enrollments(source_hash,state,expires_at);
CREATE INDEX device_enrollments_poll_due_idx ON device_enrollments(device_code_hash,next_poll_at,expires_at);

ALTER TABLE auth_challenges ADD COLUMN source_hash TEXT;
CREATE INDEX auth_challenges_source_expiry_idx ON auth_challenges(source_hash,expires_at,consumed_at);

ALTER TABLE normalized_events ADD COLUMN retention_class TEXT NOT NULL DEFAULT 'long_lived';
ALTER TABLE normalized_events ADD COLUMN expires_at TEXT;
CREATE INDEX normalized_events_retention_expiry_idx ON normalized_events(retention_class,expires_at,event_id);

ALTER TABLE realtime_projection_outbox ADD COLUMN coalesce_key TEXT;
CREATE INDEX realtime_projection_pending_coalesce_idx ON realtime_projection_outbox(coalesce_key,state,updated_at);

UPDATE normalized_events
SET retention_class='streaming_delta',
    expires_at=strftime('%Y-%m-%dT%H:%M:%fZ',ingested_at,'+3 days')
WHERE event_type='adapter.assistant_message_delta';

CREATE TABLE realtime_delivery_receipts (
  event_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  record_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  published_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
) STRICT;
CREATE INDEX realtime_delivery_receipts_expiry_idx ON realtime_delivery_receipts(expires_at,event_id);

CREATE TABLE retention_cleanup_state (
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  continuation_due_at TEXT,
  last_started_at TEXT,
  last_completed_at TEXT,
  last_deleted_rows INTEGER NOT NULL DEFAULT 0
) STRICT;
INSERT INTO retention_cleanup_state(singleton,last_deleted_rows) VALUES (1,0);

UPDATE schema_versions SET version=13,applied_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE component='control_plane';
