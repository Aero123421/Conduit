ALTER TABLE operation_journal ADD COLUMN connector_grant_id TEXT;
ALTER TABLE operation_journal ADD COLUMN concurrency_class TEXT CHECK (concurrency_class IS NULL OR concurrency_class IN ('commands','agentRuns','runtimeStarts'));
CREATE INDEX operation_grant_state_idx ON operation_journal(connector_grant_id,state);
UPDATE schema_versions SET version=5,applied_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE component='control_plane' AND version < 5;
