ALTER TABLE operation_journal ADD COLUMN concurrency_released_at TEXT;

CREATE INDEX operation_concurrency_projection_idx
ON operation_journal(state, concurrency_released_at)
WHERE connector_grant_id IS NOT NULL AND concurrency_class IS NOT NULL;

UPDATE schema_versions
SET version=8,applied_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
WHERE component='control_plane' AND version=7;
