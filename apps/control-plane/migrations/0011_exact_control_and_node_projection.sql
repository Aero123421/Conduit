-- Start custody and existing-target control custody share one retryable D1
-- outbox, but they carry distinct protocol frame types and target commitments.
ALTER TABLE operation_journal ADD COLUMN operation_kind TEXT NOT NULL DEFAULT 'start'
  CHECK (operation_kind IN ('start','agent_control','runtime_control'));
ALTER TABLE operation_journal ADD COLUMN target_operation_id TEXT REFERENCES operation_journal(id);
ALTER TABLE operation_journal ADD COLUMN target_runtime_id TEXT;
ALTER TABLE operation_journal ADD COLUMN target_digest TEXT CHECK (target_digest IS NULL OR length(target_digest) = 64);
ALTER TABLE operation_journal ADD COLUMN target_controller_epoch TEXT;
ALTER TABLE operation_journal ADD COLUMN expected_target_state TEXT;
ALTER TABLE operation_journal ADD COLUMN expected_target_revision INTEGER CHECK (expected_target_revision IS NULL OR expected_target_revision >= 1);
ALTER TABLE operation_journal ADD COLUMN node_state_revision INTEGER NOT NULL DEFAULT 0 CHECK (node_state_revision >= 0);

ALTER TABLE operation_dispatch_outbox ADD COLUMN frame_type TEXT NOT NULL DEFAULT 'operation.offer'
  CHECK (frame_type IN ('operation.offer','operation.input','operation.cancel','runtime.control'));

CREATE TABLE runtime_custody (
  runtime_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL UNIQUE REFERENCES runs(id) ON DELETE RESTRICT,
  start_operation_id TEXT NOT NULL UNIQUE REFERENCES operation_journal(id) ON DELETE RESTRICT,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
  provider_id TEXT NOT NULL,
  handle_digest TEXT NOT NULL CHECK (length(handle_digest) = 64),
  target_digest TEXT NOT NULL UNIQUE CHECK (length(target_digest) = 64),
  controller_epoch TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('planned','preparing','prepared','starting','running','paused','stopping','stopped','failed','lost','uncertain','recovery_required','destroying','destroyed')),
  revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE agent_sessions (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL UNIQUE REFERENCES runs(id) ON DELETE RESTRICT,
  start_operation_id TEXT NOT NULL UNIQUE REFERENCES operation_journal(id) ON DELETE RESTRICT,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
  adapter_id TEXT NOT NULL,
  native_session_id TEXT,
  target_digest TEXT NOT NULL UNIQUE CHECK (length(target_digest) = 64),
  settlement_policy TEXT NOT NULL CHECK (settlement_policy IN ('close_on_settle','waiting_input')),
  state TEXT NOT NULL CHECK (state IN ('starting','running','waiting_input','waiting_approval','closing','closed','cancelled','timed_out','failed','recovery_required')),
  controller_epoch TEXT NOT NULL,
  revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
  lease_expires_at TEXT,
  last_activity_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;
CREATE INDEX agent_sessions_lease_idx ON agent_sessions(state, lease_expires_at);

ALTER TABLE runs ADD COLUMN agent_session_id TEXT;
ALTER TABLE runs ADD COLUMN controller_epoch TEXT NOT NULL DEFAULT '1';

-- D1 projection identity is independent from Durable Object inbox custody so
-- exact duplicates remain harmless after an isolate or deployment restart.
CREATE TABLE node_projection_receipts (
  message_id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
  connection_epoch TEXT NOT NULL,
  node_sequence TEXT NOT NULL,
  frame_type TEXT NOT NULL CHECK (frame_type IN ('operation.admission','operation.status','operation.terminal','runtime.control_result','device.health')),
  correlation_id TEXT,
  operation_id TEXT REFERENCES operation_journal(id) ON DELETE RESTRICT,
  payload_digest TEXT NOT NULL CHECK (length(payload_digest) = 64),
  projection_state TEXT NOT NULL CHECK (projection_state IN ('applied','duplicate','rejected')),
  result_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(device_id, connection_epoch, node_sequence)
) STRICT;

ALTER TABLE devices ADD COLUMN health_sequence TEXT NOT NULL DEFAULT '0';
ALTER TABLE devices ADD COLUMN health_json TEXT;
ALTER TABLE devices ADD COLUMN health_observed_at TEXT;
ALTER TABLE devices ADD COLUMN node_boot_id TEXT;
ALTER TABLE devices ADD COLUMN active_run_count INTEGER NOT NULL DEFAULT 0 CHECK (active_run_count >= 0);

UPDATE schema_versions
SET version=11,applied_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
WHERE component='control_plane' AND version=10;
