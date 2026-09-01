CREATE INDEX idx_passkeys_principal_status ON passkeys(principal_id, status);
CREATE INDEX idx_owner_sessions_verifier ON owner_sessions(verifier_hash, status, expires_at);
CREATE INDEX idx_auth_challenges_expiry ON auth_challenges(expires_at, consumed_at);
CREATE INDEX idx_oauth_tokens_verifier ON oauth_tokens(verifier_hash, kind, expires_at);
CREATE INDEX idx_oauth_grants_client_status ON oauth_grants(client_id, status);
CREATE INDEX idx_device_enrollments_expiry ON device_enrollments(state, expires_at);
CREATE INDEX idx_device_keys_device_status ON device_keys(device_id, status);
CREATE INDEX idx_locations_source_device ON locations(source_id, device_id, status);
CREATE INDEX idx_messages_session_created ON messages(session_id, created_at);
CREATE INDEX idx_assignments_session_state ON assignments(session_id, state);
CREATE INDEX idx_runs_device_state ON runs(device_id, state);
CREATE INDEX idx_operations_device_state ON operation_journal(device_id, state);
CREATE INDEX idx_artifacts_run ON artifacts(run_id, status);
CREATE INDEX idx_normalized_events_run_sequence ON normalized_events(run_id, sequence);
CREATE INDEX idx_security_events_created ON security_events(created_at, event_type);

CREATE TABLE connector_policy_history (
  policy_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  snapshot_json TEXT NOT NULL,
  changed_by_principal_id TEXT NOT NULL,
  change_reason TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY(policy_id, revision)
) STRICT;

CREATE TRIGGER connector_policy_history_immutable_update
BEFORE UPDATE ON connector_policy_history BEGIN SELECT RAISE(ABORT, 'connector policy history is immutable'); END;
CREATE TRIGGER connector_policy_history_immutable_delete
BEFORE DELETE ON connector_policy_history BEGIN SELECT RAISE(ABORT, 'connector policy history is immutable'); END;

UPDATE schema_versions
SET version = 2, applied_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE component = 'control_plane' AND version = 1;
