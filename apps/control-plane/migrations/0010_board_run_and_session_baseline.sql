-- Board assignments bind every authority-bearing launch input before an
-- operation can enter the durable dispatch outbox.
CREATE TABLE assignment_run_bindings (
  assignment_id TEXT PRIMARY KEY REFERENCES assignments(id) ON DELETE RESTRICT,
  project_agent_id TEXT NOT NULL REFERENCES project_agents(id) ON DELETE RESTRICT,
  project_agent_revision INTEGER NOT NULL CHECK (project_agent_revision >= 1),
  project_revision INTEGER NOT NULL CHECK (project_revision >= 1),
  session_revision INTEGER NOT NULL CHECK (session_revision >= 1),
  message_revision INTEGER NOT NULL CHECK (message_revision >= 1),
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
  device_revision INTEGER NOT NULL CHECK (device_revision >= 1),
  runtime_kind TEXT NOT NULL CHECK (runtime_kind IN ('native','restricted_native','container','vm')),
  runtime_provider_id TEXT NOT NULL,
  runtime_configuration_revision INTEGER NOT NULL CHECK (runtime_configuration_revision >= 1),
  adapter_id TEXT NOT NULL,
  role TEXT NOT NULL,
  model TEXT NOT NULL,
  effort TEXT NOT NULL,
  access_scope TEXT NOT NULL CHECK (access_scope IN ('read_only','selected_sources','project_full','full_user','full_device','custom')),
  approval_mode TEXT NOT NULL CHECK (approval_mode IN ('always','outside_scope','risk_classes','never')),
  source_revisions_json TEXT NOT NULL,
  agent_configuration_json TEXT NOT NULL,
  verification_policy_json TEXT NOT NULL,
  request_digest TEXT NOT NULL CHECK (length(request_digest) = 64),
  binding_digest TEXT NOT NULL CHECK (length(binding_digest) = 64),
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE context_snapshots (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE RESTRICT,
  operation_id TEXT NOT NULL REFERENCES operation_journal(id) DEFERRABLE INITIALLY DEFERRED,
  mode TEXT NOT NULL CHECK (mode IN ('initial','answer','follow_up','steer','resume','queued_instruction')),
  project_revision INTEGER NOT NULL CHECK (project_revision >= 1),
  session_revision INTEGER NOT NULL CHECK (session_revision >= 1),
  message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE RESTRICT,
  message_revision INTEGER NOT NULL CHECK (message_revision >= 1),
  compiler_version TEXT NOT NULL,
  item_manifest_json TEXT NOT NULL,
  compiled_content_digest TEXT NOT NULL CHECK (length(compiled_content_digest) = 64),
  snapshot_digest TEXT NOT NULL UNIQUE CHECK (length(snapshot_digest) = 64),
  created_at TEXT NOT NULL
) STRICT;
CREATE INDEX context_snapshots_run_idx ON context_snapshots(run_id, created_at);

-- Immutable accepted state. The mutable collaboration_sessions pointer is the
-- compare-and-swap projection of these rows.
CREATE TABLE baseline_revisions (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES collaboration_sessions(id) ON DELETE RESTRICT,
  revision INTEGER NOT NULL CHECK (revision >= 1),
  predecessor_id TEXT REFERENCES baseline_revisions(id) ON DELETE RESTRICT,
  accepted_change_set_id TEXT REFERENCES change_sets(id) ON DELETE RESTRICT,
  vector_json TEXT NOT NULL,
  vector_digest TEXT NOT NULL CHECK (length(vector_digest) = 64),
  accepting_principal_id TEXT NOT NULL REFERENCES owner_principals(id) ON DELETE RESTRICT,
  accepting_client_id TEXT NOT NULL,
  prepared_receipt_digest TEXT NOT NULL CHECK (length(prepared_receipt_digest) = 64),
  materialization_state TEXT NOT NULL CHECK (materialization_state IN ('pending','complete','degraded')),
  created_at TEXT NOT NULL,
  UNIQUE(session_id, revision),
  UNIQUE(session_id, vector_digest)
) STRICT;

CREATE TABLE change_sets (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES collaboration_sessions(id) ON DELETE RESTRICT,
  assignment_id TEXT NOT NULL REFERENCES assignments(id) ON DELETE RESTRICT,
  run_id TEXT NOT NULL UNIQUE REFERENCES runs(id) ON DELETE RESTRICT,
  parent_baseline_id TEXT REFERENCES baseline_revisions(id) ON DELETE RESTRICT,
  supersedes_change_set_id TEXT REFERENCES change_sets(id) ON DELETE RESTRICT,
  source_changes_json TEXT NOT NULL,
  unchanged_sources_json TEXT NOT NULL,
  application_order_json TEXT NOT NULL,
  artifact_commitments_json TEXT NOT NULL,
  provenance_json TEXT NOT NULL,
  custody_json TEXT NOT NULL,
  verification_policy_json TEXT NOT NULL,
  change_set_digest TEXT NOT NULL UNIQUE CHECK (length(change_set_digest) = 64),
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE change_set_state (
  change_set_id TEXT PRIMARY KEY REFERENCES change_sets(id) ON DELETE RESTRICT,
  state TEXT NOT NULL CHECK (state IN ('draft','proposed','under_review','changes_requested','approved','accepted','rejected','withdrawn','superseded','stale','conflicted')),
  revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE verification_records (
  id TEXT PRIMARY KEY,
  change_set_id TEXT NOT NULL REFERENCES change_sets(id) ON DELETE RESTRICT,
  check_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('passed','failed','skipped','unavailable')),
  evidence_refs_json TEXT NOT NULL,
  observed_digest TEXT NOT NULL CHECK (length(observed_digest) = 64),
  created_at TEXT NOT NULL,
  UNIQUE(change_set_id, check_id)
) STRICT;

CREATE TABLE reviews (
  id TEXT PRIMARY KEY,
  change_set_id TEXT NOT NULL REFERENCES change_sets(id) ON DELETE RESTRICT,
  change_set_digest TEXT NOT NULL CHECK (length(change_set_digest) = 64),
  reviewer_principal_id TEXT REFERENCES owner_principals(id) ON DELETE RESTRICT,
  reviewer_project_agent_id TEXT REFERENCES project_agents(id) ON DELETE RESTRICT,
  source_change_digests_json TEXT NOT NULL,
  verification_state_digest TEXT NOT NULL CHECK (length(verification_state_digest) = 64),
  findings_json TEXT NOT NULL,
  evidence_refs_json TEXT NOT NULL,
  verdict TEXT NOT NULL CHECK (verdict IN ('approved','changes_requested','rejected','unable_to_review')),
  created_at TEXT NOT NULL
) STRICT;
CREATE INDEX reviews_change_set_idx ON reviews(change_set_id, created_at);

CREATE TABLE baseline_acceptances (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES collaboration_sessions(id) ON DELETE RESTRICT,
  change_set_id TEXT NOT NULL UNIQUE REFERENCES change_sets(id) ON DELETE RESTRICT,
  expected_baseline_id TEXT,
  committed_baseline_id TEXT NOT NULL UNIQUE REFERENCES baseline_revisions(id) ON DELETE RESTRICT,
  prepared_receipt_digest TEXT NOT NULL CHECK (length(prepared_receipt_digest) = 64),
  accepted_by_principal_id TEXT NOT NULL REFERENCES owner_principals(id) ON DELETE RESTRICT,
  accepted_by_client_id TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT;

CREATE TRIGGER assignment_run_bindings_immutable_update BEFORE UPDATE ON assignment_run_bindings BEGIN SELECT RAISE(ABORT, 'assignment run binding is immutable'); END;
CREATE TRIGGER assignment_run_bindings_immutable_delete BEFORE DELETE ON assignment_run_bindings BEGIN SELECT RAISE(ABORT, 'assignment run binding is immutable'); END;
CREATE TRIGGER context_snapshots_immutable_update BEFORE UPDATE ON context_snapshots BEGIN SELECT RAISE(ABORT, 'context snapshot is immutable'); END;
CREATE TRIGGER context_snapshots_immutable_delete BEFORE DELETE ON context_snapshots BEGIN SELECT RAISE(ABORT, 'context snapshot is immutable'); END;
CREATE TRIGGER baseline_revisions_immutable_update BEFORE UPDATE ON baseline_revisions BEGIN SELECT RAISE(ABORT, 'baseline revision is immutable'); END;
CREATE TRIGGER baseline_revisions_immutable_delete BEFORE DELETE ON baseline_revisions BEGIN SELECT RAISE(ABORT, 'baseline revision is immutable'); END;
CREATE TRIGGER change_sets_immutable_update BEFORE UPDATE ON change_sets BEGIN SELECT RAISE(ABORT, 'change set is immutable'); END;
CREATE TRIGGER change_sets_immutable_delete BEFORE DELETE ON change_sets BEGIN SELECT RAISE(ABORT, 'change set is immutable'); END;
CREATE TRIGGER verification_records_immutable_update BEFORE UPDATE ON verification_records BEGIN SELECT RAISE(ABORT, 'verification record is immutable'); END;
CREATE TRIGGER verification_records_immutable_delete BEFORE DELETE ON verification_records BEGIN SELECT RAISE(ABORT, 'verification record is immutable'); END;
CREATE TRIGGER reviews_immutable_update BEFORE UPDATE ON reviews BEGIN SELECT RAISE(ABORT, 'review is immutable'); END;
CREATE TRIGGER reviews_immutable_delete BEFORE DELETE ON reviews BEGIN SELECT RAISE(ABORT, 'review is immutable'); END;
CREATE TRIGGER baseline_acceptances_immutable_update BEFORE UPDATE ON baseline_acceptances BEGIN SELECT RAISE(ABORT, 'baseline acceptance is immutable'); END;
CREATE TRIGGER baseline_acceptances_immutable_delete BEFORE DELETE ON baseline_acceptances BEGIN SELECT RAISE(ABORT, 'baseline acceptance is immutable'); END;

UPDATE schema_versions
SET version=10,applied_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
WHERE component='control_plane' AND version=9;
