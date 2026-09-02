-- Public, bounded Control Plane evidence for the optional root-owned Linux
-- helper. Private keys, canonical local paths, plans, credentials, and raw
-- process output never enter D1.
CREATE TABLE privilege_issuer_keys (
  key_id TEXT PRIMARY KEY,
  revision INTEGER NOT NULL UNIQUE CHECK (revision >= 1),
  public_jwk_json TEXT NOT NULL,
  fingerprint TEXT NOT NULL UNIQUE CHECK (length(fingerprint) = 64),
  status TEXT NOT NULL CHECK (status IN ('active','retiring','revoked')),
  valid_from TEXT NOT NULL,
  valid_until TEXT,
  predecessor_key_id TEXT REFERENCES privilege_issuer_keys(key_id) ON DELETE RESTRICT,
  rotation_statement_digest TEXT CHECK (rotation_statement_digest IS NULL OR length(rotation_statement_digest) = 64),
  rotation_signature TEXT,
  created_at TEXT NOT NULL,
  revoked_at TEXT
) STRICT;
CREATE UNIQUE INDEX privilege_issuer_one_active_idx ON privilege_issuer_keys(status) WHERE status='active';

CREATE TABLE device_privilege_installations (
  installation_id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
  expected_uid INTEGER NOT NULL CHECK (expected_uid BETWEEN 1 AND 4294967294),
  public_origin TEXT NOT NULL,
  helper_version TEXT NOT NULL,
  protocol_version TEXT NOT NULL CHECK (protocol_version='conduit.privileged/1'),
  active_key_id TEXT,
  active_policy_revision INTEGER CHECK (active_policy_revision IS NULL OR active_policy_revision >= 1),
  active_policy_digest TEXT CHECK (active_policy_digest IS NULL OR length(active_policy_digest) = 64),
  capability_digest TEXT NOT NULL CHECK (length(capability_digest) = 64),
  capability_summary_json TEXT NOT NULL,
  device_attestation_digest TEXT NOT NULL CHECK (length(device_attestation_digest) = 64),
  device_key_id TEXT NOT NULL REFERENCES device_keys(id) ON DELETE RESTRICT,
  status TEXT NOT NULL CHECK (status IN ('pending_owner','active','policy_review','disabled','revoked','recovery_required')),
  owner_principal_id TEXT REFERENCES owner_principals(id) ON DELETE RESTRICT,
  owner_decision_digest TEXT CHECK (owner_decision_digest IS NULL OR length(owner_decision_digest) = 64),
  approved_at TEXT,
  last_observed_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(device_id, expected_uid, public_origin)
) STRICT;
CREATE INDEX device_privilege_installations_device_status_idx ON device_privilege_installations(device_id,status);

CREATE TABLE privilege_registration_attestations (
  request_id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
  installation_id TEXT NOT NULL REFERENCES device_privilege_installations(installation_id) ON DELETE RESTRICT,
  attestation_kind TEXT NOT NULL CHECK (attestation_kind IN ('initial','key_rotation','policy_update','device_policy_update','combined_update')),
  request_digest TEXT NOT NULL CHECK (length(request_digest) = 64),
  device_key_id TEXT NOT NULL REFERENCES device_keys(id) ON DELETE RESTRICT,
  device_signature TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT;
CREATE INDEX privilege_registration_installation_idx ON privilege_registration_attestations(installation_id,created_at);
CREATE TRIGGER privilege_registration_attestations_immutable_update BEFORE UPDATE ON privilege_registration_attestations BEGIN SELECT RAISE(ABORT, 'privilege registration attestation is immutable'); END;
CREATE TRIGGER privilege_registration_attestations_immutable_delete BEFORE DELETE ON privilege_registration_attestations BEGIN SELECT RAISE(ABORT, 'privilege registration attestation is immutable'); END;

CREATE TABLE privilege_installation_keys (
  installation_id TEXT NOT NULL REFERENCES device_privilege_installations(installation_id) ON DELETE RESTRICT,
  key_id TEXT NOT NULL,
  public_jwk_json TEXT NOT NULL,
  fingerprint TEXT NOT NULL CHECK (length(fingerprint) = 64),
  status TEXT NOT NULL CHECK (status IN ('pending_owner','active','retiring','revoked')),
  valid_from TEXT NOT NULL,
  valid_until TEXT,
  predecessor_key_id TEXT,
  rotation_statement_digest TEXT CHECK (rotation_statement_digest IS NULL OR length(rotation_statement_digest) = 64),
  self_signature TEXT NOT NULL,
  approved_at TEXT,
  revoked_at TEXT,
  created_at TEXT NOT NULL,
  PRIMARY KEY(installation_id,key_id),
  UNIQUE(installation_id,fingerprint),
  FOREIGN KEY(installation_id,predecessor_key_id) REFERENCES privilege_installation_keys(installation_id,key_id) ON DELETE RESTRICT
) STRICT;
CREATE UNIQUE INDEX privilege_installation_one_active_key_idx ON privilege_installation_keys(installation_id,status) WHERE status='active';

CREATE TABLE privilege_policy_attestations (
  installation_id TEXT NOT NULL REFERENCES device_privilege_installations(installation_id) ON DELETE RESTRICT,
  revision INTEGER NOT NULL CHECK (revision >= 1),
  policy_digest TEXT NOT NULL CHECK (length(policy_digest) = 64),
  previous_policy_digest TEXT CHECK (previous_policy_digest IS NULL OR length(previous_policy_digest) = 64),
  public_summary_json TEXT NOT NULL,
  change_class TEXT NOT NULL CHECK (change_class IN ('initial','same','narrowed','broadened')),
  helper_key_id TEXT NOT NULL,
  helper_signature TEXT NOT NULL,
  attestation_digest TEXT NOT NULL UNIQUE CHECK (length(attestation_digest) = 64),
  status TEXT NOT NULL CHECK (status IN ('pending_owner','active','superseded','revoked')),
  observed_at TEXT NOT NULL,
  approved_by TEXT REFERENCES owner_principals(id) ON DELETE RESTRICT,
  approved_at TEXT,
  created_at TEXT NOT NULL,
  PRIMARY KEY(installation_id,revision),
  UNIQUE(installation_id,policy_digest),
  FOREIGN KEY(installation_id,helper_key_id) REFERENCES privilege_installation_keys(installation_id,key_id) ON DELETE RESTRICT
) STRICT;
CREATE INDEX privilege_policy_attestations_status_idx ON privilege_policy_attestations(installation_id,status,revision);

CREATE TABLE device_user_policy_attestations (
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
  revision INTEGER NOT NULL CHECK (revision >= 1),
  policy_digest TEXT NOT NULL CHECK (length(policy_digest) = 64),
  previous_policy_digest TEXT CHECK (previous_policy_digest IS NULL OR length(previous_policy_digest) = 64),
  public_summary_json TEXT NOT NULL,
  device_key_id TEXT NOT NULL REFERENCES device_keys(id) ON DELETE RESTRICT,
  device_signature TEXT NOT NULL,
  attestation_digest TEXT NOT NULL UNIQUE CHECK (length(attestation_digest) = 64),
  status TEXT NOT NULL CHECK (status IN ('pending_owner','active','superseded','revoked')),
  observed_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY(device_id,revision),
  UNIQUE(device_id,policy_digest)
) STRICT;
CREATE INDEX device_user_policy_active_idx ON device_user_policy_attestations(device_id,status,revision);

CREATE TABLE privilege_ticket_requests (
  request_id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
  device_key_id TEXT NOT NULL REFERENCES device_keys(id) ON DELETE RESTRICT,
  connection_epoch TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  idempotency_key_digest TEXT NOT NULL CHECK (length(idempotency_key_digest) = 64),
  installation_id TEXT NOT NULL REFERENCES device_privilege_installations(installation_id) ON DELETE RESTRICT,
  operation_id TEXT NOT NULL REFERENCES operation_journal(id) ON DELETE RESTRICT,
  assignment_id TEXT REFERENCES assignments(id) ON DELETE RESTRICT,
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE RESTRICT,
  runtime_id TEXT NOT NULL,
  runtime_spec_digest TEXT NOT NULL CHECK (length(runtime_spec_digest) = 64),
  launch_plan_digest TEXT NOT NULL CHECK (length(launch_plan_digest) = 64),
  local_execution_plan_digest TEXT NOT NULL CHECK (length(local_execution_plan_digest) = 64),
  control_request_digest TEXT CHECK (control_request_digest IS NULL OR length(control_request_digest) = 64),
  operation_request_digest TEXT NOT NULL CHECK (length(operation_request_digest) = 64),
  run_manifest_digest TEXT NOT NULL CHECK (length(run_manifest_digest) = 64),
  helper_policy_revision INTEGER NOT NULL CHECK (helper_policy_revision >= 1),
  helper_policy_digest TEXT NOT NULL CHECK (length(helper_policy_digest) = 64),
  device_policy_revision INTEGER NOT NULL CHECK (device_policy_revision >= 1),
  connector_policy_id TEXT NOT NULL,
  connector_policy_revision INTEGER NOT NULL CHECK (connector_policy_revision >= 1),
  project_revision INTEGER CHECK (project_revision IS NULL OR project_revision >= 1),
  project_agent_id TEXT,
  project_agent_revision INTEGER CHECK (project_agent_revision IS NULL OR project_agent_revision >= 1),
  device_revision INTEGER NOT NULL CHECK (device_revision >= 1),
  runtime_configuration_revision INTEGER NOT NULL CHECK (runtime_configuration_revision >= 1),
  approval_receipt_digest TEXT CHECK (approval_receipt_digest IS NULL OR length(approval_receipt_digest) = 64),
  approval_enforcement TEXT NOT NULL CHECK (approval_enforcement IN ('exact_command','adapter_mediated','unavailable')),
  allowed_operation TEXT NOT NULL CHECK (allowed_operation IN ('prepare','start','inspect','input','resize_pty','pause','resume','graceful_stop','force_stop','reconcile')),
  resource_ceilings_json TEXT NOT NULL,
  redacted_summary_json TEXT NOT NULL,
  request_digest TEXT NOT NULL CHECK (length(request_digest) = 64),
  device_signature TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','issued','denied','expired','conflict')),
  denial_code TEXT,
  requested_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  terminal_at TEXT,
  UNIQUE(device_id,idempotency_key)
) STRICT;
CREATE INDEX privilege_ticket_requests_status_expiry_idx ON privilege_ticket_requests(status,expires_at,request_id);
CREATE INDEX privilege_ticket_requests_operation_idx ON privilege_ticket_requests(operation_id,request_id);

CREATE TABLE privilege_ticket_issuance (
  ticket_id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL UNIQUE REFERENCES privilege_ticket_requests(request_id) ON DELETE RESTRICT,
  issuer_key_id TEXT NOT NULL REFERENCES privilege_issuer_keys(key_id) ON DELETE RESTRICT,
  issuer_key_revision INTEGER NOT NULL CHECK (issuer_key_revision >= 1),
  canonical_ticket_json TEXT NOT NULL,
  signature TEXT NOT NULL,
  ticket_digest TEXT NOT NULL UNIQUE CHECK (length(ticket_digest) = 64),
  status TEXT NOT NULL CHECK (status IN ('active','revoked')),
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT
) STRICT;
CREATE INDEX privilege_ticket_issuance_expiry_idx ON privilege_ticket_issuance(status,expires_at,ticket_id);

CREATE TABLE privilege_receipt_projections (
  receipt_digest TEXT PRIMARY KEY CHECK (length(receipt_digest) = 64),
  receipt_id TEXT NOT NULL UNIQUE,
  installation_id TEXT NOT NULL REFERENCES device_privilege_installations(installation_id) ON DELETE RESTRICT,
  helper_key_id TEXT NOT NULL,
  ticket_id TEXT NOT NULL REFERENCES privilege_ticket_issuance(ticket_id) ON DELETE RESTRICT,
  ticket_digest TEXT NOT NULL CHECK (length(ticket_digest) = 64),
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
  operation_id TEXT NOT NULL REFERENCES operation_journal(id) ON DELETE RESTRICT,
  request_digest TEXT NOT NULL CHECK (length(request_digest) = 64),
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE RESTRICT,
  runtime_id TEXT NOT NULL,
  runtime_spec_digest TEXT NOT NULL CHECK (length(runtime_spec_digest) = 64),
  launch_plan_digest TEXT NOT NULL CHECK (length(launch_plan_digest) = 64),
  local_execution_plan_digest TEXT NOT NULL CHECK (length(local_execution_plan_digest) = 64),
  control_request_digest TEXT CHECK (control_request_digest IS NULL OR length(control_request_digest) = 64),
  controller_epoch INTEGER NOT NULL CHECK (controller_epoch >= 1),
  state_revision INTEGER NOT NULL CHECK (state_revision >= 1),
  transition TEXT NOT NULL CHECK (transition IN ('admitted','prepared','unit_created','running','paused','resumed','input_applied','stopping','completed','failed','cancelled','timed_out','uncertain','recovery_required')),
  previous_receipt_digest TEXT REFERENCES privilege_receipt_projections(receipt_digest) ON DELETE RESTRICT,
  unit_name TEXT NOT NULL,
  invocation_id TEXT,
  cgroup_identity_digest TEXT CHECK (cgroup_identity_digest IS NULL OR length(cgroup_identity_digest) = 64),
  main_pid INTEGER CHECK (main_pid IS NULL OR main_pid >= 1),
  process_birth_digest TEXT CHECK (process_birth_digest IS NULL OR length(process_birth_digest) = 64),
  effective_uid INTEGER,
  effective_gid INTEGER,
  stdout_cursor INTEGER NOT NULL CHECK (stdout_cursor >= 0),
  stderr_cursor INTEGER NOT NULL CHECK (stderr_cursor >= 0),
  exit_code INTEGER,
  signal INTEGER,
  helper_version TEXT NOT NULL,
  helper_policy_revision INTEGER NOT NULL CHECK (helper_policy_revision >= 1),
  helper_policy_digest TEXT NOT NULL CHECK (length(helper_policy_digest) = 64),
  observed_at TEXT NOT NULL,
  helper_signature TEXT NOT NULL,
  verified_at TEXT NOT NULL,
  UNIQUE(runtime_id,state_revision),
  FOREIGN KEY(installation_id,helper_key_id) REFERENCES privilege_installation_keys(installation_id,key_id) ON DELETE RESTRICT
) STRICT;
CREATE INDEX privilege_receipt_projection_operation_idx ON privilege_receipt_projections(operation_id,state_revision);
CREATE INDEX privilege_receipt_projection_runtime_idx ON privilege_receipt_projections(runtime_id,state_revision);

-- Issued authorization and verified root evidence are append-only. Status
-- changes use request/ticket revocation fields, never replacement of evidence.
CREATE TRIGGER privilege_ticket_issuance_immutable_update BEFORE UPDATE ON privilege_ticket_issuance
WHEN NEW.ticket_id IS NOT OLD.ticket_id OR NEW.request_id IS NOT OLD.request_id OR NEW.issuer_key_id IS NOT OLD.issuer_key_id
  OR NEW.issuer_key_revision IS NOT OLD.issuer_key_revision OR NEW.canonical_ticket_json IS NOT OLD.canonical_ticket_json
  OR NEW.signature IS NOT OLD.signature OR NEW.ticket_digest IS NOT OLD.ticket_digest OR NEW.issued_at IS NOT OLD.issued_at
  OR NEW.expires_at IS NOT OLD.expires_at OR OLD.status='revoked' OR NEW.status<>'revoked' OR NEW.revoked_at IS NULL
BEGIN SELECT RAISE(ABORT, 'privilege ticket issuance is immutable'); END;
CREATE TRIGGER privilege_ticket_issuance_immutable_delete BEFORE DELETE ON privilege_ticket_issuance BEGIN SELECT RAISE(ABORT, 'privilege ticket issuance is immutable'); END;
CREATE TRIGGER privilege_receipt_projections_immutable_update BEFORE UPDATE ON privilege_receipt_projections BEGIN SELECT RAISE(ABORT, 'privilege receipt projection is immutable'); END;
CREATE TRIGGER privilege_receipt_projections_immutable_delete BEFORE DELETE ON privilege_receipt_projections BEGIN SELECT RAISE(ABORT, 'privilege receipt projection is immutable'); END;
CREATE TRIGGER privilege_policy_attestations_immutable_delete BEFORE DELETE ON privilege_policy_attestations BEGIN SELECT RAISE(ABORT, 'privilege policy attestation is immutable'); END;
CREATE TRIGGER device_user_policy_attestations_immutable_delete BEFORE DELETE ON device_user_policy_attestations BEGIN SELECT RAISE(ABORT, 'Device policy attestation is immutable'); END;
CREATE TRIGGER privilege_issuer_keys_immutable_delete BEFORE DELETE ON privilege_issuer_keys BEGIN SELECT RAISE(ABORT, 'privilege issuer key history is immutable'); END;

UPDATE schema_versions
SET version=14,applied_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
WHERE component='control_plane' AND version=13;
