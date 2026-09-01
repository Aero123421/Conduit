PRAGMA foreign_keys = ON;

CREATE TABLE schema_versions (
  component TEXT PRIMARY KEY,
  version INTEGER NOT NULL CHECK (version >= 1),
  applied_at TEXT NOT NULL
) STRICT;
INSERT INTO schema_versions(component, version, applied_at)
VALUES ('control_plane', 1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));

CREATE TABLE owner_principals (
  id TEXT PRIMARY KEY,
  display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 128),
  status TEXT NOT NULL CHECK (status IN ('active','recovery_required','disabled')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE passkeys (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES owner_principals(id),
  credential_id TEXT NOT NULL UNIQUE,
  public_key BLOB NOT NULL,
  relying_party_id TEXT NOT NULL,
  label TEXT CHECK (label IS NULL OR length(label) <= 128),
  transports_json TEXT NOT NULL DEFAULT '[]',
  authenticator_attachment TEXT,
  sign_count INTEGER NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
  status TEXT NOT NULL CHECK (status IN ('active','revoked')),
  created_at TEXT NOT NULL,
  last_used_at TEXT,
  revoked_at TEXT
) STRICT;

CREATE TABLE auth_challenges (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('registration','authentication','step_up','recovery_registration')),
  principal_id TEXT REFERENCES owner_principals(id),
  session_id TEXT,
  challenge_hash TEXT NOT NULL,
  binding_digest TEXT,
  expected_origin TEXT NOT NULL,
  expected_rp_id TEXT NOT NULL,
  state_json TEXT NOT NULL DEFAULT '{}',
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE owner_sessions (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES owner_principals(id),
  verifier_hash TEXT NOT NULL UNIQUE,
  csrf_hash TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'owner' CHECK (kind IN ('owner','recovery')),
  status TEXT NOT NULL CHECK (status IN ('active','revoked','expired')),
  authenticated_at TEXT NOT NULL,
  fresh_authenticated_at TEXT,
  last_activity_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  user_verified INTEGER NOT NULL CHECK (user_verified IN (0,1)),
  revoked_at TEXT
) STRICT;

CREATE TABLE owner_api_tokens (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES owner_principals(id),
  verifier_hash TEXT NOT NULL UNIQUE,
  label TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 128),
  status TEXT NOT NULL CHECK (status IN ('active','revoked','expired')),
  issued_from_session_id TEXT REFERENCES owner_sessions(id),
  created_at TEXT NOT NULL,
  last_used_at TEXT,
  expires_at TEXT NOT NULL,
  revoked_at TEXT
) STRICT;
CREATE INDEX owner_api_tokens_principal_status_idx ON owner_api_tokens(principal_id,status);

CREATE TABLE recovery_codes (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES owner_principals(id),
  verifier_hash TEXT NOT NULL UNIQUE,
  batch_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT,
  consumed_at TEXT,
  revoked_at TEXT
) STRICT;

CREATE TABLE oauth_clients (
  client_id TEXT PRIMARY KEY,
  registration_mechanism TEXT NOT NULL CHECK (registration_mechanism IN ('pre_registered','client_id_metadata_document','dynamic')),
  client_name TEXT NOT NULL,
  metadata_uri TEXT,
  redirect_uris_json TEXT NOT NULL,
  token_endpoint_auth_method TEXT NOT NULL CHECK (token_endpoint_auth_method IN ('none','client_secret_basic','client_secret_post','private_key_jwt')),
  client_secret_hash TEXT,
  metadata_digest TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending_owner','active','metadata_changed','revoked')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE rate_limit_profiles (
  id TEXT PRIMARY KEY,
  revision INTEGER NOT NULL CHECK (revision >= 1),
  status TEXT NOT NULL CHECK (status IN ('active','disabled')),
  name TEXT NOT NULL,
  profile_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE connector_policies (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES owner_principals(id),
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id),
  revision INTEGER NOT NULL CHECK (revision >= 1),
  status TEXT NOT NULL CHECK (status IN ('active','paused','reauthorization_required','revoked','expired')),
  device_selector_json TEXT NOT NULL,
  project_selector_json TEXT NOT NULL,
  allowed_operations_json TEXT NOT NULL,
  allowed_runtimes_json TEXT NOT NULL,
  max_access_scope TEXT NOT NULL CHECK (max_access_scope IN ('read_only','selected_sources','project_full','full_user','full_device','custom')),
  most_permissive_approval_mode TEXT NOT NULL CHECK (most_permissive_approval_mode IN ('always','outside_scope','risk_classes','never')),
  required_risk_classes_json TEXT NOT NULL DEFAULT '[]',
  allow_raw_content INTEGER NOT NULL CHECK (allow_raw_content IN (0,1)),
  allow_artifact_upload INTEGER NOT NULL CHECK (allow_artifact_upload IN (0,1)),
  rate_limit_profile_id TEXT NOT NULL REFERENCES rate_limit_profiles(id),
  max_command_seconds INTEGER NOT NULL,
  max_run_seconds INTEGER NOT NULL,
  expires_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (id, revision)
) STRICT;

CREATE TABLE oauth_grants (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES owner_principals(id),
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id),
  resource TEXT NOT NULL,
  scopes_json TEXT NOT NULL,
  connector_policy_id TEXT NOT NULL,
  connector_policy_revision INTEGER NOT NULL,
  token_family_id TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL CHECK (status IN ('active','paused','reauthorization_required','revoked','expired')),
  created_at TEXT NOT NULL,
  last_used_at TEXT,
  expires_at TEXT,
  revoked_at TEXT
) STRICT;

CREATE TABLE oauth_consent_transactions (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES owner_principals(id),
  browser_session_id TEXT NOT NULL REFERENCES owner_sessions(id),
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id),
  redirect_uri TEXT NOT NULL,
  resource TEXT NOT NULL,
  scopes_json TEXT NOT NULL,
  state_value TEXT,
  code_challenge TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL CHECK (code_challenge_method = 'S256'),
  connector_policy_id TEXT NOT NULL REFERENCES connector_policies(id),
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE oauth_authorization_codes (
  id TEXT PRIMARY KEY,
  code_hash TEXT NOT NULL UNIQUE,
  consent_transaction_id TEXT NOT NULL REFERENCES oauth_consent_transactions(id),
  grant_id TEXT NOT NULL REFERENCES oauth_grants(id),
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id),
  redirect_uri TEXT NOT NULL,
  resource TEXT NOT NULL,
  scopes_json TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE oauth_tokens (
  id TEXT PRIMARY KEY,
  grant_id TEXT NOT NULL REFERENCES oauth_grants(id),
  token_family_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('access','refresh')),
  verifier_hash TEXT NOT NULL UNIQUE,
  parent_token_id TEXT REFERENCES oauth_tokens(id),
  resource TEXT NOT NULL,
  scopes_json TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  revoked_at TEXT
) STRICT;

CREATE TABLE device_enrollments (
  id TEXT PRIMARY KEY,
  state TEXT NOT NULL CHECK (state IN ('pending_owner','approved','completed','denied','expired','cancelled')),
  device_code_hash TEXT NOT NULL UNIQUE,
  user_code_hash TEXT NOT NULL UNIQUE,
  claims_json TEXT NOT NULL,
  requested_key_id TEXT NOT NULL,
  requested_public_jwk_json TEXT NOT NULL,
  requested_fingerprint TEXT NOT NULL,
  possession_challenge TEXT NOT NULL,
  possession_signature TEXT NOT NULL,
  approved_by TEXT REFERENCES owner_principals(id),
  assigned_device_id TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  terminal_at TEXT
) STRICT;

CREATE TABLE devices (
  id TEXT PRIMARY KEY,
  enrollment_id TEXT NOT NULL UNIQUE REFERENCES device_enrollments(id),
  display_label TEXT NOT NULL,
  os TEXT NOT NULL,
  arch TEXT NOT NULL,
  node_version TEXT NOT NULL,
  protocol_version TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active','revoked','recovery_review')),
  revision INTEGER NOT NULL DEFAULT 1,
  connection_epoch TEXT NOT NULL DEFAULT '0',
  last_observed_at TEXT,
  revoked_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE device_keys (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id),
  public_jwk_json TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active','retiring','revoked')),
  created_at TEXT NOT NULL,
  retire_after TEXT,
  revoked_at TEXT,
  UNIQUE(device_id, fingerprint)
) STRICT;

CREATE TABLE device_auth_challenges (
  connection_id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id),
  key_id TEXT NOT NULL REFERENCES device_keys(id),
  client_nonce TEXT NOT NULL,
  server_nonce TEXT NOT NULL,
  protocol_version TEXT NOT NULL,
  server_time TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT
) STRICT;

CREATE TABLE projects (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  revision INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'active',
  policy_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE sources (
  id TEXT PRIMARY KEY,
  project_id TEXT REFERENCES projects(id),
  display_name TEXT NOT NULL,
  source_kind TEXT NOT NULL CHECK (source_kind IN ('git','folder')),
  repository_identity TEXT,
  revision INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE locations (
  id TEXT PRIMARY KEY,
  source_id TEXT NOT NULL REFERENCES sources(id),
  device_id TEXT NOT NULL REFERENCES devices(id),
  opaque_local_id TEXT NOT NULL,
  display_label TEXT NOT NULL,
  revision INTEGER NOT NULL DEFAULT 1,
  observed_state_json TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'active',
  last_observed_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(source_id, device_id, opaque_local_id)
) STRICT;

CREATE TABLE collaboration_sessions (
  id TEXT PRIMARY KEY,
  project_id TEXT REFERENCES projects(id),
  title TEXT NOT NULL,
  revision INTEGER NOT NULL DEFAULT 1,
  accepted_baseline_id TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE messages (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES collaboration_sessions(id),
  author_principal_id TEXT,
  origin TEXT NOT NULL,
  body TEXT NOT NULL CHECK (length(body) <= 32768),
  revision INTEGER NOT NULL DEFAULT 1,
  attachments_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE message_revisions (
  message_id TEXT NOT NULL REFERENCES messages(id),
  revision INTEGER NOT NULL CHECK (revision >= 1),
  body TEXT NOT NULL CHECK (length(body) <= 32768),
  editor_principal_id TEXT,
  created_at TEXT NOT NULL,
  PRIMARY KEY(message_id, revision)
) STRICT;

CREATE TABLE structured_mentions (
  id TEXT PRIMARY KEY,
  message_id TEXT NOT NULL REFERENCES messages(id),
  mention_type TEXT NOT NULL CHECK (mention_type IN ('project_agent','principal','assignment_proposal')),
  target_id TEXT NOT NULL,
  start_offset INTEGER NOT NULL,
  end_offset INTEGER NOT NULL,
  payload_json TEXT NOT NULL DEFAULT '{}'
) STRICT;

CREATE TABLE project_agents (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id),
  name TEXT NOT NULL,
  adapter_id TEXT NOT NULL,
  role TEXT NOT NULL,
  configuration_json TEXT NOT NULL,
  revision INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE assignments (
  id TEXT PRIMARY KEY,
  project_id TEXT REFERENCES projects(id),
  session_id TEXT REFERENCES collaboration_sessions(id),
  source_message_id TEXT REFERENCES messages(id),
  title TEXT NOT NULL,
  body TEXT NOT NULL CHECK (length(body) <= 32768),
  state TEXT NOT NULL CHECK (state IN ('draft','queued','active','waiting_input','waiting_approval','ready_for_review','accepted','rejected','cancelled','failed')),
  revision INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE assignment_transitions (
  id TEXT PRIMARY KEY,
  assignment_id TEXT NOT NULL REFERENCES assignments(id),
  from_state TEXT,
  to_state TEXT NOT NULL,
  reason_code TEXT NOT NULL,
  evidence_ref TEXT,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE runs (
  id TEXT PRIMARY KEY,
  assignment_id TEXT REFERENCES assignments(id),
  project_id TEXT REFERENCES projects(id),
  session_id TEXT REFERENCES collaboration_sessions(id),
  device_id TEXT NOT NULL REFERENCES devices(id),
  runtime_kind TEXT NOT NULL CHECK (runtime_kind IN ('native','restricted_native','container','vm')),
  access_scope TEXT NOT NULL CHECK (access_scope IN ('read_only','selected_sources','project_full','full_user','full_device','custom')),
  approval_mode TEXT NOT NULL CHECK (approval_mode IN ('always','outside_scope','risk_classes','never')),
  state TEXT NOT NULL,
  revision INTEGER NOT NULL DEFAULT 1,
  manifest_digest TEXT,
  manifest_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE run_transitions (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(id),
  from_state TEXT,
  to_state TEXT NOT NULL,
  receipt_kind TEXT NOT NULL,
  receipt_digest TEXT,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE operation_journal (
  id TEXT PRIMARY KEY,
  idempotency_key TEXT NOT NULL UNIQUE,
  actor_principal_id TEXT NOT NULL REFERENCES owner_principals(id),
  client_id TEXT NOT NULL,
  device_id TEXT NOT NULL REFERENCES devices(id),
  project_id TEXT REFERENCES projects(id),
  session_id TEXT REFERENCES collaboration_sessions(id),
  assignment_id TEXT REFERENCES assignments(id),
  run_id TEXT REFERENCES runs(id),
  connector_policy_id TEXT,
  connector_policy_revision INTEGER,
  capability TEXT NOT NULL,
  payload_digest TEXT NOT NULL,
  request_json TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('created','admitted','queued','offered','claimed','completed','failed','cancelled','expired','rejected','uncertain')),
  expires_at TEXT NOT NULL,
  result_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE idempotency_records (
  scope TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  payload_digest TEXT NOT NULL,
  operation_id TEXT NOT NULL REFERENCES operation_journal(id),
  state TEXT NOT NULL,
  response_status INTEGER,
  response_json TEXT,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY(scope, idempotency_key)
) STRICT;

CREATE TABLE effect_idempotency_records (
  scope TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  payload_digest TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('reserved','completed','uncertain')),
  response_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  PRIMARY KEY(scope,idempotency_key)
) STRICT;

CREATE TABLE approvals (
  id TEXT PRIMARY KEY,
  operation_id TEXT NOT NULL REFERENCES operation_journal(id),
  requester_principal_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  run_id TEXT,
  commitment_digest TEXT NOT NULL,
  operation_type TEXT NOT NULL,
  normalized_arguments_json TEXT NOT NULL,
  revisions_json TEXT NOT NULL,
  decision TEXT CHECK (decision IN ('approved','denied')),
  reuse_scope_json TEXT,
  expires_at TEXT NOT NULL,
  resolved_at TEXT,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE tasks (
  id TEXT PRIMARY KEY,
  project_id TEXT REFERENCES projects(id),
  session_id TEXT REFERENCES collaboration_sessions(id),
  assignment_id TEXT REFERENCES assignments(id),
  title TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL,
  revision INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE task_dependencies (
  task_id TEXT NOT NULL REFERENCES tasks(id),
  depends_on_task_id TEXT NOT NULL REFERENCES tasks(id),
  created_at TEXT NOT NULL,
  PRIMARY KEY(task_id, depends_on_task_id),
  CHECK(task_id <> depends_on_task_id)
) STRICT;

CREATE TABLE task_links (
  task_id TEXT NOT NULL REFERENCES tasks(id),
  link_kind TEXT NOT NULL CHECK (link_kind IN ('message','assignment','run','change_set','artifact')),
  target_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY(task_id, link_kind, target_id)
) STRICT;

CREATE TABLE artifacts (
  id TEXT PRIMARY KEY,
  run_id TEXT REFERENCES runs(id),
  project_id TEXT REFERENCES projects(id),
  artifact_kind TEXT NOT NULL,
  content_digest TEXT NOT NULL,
  bytes INTEGER NOT NULL CHECK (bytes >= 0),
  sensitivity TEXT NOT NULL,
  retention_class TEXT NOT NULL,
  custody TEXT NOT NULL CHECK (custody IN ('device','upload_pending','r2','exported','expired')),
  opaque_device_locator TEXT,
  r2_key TEXT,
  upload_policy_json TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE trace_indexes (
  run_id TEXT PRIMARY KEY REFERENCES runs(id),
  device_id TEXT NOT NULL REFERENCES devices(id),
  first_sequence TEXT NOT NULL,
  last_sequence TEXT NOT NULL,
  chain_hash TEXT NOT NULL,
  observability_state TEXT NOT NULL,
  event_counts_json TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE evidence_summaries (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(id),
  evidence_kind TEXT NOT NULL,
  evidence_level TEXT NOT NULL CHECK (evidence_level IN ('explicit','observed','inferred','unknown')),
  summary_json TEXT NOT NULL,
  source_digest TEXT,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE normalized_events (
  event_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(id),
  device_id TEXT NOT NULL REFERENCES devices(id),
  sequence TEXT NOT NULL,
  event_type TEXT NOT NULL,
  event_digest TEXT NOT NULL,
  chain_hash TEXT NOT NULL,
  evidence_level TEXT NOT NULL,
  sensitivity TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  ingested_at TEXT NOT NULL,
  UNIQUE(run_id, sequence),
  UNIQUE(run_id, event_id, event_digest)
) STRICT;

CREATE TABLE security_events (
  id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  principal_id TEXT,
  client_id TEXT,
  device_id TEXT,
  reason_code TEXT,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
) STRICT;

CREATE TRIGGER security_events_immutable_update
BEFORE UPDATE ON security_events BEGIN SELECT RAISE(ABORT, 'security_events are immutable'); END;
CREATE TRIGGER security_events_immutable_delete
BEFORE DELETE ON security_events BEGIN SELECT RAISE(ABORT, 'security_events are immutable'); END;

CREATE TRIGGER run_manifest_immutable
BEFORE UPDATE OF manifest_digest, manifest_json ON runs
WHEN OLD.manifest_digest IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'run manifest is immutable after commit'); END;
