-- Connector policy revisions are immutable snapshots recorded in
-- connector_policy_history. A grant retains the exact revision number but
-- must not foreign-key that snapshot to the mutable current-policy row.
PRAGMA foreign_keys=OFF;
CREATE TABLE oauth_grants_v2 (
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
INSERT INTO oauth_grants_v2 SELECT * FROM oauth_grants;
DROP TABLE oauth_grants;
ALTER TABLE oauth_grants_v2 RENAME TO oauth_grants;
CREATE INDEX idx_oauth_grants_client_status ON oauth_grants(client_id,status);
PRAGMA foreign_keys=ON;
UPDATE schema_versions SET version=6,applied_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE component='control_plane' AND version < 6;
