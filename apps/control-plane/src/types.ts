export interface SecretBindings {
  /** Set with `wrangler secret put BOOTSTRAP_VERIFIER`. */
  BOOTSTRAP_VERIFIER: string;
  /** Keyed hashing pepper for browser, OAuth, recovery, and enrollment tokens. */
  TOKEN_PEPPER: string;
  /** HMAC key used for signed server receipts. */
  RECEIPT_SIGNING_KEY: string;
}

export type ControlPlaneEnv = Env & SecretBindings;

export type AccessScope =
  | "read_only"
  | "selected_sources"
  | "project_full"
  | "full_user"
  | "full_device"
  | "custom";

export type ApprovalMode = "always" | "outside_scope" | "risk_classes" | "never";
export type ApprovalRiskClass =
  | "external_publish"
  | "secret_access"
  | "destructive_delete"
  | "elevation"
  | "production_deploy"
  | "device_admin"
  | "raw_log_export"
  | "lan_access"
  | "credential_export"
  | "runtime_management";
export type RuntimeKind = "native" | "restricted_native" | "container" | "vm";

export interface AuthActor {
  principalId: string;
  clientId: string;
  grantId?: string;
  policyId?: string;
  policyRevision?: number;
  scopes: string[];
  sessionKind?: "owner" | "recovery";
}

export interface QueueEventMessage {
  schemaVersion: 1;
  eventId: string;
  runId: string;
  deviceId: string;
  sequence: string;
  eventType: string;
  eventDigest: string;
  chainHash: string;
  evidenceLevel: "explicit" | "observed" | "inferred" | "unknown";
  sensitivity: string;
  payload: Record<string, unknown>;
  observedAt: string;
}

export type OperationRequest = Extract<import("@conduit/schema").NodeV1PostAuthFrame, { type: "operation.offer" }>["payload"]["operation"];
export type RuntimeRequest = OperationRequest["runtime"];
export type SourceRevision = OperationRequest["sourceRevisions"][number];
