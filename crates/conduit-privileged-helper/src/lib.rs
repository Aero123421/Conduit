//! Root-owned, networkless Linux privilege helper.
//!
//! The helper accepts only bounded typed requests over an authenticated local
//! `SOCK_SEQPACKET` connection. Every effect is reserved in the root journal
//! before the system manager is called, and every externally visible state is
//! represented by a helper-signed receipt.

mod journal;
mod service;
mod systemd;
mod transport;
mod worker;

pub use journal::{
    EffectDisposition, HelperJournal, JOURNAL_SCHEMA_VERSION, JournalEffect, RuntimeRecord,
};
pub use service::{
    AuthorityLock, HelperConfig, HelperEngine, PinnedTicketKeys, PolicyChangeEvidence, PublicJwk,
    PublicPolicyAttestation, PublicPolicySummary, RegistrationBundle, SystemdCapabilityProbe,
    build_registration_bundle, control_target_digest, load_receipt_key_root_owned,
    runtime_identity_matches,
};
pub use systemd::{FakeSystemd, SystemdBackend, SystemdManager, UnitObservation, UnitSpec};
pub use transport::{
    HelperClient, ManagedIoRequest, ManagedIoResponse, ManagedStream, Packet, PeerCredentials,
    SeqpacketClient, SeqpacketConnection, SeqpacketServer, StreamReadRequest,
};
pub use worker::{ExecutionRecord, capture_file_identity, run_exec_worker, verify_identity};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum HelperError {
    #[error("privileged protocol failed: {0}")]
    Protocol(#[from] conduit_privileged_protocol::ProtocolError),
    #[error("privileged journal failed: {0}")]
    Journal(String),
    #[error("privileged policy failed: {0}")]
    Policy(String),
    #[error("privileged authentication failed: {0}")]
    Authentication(String),
    #[error("privileged request denied: {0}")]
    Denied(String),
    #[error("privileged runtime recovery required: {0}")]
    RecoveryRequired(String),
    #[error("systemd operation failed: {0}")]
    Systemd(String),
    #[error("I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON failed: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, HelperError>;
