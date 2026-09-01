//! Structured, version-probed adapters for Linux coding-agent CLIs.

mod catalog;
mod driver;
mod process;
mod types;

pub use catalog::{AdapterCatalog, AdapterProfile};
pub use driver::ProtocolDriver;
pub use process::AdapterChild;
pub use types::{
    AdapterCapability, AdapterError, AdapterEvent, AdapterEventKind, AdapterKind, AdapterOperation,
    AdapterProbe, AdapterProtocol, AdapterState, ApprovalBridgeOwnership, ApprovalContext,
    AuthenticationState, EffectiveAccessScope, EffectiveApprovalPolicy, EffectiveSandboxPolicy,
    LaunchRequest, LaunchSpec, ProtocolFrame, SupportLevel,
};
