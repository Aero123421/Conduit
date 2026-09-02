use crate::{
    CapabilityEvidence, CapabilityReceipt, CapabilityState, CollectionReceipt, DestroyReceipt,
    DestroyRequest, ExpectedRuntime, LaunchPlan, ManagedIoPage, ManagedProcessIo, PreparedRuntime,
    ReconciliationReceipt, RuntimeAuthority, RuntimeError, RuntimeHandle, RuntimeKind,
    RuntimeProvider, RuntimeRequest, RuntimeSignal, RuntimeState, RuntimeStateReceipt,
    SnapshotReceipt, validate_request,
};
use conduit_privileged_helper::{
    HelperClient, ManagedIoResponse, ManagedStream, StreamReadRequest,
};
use conduit_privileged_protocol::{
    ControlTarget, HelperReceipt, LocalExecutionPlan, PrivilegeTicket, PrivilegedOperation,
};
use ed25519_dalek::VerifyingKey;
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Seek, SeekFrom, Write},
    os::fd::{AsRawFd, FromRawFd},
    sync::{Arc, Mutex},
};

pub trait PrivilegedTicketSource: Send + Sync {
    fn ticket(
        &self,
        runtime_id: &str,
        operation: PrivilegedOperation,
    ) -> Result<PrivilegeTicket, RuntimeError>;
}
#[derive(Debug, Clone)]
pub struct PrivilegedRuntimeReceipt {
    pub runtime: RuntimeStateReceipt,
    pub helper_receipt: HelperReceipt,
}
#[derive(Debug, Clone)]
pub struct PrivilegedPreparedRuntime {
    pub runtime: PreparedRuntime,
    pub helper_receipt: HelperReceipt,
}
pub struct PrivilegedManagedRuntime {
    pub io: Box<dyn ManagedProcessIo>,
    pub receipt: PrivilegedRuntimeReceipt,
}

#[derive(Clone)]
struct RuntimeEntry {
    plan: LocalExecutionPlan,
    receipt: HelperReceipt,
    spec_digest: String,
}
pub struct PrivilegedNativeProvider {
    client: Arc<Mutex<HelperClient>>,
    receipt_key: VerifyingKey,
    runtimes: Arc<Mutex<BTreeMap<String, RuntimeEntry>>>,
    tickets: Option<Arc<dyn PrivilegedTicketSource>>,
}

impl PrivilegedNativeProvider {
    pub fn new(client: HelperClient, receipt_key: VerifyingKey) -> Self {
        Self {
            client: Arc::new(Mutex::new(client)),
            receipt_key,
            runtimes: Arc::new(Mutex::new(BTreeMap::new())),
            tickets: None,
        }
    }
    pub fn with_ticket_source(mut self, source: Arc<dyn PrivilegedTicketSource>) -> Self {
        self.tickets = Some(source);
        self
    }
    pub fn prepare_privileged(
        &self,
        request: &RuntimeRequest,
        ticket: PrivilegeTicket,
        plan: LocalExecutionPlan,
    ) -> Result<PrivilegedPreparedRuntime, RuntimeError> {
        validate_request(request, RuntimeKind::Native, &["privileged-native"])?;
        if ticket.claims.allowed_operation != PrivilegedOperation::Prepare
            || plan.runtime_id != request.runtime_id
            || plan.run_id != request.run_id
            || ticket.claims.runtime_spec_digest != request.spec_digest
        {
            return Err(RuntimeError::Invalid(
                "privileged prepare authority mismatch".into(),
            ));
        }
        let receipt = self
            .client
            .lock()
            .map_err(lock)?
            .prepare(ticket, plan.clone())
            .map_err(helper)?;
        self.verify(&receipt)?;
        let runtime = PreparedRuntime {
            runtime_id: request.runtime_id.clone(),
            provider_id: "privileged-native".into(),
            spec_digest: request.spec_digest.clone(),
            object_id: receipt.claims.unit_name.clone(),
            state: RuntimeState::Prepared,
            evidence: evidence(),
        };
        self.runtimes.lock().map_err(lock)?.insert(
            request.runtime_id.clone(),
            RuntimeEntry {
                plan,
                receipt: receipt.clone(),
                spec_digest: request.spec_digest.clone(),
            },
        );
        Ok(PrivilegedPreparedRuntime {
            runtime,
            helper_receipt: receipt,
        })
    }
    pub fn start_privileged(
        &self,
        prepared: &PreparedRuntime,
        ticket: PrivilegeTicket,
        plan: &LocalExecutionPlan,
    ) -> Result<PrivilegedRuntimeReceipt, RuntimeError> {
        if ticket.claims.allowed_operation != PrivilegedOperation::Start {
            return Err(RuntimeError::Invalid("start ticket required".into()));
        }
        let mut records = self.runtimes.lock().map_err(lock)?;
        let entry = records
            .get_mut(&prepared.runtime_id)
            .ok_or(RuntimeError::NotFound)?;
        if &entry.plan != plan || entry.spec_digest != prepared.spec_digest {
            return Err(RuntimeError::IdentityMismatch);
        }
        let receipt = self
            .client
            .lock()
            .map_err(lock)?
            .start(
                ticket,
                plan.digest()
                    .map_err(|e| RuntimeError::Record(e.to_string()))?,
            )
            .map_err(helper)?;
        self.verify(&receipt)?;
        entry.receipt = receipt.clone();
        Ok(privileged_receipt(prepared, &receipt))
    }
    pub fn inspect_privileged(
        &self,
        handle: &RuntimeHandle,
    ) -> Result<PrivilegedRuntimeReceipt, RuntimeError> {
        let mut records = self.runtimes.lock().map_err(lock)?;
        let entry = records
            .get_mut(&handle.runtime_id)
            .ok_or(RuntimeError::NotFound)?;
        let target = target(handle, &entry.receipt)?;
        let receipt = self
            .client
            .lock()
            .map_err(lock)?
            .inspect(target)
            .map_err(helper)?;
        self.verify(&receipt)?;
        entry.receipt = receipt.clone();
        Ok(privileged_receipt_from_handle(handle, &receipt))
    }
    pub fn control_privileged(
        &self,
        handle: &RuntimeHandle,
        signal: RuntimeSignal,
        ticket: PrivilegeTicket,
    ) -> Result<PrivilegedRuntimeReceipt, RuntimeError> {
        let operation = signal_operation(signal);
        if ticket.claims.allowed_operation != operation {
            return Err(RuntimeError::Invalid(
                "control ticket operation mismatch".into(),
            ));
        }
        let mut records = self.runtimes.lock().map_err(lock)?;
        let entry = records
            .get_mut(&handle.runtime_id)
            .ok_or(RuntimeError::NotFound)?;
        let receipt = self
            .client
            .lock()
            .map_err(lock)?
            .control(ticket, target(handle, &entry.receipt)?, operation)
            .map_err(helper)?;
        self.verify(&receipt)?;
        entry.receipt = receipt.clone();
        Ok(privileged_receipt_from_handle(handle, &receipt))
    }
    pub fn input_authorized(
        &self,
        handle: &RuntimeHandle,
        bytes: &[u8],
        ticket: PrivilegeTicket,
    ) -> Result<PrivilegedRuntimeReceipt, RuntimeError> {
        if ticket.claims.allowed_operation != PrivilegedOperation::Input {
            return Err(RuntimeError::Invalid("input ticket required".into()));
        }
        let mut records = self.runtimes.lock().map_err(lock)?;
        let entry = records
            .get_mut(&handle.runtime_id)
            .ok_or(RuntimeError::NotFound)?;
        let name = std::ffi::CString::new("conduit-input").unwrap();
        let raw = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
        if raw < 0 {
            return Err(RuntimeError::Io(std::io::Error::last_os_error()));
        }
        let mut file = unsafe { File::from_raw_fd(raw) };
        file.write_all(bytes)?;
        file.seek(SeekFrom::Start(0))?;
        let receipt = self
            .client
            .lock()
            .map_err(lock)?
            .send_input(ticket, target(handle, &entry.receipt)?, file.as_raw_fd())
            .map_err(helper)?;
        self.verify(&receipt)?;
        entry.receipt = receipt.clone();
        Ok(privileged_receipt_from_handle(handle, &receipt))
    }
    pub fn resize_authorized(
        &self,
        handle: &RuntimeHandle,
        rows: u16,
        columns: u16,
        ticket: PrivilegeTicket,
    ) -> Result<PrivilegedRuntimeReceipt, RuntimeError> {
        if ticket.claims.allowed_operation != PrivilegedOperation::ResizePty {
            return Err(RuntimeError::Invalid("resize ticket required".into()));
        }
        let mut records = self.runtimes.lock().map_err(lock)?;
        let entry = records
            .get_mut(&handle.runtime_id)
            .ok_or(RuntimeError::NotFound)?;
        let receipt = self
            .client
            .lock()
            .map_err(lock)?
            .resize_pty(ticket, target(handle, &entry.receipt)?, rows, columns)
            .map_err(helper)?;
        self.verify(&receipt)?;
        entry.receipt = receipt.clone();
        Ok(privileged_receipt_from_handle(handle, &receipt))
    }
    pub fn start_managed_privileged(
        &self,
        prepared: &PreparedRuntime,
        ticket: PrivilegeTicket,
        plan: &LocalExecutionPlan,
    ) -> Result<PrivilegedManagedRuntime, RuntimeError> {
        let receipt = self.start_privileged(prepared, ticket, plan)?;
        let source = self.tickets.clone().ok_or_else(|| {
            RuntimeError::CapabilityUnavailable("privileged managed I/O ticket source".into())
        })?;
        let io = PrivilegedIo {
            client: self.client.clone(),
            receipt_key: self.receipt_key,
            records: self.runtimes.clone(),
            runtime_id: prepared.runtime_id.clone(),
            ticket_source: source,
        };
        Ok(PrivilegedManagedRuntime {
            io: Box::new(io),
            receipt,
        })
    }
    fn verify(&self, receipt: &HelperReceipt) -> Result<(), RuntimeError> {
        HelperClient::verify_receipt(receipt, &self.receipt_key).map_err(helper)
    }
}

impl RuntimeProvider for PrivilegedNativeProvider {
    fn provider_id(&self) -> &str {
        "privileged-native"
    }
    fn probe(&self) -> Result<CapabilityReceipt, RuntimeError> {
        let capability = self.client.lock().map_err(lock)?.probe().map_err(helper)?;
        HelperClient::verify_capability(&capability, &self.receipt_key).map_err(helper)?;
        Ok(CapabilityReceipt {
            provider_id: self.provider_id().into(),
            provider_version: Some(capability.claims.helper_version),
            capabilities: evidence(),
        })
    }
    fn prepare(&self, _: &RuntimeRequest) -> Result<PreparedRuntime, RuntimeError> {
        Err(RuntimeError::CapabilityUnavailable(
            "signed privilege ticket".into(),
        ))
    }
    fn start(
        &self,
        _: &PreparedRuntime,
        _: &LaunchPlan,
    ) -> Result<RuntimeStateReceipt, RuntimeError> {
        Err(RuntimeError::CapabilityUnavailable(
            "signed start ticket".into(),
        ))
    }
    fn inspect(&self, _: &RuntimeHandle) -> Result<RuntimeStateReceipt, RuntimeError> {
        Err(RuntimeError::CapabilityUnavailable(
            "privileged authority".into(),
        ))
    }
    fn signal(
        &self,
        _: &RuntimeHandle,
        _: RuntimeSignal,
    ) -> Result<RuntimeStateReceipt, RuntimeError> {
        Err(RuntimeError::CapabilityUnavailable(
            "signed control ticket".into(),
        ))
    }
    fn snapshot(&self, _: &RuntimeHandle, _: &str) -> Result<SnapshotReceipt, RuntimeError> {
        Err(RuntimeError::CapabilityUnavailable(
            "privileged snapshot".into(),
        ))
    }
    fn collect(&self, handle: &RuntimeHandle) -> Result<CollectionReceipt, RuntimeError> {
        let receipt = self.inspect_privileged(handle)?;
        Ok(CollectionReceipt {
            runtime_id: handle.runtime_id.clone(),
            collection_id: receipt.helper_receipt.claims.receipt_id.clone(),
            custody_complete: receipt.helper_receipt.claims.stdout_cursor
                == receipt.helper_receipt.claims.stderr_cursor,
            digest: receipt
                .helper_receipt
                .digest()
                .map_err(|e| RuntimeError::Record(e.to_string()))?,
        })
    }
    fn destroy(
        &self,
        _: &RuntimeHandle,
        _: &DestroyRequest,
    ) -> Result<DestroyReceipt, RuntimeError> {
        Err(RuntimeError::CapabilityUnavailable(
            "explicit stopped runtime purge".into(),
        ))
    }
    fn reconcile(
        &self,
        records: &[ExpectedRuntime],
    ) -> Result<Vec<ReconciliationReceipt>, RuntimeError> {
        records
            .iter()
            .map(|expected| {
                self.inspect_privileged(&expected.handle)
                    .map(|receipt| ReconciliationReceipt {
                        runtime_id: expected.handle.runtime_id.clone(),
                        state: receipt.runtime.state,
                        reason_code: receipt.helper_receipt.claims.transition,
                        observed_identity: receipt.helper_receipt.claims.invocation_id,
                    })
            })
            .collect()
    }
    fn prepare_authorized(
        &self,
        request: &RuntimeRequest,
        authority: &RuntimeAuthority,
    ) -> Result<PreparedRuntime, RuntimeError> {
        match authority {
            RuntimeAuthority::Privileged(value) => Ok(self
                .prepare_privileged(request, value.ticket.clone(), value.plan.clone())?
                .runtime),
            _ => Err(RuntimeError::CapabilityUnavailable(
                "privileged authority".into(),
            )),
        }
    }
    fn start_authorized(
        &self,
        prepared: &PreparedRuntime,
        _: &LaunchPlan,
        authority: &RuntimeAuthority,
    ) -> Result<RuntimeStateReceipt, RuntimeError> {
        match authority {
            RuntimeAuthority::Privileged(value) => Ok(self
                .start_privileged(prepared, value.ticket.clone(), &value.plan)?
                .runtime),
            _ => Err(RuntimeError::CapabilityUnavailable(
                "privileged authority".into(),
            )),
        }
    }
    fn inspect_authorized(
        &self,
        handle: &RuntimeHandle,
        authority: &RuntimeAuthority,
    ) -> Result<RuntimeStateReceipt, RuntimeError> {
        if !matches!(authority, RuntimeAuthority::Privileged(_)) {
            return Err(RuntimeError::CapabilityUnavailable(
                "privileged authority".into(),
            ));
        }
        Ok(self.inspect_privileged(handle)?.runtime)
    }
    fn signal_authorized(
        &self,
        handle: &RuntimeHandle,
        signal: RuntimeSignal,
        authority: &RuntimeAuthority,
    ) -> Result<RuntimeStateReceipt, RuntimeError> {
        match authority {
            RuntimeAuthority::Privileged(value) => Ok(self
                .control_privileged(handle, signal, value.ticket.clone())?
                .runtime),
            _ => Err(RuntimeError::CapabilityUnavailable(
                "privileged authority".into(),
            )),
        }
    }
}

struct PrivilegedIo {
    client: Arc<Mutex<HelperClient>>,
    receipt_key: VerifyingKey,
    records: Arc<Mutex<BTreeMap<String, RuntimeEntry>>>,
    runtime_id: String,
    ticket_source: Arc<dyn PrivilegedTicketSource>,
}
impl PrivilegedIo {
    fn with_target<T>(
        &self,
        f: impl FnOnce(&HelperClient, ControlTarget) -> Result<T, RuntimeError>,
    ) -> Result<T, RuntimeError> {
        let records = self.records.lock().map_err(lock)?;
        let entry = records
            .get(&self.runtime_id)
            .ok_or(RuntimeError::NotFound)?;
        let handle = handle(&self.runtime_id, &entry.spec_digest, &entry.receipt);
        let target = target(&handle, &entry.receipt)?;
        let client = self.client.lock().map_err(lock)?;
        f(&client, target)
    }
    fn update(&self, receipt: HelperReceipt) -> Result<(), RuntimeError> {
        HelperClient::verify_receipt(&receipt, &self.receipt_key).map_err(helper)?;
        self.records
            .lock()
            .map_err(lock)?
            .get_mut(&self.runtime_id)
            .ok_or(RuntimeError::NotFound)?
            .receipt = receipt;
        Ok(())
    }
}
impl ManagedProcessIo for PrivilegedIo {
    fn write_input(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        let ticket = self
            .ticket_source
            .ticket(&self.runtime_id, PrivilegedOperation::Input)?;
        let name = std::ffi::CString::new("conduit-input").unwrap();
        let raw = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
        if raw < 0 {
            return Err(RuntimeError::Io(std::io::Error::last_os_error()));
        }
        let mut file = unsafe { File::from_raw_fd(raw) };
        file.write_all(bytes)?;
        file.seek(SeekFrom::Start(0))?;
        let receipt = self.with_target(|client, target| {
            client
                .send_input(ticket, target, file.as_raw_fd())
                .map_err(helper)
        })?;
        self.update(receipt)
    }
    fn close_input(&mut self) -> Result<(), RuntimeError> {
        self.write_input(&[])
    }
    fn read_stdout(
        &mut self,
        cursor: u64,
        max_bytes: usize,
    ) -> Result<ManagedIoPage, RuntimeError> {
        read(self, ManagedStream::Stdout, cursor, max_bytes)
    }
    fn read_stderr(
        &mut self,
        cursor: u64,
        max_bytes: usize,
    ) -> Result<ManagedIoPage, RuntimeError> {
        read(self, ManagedStream::Stderr, cursor, max_bytes)
    }
    fn resize_pty(&mut self, rows: u16, columns: u16) -> Result<(), RuntimeError> {
        let ticket = self
            .ticket_source
            .ticket(&self.runtime_id, PrivilegedOperation::ResizePty)?;
        let receipt = self.with_target(|client, target| {
            client
                .resize_pty(ticket, target, rows, columns)
                .map_err(helper)
        })?;
        self.update(receipt)
    }
}
fn read(
    io: &PrivilegedIo,
    stream: ManagedStream,
    cursor: u64,
    max_bytes: usize,
) -> Result<ManagedIoPage, RuntimeError> {
    let response = io.with_target(|client, target| {
        client
            .read_stream(StreamReadRequest {
                target,
                stream,
                cursor,
                max_bytes: u32::try_from(max_bytes)
                    .map_err(|_| RuntimeError::Invalid("read bound".into()))?,
            })
            .map_err(helper)
    })?;
    match response {
        ManagedIoResponse::StreamChunk {
            data,
            next_cursor,
            eof,
            ..
        } => Ok(ManagedIoPage {
            bytes: data,
            next_cursor,
            eof,
        }),
        ManagedIoResponse::Error { code, .. } => Err(RuntimeError::Provider { code }),
    }
}
fn evidence() -> Vec<CapabilityEvidence> {
    vec![CapabilityEvidence {
        capability: "full_device".into(),
        state: CapabilityState::Effective,
        source: "helper_signed_capability".into(),
        reason_code: "effective".into(),
        detail: "root helper and systemd system manager".into(),
    }]
}
fn helper(error: conduit_privileged_helper::HelperError) -> RuntimeError {
    RuntimeError::Provider {
        code: error.to_string(),
    }
}
fn lock<T>(_: std::sync::PoisonError<T>) -> RuntimeError {
    RuntimeError::Uncertain("privileged provider lock poisoned".into())
}
fn signal_operation(signal: RuntimeSignal) -> PrivilegedOperation {
    match signal {
        RuntimeSignal::GracefulStop => PrivilegedOperation::GracefulStop,
        RuntimeSignal::ForceStop => PrivilegedOperation::ForceStop,
        RuntimeSignal::Pause => PrivilegedOperation::Pause,
        RuntimeSignal::Resume => PrivilegedOperation::Resume,
    }
}
fn state(receipt: &HelperReceipt) -> RuntimeState {
    match receipt.claims.transition.as_str() {
        "prepared" => RuntimeState::Prepared,
        "started" | "already_running" | "running" | "input_applied" | "pty_resized" => {
            RuntimeState::Running
        }
        "paused" => RuntimeState::Paused,
        "stopped" | "already_stopped" => RuntimeState::Stopped,
        "failed" => RuntimeState::Failed,
        "recovery_required" | "missing" => RuntimeState::RecoveryRequired,
        _ => RuntimeState::Uncertain,
    }
}
fn handle(runtime_id: &str, spec_digest: &str, receipt: &HelperReceipt) -> RuntimeHandle {
    RuntimeHandle {
        runtime_id: runtime_id.into(),
        provider_id: "privileged-native".into(),
        spec_digest: spec_digest.into(),
        object_id: receipt.claims.unit_name.clone(),
        process_identity: receipt.claims.invocation_id.clone(),
    }
}
fn privileged_receipt(
    prepared: &PreparedRuntime,
    receipt: &HelperReceipt,
) -> PrivilegedRuntimeReceipt {
    privileged_receipt_from_handle(
        &handle(&prepared.runtime_id, &prepared.spec_digest, receipt),
        receipt,
    )
}
fn privileged_receipt_from_handle(
    handle: &RuntimeHandle,
    receipt: &HelperReceipt,
) -> PrivilegedRuntimeReceipt {
    PrivilegedRuntimeReceipt {
        runtime: RuntimeStateReceipt {
            handle: handle.clone(),
            state: state(receipt),
            exit_code: receipt.claims.exit_code,
            evidence: evidence(),
        },
        helper_receipt: receipt.clone(),
    }
}
fn target(handle: &RuntimeHandle, receipt: &HelperReceipt) -> Result<ControlTarget, RuntimeError> {
    let invocation = receipt
        .claims
        .invocation_id
        .clone()
        .ok_or_else(|| RuntimeError::Uncertain("helper invocation missing".into()))?;
    let mut target = ControlTarget {
        runtime_id: handle.runtime_id.clone(),
        unit_name: receipt.claims.unit_name.clone(),
        invocation_id: invocation,
        controller_epoch: receipt.claims.controller_epoch,
        expected_state_revision: receipt.claims.state_revision,
        runtime_handle_digest: String::new(),
    };
    target.runtime_handle_digest =
        conduit_privileged_helper::control_target_digest(&target).map_err(helper)?;
    Ok(target)
}
