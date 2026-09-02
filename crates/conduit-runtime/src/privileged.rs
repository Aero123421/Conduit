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
    os::fd::{AsRawFd, FromRawFd, RawFd},
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
    pub helper_receipts: Vec<HelperReceipt>,
}
impl PrivilegedRuntimeReceipt {
    pub fn final_helper_receipt(&self) -> &HelperReceipt {
        self.helper_receipts
            .last()
            .expect("privileged receipt chains are validated as non-empty")
    }
}
#[derive(Debug, Clone)]
pub struct PrivilegedPreparedRuntime {
    pub runtime: PreparedRuntime,
    pub helper_receipts: Vec<HelperReceipt>,
}
impl PrivilegedPreparedRuntime {
    pub fn final_helper_receipt(&self) -> &HelperReceipt {
        self.helper_receipts
            .last()
            .expect("privileged receipt chains are validated as non-empty")
    }
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
    pub fn attach_reconciled_privileged(
        &self,
        plan: LocalExecutionPlan,
        spec_digest: String,
    ) -> Result<PrivilegedRuntimeReceipt, RuntimeError> {
        let receipts = self
            .client
            .lock()
            .map_err(lock)?
            .reconcile(vec![plan.runtime_id.clone()])
            .map_err(helper)?;
        if receipts.is_empty() {
            return Err(RuntimeError::NotFound);
        }
        for receipt in &receipts {
            self.verify(receipt)?;
        }
        for pair in receipts.windows(2) {
            let previous_digest = pair[0]
                .digest()
                .map_err(|error| RuntimeError::Record(error.to_string()))?;
            if pair[1].claims.previous_receipt_digest.as_deref() != Some(previous_digest.as_str())
                || pair[1].claims.state_revision != pair[0].claims.state_revision + 1
                || pair[1].claims.runtime_id != pair[0].claims.runtime_id
            {
                return Err(RuntimeError::Uncertain(
                    "helper reconcile receipt chain linkage".into(),
                ));
            }
        }
        let receipt = receipts.last().expect("non-empty reconcile chain").clone();
        let plan_digest = plan
            .digest()
            .map_err(|error| RuntimeError::Record(error.to_string()))?;
        if receipt.claims.runtime_id != plan.runtime_id
            || receipt.claims.run_id != plan.run_id
            || receipt.claims.local_execution_plan_digest != plan_digest
            || receipt.claims.runtime_spec_digest != spec_digest
            || !matches!(
                receipt.claims.transition.as_str(),
                "prepared"
                    | "running"
                    | "paused"
                    | "stopped"
                    | "failed"
                    | "missing"
                    | "recovery_required"
            )
        {
            return Err(RuntimeError::IdentityMismatch);
        }
        let handle = handle(&plan.runtime_id, &spec_digest, &receipt);
        self.runtimes.lock().map_err(lock)?.insert(
            plan.runtime_id.clone(),
            RuntimeEntry {
                plan,
                receipt: receipt.clone(),
                spec_digest,
            },
        );
        Ok(privileged_receipt_from_handle(&handle, receipts))
    }
    pub fn prepare_privileged(
        &self,
        request: &RuntimeRequest,
        ticket: PrivilegeTicket,
        plan: LocalExecutionPlan,
    ) -> Result<PrivilegedPreparedRuntime, RuntimeError> {
        self.prepare_privileged_with_descriptors(request, ticket, plan, &[])
    }

    pub fn prepare_privileged_with_descriptors(
        &self,
        request: &RuntimeRequest,
        ticket: PrivilegeTicket,
        plan: LocalExecutionPlan,
        descriptors: &[RawFd],
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
        let receipts = self
            .client
            .lock()
            .map_err(lock)?
            .prepare_chain(ticket, plan.clone(), descriptors)
            .map_err(helper)?;
        self.verify_chain(&receipts, None, &["admitted", "prepared"])?;
        let receipt = receipts
            .last()
            .expect("verified receipt chain is non-empty")
            .clone();
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
            helper_receipts: receipts,
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
        let receipts = self
            .client
            .lock()
            .map_err(lock)?
            .start_chain(
                ticket,
                plan.digest()
                    .map_err(|e| RuntimeError::Record(e.to_string()))?,
            )
            .map_err(helper)?;
        let exact_replay = receipts.last() == Some(&entry.receipt);
        if exact_replay {
            self.verify_exact_replay_chain(
                &receipts,
                &entry.receipt,
                &["unit_created", "running"],
            )?;
        } else {
            self.verify_chain(
                &receipts,
                Some(&entry.receipt),
                &["unit_created", "running"],
            )?;
        }
        let receipt = receipts
            .last()
            .expect("verified receipt chain is non-empty")
            .clone();
        entry.receipt = receipt.clone();
        Ok(privileged_receipt(prepared, receipts))
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
        self.verify_chain(std::slice::from_ref(&receipt), Some(&entry.receipt), &[])?;
        entry.receipt = receipt.clone();
        Ok(privileged_receipt_from_handle(handle, vec![receipt]))
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
        self.verify_chain(std::slice::from_ref(&receipt), Some(&entry.receipt), &[])?;
        entry.receipt = receipt.clone();
        Ok(privileged_receipt_from_handle(handle, vec![receipt]))
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
        self.verify_chain(
            std::slice::from_ref(&receipt),
            Some(&entry.receipt),
            &["input_applied"],
        )?;
        entry.receipt = receipt.clone();
        Ok(privileged_receipt_from_handle(handle, vec![receipt]))
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
        self.verify_chain(
            std::slice::from_ref(&receipt),
            Some(&entry.receipt),
            &["pty_resized"],
        )?;
        entry.receipt = receipt.clone();
        Ok(privileged_receipt_from_handle(handle, vec![receipt]))
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
    fn verify_chain(
        &self,
        receipts: &[HelperReceipt],
        previous: Option<&HelperReceipt>,
        expected_transitions: &[&str],
    ) -> Result<(), RuntimeError> {
        verify_receipt_chain(receipts, previous, expected_transitions, |receipt| {
            self.verify(receipt)
        })
    }

    fn verify_exact_replay_chain(
        &self,
        receipts: &[HelperReceipt],
        current: &HelperReceipt,
        expected_transitions: &[&str],
    ) -> Result<(), RuntimeError> {
        verify_exact_replay_chain(receipts, current, expected_transitions, |receipt| {
            self.verify(receipt)
        })
    }
}

fn verify_exact_replay_chain(
    receipts: &[HelperReceipt],
    current: &HelperReceipt,
    expected_transitions: &[&str],
    verify: impl Fn(&HelperReceipt) -> Result<(), RuntimeError>,
) -> Result<(), RuntimeError> {
    if receipts.last() != Some(current)
        || receipts.len() != expected_transitions.len()
        || receipts
            .iter()
            .zip(expected_transitions)
            .any(|(receipt, transition)| receipt.claims.transition != *transition)
    {
        return Err(RuntimeError::Uncertain(
            "helper replay did not reproduce exact durable custody".into(),
        ));
    }
    for receipt in receipts {
        verify(receipt)?;
    }
    for pair in receipts.windows(2) {
        let previous_digest = pair[0]
            .digest()
            .map_err(|error| RuntimeError::Record(error.to_string()))?;
        if pair[1].claims.previous_receipt_digest.as_deref() != Some(previous_digest.as_str())
            || pair[1].claims.state_revision != pair[0].claims.state_revision + 1
            || pair[1].claims.runtime_id != pair[0].claims.runtime_id
            || pair[1].claims.operation_id != pair[0].claims.operation_id
        {
            return Err(RuntimeError::Uncertain(
                "helper replay receipt chain linkage is invalid".into(),
            ));
        }
    }
    Ok(())
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
        let helper_receipt = receipt.final_helper_receipt();
        Ok(CollectionReceipt {
            runtime_id: handle.runtime_id.clone(),
            collection_id: helper_receipt.claims.receipt_id.clone(),
            custody_complete: helper_receipt.claims.stdout_cursor
                == helper_receipt.claims.stderr_cursor,
            digest: helper_receipt
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
                self.inspect_privileged(&expected.handle).map(|receipt| {
                    let helper_receipt = receipt.final_helper_receipt();
                    ReconciliationReceipt {
                        runtime_id: expected.handle.runtime_id.clone(),
                        state: receipt.runtime.state,
                        reason_code: helper_receipt.claims.transition.clone(),
                        observed_identity: helper_receipt.claims.invocation_id.clone(),
                    }
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
        ManagedIoResponse::RegistrationBundle(_) => Err(RuntimeError::Uncertain(
            "helper returned registration evidence for a stream read".into(),
        )),
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
        "started" | "already_running" | "running" | "resumed" | "input_applied" | "pty_resized" => {
            RuntimeState::Running
        }
        "paused" => RuntimeState::Paused,
        "stopped" | "already_stopped" | "completed" => RuntimeState::Stopped,
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
    helper_receipts: Vec<HelperReceipt>,
) -> PrivilegedRuntimeReceipt {
    let receipt = helper_receipts
        .last()
        .expect("privileged receipt chains are validated as non-empty");
    privileged_receipt_from_handle(
        &handle(&prepared.runtime_id, &prepared.spec_digest, receipt),
        helper_receipts,
    )
}
fn privileged_receipt_from_handle(
    handle: &RuntimeHandle,
    helper_receipts: Vec<HelperReceipt>,
) -> PrivilegedRuntimeReceipt {
    let receipt = helper_receipts
        .last()
        .expect("privileged receipt chains are validated as non-empty");
    PrivilegedRuntimeReceipt {
        runtime: RuntimeStateReceipt {
            handle: handle.clone(),
            state: state(receipt),
            exit_code: receipt.claims.exit_code,
            evidence: evidence(),
        },
        helper_receipts,
    }
}
fn verify_receipt_chain(
    receipts: &[HelperReceipt],
    previous: Option<&HelperReceipt>,
    expected_transitions: &[&str],
    mut verify: impl FnMut(&HelperReceipt) -> Result<(), RuntimeError>,
) -> Result<(), RuntimeError> {
    if receipts.is_empty() {
        return Err(RuntimeError::Uncertain(
            "helper returned an empty receipt chain".into(),
        ));
    }
    if !expected_transitions.is_empty()
        && (receipts.len() != expected_transitions.len()
            || receipts
                .iter()
                .zip(expected_transitions)
                .any(|(receipt, transition)| receipt.claims.transition != *transition))
    {
        return Err(RuntimeError::Uncertain(
            "helper returned an incomplete custody boundary chain".into(),
        ));
    }
    for receipt in receipts {
        verify(receipt)?;
    }
    let first = &receipts[0];
    if let Some(previous) = previous {
        let previous_digest = previous
            .digest()
            .map_err(|error| RuntimeError::Record(error.to_string()))?;
        if first.claims.previous_receipt_digest.as_deref() != Some(previous_digest.as_str())
            || first.claims.state_revision != previous.claims.state_revision.saturating_add(1)
        {
            return Err(RuntimeError::Uncertain(
                "helper receipt chain does not extend local custody".into(),
            ));
        }
    } else if first.claims.previous_receipt_digest.is_some() {
        return Err(RuntimeError::Uncertain(
            "initial helper receipt unexpectedly extends unknown custody".into(),
        ));
    }
    for pair in receipts.windows(2) {
        let previous_digest = pair[0]
            .digest()
            .map_err(|error| RuntimeError::Record(error.to_string()))?;
        if pair[1].claims.previous_receipt_digest.as_deref() != Some(previous_digest.as_str())
            || pair[1].claims.state_revision != pair[0].claims.state_revision.saturating_add(1)
            || pair[1].claims.runtime_id != pair[0].claims.runtime_id
            || pair[1].claims.operation_id != pair[0].claims.operation_id
        {
            return Err(RuntimeError::Uncertain(
                "helper receipt chain linkage is invalid".into(),
            ));
        }
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use conduit_privileged_protocol::{PROTOCOL, ReceiptClaims, SignedClaims};
    use ed25519_dalek::SigningKey;

    fn signed_receipt(
        key: &SigningKey,
        revision: u64,
        transition: &str,
        operation_id: &str,
        previous_receipt_digest: Option<String>,
    ) -> HelperReceipt {
        SignedClaims::sign(
            "hkey_test",
            ReceiptClaims {
                protocol: PROTOCOL.into(),
                receipt_id: format!("receipt-{revision}"),
                installation_id: "installation-test".into(),
                receipt_key_id: "hkey_test".into(),
                helper_version: "test".into(),
                policy_revision: 1,
                policy_digest: "11".repeat(32),
                ticket_id: format!("ticket-{operation_id}"),
                ticket_digest: "22".repeat(32),
                operation_id: operation_id.into(),
                request_digest: "33".repeat(32),
                run_id: "run-test".into(),
                runtime_id: "runtime-test".into(),
                runtime_spec_digest: "44".repeat(32),
                launch_plan_digest: "55".repeat(32),
                local_execution_plan_digest: "66".repeat(32),
                control_request_digest: None,
                controller_epoch: 1,
                state_revision: revision,
                transition: transition.into(),
                unit_name: "conduit-elevated-test.service".into(),
                invocation_id: (revision >= 3).then(|| "invocation-test".into()),
                cgroup: None,
                main_pid: None,
                process_birth: None,
                effective_uid: None,
                effective_gid: None,
                stdout_cursor: 0,
                stderr_cursor: 0,
                exit_code: None,
                signal: None,
                observed_at: "2026-01-01T00:00:00Z".into(),
                previous_receipt_digest,
            },
            key,
        )
        .unwrap()
    }

    #[test]
    fn provider_exposes_all_four_prepare_and_start_custody_boundaries() {
        let key = SigningKey::from_bytes(&[73; 32]);
        let admitted = signed_receipt(&key, 1, "admitted", "prepare", None);
        let prepared = signed_receipt(
            &key,
            2,
            "prepared",
            "prepare",
            Some(admitted.digest().unwrap()),
        );
        let unit_created = signed_receipt(
            &key,
            3,
            "unit_created",
            "start",
            Some(prepared.digest().unwrap()),
        );
        let running = signed_receipt(
            &key,
            4,
            "running",
            "start",
            Some(unit_created.digest().unwrap()),
        );
        let prepared_chain = vec![admitted, prepared];
        let started_chain = vec![unit_created, running];
        verify_receipt_chain(
            &prepared_chain,
            None,
            &["admitted", "prepared"],
            |receipt| HelperClient::verify_receipt(receipt, &key.verifying_key()).map_err(helper),
        )
        .unwrap();
        verify_receipt_chain(
            &started_chain,
            prepared_chain.last(),
            &["unit_created", "running"],
            |receipt| HelperClient::verify_receipt(receipt, &key.verifying_key()).map_err(helper),
        )
        .unwrap();
        verify_exact_replay_chain(
            &started_chain,
            started_chain.last().unwrap(),
            &["unit_created", "running"],
            |receipt| HelperClient::verify_receipt(receipt, &key.verifying_key()).map_err(helper),
        )
        .unwrap();
        let exposed = prepared_chain
            .iter()
            .chain(&started_chain)
            .map(|receipt| receipt.claims.transition.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            exposed,
            vec!["admitted", "prepared", "unit_created", "running"]
        );
    }
}
