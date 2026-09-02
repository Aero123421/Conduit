use crate::{HelperError, Result};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use conduit_privileged_protocol::{HelperReceipt, HelperRequest, HelperResponse, SignedCapability};
use conduit_privileged_protocol::{MAX_DESCRIPTORS, MAX_PACKET_BYTES};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::{
    fs, io, mem,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    os::unix::{ffi::OsStrExt, fs::FileTypeExt},
    path::Path,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredentials {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

pub struct Packet {
    pub bytes: Vec<u8>,
    pub descriptors: Vec<OwnedFd>,
}

pub struct SeqpacketServer {
    fd: OwnedFd,
    unlink: Option<std::path::PathBuf>,
}
pub struct SeqpacketConnection {
    fd: OwnedFd,
    peer: PeerCredentials,
}
pub struct SeqpacketClient {
    fd: OwnedFd,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedStream {
    Stdout,
    Stderr,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StreamReadRequest {
    pub target: conduit_privileged_protocol::ControlTarget,
    pub stream: ManagedStream,
    pub cursor: u64,
    pub max_bytes: u32,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum ManagedIoRequest {
    ReadStream(StreamReadRequest),
    PolicyAttest,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum ManagedIoResponse {
    StreamChunk {
        data: Vec<u8>,
        next_cursor: u64,
        eof: bool,
        terminal: bool,
    },
    RegistrationBundle(crate::RegistrationBundle),
    Error {
        code: String,
        retryable: bool,
    },
}

impl SeqpacketServer {
    pub fn bind(path: &Path, mode: u32) -> Result<Self> {
        let parent = path
            .parent()
            .ok_or_else(|| HelperError::Authentication("socket parent missing".into()))?;
        let parent_metadata = fs::symlink_metadata(parent)?;
        if !parent_metadata.is_dir() || parent_metadata.file_type().is_symlink() {
            return Err(HelperError::Authentication("socket parent invalid".into()));
        }
        if path.exists() {
            let metadata = fs::symlink_metadata(path)?;
            if metadata.file_type().is_socket() {
                fs::remove_file(path)?;
            } else {
                return Err(HelperError::Authentication("socket path occupied".into()));
            }
        }
        let fd = socket()?;
        enable_passcred(fd.as_raw_fd())?;
        let (address, length) = address(path)?;
        cvt(unsafe { libc::bind(fd.as_raw_fd(), &address as *const _ as *const _, length) })?;
        let cpath = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| HelperError::Authentication("invalid socket path".into()))?;
        cvt(unsafe { libc::chmod(cpath.as_ptr(), mode) })?;
        cvt(unsafe { libc::listen(fd.as_raw_fd(), 64) })?;
        Ok(Self {
            fd,
            unlink: Some(path.into()),
        })
    }

    /// Takes ownership of a systemd socket-activated descriptor after checking
    /// both type and close-on-exec state.
    pub unsafe fn from_fd(fd: RawFd) -> Result<Self> {
        let mut ty = 0i32;
        let mut len = mem::size_of::<i32>() as libc::socklen_t;
        cvt(unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                (&mut ty as *mut i32).cast(),
                &mut len,
            )
        })?;
        if ty != libc::SOCK_SEQPACKET {
            return Err(HelperError::Authentication(
                "activated socket is not seqpacket".into(),
            ));
        }
        cvt(unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) })?;
        enable_passcred(fd)?;
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
            unlink: None,
        })
    }

    pub fn accept(&self) -> Result<SeqpacketConnection> {
        let fd = cvt(unsafe {
            libc::accept4(
                self.fd.as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        })?;
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let peer = peer_credentials(fd.as_raw_fd())?;
        Ok(SeqpacketConnection { fd, peer })
    }
}

impl Drop for SeqpacketServer {
    fn drop(&mut self) {
        if let Some(path) = &self.unlink {
            let _ = fs::remove_file(path);
        }
    }
}

impl SeqpacketConnection {
    pub fn peer_credentials(&self) -> PeerCredentials {
        self.peer
    }
    pub fn receive(&self) -> Result<Packet> {
        receive(self.fd.as_raw_fd(), Some(self.peer))
    }
    pub fn send(&self, bytes: &[u8], descriptors: &[RawFd]) -> Result<()> {
        send(self.fd.as_raw_fd(), bytes, descriptors)
    }
}

impl SeqpacketClient {
    pub fn connect(path: &Path) -> Result<Self> {
        let fd = socket()?;
        let (address, length) = address(path)?;
        cvt(unsafe { libc::connect(fd.as_raw_fd(), &address as *const _ as *const _, length) })?;
        Ok(Self { fd })
    }
    pub fn receive(&self) -> Result<Packet> {
        receive(self.fd.as_raw_fd(), None)
    }
    pub fn send(&self, bytes: &[u8], descriptors: &[RawFd]) -> Result<()> {
        send(self.fd.as_raw_fd(), bytes, descriptors)
    }
    pub fn call(&self, request: &HelperRequest, descriptors: &[RawFd]) -> Result<Packet> {
        let bytes = serde_jcs::to_vec(request)?;
        self.send(&bytes, descriptors)?;
        self.receive()
    }
    pub fn call_serialized<T: Serialize>(
        &self,
        request: &T,
        descriptors: &[RawFd],
    ) -> Result<Packet> {
        let bytes = serde_jcs::to_vec(request)?;
        self.send(&bytes, descriptors)?;
        self.receive()
    }
}

/// Typed Node-side facade. It performs the challenge/proof exchange before any
/// effectful request and preserves the helper receipt rather than translating it
/// into a weaker runtime-only receipt.
pub struct HelperClient {
    connection: SeqpacketClient,
    installation_id: String,
    policy_revision: u64,
}

impl HelperClient {
    pub fn connect_and_authenticate_with<F>(
        path: &Path,
        device_id: &str,
        node_boot_id: &str,
        sign: F,
    ) -> Result<Self>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>>,
    {
        let connection = SeqpacketClient::connect(path)?;
        let nonce = getrandom::u64().map_err(|e| HelperError::Policy(e.to_string()))?;
        let hello = HelperRequest::Hello {
            protocol_versions: vec![conduit_privileged_protocol::PROTOCOL.into()],
            device_id: device_id.into(),
            node_boot_id: node_boot_id.into(),
            nonce: hex::encode(nonce.to_ne_bytes()),
        };
        let challenge = match decode_response(connection.call(&hello, &[])?)? {
            HelperResponse::Challenge(v) => v,
            _ => {
                return Err(HelperError::Authentication(
                    "helper challenge missing".into(),
                ));
            }
        };
        let signature = URL_SAFE_NO_PAD.encode(sign(&serde_jcs::to_vec(&challenge)?)?);
        let response = decode_response(connection.call(
            &HelperRequest::Prove {
                challenge,
                signature,
            },
            &[],
        )?)?;
        match response {
            HelperResponse::Accepted {
                protocol,
                installation_id,
                policy_revision,
            } if protocol == conduit_privileged_protocol::PROTOCOL => Ok(Self {
                connection,
                installation_id,
                policy_revision,
            }),
            _ => Err(HelperError::Authentication("helper proof rejected".into())),
        }
    }

    pub fn connect_and_authenticate(
        path: &Path,
        device_id: &str,
        node_boot_id: &str,
        node_key: &SigningKey,
    ) -> Result<Self> {
        Self::connect_and_authenticate_with(path, device_id, node_boot_id, |bytes| {
            Ok(node_key.sign(bytes).to_bytes().to_vec())
        })
    }
    pub fn installation_id(&self) -> &str {
        &self.installation_id
    }
    pub fn policy_revision(&self) -> u64 {
        self.policy_revision
    }
    pub fn call(&self, request: &HelperRequest, descriptors: &[RawFd]) -> Result<HelperResponse> {
        decode_response(self.connection.call(request, descriptors)?)
    }
    pub fn probe(&self) -> Result<SignedCapability> {
        match self.call(&HelperRequest::Probe, &[])? {
            HelperResponse::Capability(v) => Ok(v),
            HelperResponse::Error { code, .. } => Err(HelperError::Denied(code)),
            _ => Err(HelperError::Protocol(
                conduit_privileged_protocol::ProtocolError::Invalid("capability response".into()),
            )),
        }
    }
    pub fn receipt(&self, request: &HelperRequest, descriptors: &[RawFd]) -> Result<HelperReceipt> {
        self.receipt_chain(request, descriptors)?
            .pop()
            .ok_or_else(|| HelperError::RecoveryRequired("empty receipt chain".into()))
    }
    pub fn receipt_chain(
        &self,
        request: &HelperRequest,
        descriptors: &[RawFd],
    ) -> Result<Vec<HelperReceipt>> {
        match self.call(request, descriptors)? {
            HelperResponse::Receipt(v) => Ok(vec![v]),
            HelperResponse::Receipts(values) if !values.is_empty() => Ok(values),
            HelperResponse::Receipts(_) => {
                Err(HelperError::RecoveryRequired("empty receipt chain".into()))
            }
            HelperResponse::Error { code, .. } => Err(HelperError::Denied(code)),
            _ => Err(HelperError::Protocol(
                conduit_privileged_protocol::ProtocolError::Invalid("receipt response".into()),
            )),
        }
    }
    pub fn prepare_chain(
        &self,
        ticket: conduit_privileged_protocol::PrivilegeTicket,
        plan: conduit_privileged_protocol::LocalExecutionPlan,
        descriptors: &[RawFd],
    ) -> Result<Vec<HelperReceipt>> {
        self.receipt_chain(&HelperRequest::Prepare { ticket, plan }, descriptors)
    }
    pub fn start_chain(
        &self,
        ticket: conduit_privileged_protocol::PrivilegeTicket,
        plan_digest: String,
    ) -> Result<Vec<HelperReceipt>> {
        self.receipt_chain(
            &HelperRequest::Start {
                ticket,
                plan_digest,
            },
            &[],
        )
    }
    pub fn prepare(
        &self,
        ticket: conduit_privileged_protocol::PrivilegeTicket,
        plan: conduit_privileged_protocol::LocalExecutionPlan,
    ) -> Result<HelperReceipt> {
        self.receipt(&HelperRequest::Prepare { ticket, plan }, &[])
    }
    pub fn prepare_with_descriptors(
        &self,
        ticket: conduit_privileged_protocol::PrivilegeTicket,
        plan: conduit_privileged_protocol::LocalExecutionPlan,
        descriptors: &[RawFd],
    ) -> Result<HelperReceipt> {
        self.receipt(&HelperRequest::Prepare { ticket, plan }, descriptors)
    }
    pub fn start(
        &self,
        ticket: conduit_privileged_protocol::PrivilegeTicket,
        plan_digest: String,
    ) -> Result<HelperReceipt> {
        self.receipt(
            &HelperRequest::Start {
                ticket,
                plan_digest,
            },
            &[],
        )
    }
    pub fn inspect(
        &self,
        target: conduit_privileged_protocol::ControlTarget,
    ) -> Result<HelperReceipt> {
        self.receipt(&HelperRequest::Inspect { target }, &[])
    }
    pub fn control(
        &self,
        ticket: conduit_privileged_protocol::PrivilegeTicket,
        target: conduit_privileged_protocol::ControlTarget,
        operation: conduit_privileged_protocol::PrivilegedOperation,
    ) -> Result<HelperReceipt> {
        self.receipt(
            &HelperRequest::Control {
                ticket,
                target,
                operation,
            },
            &[],
        )
    }
    pub fn send_input(
        &self,
        ticket: conduit_privileged_protocol::PrivilegeTicket,
        target: conduit_privileged_protocol::ControlTarget,
        descriptor: RawFd,
    ) -> Result<HelperReceipt> {
        self.receipt(
            &HelperRequest::Input {
                ticket,
                target,
                descriptor_index: 0,
            },
            &[descriptor],
        )
    }
    pub fn resize_pty(
        &self,
        ticket: conduit_privileged_protocol::PrivilegeTicket,
        target: conduit_privileged_protocol::ControlTarget,
        rows: u16,
        columns: u16,
    ) -> Result<HelperReceipt> {
        self.receipt(
            &HelperRequest::ResizePty {
                ticket,
                target,
                rows,
                columns,
            },
            &[],
        )
    }
    pub fn reconcile(&self, runtime_ids: Vec<String>) -> Result<Vec<HelperReceipt>> {
        match self.call(&HelperRequest::Reconcile { runtime_ids }, &[])? {
            HelperResponse::Receipt(receipt) => Ok(vec![receipt]),
            HelperResponse::Receipts(receipts) => Ok(receipts),
            HelperResponse::Error { code, .. } => Err(HelperError::Denied(code)),
            _ => Err(HelperError::Protocol(
                conduit_privileged_protocol::ProtocolError::Invalid("reconcile response".into()),
            )),
        }
    }
    pub fn read_stream(&self, request: StreamReadRequest) -> Result<ManagedIoResponse> {
        let packet = self
            .connection
            .call_serialized(&ManagedIoRequest::ReadStream(request), &[])?;
        if !packet.descriptors.is_empty() {
            return Err(HelperError::Authentication(
                "unexpected stream descriptors".into(),
            ));
        }
        Ok(conduit_privileged_protocol::decode_packet(&packet.bytes)?)
    }
    pub fn registration_bundle(&self) -> Result<crate::RegistrationBundle> {
        let packet = self
            .connection
            .call_serialized(&ManagedIoRequest::PolicyAttest, &[])?;
        if !packet.descriptors.is_empty() {
            return Err(HelperError::Authentication(
                "unexpected registration bundle descriptors".into(),
            ));
        }
        match conduit_privileged_protocol::decode_packet(&packet.bytes)? {
            ManagedIoResponse::RegistrationBundle(bundle) => Ok(bundle),
            ManagedIoResponse::Error { code, .. } => Err(HelperError::Denied(code)),
            _ => Err(HelperError::Protocol(
                conduit_privileged_protocol::ProtocolError::Invalid(
                    "registration bundle response".into(),
                ),
            )),
        }
    }
    pub fn verify_capability(value: &SignedCapability, key: &VerifyingKey) -> Result<()> {
        value.verify(key.as_bytes()).map_err(Into::into)
    }
    pub fn verify_receipt(value: &HelperReceipt, key: &VerifyingKey) -> Result<()> {
        value.verify(key.as_bytes()).map_err(Into::into)
    }
}

fn decode_response(packet: Packet) -> Result<HelperResponse> {
    if !packet.descriptors.is_empty() {
        return Err(HelperError::Authentication(
            "unexpected response descriptors".into(),
        ));
    }
    Ok(conduit_privileged_protocol::decode_packet(&packet.bytes)?)
}

fn socket() -> Result<OwnedFd> {
    let fd =
        cvt(unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) })?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn address(path: &Path) -> Result<(libc::sockaddr_un, libc::socklen_t)> {
    let bytes = path.as_os_str().as_bytes();
    let mut address: libc::sockaddr_un = unsafe { mem::zeroed() };
    if bytes.is_empty() || bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
        return Err(HelperError::Authentication(
            "invalid unix socket path".into(),
        ));
    }
    address.sun_family = libc::AF_UNIX as _;
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            address.sun_path.as_mut_ptr().cast(),
            bytes.len(),
        );
    }
    let length = (mem::size_of_val(&address.sun_family) + bytes.len() + 1) as libc::socklen_t;
    Ok((address, length))
}

fn peer_credentials(fd: RawFd) -> Result<PeerCredentials> {
    let mut credentials: libc::ucred = unsafe { mem::zeroed() };
    let mut length = mem::size_of::<libc::ucred>() as libc::socklen_t;
    cvt(unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    })?;
    if length as usize != mem::size_of::<libc::ucred>() || credentials.pid <= 0 {
        return Err(HelperError::Authentication(
            "invalid peer credentials".into(),
        ));
    }
    Ok(PeerCredentials {
        pid: credentials.pid as u32,
        uid: credentials.uid,
        gid: credentials.gid,
    })
}

fn send(fd: RawFd, bytes: &[u8], descriptors: &[RawFd]) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_PACKET_BYTES || descriptors.len() > MAX_DESCRIPTORS {
        return Err(HelperError::Protocol(
            conduit_privileged_protocol::ProtocolError::Invalid(
                "packet or descriptor bound".into(),
            ),
        ));
    }
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr() as *mut _,
        iov_len: bytes.len(),
    };
    let control_len = if descriptors.is_empty() {
        0
    } else {
        unsafe { libc::CMSG_SPACE((descriptors.len() * mem::size_of::<RawFd>()) as _) as usize }
    };
    let mut control = vec![0u8; control_len];
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    if !descriptors.is_empty() {
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = control.len();
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len =
                libc::CMSG_LEN((descriptors.len() * mem::size_of::<RawFd>()) as _) as _;
            std::ptr::copy_nonoverlapping(
                descriptors.as_ptr(),
                libc::CMSG_DATA(header).cast(),
                descriptors.len(),
            );
        }
    }
    let written = cvt_size(unsafe { libc::sendmsg(fd, &message, libc::MSG_NOSIGNAL) })? as usize;
    if written != bytes.len() {
        return Err(HelperError::Io(io::Error::new(
            io::ErrorKind::WriteZero,
            "short seqpacket send",
        )));
    }
    Ok(())
}

fn receive(fd: RawFd, expected_peer: Option<PeerCredentials>) -> Result<Packet> {
    let mut bytes = vec![0u8; MAX_PACKET_BYTES];
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut control = vec![
        0u8;
        unsafe {
            libc::CMSG_SPACE((MAX_DESCRIPTORS * mem::size_of::<RawFd>()) as _) as usize
                + libc::CMSG_SPACE(mem::size_of::<libc::ucred>() as _) as usize
        }
    ];
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len();
    let count =
        cvt_size(unsafe { libc::recvmsg(fd, &mut message, libc::MSG_CMSG_CLOEXEC) })? as usize;
    if count == 0 {
        return Err(HelperError::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "peer disconnected",
        )));
    }
    let mut descriptors = Vec::new();
    let mut credentials = None;
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&message);
        while !header.is_null() {
            if (*header).cmsg_len < libc::CMSG_LEN(0) as usize {
                close_all(&mut descriptors);
                return Err(HelperError::Authentication(
                    "malformed ancillary data".into(),
                ));
            }
            if (*header).cmsg_level == libc::SOL_SOCKET
                && (*header).cmsg_type == libc::SCM_CREDENTIALS
            {
                if (*header).cmsg_len as usize
                    != libc::CMSG_LEN(mem::size_of::<libc::ucred>() as _) as usize
                    || credentials.is_some()
                {
                    close_all(&mut descriptors);
                    return Err(HelperError::Authentication("malformed credentials".into()));
                }
                let value = *libc::CMSG_DATA(header).cast::<libc::ucred>();
                credentials = Some(PeerCredentials {
                    pid: value.pid as u32,
                    uid: value.uid,
                    gid: value.gid,
                });
                header = libc::CMSG_NXTHDR(&message, header);
                continue;
            }
            if (*header).cmsg_level != libc::SOL_SOCKET || (*header).cmsg_type != libc::SCM_RIGHTS {
                close_all(&mut descriptors);
                return Err(HelperError::Authentication(
                    "unexpected ancillary data".into(),
                ));
            }
            let data_len = (*header).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
            if data_len % mem::size_of::<RawFd>() != 0 {
                close_all(&mut descriptors);
                return Err(HelperError::Authentication(
                    "malformed ancillary data".into(),
                ));
            }
            let number = data_len / mem::size_of::<RawFd>();
            for index in 0..number {
                let raw = *libc::CMSG_DATA(header).cast::<RawFd>().add(index);
                descriptors.push(OwnedFd::from_raw_fd(raw));
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
    }
    if let Some(expected) = expected_peer {
        if credentials != Some(expected) {
            return Err(HelperError::Authentication(
                "SCM_CREDENTIALS mismatch".into(),
            ));
        }
    }
    if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
        || descriptors.len() > MAX_DESCRIPTORS
    {
        drop(descriptors);
        return Err(HelperError::Authentication(
            "truncated packet or ancillary data".into(),
        ));
    }
    bytes.truncate(count);
    Ok(Packet { bytes, descriptors })
}

fn close_all(descriptors: &mut Vec<OwnedFd>) {
    descriptors.clear();
}
fn cvt(value: i32) -> Result<i32> {
    if value < 0 {
        Err(HelperError::Io(io::Error::last_os_error()))
    } else {
        Ok(value)
    }
}
fn cvt_size(value: isize) -> Result<isize> {
    if value < 0 {
        Err(HelperError::Io(io::Error::last_os_error()))
    } else {
        Ok(value)
    }
}
fn enable_passcred(fd: RawFd) -> Result<()> {
    let enabled: libc::c_int = 1;
    cvt(unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PASSCRED,
            (&enabled as *const libc::c_int).cast(),
            mem::size_of_val(&enabled) as _,
        )
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::fd::AsRawFd, thread};
    use tempfile::tempdir;
    #[test]
    fn preserves_packet_boundary_peer_identity_and_cloexec_descriptors() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("helper.sock");
        let server = SeqpacketServer::bind(&path, 0o600).unwrap();
        let child = thread::spawn(move || {
            let connection = server.accept().unwrap();
            assert_eq!(connection.peer_credentials().uid, unsafe {
                libc::geteuid()
            });
            let packet = connection.receive().unwrap();
            assert_eq!(packet.bytes, b"request");
            assert_eq!(packet.descriptors.len(), 1);
            assert_ne!(
                unsafe { libc::fcntl(packet.descriptors[0].as_raw_fd(), libc::F_GETFD) }
                    & libc::FD_CLOEXEC,
                0
            );
            connection.send(b"response", &[]).unwrap();
        });
        let client = SeqpacketClient::connect(&path).unwrap();
        let file = fs::File::open("/dev/null").unwrap();
        client.send(b"request", &[file.as_raw_fd()]).unwrap();
        assert_eq!(client.receive().unwrap().bytes, b"response");
        child.join().unwrap();
    }

    #[test]
    fn rejects_oversize_packets_and_descriptor_manifests_before_send() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("helper.sock");
        let server = SeqpacketServer::bind(&path, 0o600).unwrap();
        let client = SeqpacketClient::connect(&path).unwrap();
        let file = fs::File::open("/dev/null").unwrap();
        assert!(client.send(&vec![b'x'; MAX_PACKET_BYTES + 1], &[]).is_err());
        assert!(
            client
                .send(b"request", &vec![file.as_raw_fd(); MAX_DESCRIPTORS + 1])
                .is_err()
        );
        drop(server);
    }
}
