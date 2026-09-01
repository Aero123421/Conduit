use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs,
    io::{Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

pub const MAX_IPC_FRAME: usize = 1024 * 1024;
#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    #[error("IPC I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("IPC peer is not the node owner")]
    PeerDenied,
    #[error("IPC frame exceeds bound")]
    FrameTooLarge,
    #[error("IPC frame malformed")]
    Malformed,
    #[error("IPC endpoint is unsafe")]
    UnsafeEndpoint,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct IpcRequest {
    pub request_id: String,
    pub method: String,
    #[serde(default)]
    pub version: Option<u32>,
    #[serde(default)]
    pub revision: Option<u64>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
    #[serde(default)]
    pub params: Value,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct IpcResponse {
    pub request_id: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<IpcFailure>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct IpcFailure {
    pub code: String,
    pub message: String,
    pub retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}
pub trait IpcHandler: Send + Sync + 'static {
    fn handle(&self, request: &IpcRequest) -> Result<Value, String>;
}

pub struct IpcServer {
    path: PathBuf,
    listener: UnixListener,
    owner_uid: u32,
    stopping: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
}
impl IpcServer {
    pub fn bind(path: impl AsRef<Path>) -> Result<Self, IpcError> {
        let path = path.as_ref().to_path_buf();
        if !path.is_absolute() || has_symlink_component(&path)? {
            return Err(IpcError::UnsafeEndpoint);
        }
        if let Some(parent) = path.parent()
            && !parent.exists()
        {
            fs::create_dir_all(parent)?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
        if let Some(parent) = path.parent() {
            let meta = fs::symlink_metadata(parent)?;
            if !meta.file_type().is_dir()
                || meta.uid() != unsafe { libc::geteuid() }
                || meta.permissions().mode() & 0o077 != 0
            {
                return Err(IpcError::UnsafeEndpoint);
            }
        }
        if let Ok(meta) = fs::symlink_metadata(&path) {
            if !meta.file_type().is_socket()
                || meta.uid() != unsafe { libc::geteuid() }
                || meta.permissions().mode() & 0o777 != 0o600
            {
                return Err(IpcError::UnsafeEndpoint);
            }
            fs::remove_file(&path)?;
        }
        let listener = UnixListener::bind(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let socket_meta = fs::symlink_metadata(&path)?;
        if !socket_meta.file_type().is_socket()
            || socket_meta.uid() != unsafe { libc::geteuid() }
            || socket_meta.permissions().mode() & 0o777 != 0o600
        {
            return Err(IpcError::UnsafeEndpoint);
        }
        Ok(Self {
            path,
            listener,
            owner_uid: unsafe { libc::geteuid() },
            stopping: Arc::new(AtomicBool::new(false)),
            active: Arc::new(AtomicUsize::new(0)),
        })
    }
    pub fn local_addr(&self) -> &Path {
        &self.path
    }
    pub fn stop_handle(&self) -> Arc<AtomicBool> {
        self.stopping.clone()
    }
    pub fn serve(self, handler: Arc<dyn IpcHandler>) -> Result<(), IpcError> {
        self.listener.set_nonblocking(false)?;
        while !self.stopping.load(Ordering::Relaxed) {
            let (stream, _) = self.listener.accept()?;
            if peer_uid(&stream)? != self.owner_uid {
                continue;
            }
            if self.active.fetch_add(1, Ordering::AcqRel) >= 32 {
                self.active.fetch_sub(1, Ordering::AcqRel);
                continue;
            }
            let h = handler.clone();
            let active = self.active.clone();
            std::thread::spawn(move || {
                struct Guard(Arc<AtomicUsize>);
                impl Drop for Guard {
                    fn drop(&mut self) {
                        self.0.fetch_sub(1, Ordering::AcqRel);
                    }
                }
                let _guard = Guard(active);
                let _ = serve_peer(stream, h);
            });
        }
        Ok(())
    }
}
fn has_symlink_component(path: &Path) -> Result<bool, IpcError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        if current == path {
            break;
        }
        match fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(IpcError::Io(error)),
        }
    }
    Ok(false)
}
impl Drop for IpcServer {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
fn peer_uid(stream: &UnixStream) -> Result<u32, IpcError> {
    unsafe {
        let fd = std::os::fd::AsRawFd::as_raw_fd(stream);
        let mut cred: libc::ucred = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        if libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut _,
            &mut len,
        ) != 0
        {
            return Err(IpcError::Io(std::io::Error::last_os_error()));
        }
        if len as usize != std::mem::size_of::<libc::ucred>() {
            return Err(IpcError::PeerDenied);
        }
        Ok(cred.uid)
    }
}
fn serve_peer(mut stream: UnixStream, handler: Arc<dyn IpcHandler>) -> Result<(), IpcError> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    loop {
        let request: IpcRequest = match read_frame(&mut stream) {
            Ok(v) => v,
            Err(IpcError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        if request.request_id.is_empty()
            || request.request_id.len() > 128
            || request.method.is_empty()
            || request.method.len() > 128
            || request
                .idempotency_key
                .as_ref()
                .is_some_and(|v| v.len() > 256)
        {
            return Err(IpcError::Malformed);
        }
        let response = match handler.handle(&request) {
            Ok(v) => IpcResponse {
                request_id: request.request_id,
                ok: true,
                result: Some(v),
                error: None,
            },
            Err(e) => IpcResponse {
                request_id: request.request_id,
                ok: false,
                result: None,
                error: Some(failure(&e)),
            },
        };
        write_frame(&mut stream, &response)?;
    }
}
fn failure(message: &str) -> IpcFailure {
    let bounded: String = message.chars().take(512).collect();
    if let Some(method) = bounded.strip_prefix("capability_unavailable:") {
        IpcFailure {
            code: "capability_unavailable".into(),
            message: "the installed node does not implement this local capability".into(),
            retryable: false,
            details: Some(serde_json::json!({"method": method})),
        }
    } else if bounded == "method_unknown" {
        IpcFailure {
            code: "method_unknown".into(),
            message: bounded,
            retryable: false,
            details: None,
        }
    } else {
        IpcFailure {
            code: "request_failed".into(),
            message: bounded,
            retryable: false,
            details: None,
        }
    }
}
pub fn read_frame<T: for<'de> Deserialize<'de>>(stream: &mut impl Read) -> Result<T, IpcError> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length)?;
    let len = u32::from_be_bytes(length) as usize;
    if len > MAX_IPC_FRAME {
        return Err(IpcError::FrameTooLarge);
    }
    let mut body = vec![0; len];
    stream.read_exact(&mut body)?;
    serde_json::from_slice(&body).map_err(|_| IpcError::Malformed)
}
pub fn write_frame<T: Serialize>(stream: &mut impl Write, value: &T) -> Result<(), IpcError> {
    let body = serde_json::to_vec(value).map_err(|_| IpcError::Malformed)?;
    if body.len() > MAX_IPC_FRAME {
        return Err(IpcError::FrameTooLarge);
    }
    stream.write_all(&(body.len() as u32).to_be_bytes())?;
    stream.write_all(&body)?;
    stream.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    struct Echo;
    impl IpcHandler for Echo {
        fn handle(&self, r: &IpcRequest) -> Result<Value, String> {
            Ok(r.params.clone())
        }
    }
    #[test]
    fn socket_is_owner_only_and_peer_authenticated() {
        let d = tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let server = IpcServer::bind(d.path().join("node.sock")).unwrap();
        let p = server.local_addr().to_owned();
        let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let stop = server.stop_handle();
        let t = std::thread::spawn(move || server.serve(Arc::new(Echo)));
        let mut c = UnixStream::connect(&p).unwrap();
        write_frame(
            &mut c,
            &IpcRequest {
                request_id: "1".into(),
                method: "echo".into(),
                params: serde_json::json!({"ok":true}),
                version: None,
                revision: None,
                idempotency_key: None,
            },
        )
        .unwrap();
        let r: IpcResponse = read_frame(&mut c).unwrap();
        assert!(r.ok);
        stop.store(true, Ordering::Relaxed);
        drop(c);
        let _ = UnixStream::connect(&p);
        t.join().unwrap().unwrap();
    }
    #[test]
    fn rejects_non_owner_only_or_symlinked_parent() {
        let d = tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            IpcServer::bind(d.path().join("node.sock")),
            Err(IpcError::UnsafeEndpoint)
        ));
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let real = d.path().join("real");
        fs::create_dir(&real).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&real, d.path().join("link")).unwrap();
        assert!(matches!(
            IpcServer::bind(d.path().join("link/node.sock")),
            Err(IpcError::UnsafeEndpoint)
        ));
    }
}
