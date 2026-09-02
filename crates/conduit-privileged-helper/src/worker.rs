use crate::{HelperError, Result, journal::validate_regular};
use conduit_privileged_protocol::{FileIdentity, LocalExecutionPlan, SignedClaims, StdioMode};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::Read,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionRecord {
    pub protocol: String,
    pub plan_digest: String,
    pub plan: LocalExecutionPlan,
}

pub type SignedExecutionRecord = SignedClaims<ExecutionRecord>;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WorkerControl {
    Input { data: Vec<u8> },
    Resize { rows: u16, columns: u16 },
}

pub fn write_execution_record(
    path: &Path,
    plan: &LocalExecutionPlan,
    key_id: &str,
    key: &SigningKey,
    expected_uid: u32,
) -> Result<()> {
    plan.validate()?;
    let record = SignedClaims::sign(
        key_id,
        ExecutionRecord {
            protocol: conduit_privileged_protocol::PROTOCOL.into(),
            plan_digest: plan.digest()?,
            plan: plan.clone(),
        },
        key,
    )?;
    let bytes = serde_jcs::to_vec(&record)?;
    atomic_owner_only(path, &bytes, expected_uid)
}

pub fn run_exec_worker(record_path: &Path, public_key: &VerifyingKey) -> Result<()> {
    let expected_uid = unsafe { libc::geteuid() };
    validate_regular(record_path, expected_uid, 0o600)?;
    let bytes = fs::read(record_path)?;
    if bytes.len() > 256 * 1024 {
        return Err(HelperError::Denied("execution_record_too_large".into()));
    }
    let record: SignedExecutionRecord = serde_json::from_slice(&bytes)?;
    record.verify(public_key.as_bytes())?;
    if record.claims.protocol != conduit_privileged_protocol::PROTOCOL
        || record.claims.plan_digest != record.claims.plan.digest()?
    {
        return Err(HelperError::Denied("execution_record_mismatch".into()));
    }
    match record.claims.plan.stdio {
        StdioMode::Pipes => {
            let directory = record_path
                .parent()
                .ok_or_else(|| HelperError::Denied("record parent".into()))?;
            let fifo = directory.join("stdin.fifo");
            let raw = unsafe {
                libc::open(
                    CString::new(fifo.as_os_str().as_encoded_bytes())
                        .unwrap()
                        .as_ptr(),
                    libc::O_RDWR | libc::O_CLOEXEC,
                )
            };
            if raw < 0 {
                return Err(HelperError::Io(std::io::Error::last_os_error()));
            }
            let stdin = unsafe { OwnedFd::from_raw_fd(raw) };
            let stdout = open_spool(&directory.join("stdout.spool"))?;
            let stderr = open_spool(&directory.join("stderr.spool"))?;
            cvt(unsafe { libc::dup2(stdin.as_raw_fd(), libc::STDIN_FILENO) })?;
            cvt(unsafe { libc::dup2(stdout.as_raw_fd(), libc::STDOUT_FILENO) })?;
            cvt(unsafe { libc::dup2(stderr.as_raw_fd(), libc::STDERR_FILENO) })?;
            execute(&record.claims.plan)
        }
        StdioMode::Pty => run_pty_supervisor(record_path, &record.claims.plan),
    }
}

fn open_spool(path: &Path) -> Result<File> {
    validate_regular(path, unsafe { libc::geteuid() }, 0o600)?;
    OpenOptions::new()
        .append(true)
        .open(path)
        .map_err(HelperError::Io)
}

fn run_pty_supervisor(record_path: &Path, plan: &LocalExecutionPlan) -> Result<()> {
    let mut master = -1;
    let mut slave = -1;
    let mut size = libc::winsize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    cvt(unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            &mut size,
        )
    })?;
    let master = unsafe { OwnedFd::from_raw_fd(master) };
    let slave = unsafe { OwnedFd::from_raw_fd(slave) };
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(HelperError::Io(std::io::Error::last_os_error()));
    }
    if pid == 0 {
        drop(master);
        unsafe {
            libc::setsid();
            libc::ioctl(slave.as_raw_fd(), libc::TIOCSCTTY, 0);
            libc::dup2(slave.as_raw_fd(), 0);
            libc::dup2(slave.as_raw_fd(), 1);
            libc::dup2(slave.as_raw_fd(), 2)
        };
        return execute(plan);
    }
    drop(slave);
    let directory = record_path.parent().unwrap();
    let control = directory.join("control.sock");
    let server = crate::SeqpacketServer::bind(&control, 0o600)?;
    let control_master = master.try_clone()?;
    std::thread::spawn(move || {
        loop {
            let connection = match server.accept() {
                Ok(v) => v,
                Err(_) => break,
            };
            let packet = match connection.receive() {
                Ok(v) => v,
                Err(_) => continue,
            };
            if !packet.descriptors.is_empty() {
                continue;
            }
            let command: WorkerControl =
                match conduit_privileged_protocol::decode_packet(&packet.bytes) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
            match command {
                WorkerControl::Input { data } => {
                    let _ = unsafe {
                        libc::write(control_master.as_raw_fd(), data.as_ptr().cast(), data.len())
                    };
                }
                WorkerControl::Resize { rows, columns } => {
                    let size = libc::winsize {
                        ws_row: rows,
                        ws_col: columns,
                        ws_xpixel: 0,
                        ws_ypixel: 0,
                    };
                    let _ =
                        unsafe { libc::ioctl(control_master.as_raw_fd(), libc::TIOCSWINSZ, &size) };
                }
            }
        }
    });
    let mut source = File::from(master);
    let mut output = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(directory.join("stdout.spool"))?;
    std::io::copy(&mut source, &mut output)?;
    let mut status = 0;
    cvt(unsafe { libc::waitpid(pid, &mut status, 0) })?;
    if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
        Ok(())
    } else {
        Err(HelperError::Denied("managed_child_failed".into()))
    }
}

fn execute(plan: &LocalExecutionPlan) -> Result<()> {
    plan.validate()?;
    let executable = open_verified(&plan.executable, true)?;
    let cwd = open_verified(&plan.cwd, false)?;
    let mut first = [0u8; 2];
    let mut duplicate = unsafe { File::from_raw_fd(libc::dup(executable.as_raw_fd())) };
    let read = duplicate.read(&mut first)?;
    drop(duplicate);
    if read == 2 && first == *b"#!" {
        if plan.interpreter.is_none() {
            return Err(HelperError::Denied("unbound_interpreter".into()));
        }
    }
    let mut argv_values = plan.argv.clone();
    let exec_fd = if let Some(identity) = &plan.interpreter {
        let interpreter = open_verified(identity, true)?;
        cvt(unsafe { libc::fcntl(executable.as_raw_fd(), libc::F_SETFD, 0) })?;
        let script = format!("/proc/self/fd/{}", executable.as_raw_fd());
        argv_values = std::iter::once(identity.opaque_path_id.clone())
            .chain(std::iter::once(script))
            .chain(plan.argv.iter().skip(1).cloned())
            .collect();
        interpreter
    } else {
        executable.try_clone()?
    };
    let argv = argv_values
        .iter()
        .map(|v| CString::new(v.as_bytes()).map_err(|_| HelperError::Denied("argv_nul".into())))
        .collect::<Result<Vec<_>>>()?;
    let environment = clean_environment(&plan.environment)?;
    cvt(unsafe { libc::fchdir(cwd.as_raw_fd()) })?;
    let argv_ptrs = argv
        .iter()
        .map(|v| v.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect::<Vec<_>>();
    let env_ptrs = environment
        .iter()
        .map(|v| v.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect::<Vec<_>>();
    let empty = CString::new("").unwrap();
    let result = unsafe {
        libc::syscall(
            libc::SYS_execveat,
            exec_fd.as_raw_fd(),
            empty.as_ptr(),
            argv_ptrs.as_ptr(),
            env_ptrs.as_ptr(),
            libc::AT_EMPTY_PATH,
        )
    } as i32;
    cvt(result)?;
    unreachable!()
}

pub fn verify_identity(identity: &FileIdentity, executable: bool) -> Result<()> {
    let _ = open_verified(identity, executable)?;
    Ok(())
}

pub fn capture_file_identity(path: &Path, executable: bool) -> Result<FileIdentity> {
    if !path.is_absolute() {
        return Err(HelperError::Denied("path_not_absolute".into()));
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || (!metadata.is_file() && !metadata.is_dir())
        || (executable && (!metadata.is_file() || metadata.mode() & 0o111 == 0))
    {
        return Err(HelperError::Denied("unsupported_file_identity".into()));
    }
    let sha256 = if metadata.is_file() {
        let mut file = File::open(path)?;
        let mut h = Sha256::new();
        std::io::copy(&mut file, &mut h)?;
        hex::encode(h.finalize())
    } else {
        directory_digest(&metadata)
    };
    Ok(FileIdentity {
        opaque_path_id: path.to_string_lossy().into(),
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
        uid: metadata.uid(),
        size: metadata.size(),
        sha256,
    })
}

fn open_verified(identity: &FileIdentity, executable: bool) -> Result<OwnedFd> {
    let path = Path::new(&identity.opaque_path_id);
    if !path.is_absolute() {
        return Err(HelperError::Denied("path_not_absolute".into()));
    }
    let cpath = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| HelperError::Denied("path_nul".into()))?;
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
        mode: 0,
        resolve: RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };
    let raw = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            cpath.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    } as i32;
    if raw < 0 {
        return Err(HelperError::Denied(format!(
            "identity_open_failed:{}",
            std::io::Error::last_os_error()
        )));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let metadata = File::from(fd.try_clone()?).metadata()?;
    if metadata.dev() != identity.device
        || metadata.ino() != identity.inode
        || metadata.mode() != identity.mode
        || metadata.uid() != identity.uid
        || metadata.size() != identity.size
        || (executable && metadata.mode() & 0o111 == 0)
        || (!executable && !metadata.is_dir())
    {
        return Err(HelperError::Denied("file_identity_changed".into()));
    }
    if metadata.is_file() {
        let mut file = File::from(fd.try_clone()?);
        let mut hasher = Sha256::new();
        std::io::copy(&mut file, &mut hasher)?;
        if hex::encode(hasher.finalize()) != identity.sha256 {
            return Err(HelperError::Denied("file_digest_changed".into()));
        }
    } else if directory_digest(&metadata) != identity.sha256 {
        return Err(HelperError::Denied("directory_identity_changed".into()));
    }
    Ok(fd)
}

fn clean_environment(values: &BTreeMap<String, String>) -> Result<Vec<CString>> {
    values
        .iter()
        .map(|(k, v)| {
            if conduit_privileged_protocol::dangerous_environment_key(k) {
                return Err(HelperError::Denied("dangerous_environment".into()));
            }
            CString::new(format!("{k}={v}"))
                .map_err(|_| HelperError::Denied("environment_nul".into()))
        })
        .collect()
}
fn directory_digest(metadata: &fs::Metadata) -> String {
    hex::encode(Sha256::digest(
        format!(
            "directory\0{}\0{}\0{}\0{}",
            metadata.dev(),
            metadata.ino(),
            metadata.mode(),
            metadata.uid()
        )
        .as_bytes(),
    ))
}

fn atomic_owner_only(path: &Path, bytes: &[u8], expected_uid: u32) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| HelperError::Policy("record parent missing".into()))?;
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    let nonce = getrandom::u64().map_err(|e| HelperError::Policy(e.to_string()))?;
    let temporary: PathBuf = parent.join(format!(
        ".record-{}-{}",
        std::process::id(),
        hex::encode(nonce.to_ne_bytes())
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    use std::io::Write;
    file.write_all(bytes)?;
    file.sync_all()?;
    if file.metadata()?.uid() != expected_uid {
        return Err(HelperError::Policy("record owner mismatch".into()));
    }
    fs::rename(&temporary, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn cvt(value: i32) -> Result<i32> {
    if value < 0 {
        Err(HelperError::Io(std::io::Error::last_os_error()))
    } else {
        Ok(value)
    }
}
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    fn identity(path: &Path) -> FileIdentity {
        let metadata = fs::metadata(path).unwrap();
        let mut file = File::open(path).unwrap();
        let mut h = Sha256::new();
        std::io::copy(&mut file, &mut h).unwrap();
        FileIdentity {
            opaque_path_id: path.to_string_lossy().into(),
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            size: metadata.size(),
            sha256: hex::encode(h.finalize()),
        }
    }
    #[test]
    fn rejects_symlink_and_replaced_file() {
        let d = tempdir().unwrap();
        let p = d.path().join("tool");
        fs::write(&p, b"first").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        let id = identity(&p);
        assert!(verify_identity(&id, true).is_ok());
        fs::remove_file(&p).unwrap();
        fs::write(&p, b"second").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(verify_identity(&id, true).is_err());
        let l = d.path().join("link");
        std::os::unix::fs::symlink(&p, &l).unwrap();
        let mut lid = identity(&p);
        lid.opaque_path_id = l.to_string_lossy().into();
        assert!(verify_identity(&lid, true).is_err());
    }
    #[test]
    fn rejects_loader_environment() {
        let mut env = BTreeMap::new();
        env.insert("LD_PRELOAD".into(), "/tmp/x".into());
        assert!(clean_environment(&env).is_err());
    }
    #[test]
    fn captures_directory_and_detects_interpreter_replacement() {
        let directory = tempdir().unwrap();
        let cwd = capture_file_identity(directory.path(), false).unwrap();
        assert!(verify_identity(&cwd, false).is_ok());
        let interpreter = directory.path().join("interpreter");
        fs::write(&interpreter, b"binary-v1").unwrap();
        fs::set_permissions(&interpreter, fs::Permissions::from_mode(0o700)).unwrap();
        let identity = capture_file_identity(&interpreter, true).unwrap();
        fs::write(&interpreter, b"binary-v2").unwrap();
        assert!(verify_identity(&identity, true).is_err());
    }
}
