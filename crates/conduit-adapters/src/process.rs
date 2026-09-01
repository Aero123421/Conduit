use std::{
    io::{BufRead, BufReader, Read, Write},
    os::unix::process::CommandExt,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::mpsc::{self, Receiver, TryRecvError, TrySendError},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use crate::{
    LaunchSpec, ProtocolFrame,
    types::{AdapterError, MAX_PROTOCOL_FRAME_BYTES},
};

/// A supervised structured adapter child.
///
/// Runtime custody (cgroups, signals, timeout and reconciliation) remains with
/// `conduit-runtime`; this type owns only bounded stdio framing and child
/// lifetime. Stderr is inherited so it never contaminates the protocol stream.
pub struct AdapterChild {
    child: Child,
    stdin: Option<ChildStdin>,
    records: Receiver<Result<Vec<u8>, AdapterReadError>>,
    stdout_drain: Option<JoinHandle<()>>,
    stderr_drain: Option<JoinHandle<()>>,
}

#[derive(Debug)]
enum AdapterReadError {
    Io(std::io::Error),
    InvalidFrame,
    FrameTooLarge(usize),
}

impl AdapterChild {
    pub fn spawn(spec: &LaunchSpec) -> Result<Self, AdapterError> {
        let mut adapter = Self::spawn_uninitialized(spec)?;
        if let Err(error) = adapter.initialize(spec) {
            let _ = adapter.terminate();
            return Err(error);
        }
        Ok(adapter)
    }

    /// Spawns the structured adapter process without admitting any protocol
    /// work. The Node uses this boundary to persist the exact PID/birth/PGID
    /// identity before a prompt or resume frame can have an effect.
    pub fn spawn_uninitialized(spec: &LaunchSpec) -> Result<Self, AdapterError> {
        let mut command = Command::new(&spec.executable);
        command
            .args(&spec.args)
            .current_dir(&spec.cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command.process_group(0);
        let child = command.spawn()?;
        Self::from_child(child)
    }

    /// Adopts a child spawned through a Runtime Provider's interactive I/O
    /// boundary. The provider has already reserved and verified Runtime
    /// identity; this layer only owns bounded protocol framing.
    pub fn from_child(mut child: Child) -> Result<Self, AdapterError> {
        let stdin = child.stdin.take().ok_or(AdapterError::InvalidExecutable)?;
        let stdout = child.stdout.take().ok_or(AdapterError::InvalidExecutable)?;
        let mut stderr = child.stderr.take().ok_or(AdapterError::InvalidExecutable)?;
        let stderr_drain = thread::spawn(move || {
            let mut buffer = [0_u8; 8 * 1024];
            while let Ok(read) = stderr.read(&mut buffer) {
                if read == 0 {
                    break;
                }
            }
        });
        let (records_tx, records) = mpsc::sync_channel(128);
        let stdout_drain = thread::spawn(move || {
            let mut stdout = BufReader::new(stdout);
            loop {
                let record = read_record_from(&mut stdout).map_err(|error| match error {
                    AdapterError::Process(error) => AdapterReadError::Io(error),
                    AdapterError::InvalidFrame => AdapterReadError::InvalidFrame,
                    AdapterError::FrameTooLarge { actual, .. } => {
                        AdapterReadError::FrameTooLarge(actual)
                    }
                    _ => AdapterReadError::InvalidFrame,
                });
                let terminal = matches!(record, Ok(None) | Err(_));
                match record {
                    Ok(Some(record)) => match records_tx.try_send(Ok(record)) {
                        Ok(()) => {}
                        Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => break,
                    },
                    Ok(None) => break,
                    Err(error) => {
                        let _ = records_tx.try_send(Err(error));
                    }
                }
                if terminal {
                    break;
                }
            }
        });
        Ok(Self {
            child,
            stdin: Some(stdin),
            records,
            stdout_drain: Some(stdout_drain),
            stderr_drain: Some(stderr_drain),
        })
    }

    pub fn initialize(&mut self, spec: &LaunchSpec) -> Result<(), AdapterError> {
        for frame in &spec.initial_frames {
            self.write(frame)?;
        }
        if matches!(
            spec.protocol,
            crate::AdapterProtocol::ClaudeStreamJson | crate::AdapterProtocol::AgyStreamJson
        ) {
            self.close_stdin();
        }
        Ok(())
    }

    pub fn id(&self) -> u32 {
        self.child.id()
    }

    pub fn write(&mut self, frame: &ProtocolFrame) -> Result<(), AdapterError> {
        if frame.0.is_empty()
            || frame.0.len() > MAX_PROTOCOL_FRAME_BYTES
            || !frame.0.ends_with(b"\n")
        {
            return Err(AdapterError::InvalidFrame);
        }
        let stdin = self
            .stdin
            .as_mut()
            .ok_or(AdapterError::UnexpectedResponse {
                phase: "process_closed",
                reason: "adapter stdin is closed",
            })?;
        stdin.write_all(&frame.0)?;
        stdin.flush()?;
        Ok(())
    }

    /// Reads exactly one strict LF-framed record without allowing an unbounded
    /// allocation. A trailing CR is retained for the protocol decoder.
    pub fn read_record(&mut self) -> Result<Option<Vec<u8>>, AdapterError> {
        self.records.recv().map_or(Ok(None), map_record)
    }

    /// Polls one already-framed protocol record without blocking the node
    /// transport loop. `None` means no record is currently ready; process exit
    /// remains observable through `try_wait`.
    pub fn try_read_record(&mut self) -> Result<Option<Vec<u8>>, AdapterError> {
        match self.records.try_recv() {
            Ok(record) => map_record(record),
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => Ok(None),
        }
    }

    pub fn try_wait(&mut self) -> Result<Option<std::process::ExitStatus>, AdapterError> {
        self.child.try_wait().map_err(AdapterError::from)
    }

    pub fn close_stdin(&mut self) {
        self.stdin.take();
    }

    pub fn terminate(&mut self) -> Result<std::process::ExitStatus, AdapterError> {
        self.stdin.take();
        if let Some(status) = self.child.try_wait()? {
            self.join_stderr();
            return Ok(status);
        }
        signal_group(self.child.id(), libc::SIGTERM);
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(status) = self.child.try_wait()? {
                self.join_stderr();
                return Ok(status);
            }
            if Instant::now() >= deadline {
                signal_group(self.child.id(), libc::SIGKILL);
                let status = self.child.wait()?;
                self.join_stderr();
                return Ok(status);
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn join_stderr(&mut self) {
        if let Some(thread) = self.stdout_drain.take() {
            let _ = thread.join();
        }
        if let Some(thread) = self.stderr_drain.take() {
            let _ = thread.join();
        }
    }
}

fn read_record_from(stdout: &mut BufReader<ChildStdout>) -> Result<Option<Vec<u8>>, AdapterError> {
    let mut record = Vec::with_capacity(4_096);
    loop {
        let available = stdout.fill_buf()?;
        if available.is_empty() {
            return if record.is_empty() {
                Ok(None)
            } else {
                Err(AdapterError::InvalidFrame)
            };
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        if record.len().saturating_add(take) > MAX_PROTOCOL_FRAME_BYTES {
            return Err(AdapterError::FrameTooLarge {
                actual: record.len().saturating_add(take),
                maximum: MAX_PROTOCOL_FRAME_BYTES,
            });
        }
        record.extend_from_slice(&available[..take]);
        stdout.consume(take);
        if record.ends_with(b"\n") {
            return Ok(Some(record));
        }
    }
}

fn map_record(record: Result<Vec<u8>, AdapterReadError>) -> Result<Option<Vec<u8>>, AdapterError> {
    match record {
        Ok(record) => Ok(Some(record)),
        Err(AdapterReadError::Io(error)) => Err(AdapterError::Process(error)),
        Err(AdapterReadError::InvalidFrame) => Err(AdapterError::InvalidFrame),
        Err(AdapterReadError::FrameTooLarge(actual)) => Err(AdapterError::FrameTooLarge {
            actual,
            maximum: MAX_PROTOCOL_FRAME_BYTES,
        }),
    }
}

impl Drop for AdapterChild {
    fn drop(&mut self) {
        self.stdin.take();
        if self.child.try_wait().ok().flatten().is_none() {
            signal_group(self.child.id(), libc::SIGKILL);
            let _ = self.child.wait();
        }
        self.join_stderr();
    }
}

fn signal_group(pid: u32, signal: i32) {
    // SAFETY: AdapterChild creates the child as a process-group leader and the
    // negative PID therefore targets only that supervised adapter group.
    unsafe {
        libc::kill(-(pid as i32), signal);
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::AdapterProtocol;

    #[test]
    fn child_uses_strict_bounded_jsonl_io() {
        let spec = LaunchSpec {
            executable: PathBuf::from("/bin/sh"),
            args: vec![
                "-c".to_owned(),
                "IFS= read -r line; printf '%s\\n' \"$line\"".to_owned(),
            ],
            cwd: PathBuf::from("/tmp"),
            protocol: AdapterProtocol::PiRpcJsonl,
            initial_frames: vec![ProtocolFrame(b"{\"type\":\"get_state\"}\n".to_vec())],
        };
        let mut child = AdapterChild::spawn(&spec).unwrap();
        assert_eq!(
            child.read_record().unwrap().unwrap(),
            b"{\"type\":\"get_state\"}\n"
        );
        child.close_stdin();
        assert!(child.terminate().unwrap().success());
    }
}
