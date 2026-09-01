use std::{
    io::{BufRead, BufReader, Read, Write},
    os::unix::process::CommandExt,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
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
    stdout: BufReader<ChildStdout>,
    stderr_drain: Option<JoinHandle<()>>,
}

impl AdapterChild {
    pub fn spawn(spec: &LaunchSpec) -> Result<Self, AdapterError> {
        let mut command = Command::new(&spec.executable);
        command
            .args(&spec.args)
            .current_dir(&spec.cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command.process_group(0);
        let mut child = command.spawn()?;
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
        let mut adapter = Self {
            child,
            stdin: Some(stdin),
            stdout: BufReader::new(stdout),
            stderr_drain: Some(stderr_drain),
        };
        for frame in &spec.initial_frames {
            adapter.write(frame)?;
        }
        if matches!(spec.protocol, crate::AdapterProtocol::ClaudeStreamJson) {
            adapter.close_stdin();
        }
        Ok(adapter)
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
        let mut record = Vec::with_capacity(4_096);
        loop {
            let available = self.stdout.fill_buf()?;
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
            self.stdout.consume(take);
            if record.ends_with(b"\n") {
                return Ok(Some(record));
            }
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
        if let Some(thread) = self.stderr_drain.take() {
            let _ = thread.join();
        }
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
