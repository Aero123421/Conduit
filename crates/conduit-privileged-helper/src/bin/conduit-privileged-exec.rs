use conduit_privileged_helper::run_exec_worker;
use ed25519_dalek::VerifyingKey;
use std::{
    env, fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

fn main() {
    if let Err(error) = run() {
        eprintln!("conduit-privileged-exec: {error}");
        std::process::exit(1);
    }
}

fn run() -> conduit_privileged_helper::Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.as_slice() == ["--version"] {
        println!("conduit-privileged-exec {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if args.first().map(String::as_str) != Some("exec-worker") {
        return Err(conduit_privileged_helper::HelperError::Policy(
            "expected exec-worker".into(),
        ));
    }
    let record = required_path(&args, "--record")?;
    let receipt_public = required_path(&args, "--receipt-public-key")?;
    if args.len() != 5 {
        return Err(conduit_privileged_helper::HelperError::Policy(
            "unknown or duplicate exec-worker argument".into(),
        ));
    }
    run_exec_worker(&record, &load_root_public_key(&receipt_public)?)
}

fn required_path(args: &[String], name: &str) -> conduit_privileged_helper::Result<PathBuf> {
    let matches = args
        .windows(2)
        .filter(|pair| pair[0] == name)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(conduit_privileged_helper::HelperError::Policy(format!(
            "{name} required exactly once"
        )));
    }
    let path = PathBuf::from(&matches[0][1]);
    if !path.is_absolute() {
        return Err(conduit_privileged_helper::HelperError::Policy(format!(
            "{name} must be absolute"
        )));
    }
    Ok(path)
}

fn load_root_public_key(path: &Path) -> conduit_privileged_helper::Result<VerifyingKey> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.len() != 32
    {
        return Err(conduit_privileged_helper::HelperError::Policy(
            "receipt public key custody invalid".into(),
        ));
    }
    let raw: [u8; 32] = fs::read(path)?.try_into().map_err(|_| {
        conduit_privileged_helper::HelperError::Policy("receipt public key length".into())
    })?;
    VerifyingKey::from_bytes(&raw).map_err(|_| {
        conduit_privileged_helper::HelperError::Policy("receipt public key invalid".into())
    })
}
