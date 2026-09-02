use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

use reqwest::Url;
use serde_json::{Value, json};

use crate::{
    CliError,
    command::{PrivilegedCommand, PrivilegedPrepareArgs},
};

const HELPER: &str = "/usr/libexec/conduit/conduit-privileged-helper";
const MAX_HELPER_OUTPUT_BYTES: usize = 128 * 1024;

pub(crate) fn execute(command: &PrivilegedCommand) -> Result<Value, CliError> {
    let uid = rustix::process::getuid().as_raw();
    let helper = Path::new(HELPER);
    let installed = helper_custody(helper)?;
    if !installed {
        return match command {
            PrivilegedCommand::Status | PrivilegedCommand::Doctor => Ok(json!({
                "schemaVersion": 1,
                "installed": false,
                "enabled": false,
                "effective": false,
                "reasonCode": "privileged_helper_not_installed",
                "remediationCode": "install_privileged_helper_as_root"
            })),
            _ => Err(CliError::Unavailable(
                "privileged_helper_not_installed: install the reviewed root package locally"
                    .to_owned(),
            )),
        };
    }

    let args = match command {
        PrivilegedCommand::Status => vec![
            "admin".to_owned(),
            "status".to_owned(),
            "--uid".to_owned(),
            uid.to_string(),
            "--output".to_owned(),
            "json".to_owned(),
        ],
        PrivilegedCommand::Doctor => vec![
            "admin".to_owned(),
            "doctor".to_owned(),
            "--uid".to_owned(),
            uid.to_string(),
            "--output".to_owned(),
            "json".to_owned(),
        ],
        PrivilegedCommand::RegistrationBundle => vec![
            "admin".to_owned(),
            "registration-bundle".to_owned(),
            "--uid".to_owned(),
            uid.to_string(),
            "--output".to_owned(),
            "json".to_owned(),
        ],
        PrivilegedCommand::Prepare(args) => prepare_arguments(uid, args)?,
    };
    run_root_helper(helper, &args)
}

pub(crate) fn doctor_probe() -> Value {
    match execute(&PrivilegedCommand::Doctor) {
        Ok(value) => value,
        Err(error) => json!({
            "schemaVersion": 1,
            "installed": true,
            "effective": false,
            "reasonCode": "privileged_helper_diagnostic_failed",
            "remediationCode": "run_conduit_privileged_doctor_with_local_root_authorization",
            "error": error.to_string().chars().take(512).collect::<String>()
        }),
    }
}

fn prepare_arguments(uid: u32, args: &PrivilegedPrepareArgs) -> Result<Vec<String>, CliError> {
    if !valid_prefixed_id(&args.device_id, "dev_") {
        return Err(CliError::Usage(
            "--device-id must be a bounded dev_ identifier".to_owned(),
        ));
    }
    validate_public_origin(&args.public_origin)?;
    validate_node_public_key(&args.node_public_key_file, uid)?;
    Ok(vec![
        "admin".to_owned(),
        "prepare".to_owned(),
        "--uid".to_owned(),
        uid.to_string(),
        "--device-id".to_owned(),
        args.device_id.clone(),
        "--public-origin".to_owned(),
        args.public_origin.clone(),
        "--node-public-key-file".to_owned(),
        args.node_public_key_file
            .as_os_str()
            .to_string_lossy()
            .into_owned(),
        "--output".to_owned(),
        "json".to_owned(),
    ])
}

fn run_root_helper(helper: &Path, args: &[String]) -> Result<Value, CliError> {
    let output = if rustix::process::geteuid().is_root() {
        bounded_output(Command::new(helper).args(args))?
    } else {
        let sudo = [Path::new("/usr/bin/sudo"), Path::new("/bin/sudo")]
            .into_iter()
            .find(|path| path.is_file())
            .ok_or_else(|| {
                CliError::Unavailable(
                    "explicit local root authorization requires an installed sudo binary"
                        .to_owned(),
                )
            })?;
        root_executable_custody(sudo)?;
        let mut command = Command::new(sudo);
        command.arg("-n").arg("--").arg(helper).args(args);
        bounded_output(&mut command)?
    };
    decode_helper_output(output)
}

fn bounded_output(command: &mut Command) -> Result<Output, CliError> {
    command
        .stdin(Stdio::null())
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .output()
        .map_err(|error| CliError::Unavailable(format!("privileged helper unavailable: {error}")))
}

fn decode_helper_output(output: Output) -> Result<Value, CliError> {
    if output.stdout.len() > MAX_HELPER_OUTPUT_BYTES
        || output.stderr.len() > MAX_HELPER_OUTPUT_BYTES
    {
        return Err(CliError::Unavailable(
            "privileged helper response exceeded the public diagnostic bound".to_owned(),
        ));
    }
    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr);
        let bounded = message
            .lines()
            .next()
            .unwrap_or("privileged helper rejected the request");
        let bounded = bounded.chars().take(512).collect::<String>();
        return if output.status.code() == Some(1) {
            Err(CliError::Denied(bounded))
        } else {
            Err(CliError::Unavailable(bounded))
        };
    }
    let value: Value = serde_json::from_slice(&output.stdout).map_err(|_| {
        CliError::Unavailable("privileged helper returned invalid bounded JSON".to_owned())
    })?;
    if !value.is_object() {
        return Err(CliError::Unavailable(
            "privileged helper returned a non-object response".to_owned(),
        ));
    }
    Ok(value)
}

fn helper_custody(path: &Path) -> Result<bool, CliError> {
    if !path.exists() {
        return Ok(false);
    }
    root_executable_custody(path)?;
    let mut current = PathBuf::new();
    for component in path
        .parent()
        .expect("fixed helper has a parent")
        .components()
    {
        current.push(component);
        if current == Path::new("/") {
            continue;
        }
        let metadata = fs::symlink_metadata(&current)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(CliError::Denied(format!(
                "privileged_helper_installation_unsafe: {}",
                current.display()
            )));
        }
    }
    Ok(true)
}

fn root_executable_custody(path: &Path) -> Result<(), CliError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.permissions().mode() & 0o111 == 0
    {
        return Err(CliError::Denied(format!(
            "root executable custody check failed: {}",
            path.display()
        )));
    }
    Ok(())
}

fn validate_node_public_key(path: &Path, uid: u32) -> Result<(), CliError> {
    if !path.is_absolute() {
        return Err(CliError::Usage(
            "--node-public-key-file must be absolute".to_owned(),
        ));
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != uid
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.len() > 4096
    {
        return Err(CliError::Denied(
            "node public key file ownership, mode, type, or size is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn validate_public_origin(value: &str) -> Result<(), CliError> {
    let url = Url::parse(value).map_err(|error| CliError::Usage(error.to_string()))?;
    if url.scheme() != "https"
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
        || url.host_str().is_none()
    {
        return Err(CliError::Usage(
            "--public-origin must be an exact HTTPS origin without credentials, path, query, or fragment"
                .to_owned(),
        ));
    }
    Ok(())
}

fn valid_prefixed_id(value: &str, prefix: &str) -> bool {
    value.starts_with(prefix)
        && (prefix.len() + 8..=128).contains(&value.len())
        && value[prefix.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_origin_is_exact_https_origin() {
        validate_public_origin("https://control.example.test").unwrap();
        for value in [
            "http://control.example.test",
            "https://control.example.test/path",
            "https://control.example.test/?query=1",
            "https://user@control.example.test/",
        ] {
            assert!(validate_public_origin(value).is_err(), "{value}");
        }
    }

    #[test]
    fn device_id_is_bounded() {
        assert!(valid_prefixed_id("dev_01234567", "dev_"));
        assert!(!valid_prefixed_id("dev_short", "dev_"));
        assert!(!valid_prefixed_id("device_01234567", "dev_"));
    }
}
