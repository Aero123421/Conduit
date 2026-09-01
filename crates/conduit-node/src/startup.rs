use conduit_node_store::{DeviceIdentity, NodeStore, StoreError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

pub const BACKUP_MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const BACKUP_DATABASE_FILE: &str = "journal.sqlite3";
pub const PENDING_RESTORE_DATABASE_FILE: &str = "restore-pending.sqlite3";
pub const PENDING_RESTORE_MANIFEST_FILE: &str = "restore-pending.manifest.json";
const STORAGE_CONFIGURATION_SCHEMA_VERSION: u32 = 1;
const MAX_CONFIGURATION_BYTES: usize = 64 * 1024;
const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_STORAGE_QUOTA_BYTES: u64 = 1 << 60;
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error("startup I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("startup journal failed: {0}")]
    Store(#[from] StoreError),
    #[error("startup custody is invalid: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StorageRoots {
    pub hot: PathBuf,
    pub archive: PathBuf,
    pub backup: PathBuf,
    pub cache: PathBuf,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StorageQuotas {
    pub hot: u64,
    pub archive: u64,
    pub backup: u64,
    pub cache: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StorageConfiguration {
    #[serde(default = "storage_schema_version")]
    pub schema_version: u32,
    pub roots: StorageRoots,
    pub quota_bytes: StorageQuotas,
}

impl StorageConfiguration {
    pub fn defaults(data_root: &Path) -> Self {
        let storage = data_root.join("storage");
        Self {
            schema_version: STORAGE_CONFIGURATION_SCHEMA_VERSION,
            roots: StorageRoots {
                hot: storage.join("hot"),
                archive: storage.join("archive"),
                backup: storage.join("backup"),
                cache: storage.join("cache"),
            },
            quota_bytes: StorageQuotas {
                hot: 64 << 30,
                archive: 256 << 30,
                backup: 256 << 30,
                cache: 64 << 30,
            },
        }
    }

    pub fn root_array(&self) -> [PathBuf; 4] {
        [
            self.roots.hot.clone(),
            self.roots.archive.clone(),
            self.roots.backup.clone(),
            self.roots.cache.clone(),
        ]
    }

    pub const fn quota_array(&self) -> [u64; 4] {
        [
            self.quota_bytes.hot,
            self.quota_bytes.archive,
            self.quota_bytes.backup,
            self.quota_bytes.cache,
        ]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BackupManifest {
    pub schema_version: u32,
    pub backup_id: String,
    pub created_at: String,
    pub database_file: String,
    pub database_digest: String,
    pub database_size: u64,
    pub journal_generation: u64,
    pub identity_key_id: String,
    pub signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BackupClaims<'a> {
    schema_version: u32,
    backup_id: &'a str,
    created_at: &'a str,
    database_file: &'a str,
    database_digest: &'a str,
    database_size: u64,
    journal_generation: u64,
    identity_key_id: &'a str,
}

impl BackupManifest {
    pub fn signed(
        identity: &DeviceIdentity,
        backup_id: String,
        created_at: String,
        database_digest: String,
        database_size: u64,
        journal_generation: u64,
    ) -> Result<Self, StartupError> {
        let mut manifest = Self {
            schema_version: BACKUP_MANIFEST_SCHEMA_VERSION,
            backup_id,
            created_at,
            database_file: BACKUP_DATABASE_FILE.into(),
            database_digest,
            database_size,
            journal_generation,
            identity_key_id: identity.key_id().into(),
            signature: String::new(),
        };
        manifest.signature = identity.sign(&manifest.claim_bytes()?);
        Ok(manifest)
    }

    pub fn verify(&self, identity: &DeviceIdentity) -> Result<(), StartupError> {
        if self.schema_version != BACKUP_MANIFEST_SCHEMA_VERSION
            || self.database_file != BACKUP_DATABASE_FILE
            || self.identity_key_id != identity.key_id()
            || !valid_backup_id(&self.backup_id)
            || !valid_digest(&self.database_digest)
            || self.database_size == 0
        {
            return Err(StartupError::Invalid(
                "backup manifest claims are invalid".into(),
            ));
        }
        identity
            .verify(&self.claim_bytes()?, &self.signature)
            .map_err(|_| StartupError::Invalid("backup manifest signature is invalid".into()))
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, StartupError> {
        serde_jcs::to_vec(self).map_err(|error| StartupError::Invalid(error.to_string()))
    }

    fn claim_bytes(&self) -> Result<Vec<u8>, StartupError> {
        serde_jcs::to_vec(&BackupClaims {
            schema_version: self.schema_version,
            backup_id: &self.backup_id,
            created_at: &self.created_at,
            database_file: &self.database_file,
            database_digest: &self.database_digest,
            database_size: self.database_size,
            journal_generation: self.journal_generation,
            identity_key_id: &self.identity_key_id,
        })
        .map_err(|error| StartupError::Invalid(error.to_string()))
    }
}

#[derive(Debug)]
pub struct VerifiedBackup {
    pub manifest_path: PathBuf,
    pub database_path: PathBuf,
    pub manifest: BackupManifest,
}

pub fn prepare_data_root(path: &Path) -> Result<PathBuf, StartupError> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.uid() != effective_uid() {
        return Err(StartupError::Invalid(
            "data root must be an owner-controlled directory".into(),
        ));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(fs::canonicalize(path)?)
}

pub fn stage_storage_configuration(
    data_root: &Path,
    value: serde_json::Value,
) -> Result<(PathBuf, StorageConfiguration), StartupError> {
    let mut configuration: StorageConfiguration =
        serde_json::from_value(value).map_err(|error| {
            StartupError::Invalid(format!("storage configuration invalid: {error}"))
        })?;
    configuration = validate_storage_configuration(configuration)?;
    let path = storage_pending_path(data_root);
    write_owner_only(
        &path,
        &serde_jcs::to_vec(&configuration).map_err(|error| {
            StartupError::Invalid(format!("storage configuration encoding failed: {error}"))
        })?,
    )?;
    sync_directory(
        path.parent()
            .ok_or_else(|| StartupError::Invalid("storage config parent missing".into()))?,
    )?;
    Ok((path, configuration))
}

pub fn activate_storage_configuration(
    data_root: &Path,
) -> Result<StorageConfiguration, StartupError> {
    let pending = storage_pending_path(data_root);
    let active = storage_active_path(data_root);
    let source = if pending.exists() {
        Some(pending.as_path())
    } else if active.exists() {
        Some(active.as_path())
    } else {
        None
    };
    let configuration = match source {
        Some(path) => {
            let bytes = read_owner_only_regular(path, MAX_CONFIGURATION_BYTES)?;
            serde_json::from_slice::<StorageConfiguration>(&bytes).map_err(|error| {
                StartupError::Invalid(format!("storage configuration invalid: {error}"))
            })?
        }
        None => StorageConfiguration::defaults(data_root),
    };
    let configuration = validate_storage_configuration(configuration)?;
    let bytes = serde_jcs::to_vec(&configuration)
        .map_err(|error| StartupError::Invalid(error.to_string()))?;
    write_owner_only(&active, &bytes)?;
    if pending.exists() {
        fs::remove_file(&pending)?;
    }
    sync_directory(
        active
            .parent()
            .ok_or_else(|| StartupError::Invalid("storage config parent missing".into()))?,
    )?;
    Ok(configuration)
}

pub fn verify_backup(
    identity: &DeviceIdentity,
    backup_root: &Path,
    requested_manifest: &Path,
    expected_backup_id: Option<&str>,
) -> Result<VerifiedBackup, StartupError> {
    let backup_root = fs::canonicalize(backup_root)?;
    let manifest_path = fs::canonicalize(requested_manifest)?;
    if !manifest_path.starts_with(&backup_root)
        || manifest_path.file_name().and_then(|value| value.to_str()) != Some("manifest.json")
    {
        return Err(StartupError::Invalid(
            "backup manifest is outside custody".into(),
        ));
    }
    let bytes = read_owner_only_regular(&manifest_path, MAX_MANIFEST_BYTES)?;
    let manifest: BackupManifest = serde_json::from_slice(&bytes)
        .map_err(|error| StartupError::Invalid(format!("backup manifest invalid: {error}")))?;
    manifest.verify(identity)?;
    if expected_backup_id.is_some_and(|expected| expected != manifest.backup_id) {
        return Err(StartupError::Invalid(
            "backup ID does not match manifest".into(),
        ));
    }
    let directory = manifest_path
        .parent()
        .ok_or_else(|| StartupError::Invalid("backup manifest parent missing".into()))?;
    if directory.parent() != Some(backup_root.as_path())
        || directory.file_name().and_then(|value| value.to_str())
            != Some(manifest.backup_id.as_str())
    {
        return Err(StartupError::Invalid(
            "backup ID is not bound to its custody directory".into(),
        ));
    }
    let database_candidate = directory.join(BACKUP_DATABASE_FILE);
    let metadata = fs::symlink_metadata(&database_candidate)?;
    if metadata.file_type().is_symlink() {
        return Err(StartupError::Invalid(
            "backup database cannot be a symlink".into(),
        ));
    }
    let database_path = fs::canonicalize(&database_candidate)?;
    if database_path.parent() != Some(directory) {
        return Err(StartupError::Invalid(
            "backup database escaped custody".into(),
        ));
    }
    validate_database_file(&database_path, &manifest)?;
    NodeStore::verify_database(&database_path)?;
    Ok(VerifiedBackup {
        manifest_path,
        database_path,
        manifest,
    })
}

pub fn stage_database_restore(
    data_root: &Path,
    backup: &VerifiedBackup,
) -> Result<(), StartupError> {
    let data_root = fs::canonicalize(data_root)?;
    let pending_database = data_root.join(PENDING_RESTORE_DATABASE_FILE);
    let pending_manifest = data_root.join(PENDING_RESTORE_MANIFEST_FILE);
    if pending_database.exists() || pending_manifest.exists() {
        return Err(StartupError::Invalid(
            "a database restore is already pending".into(),
        ));
    }
    let temporary_database = unique_path(&data_root, ".restore-stage", "sqlite3");
    copy_owner_only(&backup.database_path, &temporary_database)?;
    if let Err(error) = validate_database_file(&temporary_database, &backup.manifest) {
        let _ = fs::remove_file(&temporary_database);
        return Err(error);
    }
    let manifest_bytes = backup.manifest.canonical_bytes()?;
    let temporary_manifest = unique_path(&data_root, ".restore-stage", "manifest");
    if let Err(error) = write_new_owner_only(&temporary_manifest, &manifest_bytes) {
        let _ = fs::remove_file(&temporary_database);
        return Err(error);
    }
    fs::rename(&temporary_database, &pending_database)?;
    if let Err(error) = fs::rename(&temporary_manifest, &pending_manifest) {
        let _ = fs::remove_file(&pending_database);
        let _ = fs::remove_file(&temporary_manifest);
        return Err(error.into());
    }
    sync_directory(&data_root)?;
    Ok(())
}

pub fn open_store_with_pending_restore(
    data_root: &Path,
    identity: &DeviceIdentity,
) -> Result<NodeStore, StartupError> {
    let data_root = prepare_data_root(data_root)?;
    let pending_database = data_root.join(PENDING_RESTORE_DATABASE_FILE);
    let pending_manifest = data_root.join(PENDING_RESTORE_MANIFEST_FILE);
    if !pending_manifest.exists() {
        if pending_database.exists() {
            return Err(StartupError::Invalid(
                "orphaned pending restore database".into(),
            ));
        }
        return NodeStore::open(&data_root).map_err(StartupError::from);
    }
    if !pending_database.exists() {
        return Err(StartupError::Invalid(
            "pending restore manifest has no database".into(),
        ));
    }
    let manifest_bytes = read_owner_only_regular(&pending_manifest, MAX_MANIFEST_BYTES)?;
    let manifest: BackupManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| StartupError::Invalid(format!("pending restore invalid: {error}")))?;
    manifest.verify(identity)?;
    validate_database_file(&pending_database, &manifest)?;
    NodeStore::verify_database(&pending_database)?;

    let rollback_temporary = unique_directory(&data_root, ".restore-rollback")?;
    let current_files = ["node.sqlite3", "node.sqlite3-wal", "node.sqlite3-shm"];
    for name in current_files {
        let current = data_root.join(name);
        if current.exists() {
            validate_owner_regular(&current)?;
            fs::rename(&current, rollback_temporary.join(name))?;
        }
    }
    sync_directory(&data_root)?;
    if let Err(error) = fs::rename(&pending_database, data_root.join("node.sqlite3")) {
        rollback_files(
            &data_root,
            &rollback_temporary,
            &pending_manifest,
            "rename-failed",
        )?;
        return Err(error.into());
    }
    fs::set_permissions(
        data_root.join("node.sqlite3"),
        fs::Permissions::from_mode(0o600),
    )?;
    sync_directory(&data_root)?;

    let opened = NodeStore::open(&data_root).and_then(|store| {
        store.integrity_check()?;
        store.advance_journal_generation()?;
        Ok(store)
    });
    match opened {
        Ok(store) => {
            let final_rollback = available_directory_name(
                &data_root,
                &format!("restore-rollback-{}", manifest.backup_id),
            );
            let finalization = (|| -> Result<(), StartupError> {
                fs::rename(&rollback_temporary, &final_rollback)?;
                sync_directory(&data_root)?;
                fs::remove_file(&pending_manifest)?;
                sync_directory(&data_root)
            })();
            if let Err(error) = finalization {
                drop(store);
                let rollback = if final_rollback.exists() {
                    final_rollback
                } else {
                    rollback_temporary
                };
                rollback_files(
                    &data_root,
                    &rollback,
                    &pending_manifest,
                    &manifest.backup_id,
                )?;
                return Err(error);
            }
            Ok(store)
        }
        Err(error) => {
            rollback_files(
                &data_root,
                &rollback_temporary,
                &pending_manifest,
                &manifest.backup_id,
            )?;
            Err(error.into())
        }
    }
}

pub fn file_digest(path: &Path) -> Result<String, StartupError> {
    let mut file = fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn validate_storage_configuration(
    mut configuration: StorageConfiguration,
) -> Result<StorageConfiguration, StartupError> {
    if configuration.schema_version != STORAGE_CONFIGURATION_SCHEMA_VERSION {
        return Err(StartupError::Invalid(
            "unsupported storage configuration schema".into(),
        ));
    }
    let quotas = configuration.quota_array();
    if quotas
        .iter()
        .any(|quota| *quota == 0 || *quota > MAX_STORAGE_QUOTA_BYTES)
    {
        return Err(StartupError::Invalid("storage quota is invalid".into()));
    }
    let mut roots = configuration.root_array();
    for root in &mut roots {
        if !root.is_absolute() {
            return Err(StartupError::Invalid(
                "storage roots must be absolute".into(),
            ));
        }
        fs::create_dir_all(&*root)?;
        let metadata = fs::symlink_metadata(&*root)?;
        if !metadata.file_type().is_dir() || metadata.uid() != effective_uid() {
            return Err(StartupError::Invalid(
                "storage root must be an owner-controlled directory".into(),
            ));
        }
        fs::set_permissions(&*root, fs::Permissions::from_mode(0o700))?;
        *root = fs::canonicalize(&*root)?;
    }
    for (index, root) in roots.iter().enumerate() {
        for other in roots.iter().skip(index + 1) {
            if root.starts_with(other) || other.starts_with(root) {
                return Err(StartupError::Invalid(
                    "storage roots must not overlap".into(),
                ));
            }
        }
    }
    configuration.roots = StorageRoots {
        hot: roots[0].clone(),
        archive: roots[1].clone(),
        backup: roots[2].clone(),
        cache: roots[3].clone(),
    };
    Ok(configuration)
}

fn validate_database_file(path: &Path, manifest: &BackupManifest) -> Result<(), StartupError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != effective_uid()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() != manifest.database_size
    {
        return Err(StartupError::Invalid(
            "backup database custody is invalid".into(),
        ));
    }
    if file_digest(path)? != manifest.database_digest {
        return Err(StartupError::Invalid(
            "backup database digest does not match manifest".into(),
        ));
    }
    Ok(())
}

fn validate_owner_regular(path: &Path) -> Result<(), StartupError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != effective_uid()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(StartupError::Invalid(
            "journal file is not an owner-only regular file".into(),
        ));
    }
    Ok(())
}

fn read_owner_only_regular(path: &Path, maximum: usize) -> Result<Vec<u8>, StartupError> {
    validate_owner_regular(path)?;
    let metadata = fs::metadata(path)?;
    if metadata.len() > maximum as u64 {
        return Err(StartupError::Invalid(
            "owner-only record is too large".into(),
        ));
    }
    Ok(fs::read(path)?)
}

fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<(), StartupError> {
    let parent = path
        .parent()
        .ok_or_else(|| StartupError::Invalid("record parent missing".into()))?;
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    let temporary = unique_path(parent, ".record", "tmp");
    write_new_owner_only(&temporary, bytes)?;
    fs::rename(&temporary, path)?;
    sync_directory(parent)
}

fn write_new_owner_only(path: &Path, bytes: &[u8]) -> Result<(), StartupError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn copy_owner_only(source: &Path, destination: &Path) -> Result<(), StartupError> {
    let mut source = fs::File::open(source)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut destination = options.open(destination)?;
    std::io::copy(&mut source, &mut destination)?;
    destination.sync_all()?;
    Ok(())
}

fn rollback_files(
    data_root: &Path,
    rollback: &Path,
    pending_manifest: &Path,
    label: &str,
) -> Result<(), StartupError> {
    let pending_database = data_root.join(PENDING_RESTORE_DATABASE_FILE);
    if pending_database.exists() {
        fs::rename(
            &pending_database,
            rollback.join(format!("failed-{PENDING_RESTORE_DATABASE_FILE}")),
        )?;
    }
    for name in ["node.sqlite3", "node.sqlite3-wal", "node.sqlite3-shm"] {
        let current = data_root.join(name);
        if current.exists() {
            fs::rename(&current, rollback.join(format!("failed-{name}")))?;
        }
        let prior = rollback.join(name);
        if prior.exists() {
            fs::rename(prior, current)?;
        }
    }
    if pending_manifest.exists() {
        fs::remove_file(pending_manifest)?;
    }
    let failed = available_directory_name(data_root, &format!("restore-failed-{label}"));
    fs::rename(rollback, failed)?;
    sync_directory(data_root)
}

fn unique_directory(parent: &Path, stem: &str) -> Result<PathBuf, StartupError> {
    for _ in 0..128 {
        let path = unique_path(parent, stem, "d");
        match fs::create_dir(&path) {
            Ok(()) => {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
                return Ok(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err(StartupError::Invalid(
        "could not reserve a startup transaction directory".into(),
    ))
}

fn available_directory_name(parent: &Path, stem: &str) -> PathBuf {
    for suffix in 0..u32::MAX {
        let path = if suffix == 0 {
            parent.join(stem)
        } else {
            parent.join(format!("{stem}-{suffix}"))
        };
        if !path.exists() {
            return path;
        }
    }
    unreachable!("finite filesystem cannot contain every numeric suffix")
}

fn unique_path(parent: &Path, stem: &str, extension: &str) -> PathBuf {
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    parent.join(format!(
        "{stem}-{}-{counter}.{extension}",
        std::process::id()
    ))
}

fn storage_configuration_directory(data_root: &Path) -> PathBuf {
    data_root.join("storage")
}

fn storage_pending_path(data_root: &Path) -> PathBuf {
    storage_configuration_directory(data_root).join("configuration.pending.json")
}

fn storage_active_path(data_root: &Path) -> PathBuf {
    storage_configuration_directory(data_root).join("configuration.json")
}

fn sync_directory(path: &Path) -> Result<(), StartupError> {
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

fn effective_uid() -> u32 {
    unsafe { libc::geteuid() }
}

fn storage_schema_version() -> u32 {
    STORAGE_CONFIGURATION_SCHEMA_VERSION
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

pub fn valid_backup_id(value: &str) -> bool {
    value.strip_prefix("backup_").is_some_and(|suffix| {
        suffix.len() >= 8
            && suffix.len() <= 128
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::tempdir;

    fn identity(root: &Path) -> DeviceIdentity {
        DeviceIdentity::load_or_create(root.join("identity/device.ed25519")).unwrap()
    }

    fn create_backup(
        root: &Path,
        store: &NodeStore,
        identity: &DeviceIdentity,
        backup_id: &str,
    ) -> VerifiedBackup {
        let backup_root = root.join("storage/backup");
        fs::create_dir_all(&backup_root).unwrap();
        fs::set_permissions(&backup_root, fs::Permissions::from_mode(0o700)).unwrap();
        let directory = backup_root.join(backup_id);
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let database = directory.join(BACKUP_DATABASE_FILE);
        store.backup_database(&database).unwrap();
        fs::set_permissions(&database, fs::Permissions::from_mode(0o600)).unwrap();
        let manifest = BackupManifest::signed(
            identity,
            backup_id.into(),
            "2026-09-01T00:00:00Z".into(),
            file_digest(&database).unwrap(),
            fs::metadata(&database).unwrap().len(),
            store.journal_generation().unwrap(),
        )
        .unwrap();
        let manifest_path = directory.join("manifest.json");
        write_owner_only(&manifest_path, &manifest.canonical_bytes().unwrap()).unwrap();
        verify_backup(identity, &backup_root, &manifest_path, Some(backup_id)).unwrap()
    }

    #[test]
    fn pending_restore_is_applied_before_open_and_preserves_rollback() {
        let directory = tempdir().unwrap();
        let root = prepare_data_root(&directory.path().join("data")).unwrap();
        let identity = identity(&root);
        let store = NodeStore::open(&root).unwrap();
        let backup = create_backup(&root, &store, &identity, "backup_fixture01");
        assert_eq!(store.advance_journal_generation().unwrap(), 2);
        assert_eq!(store.advance_journal_generation().unwrap(), 3);
        stage_database_restore(&root, &backup).unwrap();
        drop(store);

        let restored = open_store_with_pending_restore(&root, &identity).unwrap();
        assert_eq!(restored.journal_generation().unwrap(), 2);
        restored.integrity_check().unwrap();
        assert!(!root.join(PENDING_RESTORE_DATABASE_FILE).exists());
        assert!(!root.join(PENDING_RESTORE_MANIFEST_FILE).exists());

        let rollback = root.join("restore-rollback-backup_fixture01");
        let prior = NodeStore::open_read_only(&rollback).unwrap();
        assert_eq!(prior.journal_generation().unwrap(), 3);
        prior.integrity_check().unwrap();
    }

    #[test]
    fn failed_restored_schema_rolls_back_the_authoritative_database() {
        let directory = tempdir().unwrap();
        let root = prepare_data_root(&directory.path().join("data")).unwrap();
        let identity = identity(&root);
        let store = NodeStore::open(&root).unwrap();
        assert_eq!(store.advance_journal_generation().unwrap(), 2);
        let mut backup = create_backup(&root, &store, &identity, "backup_future01");
        {
            let connection = Connection::open(&backup.database_path).unwrap();
            connection
                .execute("INSERT INTO schema_migrations(version) VALUES(999)", [])
                .unwrap();
        }
        backup.manifest = BackupManifest::signed(
            &identity,
            backup.manifest.backup_id.clone(),
            backup.manifest.created_at.clone(),
            file_digest(&backup.database_path).unwrap(),
            fs::metadata(&backup.database_path).unwrap().len(),
            backup.manifest.journal_generation,
        )
        .unwrap();
        write_owner_only(
            &backup.manifest_path,
            &backup.manifest.canonical_bytes().unwrap(),
        )
        .unwrap();
        stage_database_restore(&root, &backup).unwrap();
        drop(store);

        assert!(open_store_with_pending_restore(&root, &identity).is_err());
        let authoritative = NodeStore::open(&root).unwrap();
        assert_eq!(authoritative.journal_generation().unwrap(), 2);
        authoritative.integrity_check().unwrap();
        assert!(!root.join(PENDING_RESTORE_DATABASE_FILE).exists());
        assert!(!root.join(PENDING_RESTORE_MANIFEST_FILE).exists());
        assert!(root.join("restore-failed-backup_future01").exists());
    }

    #[test]
    fn non_owner_only_pending_restore_is_rejected_before_current_db_moves() {
        let directory = tempdir().unwrap();
        let root = prepare_data_root(&directory.path().join("data")).unwrap();
        let identity = identity(&root);
        let store = NodeStore::open(&root).unwrap();
        assert_eq!(store.advance_journal_generation().unwrap(), 2);
        let backup = create_backup(&root, &store, &identity, "backup_permissions01");
        stage_database_restore(&root, &backup).unwrap();
        fs::set_permissions(
            root.join(PENDING_RESTORE_DATABASE_FILE),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        drop(store);

        assert!(open_store_with_pending_restore(&root, &identity).is_err());
        let unchanged = NodeStore::open(&root).unwrap();
        assert_eq!(unchanged.journal_generation().unwrap(), 2);
        unchanged.integrity_check().unwrap();
    }

    #[test]
    fn storage_pending_is_typed_and_activated_only_on_startup() {
        let directory = tempdir().unwrap();
        let root = prepare_data_root(&directory.path().join("data")).unwrap();
        let roots = directory.path().join("configured");
        let requested = serde_json::json!({
            "schemaVersion": 1,
            "roots": {
                "hot": roots.join("hot"),
                "archive": roots.join("archive"),
                "backup": roots.join("backup"),
                "cache": roots.join("cache"),
            },
            "quotaBytes": {
                "hot": 1024,
                "archive": 2048,
                "backup": 4096,
                "cache": 8192,
            }
        });
        let (pending, staged) = stage_storage_configuration(&root, requested).unwrap();
        assert!(pending.exists());
        assert!(!storage_active_path(&root).exists());
        assert_eq!(staged.quota_bytes.backup, 4096);

        let active = activate_storage_configuration(&root).unwrap();
        assert_eq!(active, staged);
        assert!(!pending.exists());
        assert!(storage_active_path(&root).exists());
        for path in active.root_array() {
            let metadata = fs::metadata(path).unwrap();
            assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        }

        let overlap = serde_json::json!({
            "schemaVersion": 1,
            "roots": {
                "hot": roots,
                "archive": roots.join("nested"),
                "backup": directory.path().join("other-backup"),
                "cache": directory.path().join("other-cache"),
            },
            "quotaBytes": {"hot":1,"archive":1,"backup":1,"cache":1}
        });
        assert!(stage_storage_configuration(&root, overlap).is_err());
    }

    #[test]
    fn manifest_signature_id_and_fixed_database_are_bound() {
        let directory = tempdir().unwrap();
        let root = prepare_data_root(&directory.path().join("data")).unwrap();
        let identity = identity(&root);
        let store = NodeStore::open(&root).unwrap();
        let mut backup = create_backup(&root, &store, &identity, "backup_bound001");
        let backup_root = root.join("storage/backup");
        assert!(
            verify_backup(
                &identity,
                &backup_root,
                &backup.manifest_path,
                Some("backup_other01")
            )
            .is_err()
        );
        backup.manifest.database_file = "../node.sqlite3".into();
        write_owner_only(
            &backup.manifest_path,
            &backup.manifest.canonical_bytes().unwrap(),
        )
        .unwrap();
        assert!(
            verify_backup(
                &identity,
                &backup_root,
                &backup.manifest_path,
                Some("backup_bound001")
            )
            .is_err()
        );
    }
}
