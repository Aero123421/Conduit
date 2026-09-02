use crate::{NodeStore, StoreError, map_sql};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs,
    fs::File,
    io::{Seek, SeekFrom, Write},
    os::fd::{AsRawFd, FromRawFd},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionKind {
    NativeHost,
    ReadOnlyFile,
    EphemeralFile,
    Environment,
    AgentSocket,
    GuestVolume,
    LoginRequired,
}
impl ProjectionKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::NativeHost => "native_host",
            Self::ReadOnlyFile => "read_only_file",
            Self::EphemeralFile => "ephemeral_file",
            Self::Environment => "environment",
            Self::AgentSocket => "agent_socket",
            Self::GuestVolume => "guest_volume",
            Self::LoginRequired => "login_required",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialMetadata {
    pub profile_id: String,
    pub revision: u64,
    pub adapter_id: String,
    pub kind: ProjectionKind,
    pub label: String,
}

pub struct CredentialProjection {
    pub metadata: CredentialMetadata,
    pub path: Option<PathBuf>,
    pub environment_key: Option<String>,
    secret: Option<Zeroizing<Vec<u8>>>,
    remove_on_drop: bool,
}
impl std::fmt::Debug for CredentialProjection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialProjection")
            .field("metadata", &self.metadata)
            .field("path", &self.path)
            .field("environment_key", &self.environment_key)
            .finish_non_exhaustive()
    }
}
impl CredentialProjection {
    pub fn secret_bytes(&self) -> Option<&[u8]> {
        self.secret.as_deref().map(|v| v.as_slice())
    }
}
impl Drop for CredentialProjection {
    fn drop(&mut self) {
        if self.remove_on_drop
            && let Some(path) = &self.path
        {
            let _ = fs::remove_file(path);
        }
    }
}

pub struct CredentialStore {
    store: NodeStore,
    key: Zeroizing<[u8; 32]>,
    projection_root: PathBuf,
}

pub struct SealedCredentialProjection {
    pub metadata: CredentialMetadata,
    pub file: File,
    pub size: u64,
    pub sha256: String,
}
type EncryptedCredentialRow = (Vec<u8>, Vec<u8>, Vec<u8>, String);
impl CredentialStore {
    pub fn open(
        store: NodeStore,
        key_path: impl AsRef<Path>,
        projection_root: impl AsRef<Path>,
    ) -> Result<Self, StoreError> {
        const MAGIC: &[u8; 8] = b"CREDDEK1";
        let key_path = key_path.as_ref();
        if let Some(parent) = key_path.parent() {
            fs::create_dir_all(parent)?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?
        }
        let key = if key_path.exists() {
            let meta = fs::symlink_metadata(key_path)?;
            if !meta.file_type().is_file()
                || meta.uid() != unsafe { libc::geteuid() }
                || meta.permissions().mode() & 0o777 != 0o600
            {
                return Err(StoreError::Invalid(
                    "credential DEK must be a regular mode-0600 file".into(),
                ));
            }
            let bytes = Zeroizing::new(fs::read(key_path)?);
            if bytes.len() != 40 || &bytes[..8] != MAGIC {
                return Err(StoreError::Corrupt("credential DEK version invalid".into()));
            }
            let mut k = [0u8; 32];
            k.copy_from_slice(&bytes[8..]);
            k
        } else {
            let mut k = [0u8; 32];
            getrandom::fill(&mut k).map_err(|_| StoreError::Crypto)?;
            let mut o = fs::OpenOptions::new();
            o.write(true).create_new(true).mode(0o600);
            use std::io::Write;
            let mut f = o.open(key_path)?;
            f.write_all(MAGIC)?;
            f.write_all(&k)?;
            f.sync_all()?;
            k
        };
        let projection_root = projection_root.as_ref().to_path_buf();
        fs::create_dir_all(&projection_root)?;
        fs::set_permissions(&projection_root, fs::Permissions::from_mode(0o700))?;
        Ok(Self {
            store,
            key: Zeroizing::new(key),
            projection_root,
        })
    }
    pub fn put(&self, metadata: &CredentialMetadata, secret: &[u8]) -> Result<(), StoreError> {
        if secret.len() > 1024 * 1024 {
            return Err(StoreError::TooLarge { limit: 1024 * 1024 });
        }
        let encoded =
            serde_json::to_vec(metadata).map_err(|e| StoreError::Invalid(e.to_string()))?;
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce).map_err(|_| StoreError::Crypto)?;
        let cipher = XChaCha20Poly1305::new((&*self.key).into());
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: secret,
                    aad: &encoded,
                },
            )
            .map_err(|_| StoreError::Crypto)?;
        let changed = self.store.conn()?.execute("INSERT INTO credential_profiles(profile_id,revision,adapter_id,kind,nonce,ciphertext,metadata) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(profile_id) DO UPDATE SET revision=excluded.revision,adapter_id=excluded.adapter_id,kind=excluded.kind,nonce=excluded.nonce,ciphertext=excluded.ciphertext,metadata=excluded.metadata WHERE excluded.revision>credential_profiles.revision",params![metadata.profile_id,metadata.revision,metadata.adapter_id,metadata.kind.as_str(),nonce,ciphertext,encoded]).map_err(map_sql)?;
        if changed != 1 {
            return Err(StoreError::Invalid(
                "credential revision must increase".into(),
            ));
        }
        Ok(())
    }
    fn decrypt(
        &self,
        id: &str,
        adapter: &str,
    ) -> Result<(CredentialMetadata, Zeroizing<Vec<u8>>), StoreError> {
        let row:Option<EncryptedCredentialRow>=self.store.conn()?.query_row("SELECT nonce,ciphertext,metadata,adapter_id FROM credential_profiles WHERE profile_id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional().map_err(map_sql)?;
        let (nonce, ciphertext, encoded, actual) = row.ok_or(StoreError::NotFound)?;
        if actual != adapter {
            return Err(StoreError::Invalid(
                "credential profile is bound to another adapter".into(),
            ));
        }
        if nonce.len() != 24 {
            return Err(StoreError::Corrupt("credential nonce invalid".into()));
        }
        let metadata = serde_json::from_slice(&encoded)
            .map_err(|_| StoreError::Corrupt("credential metadata invalid".into()))?;
        let cipher = XChaCha20Poly1305::new((&*self.key).into());
        let clear = cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &encoded,
                },
            )
            .map_err(|_| StoreError::Crypto)?;
        Ok((metadata, Zeroizing::new(clear)))
    }
    pub fn project(
        &self,
        id: &str,
        adapter: &str,
        kind: ProjectionKind,
        target: Option<&Path>,
        env_key: Option<&str>,
    ) -> Result<CredentialProjection, StoreError> {
        let (metadata, secret) = self.decrypt(id, adapter)?;
        if metadata.kind != kind {
            return Err(StoreError::Invalid(
                "projection kind not authorized by profile".into(),
            ));
        }
        match kind {
            ProjectionKind::NativeHost | ProjectionKind::LoginRequired => Err(StoreError::Invalid(
                "credential projection requires a registered broker".into(),
            )),
            ProjectionKind::Environment => {
                let key = env_key
                    .ok_or_else(|| StoreError::Invalid("environment key required".into()))?;
                if key.is_empty()
                    || key.len() > 128
                    || !key
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
                {
                    return Err(StoreError::Invalid("invalid environment key".into()));
                }
                Ok(CredentialProjection {
                    metadata,
                    path: None,
                    environment_key: Some(key.into()),
                    secret: Some(secret),
                    remove_on_drop: false,
                })
            }
            ProjectionKind::ReadOnlyFile
            | ProjectionKind::EphemeralFile
            | ProjectionKind::GuestVolume => {
                let path = target
                    .ok_or_else(|| StoreError::Invalid("projection target required".into()))?;
                if !path.is_absolute() || !path.starts_with(&self.projection_root) {
                    return Err(StoreError::Invalid(
                        "credential projection target is outside managed root".into(),
                    ));
                }
                if let Some(p) = path.parent() {
                    fs::create_dir_all(p)?;
                    let canonical = fs::canonicalize(p)?;
                    let root = fs::canonicalize(&self.projection_root)?;
                    if !canonical.starts_with(root) {
                        return Err(StoreError::Invalid(
                            "credential projection parent escaped managed root".into(),
                        ));
                    }
                }
                let mut o = fs::OpenOptions::new();
                o.write(true).create_new(true).mode(0o400);
                use std::io::Write;
                let mut f = o.open(path)?;
                f.write_all(&secret)?;
                f.sync_all()?;
                Ok(CredentialProjection {
                    metadata,
                    path: Some(path.into()),
                    environment_key: None,
                    secret: None,
                    remove_on_drop: true,
                })
            }
            ProjectionKind::AgentSocket => Err(StoreError::Invalid(
                "agent socket projection requires a registered broker endpoint".into(),
            )),
        }
    }

    /// Decrypts one adapter-bound profile directly into a sealed anonymous
    /// descriptor. The cleartext is never written into the Node filesystem or
    /// serialized into its journal; the privileged helper receives only this
    /// descriptor plus the independently signed descriptor commitment.
    pub fn sealed_read_only(
        &self,
        id: &str,
        adapter: &str,
        expected_revision: u64,
    ) -> Result<SealedCredentialProjection, StoreError> {
        let (metadata, secret) = self.decrypt(id, adapter)?;
        if metadata.revision != expected_revision
            || !matches!(
                metadata.kind,
                ProjectionKind::ReadOnlyFile | ProjectionKind::EphemeralFile
            )
        {
            return Err(StoreError::Invalid(
                "credential projection revision or kind is not authorized".into(),
            ));
        }
        let name = CString::new("conduit-credential")
            .map_err(|_| StoreError::Invalid("credential descriptor name".into()))?;
        let raw = unsafe {
            libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING)
        };
        if raw < 0 {
            return Err(StoreError::Io(std::io::Error::last_os_error()));
        }
        let mut file = unsafe { File::from_raw_fd(raw) };
        file.write_all(&secret)?;
        file.sync_all()?;
        file.seek(SeekFrom::Start(0))?;
        let seals =
            libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
            return Err(StoreError::Io(std::io::Error::last_os_error()));
        }
        Ok(SealedCredentialProjection {
            metadata,
            size: secret.len() as u64,
            sha256: hex::encode(Sha256::digest(&*secret)),
            file,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    #[test]
    fn encrypted_at_rest_and_adapter_bound() {
        let d = tempdir().unwrap();
        let store = NodeStore::open(d.path()).unwrap();
        let cs = CredentialStore::open(
            store.clone(),
            d.path().join("credential.dek"),
            d.path().join("projections"),
        )
        .unwrap();
        let m = CredentialMetadata {
            profile_id: "cred_12345678".into(),
            revision: 1,
            adapter_id: "codex".into(),
            kind: ProjectionKind::Environment,
            label: "Codex login".into(),
        };
        cs.put(&m, b"SUPERSECRET").unwrap();
        let db = fs::read(d.path().join("node.sqlite3")).unwrap();
        assert!(!db.windows(11).any(|v| v == b"SUPERSECRET"));
        assert!(
            cs.project(
                &m.profile_id,
                "claude",
                ProjectionKind::Environment,
                None,
                Some("TOKEN")
            )
            .is_err()
        );
        let p = cs
            .project(
                &m.profile_id,
                "codex",
                ProjectionKind::Environment,
                None,
                Some("TOKEN"),
            )
            .unwrap();
        assert_eq!(p.secret_bytes(), Some(b"SUPERSECRET".as_slice()));
    }
    #[test]
    fn dek_is_owner_only_and_ephemeral_projection_is_removed() {
        let d = tempdir().unwrap();
        let store = NodeStore::open(d.path()).unwrap();
        let key_path = d.path().join("credential.dek");
        let projection_root = d.path().join("projections");
        let cs = CredentialStore::open(store, &key_path, &projection_root).unwrap();
        let mode = fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let key = fs::read(&key_path).unwrap();
        assert_eq!(&key[..8], b"CREDDEK1");
        let metadata = CredentialMetadata {
            profile_id: "cred_ephemeral_01".into(),
            revision: 1,
            adapter_id: "codex".into(),
            kind: ProjectionKind::EphemeralFile,
            label: "ephemeral".into(),
        };
        cs.put(&metadata, b"TEMPSECRET").unwrap();
        let target = projection_root.join("run/token");
        {
            let projection = cs
                .project(
                    &metadata.profile_id,
                    "codex",
                    ProjectionKind::EphemeralFile,
                    Some(&target),
                    None,
                )
                .unwrap();
            assert_eq!(projection.path.as_deref(), Some(target.as_path()));
            assert_eq!(fs::read(&target).unwrap(), b"TEMPSECRET");
        }
        assert!(!target.exists());
    }

    #[test]
    fn privileged_projection_is_sealed_revision_and_adapter_bound() {
        let d = tempdir().unwrap();
        let store = NodeStore::open(d.path()).unwrap();
        let cs = CredentialStore::open(
            store,
            d.path().join("credential.dek"),
            d.path().join("projections"),
        )
        .unwrap();
        let metadata = CredentialMetadata {
            profile_id: "cred_privileged_01".into(),
            revision: 3,
            adapter_id: "codex".into(),
            kind: ProjectionKind::ReadOnlyFile,
            label: "root agent auth".into(),
        };
        cs.put(&metadata, b"sealed-secret").unwrap();
        assert!(
            cs.sealed_read_only(&metadata.profile_id, "codex", 2)
                .is_err()
        );
        assert!(cs.sealed_read_only(&metadata.profile_id, "pi", 3).is_err());
        let projection = cs
            .sealed_read_only(&metadata.profile_id, "codex", 3)
            .unwrap();
        assert_eq!(projection.size, 13);
        assert_eq!(
            projection.sha256,
            hex::encode(Sha256::digest(b"sealed-secret"))
        );
        let seals = unsafe { libc::fcntl(projection.file.as_raw_fd(), libc::F_GET_SEALS) };
        assert_eq!(
            seals
                & (libc::F_SEAL_SEAL
                    | libc::F_SEAL_SHRINK
                    | libc::F_SEAL_GROW
                    | libc::F_SEAL_WRITE),
            libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE
        );
    }
}
