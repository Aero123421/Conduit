use crate::{DeviceIdentity, NodeStore, StoreError, map_sql};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    os::unix::fs::OpenOptionsExt,
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

pub struct CredentialStore {
    store: NodeStore,
    key: [u8; 32],
}
type EncryptedCredentialRow = (Vec<u8>, Vec<u8>, Vec<u8>, String);
impl CredentialStore {
    pub fn new(store: NodeStore, identity: &DeviceIdentity) -> Self {
        Self {
            store,
            key: identity.credential_key(),
        }
    }
    pub fn put(&self, metadata: &CredentialMetadata, secret: &[u8]) -> Result<(), StoreError> {
        if secret.len() > 1024 * 1024 {
            return Err(StoreError::TooLarge { limit: 1024 * 1024 });
        }
        let encoded =
            serde_json::to_vec(metadata).map_err(|e| StoreError::Invalid(e.to_string()))?;
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce).map_err(|_| StoreError::Crypto)?;
        let cipher = XChaCha20Poly1305::new((&self.key).into());
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: secret,
                    aad: &encoded,
                },
            )
            .map_err(|_| StoreError::Crypto)?;
        self.store.conn()?.execute("INSERT INTO credential_profiles(profile_id,revision,adapter_id,kind,nonce,ciphertext,metadata) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(profile_id) DO UPDATE SET revision=excluded.revision,adapter_id=excluded.adapter_id,kind=excluded.kind,nonce=excluded.nonce,ciphertext=excluded.ciphertext,metadata=excluded.metadata WHERE excluded.revision>credential_profiles.revision",params![metadata.profile_id,metadata.revision,metadata.adapter_id,metadata.kind.as_str(),nonce,ciphertext,encoded]).map_err(map_sql)?;
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
        let cipher = XChaCha20Poly1305::new((&self.key).into());
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
            ProjectionKind::NativeHost | ProjectionKind::LoginRequired => {
                Ok(CredentialProjection {
                    metadata,
                    path: None,
                    environment_key: None,
                    secret: None,
                })
            }
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
                })
            }
            ProjectionKind::ReadOnlyFile
            | ProjectionKind::EphemeralFile
            | ProjectionKind::GuestVolume => {
                let path = target
                    .ok_or_else(|| StoreError::Invalid("projection target required".into()))?;
                if let Some(p) = path.parent() {
                    fs::create_dir_all(p)?;
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
                })
            }
            ProjectionKind::AgentSocket => Err(StoreError::Invalid(
                "agent socket projection requires a registered broker endpoint".into(),
            )),
        }
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
        let id = DeviceIdentity::load_or_create(d.path().join("key")).unwrap();
        let cs = CredentialStore::new(store.clone(), &id);
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
}
