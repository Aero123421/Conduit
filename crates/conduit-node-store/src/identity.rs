use crate::StoreError;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};
use zeroize::Zeroizing;

/// Device Ed25519 identity. The private seed is created mode 0600 and never
/// appears in Debug output or a transport payload.
pub struct DeviceIdentity {
    signing: SigningKey,
    key_id: String,
}

impl std::fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceIdentity")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl DeviceIdentity {
    pub fn load_or_create(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let seed = if path.exists() {
            let meta = fs::symlink_metadata(path)?;
            if !meta.file_type().is_file()
                || meta.uid() != unsafe { libc::geteuid() }
                || meta.permissions().mode() & 0o777 != 0o600
            {
                return Err(StoreError::Invalid(
                    "device key must be a regular mode-0600 file".into(),
                ));
            }
            let bytes = Zeroizing::new(fs::read(path)?);
            if bytes.len() != 32 {
                return Err(StoreError::Corrupt("invalid device key length".into()));
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            seed
        } else {
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).map_err(|_| StoreError::Crypto)?;
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true).mode(0o600);
            let mut file = options.open(path)?;
            use std::io::Write;
            file.write_all(&seed)?;
            file.sync_all()?;
            seed
        };
        let signing = SigningKey::from_bytes(&seed);
        let key_id = format!(
            "dkey_{}",
            hex::encode(&Sha256::digest(signing.verifying_key().as_bytes())[..16])
        );
        Ok(Self { signing, key_id })
    }
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
    pub fn public_key_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.signing.verifying_key().as_bytes())
    }
    pub fn sign(&self, transcript: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(self.signing.sign(transcript).to_bytes())
    }
    pub fn verify(&self, transcript: &[u8], signature: &str) -> Result<(), StoreError> {
        let raw = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| StoreError::Crypto)?;
        let sig = Signature::from_slice(&raw).map_err(|_| StoreError::Crypto)?;
        self.signing
            .verifying_key()
            .verify(transcript, &sig)
            .map_err(|_| StoreError::Crypto)
    }
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    #[test]
    fn persists_and_signs() {
        let d = tempdir().unwrap();
        let p = d.path().join("device.key");
        let a = DeviceIdentity::load_or_create(&p).unwrap();
        let sig = a.sign(b"challenge");
        let id = a.key_id().to_string();
        drop(a);
        let b = DeviceIdentity::load_or_create(&p).unwrap();
        assert_eq!(b.key_id(), id);
        b.verify(b"challenge", &sig).unwrap();
        assert!(b.verify(b"other", &sig).is_err());
        assert_eq!(fs::metadata(p).unwrap().permissions().mode() & 0o777, 0o600);
    }
}
