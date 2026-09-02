use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use conduit_domain::{DeviceId, LocationId, Sha256Digest, SourceId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    GitRepository,
    ManagedFolder,
}

/// Shareable Source metadata. It intentionally cannot contain a canonical path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceRecord {
    pub source_id: SourceId,
    pub kind: SourceKind,
    pub display_name: String,
    pub repository_identity_digest: Option<Sha256Digest>,
}

/// Shareable Location metadata. `display_path` is bounded and need not be usable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocationRecord {
    pub location_id: LocationId,
    pub source_id: SourceId,
    pub device_id: DeviceId,
    pub revision: u64,
    pub display_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DeviceLocation {
    record: LocationRecord,
    canonical_path: PathBuf,
    filesystem_identity: FilesystemIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemIdentity {
    pub device: u64,
    pub inode: u64,
    pub file_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedLocation {
    pub record: LocationRecord,
    pub canonical_path: PathBuf,
    pub filesystem_identity: FilesystemIdentity,
}

#[derive(Debug, Default)]
pub struct DeviceLocationRegistry {
    sources: BTreeMap<SourceId, SourceRecord>,
    locations: BTreeMap<LocationId, DeviceLocation>,
}

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("source display name must contain 1 to 128 UTF-8 bytes")]
    InvalidSourceLabel,
    #[error("location display path must contain 1 to 160 UTF-8 bytes")]
    InvalidDisplayPath,
    #[error("source already exists")]
    SourceExists,
    #[error("source was not found")]
    SourceMissing,
    #[error("location already exists")]
    LocationExists,
    #[error("location was not found")]
    LocationMissing,
    #[error("location revision is stale")]
    SourceLocationStale,
    #[error("location path cannot be resolved: {0}")]
    PathUnavailable(std::io::Error),
    #[error("location filesystem identity changed")]
    FilesystemIdentityChanged,
}

impl DeviceLocationRegistry {
    pub fn register_source(&mut self, source: SourceRecord) -> Result<(), RegistryError> {
        if source.display_name.is_empty() || source.display_name.len() > 128 {
            return Err(RegistryError::InvalidSourceLabel);
        }
        if self.sources.contains_key(&source.source_id) {
            return Err(RegistryError::SourceExists);
        }
        self.sources.insert(source.source_id.clone(), source);
        Ok(())
    }

    pub fn register_location(
        &mut self,
        record: LocationRecord,
        local_path: &Path,
    ) -> Result<(), RegistryError> {
        if !self.sources.contains_key(&record.source_id) {
            return Err(RegistryError::SourceMissing);
        }
        if record.display_path.is_empty() || record.display_path.len() > 160 {
            return Err(RegistryError::InvalidDisplayPath);
        }
        if self.locations.contains_key(&record.location_id) {
            return Err(RegistryError::LocationExists);
        }
        let canonical_path =
            fs::canonicalize(local_path).map_err(RegistryError::PathUnavailable)?;
        let filesystem_identity = filesystem_identity(&canonical_path)?;
        self.locations.insert(
            record.location_id.clone(),
            DeviceLocation {
                record,
                canonical_path,
                filesystem_identity,
            },
        );
        Ok(())
    }

    /// Resolves and revalidates a canonical path on every use.
    pub fn resolve(
        &self,
        location_id: &LocationId,
        expected_revision: u64,
    ) -> Result<ResolvedLocation, RegistryError> {
        let location = self
            .locations
            .get(location_id)
            .ok_or(RegistryError::LocationMissing)?;
        if location.record.revision != expected_revision {
            return Err(RegistryError::SourceLocationStale);
        }
        let canonical_path =
            fs::canonicalize(&location.canonical_path).map_err(RegistryError::PathUnavailable)?;
        let identity = filesystem_identity(&canonical_path)?;
        if identity != location.filesystem_identity || canonical_path != location.canonical_path {
            return Err(RegistryError::FilesystemIdentityChanged);
        }
        Ok(ResolvedLocation {
            record: location.record.clone(),
            canonical_path,
            filesystem_identity: identity,
        })
    }

    pub fn shareable_locations(&self) -> Vec<LocationRecord> {
        self.locations
            .values()
            .map(|value| value.record.clone())
            .collect()
    }
}

fn filesystem_identity(path: &Path) -> Result<FilesystemIdentity, RegistryError> {
    let metadata = fs::metadata(path).map_err(RegistryError::PathUnavailable)?;
    let file_type = if metadata.is_dir() {
        "directory"
    } else if metadata.is_file() {
        "file"
    } else {
        "other"
    };
    Ok(FilesystemIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        file_type: file_type.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> SourceRecord {
        SourceRecord {
            source_id: SourceId::parse("src_abcdefgh").unwrap(),
            kind: SourceKind::ManagedFolder,
            display_name: "notes".into(),
            repository_identity_digest: None,
        }
    }

    #[test]
    fn cloud_metadata_never_serializes_canonical_path() {
        let json = serde_json::to_string(&LocationRecord {
            location_id: LocationId::parse("loc_abcdefgh").unwrap(),
            source_id: source().source_id,
            device_id: DeviceId::parse("dev_abcdefgh").unwrap(),
            revision: 1,
            display_path: "~/notes".into(),
        })
        .unwrap();
        assert!(!json.contains("canonical"));
        assert!(!json.contains("/home/"));
    }

    #[test]
    fn duplicate_source_does_not_replace_existing_identity() {
        let mut registry = DeviceLocationRegistry::default();
        let original = source();
        registry.register_source(original.clone()).unwrap();
        let mut replacement = original.clone();
        replacement.display_name = "replacement".into();
        assert!(matches!(
            registry.register_source(replacement),
            Err(RegistryError::SourceExists)
        ));
        assert_eq!(registry.sources.get(&original.source_id), Some(&original));
    }
}
