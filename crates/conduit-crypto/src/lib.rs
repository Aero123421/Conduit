//! Canonical JSON and digest helpers used by versioned Conduit contracts.

use conduit_domain::Sha256Digest;
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CanonicalJsonError {
    #[error("failed to canonicalize JSON: {0}")]
    Canonicalization(#[from] serde_json::Error),
}

pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonicalJsonError> {
    Ok(serde_jcs::to_vec(value)?)
}

pub fn sha256_bytes(bytes: &[u8]) -> Sha256Digest {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    Sha256Digest::from_bytes(digest)
}

pub fn canonical_sha256<T: Serialize>(value: &T) -> Result<Sha256Digest, CanonicalJsonError> {
    let bytes = canonical_json(value)?;
    Ok(sha256_bytes(&bytes))
}

pub fn domain_separated_sha256(domain: &str, payload: &[u8]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update(b"\n");
    hasher.update(payload);
    Sha256Digest::from_bytes(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use serde::Deserialize;
    use serde_json::json;

    use super::*;

    #[test]
    fn canonicalizes_object_keys() {
        let value = json!({"z": 1, "a": "x", "nested": {"b": true, "a": null}});
        let canonical = canonical_json(&value).unwrap();
        assert_eq!(
            std::str::from_utf8(&canonical).unwrap(),
            r#"{"a":"x","nested":{"a":null,"b":true},"z":1}"#
        );
    }

    #[test]
    fn domain_separation_changes_digest() {
        let payload = b"same";
        assert_ne!(
            domain_separated_sha256("conduit.a.v1", payload),
            domain_separated_sha256("conduit.b.v1", payload)
        );
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct CanonicalFixture {
        fixture_version: u8,
        algorithm: String,
        digest_algorithm: String,
        cases: Vec<CanonicalCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct CanonicalCase {
        name: String,
        value: serde_json::Value,
        expected_canonical: String,
        expected_sha256: String,
    }

    #[test]
    fn matches_shared_rfc8785_parity_fixture() {
        let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let path = workspace_root.join("spec/fixtures/canonical-json-v1.json");
        let fixture: CanonicalFixture = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();

        assert_eq!(fixture.fixture_version, 1);
        assert_eq!(fixture.algorithm, "RFC 8785");
        assert_eq!(fixture.digest_algorithm, "SHA-256");
        assert!(!fixture.cases.is_empty());

        for case in fixture.cases {
            let canonical = canonical_json(&case.value).unwrap();
            assert_eq!(
                std::str::from_utf8(&canonical).unwrap(),
                case.expected_canonical,
                "canonical bytes differ for {}",
                case.name
            );
            assert_eq!(
                sha256_bytes(&canonical).to_string(),
                case.expected_sha256,
                "SHA-256 differs for {}",
                case.name
            );
        }
    }
}
