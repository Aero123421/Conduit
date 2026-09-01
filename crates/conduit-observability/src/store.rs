use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Mutex,
    sync::atomic::{AtomicU64, Ordering},
};

use conduit_crypto::{canonical_json, canonical_sha256, sha256_bytes};
use conduit_domain::{AnyRunId, ContentObjectId, EventId, Sha256Digest, U64Decimal, UtcTimestamp};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

use crate::{
    Artifact, ContentObjectDescriptor, ContentObjectSet, EventDraft, EvidenceLevel, EvidenceState,
    NormalizedEvent, RawSegmentDescriptor, RedactionRecord, RetentionClass, RunManifest,
    Sensitivity, TraceContextSnapshot, TracePage,
};

pub const MAX_EVENT_BYTES: usize = 65_536;
pub const MAX_INLINE_PAYLOAD_BYTES: usize = 8_192;
pub const MAX_CONTENT_OBJECT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_RAW_SEGMENT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct RedactionRule {
    pub id: String,
    pub version: u32,
    pub keys: BTreeSet<String>,
    pub literal_patterns: Vec<String>,
    pub replacement_category: String,
}

#[derive(Debug, Clone, Default)]
pub struct RedactionPolicy {
    pub rules: Vec<RedactionRule>,
    /// Device-local HMAC key. When absent, no reversible/dictionary-testable
    /// digest of a redacted literal is persisted.
    pub digest_key: Option<[u8; 32]>,
}

impl RedactionPolicy {
    pub fn redact(&self, value: Value) -> (Value, Vec<RedactionRecord>) {
        let mut records = Vec::new();
        let redacted = self.redact_value(value, None, &mut records);
        (redacted, records)
    }

    fn redact_value(
        &self,
        value: Value,
        key: Option<&str>,
        records: &mut Vec<RedactionRecord>,
    ) -> Value {
        for rule in &self.rules {
            if key.is_some_and(|key| rule.keys.contains(key)) {
                records.push(record(rule, None));
                return Value::String(format!("[REDACTED:{}]", rule.replacement_category));
            }
        }
        match value {
            Value::Object(map) => Value::Object(
                map.into_iter()
                    .map(|(key, value)| {
                        let redacted = self.redact_value(value, Some(&key), records);
                        (key, redacted)
                    })
                    .collect(),
            ),
            Value::Array(values) => Value::Array(
                values
                    .into_iter()
                    .map(|value| self.redact_value(value, key, records))
                    .collect(),
            ),
            Value::String(mut text) => {
                for rule in &self.rules {
                    for pattern in &rule.literal_patterns {
                        if !pattern.is_empty() && text.contains(pattern) {
                            let keyed = self
                                .digest_key
                                .map(|key| hmac_sha256(&key, pattern.as_bytes()));
                            text = text.replace(
                                pattern,
                                &format!("[REDACTED:{}]", rule.replacement_category),
                            );
                            records.push(record(rule, keyed));
                        }
                    }
                }
                Value::String(text)
            }
            other => other,
        }
    }
}

fn record(rule: &RedactionRule, keyed_digest: Option<Sha256Digest>) -> RedactionRecord {
    RedactionRecord {
        rule_id: rule.id.clone(),
        rule_version: rule.version,
        replacement_category: rule.replacement_category.clone(),
        keyed_digest,
        evidence_level: EvidenceLevel::Explicit,
    }
}

#[derive(Debug)]
pub struct TraceStore {
    root: PathBuf,
    cursor_key: [u8; 32],
    write_guard: Mutex<()>,
}

#[derive(Debug)]
pub struct ContentPutRequest<'a> {
    pub run_id: &'a AnyRunId,
    pub content_kind: &'a str,
    pub sensitivity: Sensitivity,
    pub retention: RetentionClass,
    pub bytes: &'a [u8],
    pub created_at: UtcTimestamp,
    pub expires_at: Option<UtcTimestamp>,
}

impl TraceStore {
    pub fn open(root: impl AsRef<Path>, cursor_key: [u8; 32]) -> Result<Self, TraceError> {
        fs::create_dir_all(root.as_ref())?;
        let root = fs::canonicalize(root)?;
        secure_directory(&root)?;
        for directory in ["runs", "objects", "segments", "artifacts"] {
            let path = root.join(directory);
            fs::create_dir_all(&path)?;
            secure_directory(&path)?;
        }
        Ok(Self {
            root,
            cursor_key,
            write_guard: Mutex::new(()),
        })
    }

    /// This must complete before a caller requests Runtime start.
    pub fn commit_manifest(&self, manifest: &RunManifest) -> Result<(), TraceError> {
        let _guard = self
            .write_guard
            .lock()
            .map_err(|_| TraceError::StoreUnavailable)?;
        let recomputed = RunManifest::new(manifest.input.clone())?;
        if recomputed.manifest_digest != manifest.manifest_digest {
            return Err(TraceError::DigestMismatch);
        }
        let run_dir = self.run_dir(&manifest.input.run_id);
        fs::create_dir_all(run_dir.join("events"))?;
        fs::create_dir_all(run_dir.join("contexts"))?;
        secure_directory(&run_dir)?;
        secure_directory(&run_dir.join("events"))?;
        secure_directory(&run_dir.join("contexts"))?;
        let path = run_dir.join("manifest.json");
        write_immutable_json(&path, manifest).map_err(|error| match error {
            TraceError::AlreadyExists => TraceError::ManifestImmutable,
            other => other,
        })?;
        write_atomic(&run_dir.join("generation"), b"1")?;
        Ok(())
    }

    pub fn manifest(&self, run_id: &AnyRunId) -> Result<RunManifest, TraceError> {
        read_json(&self.run_dir(run_id).join("manifest.json"))
    }

    pub fn commit_context(&self, snapshot: &TraceContextSnapshot) -> Result<(), TraceError> {
        let _guard = self
            .write_guard
            .lock()
            .map_err(|_| TraceError::StoreUnavailable)?;
        self.require_manifest(&snapshot.run_id)?;
        let expected = context_digest(snapshot)?;
        if expected != snapshot.snapshot_digest {
            return Err(TraceError::DigestMismatch);
        }
        let path = self
            .run_dir(&snapshot.run_id)
            .join("contexts")
            .join(format!("{}.json", snapshot.context_snapshot_id.as_str()));
        write_immutable_json(&path, snapshot)
    }

    pub fn append_event(
        &self,
        run_id: &AnyRunId,
        device_id: conduit_domain::DeviceId,
        expected_sequence: u64,
        mut draft: EventDraft,
        redaction: &RedactionPolicy,
    ) -> Result<NormalizedEvent, TraceError> {
        let _guard = self
            .write_guard
            .lock()
            .map_err(|_| TraceError::StoreUnavailable)?;
        self.require_manifest(run_id)?;
        let manifest = self.manifest(run_id)?;
        if device_id != manifest.input.device_id {
            return Err(TraceError::DeviceMismatch);
        }
        draft.event_type = bound(draft.event_type, 128);
        draft.source_component = bound(draft.source_component, 128);
        draft.boot_id = bound(draft.boot_id, 128);
        draft.correlation_id = bound(draft.correlation_id, 256);
        if !valid_event_name(&draft.event_type)
            || !valid_event_name(&draft.source_component)
            || !(16..=128).contains(&draft.boot_id.len())
            || !valid_hex_id(draft.trace_id.as_deref(), 32)
            || !valid_hex_id(draft.span_id.as_deref(), 16)
            || !valid_hex_id(draft.parent_span_id.as_deref(), 16)
        {
            return Err(TraceError::InvalidEventEnvelope);
        }
        if draft.sensitivity == Sensitivity::Secret {
            draft.payload = json!({"redacted": true, "reason": "secret_sensitivity"});
            draft.sensitivity = Sensitivity::Metadata;
        }
        let (mut payload, redactions) = redaction.redact(std::mem::take(&mut draft.payload));
        if !redactions.is_empty() {
            payload = json!({"value": payload, "redactions": redactions});
        }
        let payload_bytes = canonical_json(&payload)?;
        if !payload.is_object() || payload.as_object().is_some_and(|object| object.len() > 128) {
            return Err(TraceError::InvalidEventPayload);
        }
        if payload_bytes.len() > MAX_INLINE_PAYLOAD_BYTES {
            return Err(TraceError::ContentObjectRequired);
        }
        let events = self.read_events(run_id)?;
        if let Some(existing) = events.iter().find(|event| event.event_id == draft.event_id) {
            let proposed_digest = event_core_digest(
                run_id,
                &device_id,
                expected_sequence,
                &draft,
                &payload,
                sha256_bytes(&payload_bytes),
            )?;
            return if proposed_digest == existing.event_digest {
                Ok(existing.clone())
            } else {
                Err(TraceError::DuplicateConflict)
            };
        }
        let next = events
            .last()
            .map_or(1, |event| event.sequence.get().saturating_add(1));
        if expected_sequence != next {
            return Err(TraceError::SequenceGap {
                expected: next,
                actual: expected_sequence,
            });
        }
        let payload_digest = sha256_bytes(&payload_bytes);
        let event_digest = event_core_digest(
            run_id,
            &device_id,
            expected_sequence,
            &draft,
            &payload,
            payload_digest,
        )?;
        let previous_chain_hash = events.last().map_or_else(
            || {
                sha256_bytes(
                    format!("conduit.event-chain.v1\n{}", manifest.manifest_digest).as_bytes(),
                )
            },
            |event| event.chain_hash,
        );
        let chain_hash = sha256_bytes(
            format!("conduit.event-chain.v1\n{previous_chain_hash}\n{event_digest}").as_bytes(),
        );
        let event = NormalizedEvent {
            schema_version: 1,
            kind: "normalized_event".into(),
            event_id: draft.event_id,
            run_id: run_id.clone(),
            device_id,
            sequence: U64Decimal::new(expected_sequence),
            event_type: draft.event_type,
            source_component: draft.source_component,
            observed_at: draft.observed_at,
            monotonic_ns: draft.monotonic_ns,
            boot_id: draft.boot_id,
            correlation_id: draft.correlation_id,
            parent_event_id: draft.parent_event_id,
            trace_id: draft.trace_id,
            span_id: draft.span_id,
            parent_span_id: draft.parent_span_id,
            evidence_level: draft.evidence_level,
            sensitivity: draft.sensitivity,
            retention: draft.retention,
            payload,
            payload_digest,
            event_digest,
            previous_chain_hash,
            chain_hash,
        };
        let bytes = canonical_json(&event)?;
        if bytes.len() > MAX_EVENT_BYTES {
            return Err(TraceError::EventTooLarge);
        }
        let path = self
            .run_dir(run_id)
            .join("events")
            .join(format!("{:020}.json", expected_sequence));
        write_immutable(&path, &bytes)?;
        Ok(event)
    }

    pub fn read_events(&self, run_id: &AnyRunId) -> Result<Vec<NormalizedEvent>, TraceError> {
        const MAX_EVENTS_PER_RUN: usize = 1_000_000;
        self.require_manifest(run_id)?;
        let directory = self.run_dir(run_id).join("events");
        let mut paths: Vec<_> = fs::read_dir(directory)?
            .take(MAX_EVENTS_PER_RUN + 1)
            .collect::<Result<Vec<_>, _>>()?;
        if paths.len() > MAX_EVENTS_PER_RUN {
            return Err(TraceError::InputTooLarge);
        }
        paths.sort_by_key(fs::DirEntry::file_name);
        paths
            .into_iter()
            .map(|entry| {
                let file_type = entry.file_type()?;
                let name = entry.file_name();
                let name = name.to_str().ok_or(TraceError::StoreCorrupt)?;
                if !file_type.is_file()
                    || name.len() != 25
                    || !name.ends_with(".json")
                    || !name[..20].bytes().all(|byte| byte.is_ascii_digit())
                {
                    return Err(TraceError::StoreCorrupt);
                }
                read_json_bounded(&entry.path(), MAX_EVENT_BYTES)
            })
            .collect()
    }

    pub fn verify_chain(&self, run_id: &AnyRunId) -> Result<EvidenceState, TraceError> {
        let manifest = self.manifest(run_id)?;
        let events = self.read_events(run_id)?;
        verify_chain_events(&manifest, &events)
    }

    pub fn put_content(
        &self,
        request: ContentPutRequest<'_>,
    ) -> Result<ContentObjectSet, TraceError> {
        let _guard = self
            .write_guard
            .lock()
            .map_err(|_| TraceError::StoreUnavailable)?;
        self.require_manifest(request.run_id)?;
        let mut objects = Vec::new();
        for chunk in request.bytes.chunks(MAX_CONTENT_OBJECT_BYTES) {
            let digest = sha256_bytes(chunk);
            let id = ContentObjectId::parse(format!("obj_{}", &digest.to_string()[..24]))
                .map_err(|_| TraceError::InvalidId)?;
            let relative = format!("objects/{digest}.bin");
            let path = self.root.join(&relative);
            if path.exists() {
                if sha256_bytes(&read_bounded_file(&path, MAX_CONTENT_OBJECT_BYTES)?) != digest {
                    return Err(TraceError::ContentCollision);
                }
            } else {
                write_immutable(&path, chunk)?;
            }
            let descriptor = ContentObjectDescriptor {
                object_id: id,
                run_id: request.run_id.clone(),
                content_kind: bound(request.content_kind.to_owned(), 128),
                sensitivity: request.sensitivity,
                retention: request.retention,
                uncompressed_bytes: chunk.len() as u64,
                stored_bytes: chunk.len() as u64,
                plaintext_digest: digest,
                stored_digest: digest,
                opaque_locator: relative,
                created_at: request.created_at.clone(),
                expires_at: request.expires_at.clone(),
            };
            let descriptor_directory = self.root.join("objects").join(request.run_id.as_str());
            fs::create_dir_all(&descriptor_directory)?;
            secure_directory(&descriptor_directory)?;
            let descriptor_path = descriptor_directory.join(format!("{digest}.json"));
            if !descriptor_path.exists() {
                write_immutable_json(&descriptor_path, &descriptor)?;
            }
            objects.push(descriptor);
        }
        Ok(ContentObjectSet {
            objects,
            aggregate_digest: sha256_bytes(request.bytes),
            total_bytes: request.bytes.len() as u64,
        })
    }

    pub fn read_content(
        &self,
        descriptor: &ContentObjectDescriptor,
        allow: &[Sensitivity],
    ) -> Result<Vec<u8>, TraceError> {
        self.require_manifest(&descriptor.run_id)?;
        let descriptor_path = self
            .root
            .join("objects")
            .join(descriptor.run_id.as_str())
            .join(format!("{}.json", descriptor.stored_digest));
        let stored: ContentObjectDescriptor = read_json(&descriptor_path)?;
        if &stored != descriptor {
            return Err(TraceError::ContentDescriptorMismatch);
        }
        if !allow.contains(&stored.sensitivity) {
            return Err(TraceError::ContentPermissionDenied);
        }
        let expected_locator = format!("objects/{}.bin", stored.stored_digest);
        if stored.opaque_locator != expected_locator {
            return Err(TraceError::ContentDescriptorMismatch);
        }
        let bytes = read_bounded_file(
            &self.root.join(&stored.opaque_locator),
            MAX_CONTENT_OBJECT_BYTES,
        )?;
        if sha256_bytes(&bytes) != stored.stored_digest {
            return Err(TraceError::ContentCorrupt);
        }
        Ok(bytes)
    }

    pub fn put_raw_segment(
        &self,
        run_id: &AnyRunId,
        stream_id: &str,
        records: &[RawRecord],
    ) -> Result<RawSegmentDescriptor, TraceError> {
        let _guard = self
            .write_guard
            .lock()
            .map_err(|_| TraceError::StoreUnavailable)?;
        self.require_manifest(run_id)?;
        if records.is_empty() {
            return Err(TraceError::EmptySegment);
        }
        let mut bytes = Vec::new();
        let mut previous_sequence = None;
        for record in records {
            if record.bytes.len() > MAX_RAW_SEGMENT_BYTES
                || record.direction.is_empty()
                || record.direction.len() > 32
                || previous_sequence.is_some_and(|previous| record.local_sequence != previous + 1)
            {
                return Err(TraceError::SegmentTooLarge);
            }
            previous_sequence = Some(record.local_sequence);
            let payload = canonical_json(record)?;
            let length = u32::try_from(payload.len()).map_err(|_| TraceError::SegmentTooLarge)?;
            if bytes.len().saturating_add(4).saturating_add(payload.len()) > MAX_RAW_SEGMENT_BYTES {
                return Err(TraceError::SegmentTooLarge);
            }
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes.extend_from_slice(&payload);
        }
        let digest = sha256_bytes(&bytes);
        let segment_id = format!("segment-{}", &digest.to_string()[..24]);
        let relative = format!("segments/{digest}.seg");
        write_immutable(&self.root.join(&relative), &bytes)?;
        let descriptor = RawSegmentDescriptor {
            segment_id,
            run_id: run_id.clone(),
            stream_id: bound(stream_id.to_owned(), 128),
            first_local_sequence: records.first().map_or(0, |record| record.local_sequence),
            last_local_sequence: records.last().map_or(0, |record| record.local_sequence),
            record_count: records.len() as u64,
            uncompressed_bytes: bytes.len() as u64,
            stored_digest: digest,
            opaque_locator: relative,
            gap_bytes: 0,
        };
        write_immutable_json(
            &self.root.join("segments").join(format!("{digest}.json")),
            &descriptor,
        )?;
        Ok(descriptor)
    }

    /// Recovers a `.partial` length-prefixed file, retaining every complete record
    /// and reporting bytes dropped from only the incomplete tail.
    pub fn recover_partial_segment(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<(Vec<RawRecord>, u64), TraceError> {
        let path = fs::canonicalize(path)?;
        let segments = self.root.join("segments");
        if !path.starts_with(&segments)
            || path.extension().and_then(|value| value.to_str()) != Some("partial")
        {
            return Err(TraceError::PathOutsideStore);
        }
        let bytes = read_bounded_file(&path, MAX_RAW_SEGMENT_BYTES)?;
        let mut offset = 0usize;
        let mut records = Vec::new();
        while offset + 4 <= bytes.len() {
            let length = u32::from_be_bytes(
                bytes[offset..offset + 4]
                    .try_into()
                    .map_err(|_| TraceError::SegmentCorrupt)?,
            ) as usize;
            if offset + 4 + length > bytes.len() {
                break;
            }
            records.push(
                serde_json::from_slice(&bytes[offset + 4..offset + 4 + length])
                    .map_err(|_| TraceError::SegmentCorrupt)?,
            );
            offset += 4 + length;
        }
        let gap = (bytes.len() - offset) as u64;
        if gap > 0 {
            let file = OpenOptions::new().write(true).open(&path)?;
            file.set_len(offset as u64)?;
            file.sync_all()?;
        }
        Ok((records, gap))
    }

    pub fn put_artifact(&self, artifact: &Artifact) -> Result<(), TraceError> {
        let _guard = self
            .write_guard
            .lock()
            .map_err(|_| TraceError::StoreUnavailable)?;
        self.require_manifest(&artifact.run_id)?;
        write_immutable_json(
            &self
                .root
                .join("artifacts")
                .join(format!("{}.json", artifact.artifact_id.as_str())),
            artifact,
        )
    }

    pub fn trace_page(
        &self,
        run_id: &AnyRunId,
        cursor: Option<&str>,
        max_records: usize,
        max_response_bytes: usize,
        event_type_prefix: Option<&str>,
    ) -> Result<TracePage, TraceError> {
        if max_records == 0
            || max_records > 1_000
            || max_response_bytes == 0
            || max_response_bytes > 4 * 1024 * 1024
        {
            return Err(TraceError::InvalidPageLimit);
        }
        let generation = self.generation(run_id)?;
        let filter = event_type_prefix.unwrap_or("");
        let start = match cursor {
            Some(cursor) => {
                let decoded = decode_cursor(cursor, &self.cursor_key)?;
                if decoded.run_id != run_id.as_str() || decoded.filter != filter {
                    return Err(TraceError::CursorSubstitution);
                }
                if decoded.generation != generation {
                    return Err(TraceError::CursorStale {
                        restart_sequence: decoded.next_sequence,
                    });
                }
                decoded.next_sequence
            }
            None => 1,
        };
        let all = self.read_events(run_id)?;
        let evidence_state = verify_chain_events(&self.manifest(run_id)?, &all)?;
        let max_sequence = all.last().map_or(0, |event| event.sequence.get());
        let mut page = Vec::new();
        let mut bytes = 0usize;
        let mut next = None;
        for event in all
            .into_iter()
            .filter(|event| event.sequence.get() >= start && event.event_type.starts_with(filter))
        {
            let event_bytes = canonical_json(&event)?.len();
            if page.len() >= max_records || bytes.saturating_add(event_bytes) > max_response_bytes {
                next = Some(event.sequence.get());
                break;
            }
            bytes += event_bytes;
            next = Some(event.sequence.get().saturating_add(1));
            page.push(event);
        }
        let next_cursor = next
            .filter(|sequence| *sequence <= max_sequence)
            .map(|next_sequence| {
                encode_cursor(
                    CursorCore {
                        run_id: run_id.as_str().into(),
                        next_sequence,
                        generation,
                        filter: filter.into(),
                    },
                    &self.cursor_key,
                )
            })
            .transpose()?;
        Ok(TracePage {
            events: page,
            next_cursor,
            evidence_state,
        })
    }

    pub fn compact(
        &self,
        run_id: &AnyRunId,
        removable: &[RetentionClass],
    ) -> Result<u64, TraceError> {
        if removable.contains(&RetentionClass::R0) {
            return Err(TraceError::AuthorityRetentionForbidden);
        }
        let _guard = self
            .write_guard
            .lock()
            .map_err(|_| TraceError::StoreUnavailable)?;
        let events = self.read_events(run_id)?;
        for event in events {
            if removable.contains(&event.retention) {
                let path = self
                    .run_dir(run_id)
                    .join("events")
                    .join(format!("{:020}.json", event.sequence.get()));
                fs::remove_file(path)?;
            }
        }
        let generation = self.generation(run_id)?.saturating_add(1);
        write_atomic(
            &self.run_dir(run_id).join("generation"),
            generation.to_string().as_bytes(),
        )?;
        Ok(generation)
    }

    fn require_manifest(&self, run_id: &AnyRunId) -> Result<(), TraceError> {
        if self.run_dir(run_id).join("manifest.json").is_file() {
            Ok(())
        } else {
            Err(TraceError::ManifestRequired)
        }
    }
    fn run_dir(&self, run_id: &AnyRunId) -> PathBuf {
        self.root.join("runs").join(run_id.as_str())
    }
    fn generation(&self, run_id: &AnyRunId) -> Result<u64, TraceError> {
        self.require_manifest(run_id)?;
        fs::read_to_string(self.run_dir(run_id).join("generation"))?
            .parse()
            .map_err(|_| TraceError::StoreCorrupt)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RawRecord {
    pub local_sequence: u64,
    pub monotonic_ns: u64,
    pub direction: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CursorCore {
    run_id: String,
    next_sequence: u64,
    generation: u64,
    filter: String,
}

fn encode_cursor(core: CursorCore, key: &[u8; 32]) -> Result<String, TraceError> {
    let data = canonical_json(&core)?;
    let mac = cursor_mac(key, &data);
    Ok(format!("{}.{}", hex_encode(&data), mac))
}

fn decode_cursor(value: &str, key: &[u8; 32]) -> Result<CursorCore, TraceError> {
    if value.len() > 8_192 || !value.is_ascii() {
        return Err(TraceError::CursorInvalid);
    }
    let (data, supplied) = value.split_once('.').ok_or(TraceError::CursorInvalid)?;
    let bytes = hex_decode(data).ok_or(TraceError::CursorInvalid)?;
    if !constant_time_eq(cursor_mac(key, &bytes).as_bytes(), supplied.as_bytes()) {
        return Err(TraceError::CursorInvalid);
    }
    serde_json::from_slice(&bytes).map_err(|_| TraceError::CursorInvalid)
}

fn cursor_mac(key: &[u8; 32], data: &[u8]) -> String {
    let mut input = Vec::with_capacity(18 + data.len());
    input.extend_from_slice(b"conduit.cursor.v1\n");
    input.extend_from_slice(data);
    hmac_sha256(key, &input).to_string()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EventCore<'a> {
    schema_version: u8,
    kind: &'a str,
    event_id: &'a EventId,
    run_id: &'a AnyRunId,
    device_id: &'a conduit_domain::DeviceId,
    sequence: U64Decimal,
    event_type: &'a str,
    #[serde(rename = "source")]
    source_component: &'a str,
    observed_at: &'a UtcTimestamp,
    monotonic_ns: Option<U64Decimal>,
    #[serde(rename = "nodeBootId")]
    boot_id: &'a str,
    correlation_id: &'a str,
    parent_event_id: &'a Option<EventId>,
    trace_id: &'a Option<String>,
    span_id: &'a Option<String>,
    parent_span_id: &'a Option<String>,
    evidence_level: EvidenceLevel,
    sensitivity: Sensitivity,
    #[serde(rename = "retentionClass")]
    retention: RetentionClass,
    payload: &'a Value,
    payload_digest: Sha256Digest,
}

fn event_core_digest(
    run_id: &AnyRunId,
    device_id: &conduit_domain::DeviceId,
    sequence: u64,
    draft: &EventDraft,
    payload: &Value,
    payload_digest: Sha256Digest,
) -> Result<Sha256Digest, TraceError> {
    Ok(canonical_sha256(&EventCore {
        schema_version: 1,
        kind: "normalized_event",
        event_id: &draft.event_id,
        run_id,
        device_id,
        sequence: U64Decimal::new(sequence),
        event_type: &draft.event_type,
        source_component: &draft.source_component,
        observed_at: &draft.observed_at,
        monotonic_ns: draft.monotonic_ns,
        boot_id: &draft.boot_id,
        correlation_id: &draft.correlation_id,
        parent_event_id: &draft.parent_event_id,
        trace_id: &draft.trace_id,
        span_id: &draft.span_id,
        parent_span_id: &draft.parent_span_id,
        evidence_level: draft.evidence_level,
        sensitivity: draft.sensitivity,
        retention: draft.retention,
        payload,
        payload_digest,
    })?)
}

fn stored_event_digest(event: &NormalizedEvent) -> Result<Sha256Digest, TraceError> {
    Ok(canonical_sha256(&EventCore {
        schema_version: event.schema_version,
        kind: &event.kind,
        event_id: &event.event_id,
        run_id: &event.run_id,
        device_id: &event.device_id,
        sequence: event.sequence,
        event_type: &event.event_type,
        source_component: &event.source_component,
        observed_at: &event.observed_at,
        monotonic_ns: event.monotonic_ns,
        boot_id: &event.boot_id,
        correlation_id: &event.correlation_id,
        parent_event_id: &event.parent_event_id,
        trace_id: &event.trace_id,
        span_id: &event.span_id,
        parent_span_id: &event.parent_span_id,
        evidence_level: event.evidence_level,
        sensitivity: event.sensitivity,
        retention: event.retention,
        payload: &event.payload,
        payload_digest: event.payload_digest,
    })?)
}

fn verify_chain_events(
    manifest: &RunManifest,
    events: &[NormalizedEvent],
) -> Result<EvidenceState, TraceError> {
    let mut previous =
        sha256_bytes(format!("conduit.event-chain.v1\n{}", manifest.manifest_digest).as_bytes());
    let mut expected_sequence = 1u64;
    for event in events {
        if event.schema_version != 1 || event.kind != "normalized_event" {
            return Ok(EvidenceState::EventChainMismatch);
        }
        if event.sequence.get() != expected_sequence {
            return Ok(EvidenceState::RetentionGap);
        }
        if event.previous_chain_hash != previous {
            return Ok(EvidenceState::EventChainMismatch);
        }
        let payload = canonical_json(&event.payload)?;
        if sha256_bytes(&payload) != event.payload_digest
            || stored_event_digest(event)? != event.event_digest
        {
            return Ok(EvidenceState::EventChainMismatch);
        }
        let expected = sha256_bytes(
            format!("conduit.event-chain.v1\n{previous}\n{}", event.event_digest).as_bytes(),
        );
        if expected != event.chain_hash {
            return Ok(EvidenceState::EventChainMismatch);
        }
        previous = expected;
        expected_sequence = expected_sequence.saturating_add(1);
    }
    Ok(EvidenceState::Complete)
}

fn context_digest(snapshot: &TraceContextSnapshot) -> Result<Sha256Digest, TraceError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Core<'a> {
        id: &'a conduit_domain::ContextSnapshotId,
        run_id: &'a AnyRunId,
        operation: &'a str,
        mode: &'a str,
        epoch: u64,
        project_revision: Option<u64>,
        session_revision: Option<u64>,
        selected: &'a [String],
        instructions: Sha256Digest,
        skills: Sha256Digest,
        compiler: &'a str,
        items: Sha256Digest,
        bytes: u64,
        content: Sha256Digest,
    }
    Ok(canonical_sha256(&Core {
        id: &snapshot.context_snapshot_id,
        run_id: &snapshot.run_id,
        operation: &snapshot.input_operation_id,
        mode: &snapshot.mode,
        epoch: snapshot.controller_epoch,
        project_revision: snapshot.project_context_revision,
        session_revision: snapshot.session_revision,
        selected: &snapshot.selected_record_ids,
        instructions: snapshot.instruction_catalog_digest,
        skills: snapshot.skill_catalog_digest,
        compiler: &snapshot.compiler_version,
        items: snapshot.item_manifest_digest,
        bytes: snapshot.compiled_bytes,
        content: snapshot.compiled_content_digest,
    })?)
}

fn write_immutable_json(path: &Path, value: &impl Serialize) -> Result<(), TraceError> {
    write_immutable(path, &canonical_json(value)?)
}
fn write_immutable(path: &Path, bytes: &[u8]) -> Result<(), TraceError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    if path.exists() {
        return Err(TraceError::AlreadyExists);
    }
    let temporary = temporary_path(path);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                TraceError::AlreadyExists
            } else {
                TraceError::Io(error)
            }
        })?;
    file.write_all(bytes)?;
    file.sync_all()?;
    match fs::hard_link(&temporary, path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&temporary);
            return Err(TraceError::AlreadyExists);
        }
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            return Err(TraceError::Io(error));
        }
    }
    fs::remove_file(&temporary)?;
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), TraceError> {
    let temporary = temporary_path(path);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}
fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, TraceError> {
    read_json_bounded(path, 64 * 1024 * 1024)
}

fn read_json_bounded<T: for<'de> Deserialize<'de>>(
    path: &Path,
    max: usize,
) -> Result<T, TraceError> {
    Ok(serde_json::from_slice(&read_bounded_file(path, max)?)?)
}

fn read_bounded_file(path: &Path, max: usize) -> Result<Vec<u8>, TraceError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > max as u64 {
        return Err(TraceError::InputTooLarge);
    }
    Ok(fs::read(path)?)
}

fn secure_directory(path: &Path) -> Result<(), TraceError> {
    let metadata = fs::metadata(path)?;
    let current_uid = fs::metadata("/proc/self")?.uid();
    if !metadata.is_dir() || metadata.uid() != current_uid {
        return Err(TraceError::UnsafeStoreCustody);
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn temporary_path(path: &Path) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    path.with_extension(format!(
        "tmp-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

fn hmac_sha256(key: &[u8; 32], data: &[u8]) -> Sha256Digest {
    let mut inner_key = [0x36u8; 64];
    let mut outer_key = [0x5cu8; 64];
    for (index, byte) in key.iter().enumerate() {
        inner_key[index] ^= byte;
        outer_key[index] ^= byte;
    }
    let mut inner = Vec::with_capacity(64 + data.len());
    inner.extend_from_slice(&inner_key);
    inner.extend_from_slice(data);
    let inner_digest = sha256_bytes(&inner);
    let mut outer = Vec::with_capacity(96);
    outer.extend_from_slice(&outer_key);
    outer.extend_from_slice(inner_digest.as_bytes());
    sha256_bytes(&outer)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let length = left.len().max(right.len());
    for index in 0..length {
        difference |= usize::from(
            left.get(index).copied().unwrap_or_default()
                ^ right.get(index).copied().unwrap_or_default(),
        );
    }
    difference == 0
}

fn valid_event_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_lowercase()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
        })
}

fn valid_hex_id(value: Option<&str>, length: usize) -> bool {
    value.is_none_or(|value| {
        value.len() == length
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}
fn bound(value: String, max: usize) -> String {
    if value.len() <= max {
        return value;
    }
    let mut end = max;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                HEX[(byte >> 4) as usize] as char,
                HEX[(byte & 15) as usize] as char,
            ]
        })
        .collect()
}
fn hex_decode(value: &str) -> Option<Vec<u8>> {
    if !value.is_ascii() || !value.len().is_multiple_of(2) {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).ok())
        .collect()
}

#[derive(Debug, Error)]
pub enum TraceError {
    #[error("manifest must be committed before trace records")]
    ManifestRequired,
    #[error("run manifest is immutable")]
    ManifestImmutable,
    #[error("immutable record already exists")]
    AlreadyExists,
    #[error("record digest does not match")]
    DigestMismatch,
    #[error("event payload requires a Content Object")]
    ContentObjectRequired,
    #[error("normalized Event exceeds 65,536 bytes")]
    EventTooLarge,
    #[error("normalized Event payload must be a bounded JSON object")]
    InvalidEventPayload,
    #[error("normalized Event envelope violates the v1 wire contract")]
    InvalidEventEnvelope,
    #[error("event sequence gap: expected {expected}, got {actual}")]
    SequenceGap { expected: u64, actual: u64 },
    #[error("duplicate Event ID or sequence has different content")]
    DuplicateConflict,
    #[error("content-address collision")]
    ContentCollision,
    #[error("content permission denied")]
    ContentPermissionDenied,
    #[error("content descriptor does not match authoritative store metadata")]
    ContentDescriptorMismatch,
    #[error("content digest verification failed")]
    ContentCorrupt,
    #[error("raw Segment cannot be empty")]
    EmptySegment,
    #[error("raw Segment exceeds its configured bound")]
    SegmentTooLarge,
    #[error("raw Segment is corrupt")]
    SegmentCorrupt,
    #[error("trace page limits are invalid")]
    InvalidPageLimit,
    #[error("cursor is invalid")]
    CursorInvalid,
    #[error("path resolves outside the trace store")]
    PathOutsideStore,
    #[error("trace input exceeds its configured bound")]
    InputTooLarge,
    #[error("trace store ownership or filesystem type is unsafe")]
    UnsafeStoreCustody,
    #[error("Event Device does not match the immutable Run Manifest")]
    DeviceMismatch,
    #[error("cursor cannot be substituted across Run or filter")]
    CursorSubstitution,
    #[error("cursor is stale; restart at or near sequence {restart_sequence}")]
    CursorStale { restart_sequence: u64 },
    #[error("R0 authority records cannot be compacted")]
    AuthorityRetentionForbidden,
    #[error("identifier is invalid")]
    InvalidId,
    #[error("trace store is unavailable")]
    StoreUnavailable,
    #[error("trace store metadata is corrupt")]
    StoreCorrupt,
    #[error("filesystem operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON operation failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("canonical JSON operation failed: {0}")]
    Canonical(#[from] conduit_crypto::CanonicalJsonError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CatalogEntry, RunManifestInput};
    use conduit_domain::{DeviceId, ManifestId};
    use std::collections::BTreeMap;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn digest(value: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([value; 32])
    }
    fn ts() -> UtcTimestamp {
        UtcTimestamp::parse("2026-09-01T00:00:00Z").unwrap()
    }
    fn run() -> AnyRunId {
        AnyRunId::parse("run_abcdefgh").unwrap()
    }
    fn temp() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "conduit-trace-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }
    fn manifest() -> RunManifest {
        RunManifest::new(RunManifestInput {
            manifest_id: ManifestId::parse("rman_abcdefgh").unwrap(),
            run_id: run(),
            assignment_id: None,
            operation_id: "op".into(),
            request_digest: digest(1),
            idempotency_key_digest: digest(2),
            actor_id: "owner".into(),
            client_id: "cli".into(),
            admitted_at: ts(),
            device_id: DeviceId::parse("dev_abcdefgh").unwrap(),
            node_version: "1".into(),
            node_protocol_version: "conduit.node/1".into(),
            boot_id: "boot-000000000001".into(),
            capability_digest: digest(3),
            local_policy_revision: 1,
            runtime_kind: "native".into(),
            runtime_provider_id: "native-linux".into(),
            runtime_config_digest: digest(4),
            effective_capabilities: BTreeMap::new(),
            requested_access_scope: "full_user".into(),
            effective_access_scope: "full_user".into(),
            requested_approval_mode: "never".into(),
            effective_approval_mode: "never".into(),
            policy_revision_digest: digest(5),
            source_bindings: vec![],
            adapter_id: None,
            adapter_version: None,
            executable_digest: None,
            model: None,
            effort: None,
            context_compiler_version: "1".into(),
            instruction_catalog: Vec::<CatalogEntry>::new(),
            skill_catalog: vec![],
            capture_policy_digest: digest(6),
            redaction_policy_digest: digest(7),
            retention_policy_digest: digest(8),
            evaluation_tags: BTreeMap::new(),
        })
        .unwrap()
    }
    fn draft(id: &str, payload: Value) -> EventDraft {
        EventDraft {
            event_id: EventId::parse(id).unwrap(),
            event_type: "test.completed".into(),
            source_component: "test-runner".into(),
            observed_at: ts(),
            monotonic_ns: Some(U64Decimal::new(1)),
            boot_id: "boot-000000000001".into(),
            correlation_id: "test".into(),
            parent_event_id: None,
            trace_id: Some("c128113b728b5b59fefc3db0744cd8c2".into()),
            span_id: Some("28b3d2982c033dee".into()),
            parent_span_id: None,
            evidence_level: EvidenceLevel::Observed,
            sensitivity: Sensitivity::ProjectContent,
            retention: RetentionClass::R1,
            payload,
        }
    }

    #[test]
    fn manifest_precedes_events_and_chain_detects_sequence_integrity() {
        let root = temp();
        let store = TraceStore::open(&root, [9; 32]).unwrap();
        assert!(matches!(
            store.append_event(
                &run(),
                DeviceId::parse("dev_abcdefgh").unwrap(),
                1,
                draft("evt_abcdefgh", json!({})),
                &RedactionPolicy::default()
            ),
            Err(TraceError::ManifestRequired)
        ));
        store.commit_manifest(&manifest()).unwrap();
        store
            .append_event(
                &run(),
                DeviceId::parse("dev_abcdefgh").unwrap(),
                1,
                draft("evt_abcdefgh", json!({"ok":true})),
                &RedactionPolicy::default(),
            )
            .unwrap();
        store
            .append_event(
                &run(),
                DeviceId::parse("dev_abcdefgh").unwrap(),
                2,
                draft("evt_ijklmnop", json!({"ok":true})),
                &RedactionPolicy::default(),
            )
            .unwrap();
        let duplicate = store
            .append_event(
                &run(),
                DeviceId::parse("dev_abcdefgh").unwrap(),
                2,
                draft("evt_ijklmnop", json!({"ok":true})),
                &RedactionPolicy::default(),
            )
            .unwrap();
        assert_eq!(duplicate.sequence.get(), 2);
        assert!(matches!(
            store.append_event(
                &run(),
                DeviceId::parse("dev_abcdefgh").unwrap(),
                2,
                draft("evt_ijklmnop", json!({"ok":false})),
                &RedactionPolicy::default(),
            ),
            Err(TraceError::DuplicateConflict)
        ));
        assert_eq!(store.verify_chain(&run()).unwrap(), EvidenceState::Complete);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn redacts_before_persistence_and_cursor_cannot_cross_filters() {
        let root = temp();
        let store = TraceStore::open(&root, [7; 32]).unwrap();
        store.commit_manifest(&manifest()).unwrap();
        let policy = RedactionPolicy {
            rules: vec![RedactionRule {
                id: "secret-key".into(),
                version: 1,
                keys: BTreeSet::from(["token".into()]),
                literal_patterns: vec!["hunter2".into()],
                replacement_category: "credential".into(),
            }],
            digest_key: Some([4; 32]),
        };
        let event = store
            .append_event(
                &run(),
                DeviceId::parse("dev_abcdefgh").unwrap(),
                1,
                draft(
                    "evt_abcdefgh",
                    json!({"token":"hunter2","output":"saw hunter2"}),
                ),
                &policy,
            )
            .unwrap();
        store
            .append_event(
                &run(),
                DeviceId::parse("dev_abcdefgh").unwrap(),
                2,
                draft("evt_ijklmnop", json!({"output":"safe"})),
                &policy,
            )
            .unwrap();
        assert!(!serde_json::to_string(&event).unwrap().contains("hunter2"));
        let page = store
            .trace_page(&run(), None, 1, 65_536, Some("test"))
            .unwrap();
        let cursor = page.next_cursor.expect("a second matching Event remains");
        assert!(matches!(
            store.trace_page(&run(), Some(&cursor), 1, 65_536, Some("command")),
            Err(TraceError::CursorSubstitution)
        ));
        store.compact(&run(), &[RetentionClass::R2]).unwrap();
        assert!(matches!(
            store.trace_page(&run(), Some(&cursor), 1, 65_536, Some("test")),
            Err(TraceError::CursorStale { .. })
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn large_content_splits_and_raw_partial_recovery_reports_gap() {
        let root = temp();
        let store = TraceStore::open(&root, [3; 32]).unwrap();
        store.commit_manifest(&manifest()).unwrap();
        let content = vec![42; MAX_CONTENT_OBJECT_BYTES + 17];
        let run_id = run();
        let set = store
            .put_content(ContentPutRequest {
                run_id: &run_id,
                content_kind: "command_output",
                sensitivity: Sensitivity::RawLog,
                retention: RetentionClass::R3,
                bytes: &content,
                created_at: ts(),
                expires_at: None,
            })
            .unwrap();
        assert_eq!(set.objects.len(), 2);
        let segment = store
            .put_raw_segment(
                &run(),
                "terminal",
                &[RawRecord {
                    local_sequence: 1,
                    monotonic_ns: 1,
                    direction: "output".into(),
                    bytes: b"hello".to_vec(),
                }],
            )
            .unwrap();
        let mut partial = fs::read(root.join(segment.opaque_locator)).unwrap();
        partial.extend_from_slice(&100u32.to_be_bytes());
        partial.extend_from_slice(b"bad");
        let path = root.join("segments/crash.partial");
        fs::write(&path, partial).unwrap();
        let (records, gap) = store.recover_partial_segment(path).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(gap, 7);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn chain_verification_detects_payload_tampering() {
        let root = temp();
        let store = TraceStore::open(&root, [5; 32]).unwrap();
        store.commit_manifest(&manifest()).unwrap();
        store
            .append_event(
                &run(),
                DeviceId::parse("dev_abcdefgh").unwrap(),
                1,
                draft("evt_abcdefgh", json!({"ok":true})),
                &RedactionPolicy::default(),
            )
            .unwrap();
        let path = root.join("runs/run_abcdefgh/events/00000000000000000001.json");
        let mut stored: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        stored["payload"] = json!({"ok":false});
        fs::write(&path, serde_json::to_vec(&stored).unwrap()).unwrap();
        assert_eq!(
            store.verify_chain(&run()).unwrap(),
            EvidenceState::EventChainMismatch
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn event_wire_shape_and_content_descriptor_are_bound() {
        let root = temp();
        let store = TraceStore::open(&root, [6; 32]).unwrap();
        store.commit_manifest(&manifest()).unwrap();
        let event = store
            .append_event(
                &run(),
                DeviceId::parse("dev_abcdefgh").unwrap(),
                1,
                draft("evt_abcdefgh", json!({"ok":true})),
                &RedactionPolicy::default(),
            )
            .unwrap();
        let wire = serde_json::to_value(&event).unwrap();
        for key in [
            "schemaVersion",
            "kind",
            "source",
            "nodeBootId",
            "retentionClass",
            "traceId",
            "spanId",
        ] {
            assert!(wire.get(key).is_some(), "missing wire key {key}");
        }
        assert!(wire.get("sourceComponent").is_none());

        let set = store
            .put_content(ContentPutRequest {
                run_id: &run(),
                content_kind: "test",
                sensitivity: Sensitivity::ProjectContent,
                retention: RetentionClass::R1,
                bytes: b"content",
                created_at: ts(),
                expires_at: None,
            })
            .unwrap();
        let mut forged = set.objects[0].clone();
        forged.opaque_locator = "/etc/passwd".into();
        forged.sensitivity = Sensitivity::Public;
        assert!(matches!(
            store.read_content(&forged, &[Sensitivity::Public]),
            Err(TraceError::ContentDescriptorMismatch)
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn redaction_digest_is_hmac_not_plain_sha256() {
        let policy = RedactionPolicy {
            rules: vec![RedactionRule {
                id: "secret".into(),
                version: 1,
                keys: BTreeSet::new(),
                literal_patterns: vec!["short-password".into()],
                replacement_category: "credential".into(),
            }],
            digest_key: Some([9; 32]),
        };
        let (_, records) = policy.redact(json!({"text":"short-password"}));
        assert_ne!(
            records[0].keyed_digest,
            Some(sha256_bytes(b"short-password"))
        );
    }
}
