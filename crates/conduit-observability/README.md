# conduit-observability

Device-local authoritative trace and evidence implementation.

`TraceStore` requires an immutable Run Manifest before Context Snapshots or Events. Events are bounded canonical JSON records with persistent sequence numbers and the `conduit.event-chain.v1` hash chain. Large content is split into immutable 8 MiB objects; raw streams use bounded length-prefixed Segments with incomplete-tail recovery.

Redaction runs before normalized persistence. Sensitivity and R0-R3 retention remain separate. Cursor MACs bind Run, filter, position, and store generation; compaction makes old cursors explicitly stale. Artifact custody metadata is immutable.

Derived services provide bounded Run/Event search, failure clustering, instruction and Skill evidence-level reports, matched-comparison safeguards, candidate rollout records, and an OpenTelemetry adapter. OTel export records omitted fields and never reconstructs content that capture policy did not retain.
