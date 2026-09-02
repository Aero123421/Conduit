//! Bounded, durable-transport friendly batching primitives.
//!
//! These types deliberately do not own any transport or storage state.  The
//! service records each event locally first and uses the accumulator only to
//! decide when a cloud `event.batch` frame is ready.  Keeping the policy here
//! makes the byte, count, timer, health, and acknowledgement boundaries
//! independently testable.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

/// The first flush boundary is intentionally at the upper end of the review
/// window.  A caller may flush earlier for priority events or when a socket is
/// being closed.
pub const EVENT_BATCH_FLUSH_AFTER: Duration = Duration::from_millis(100);
pub const EVENT_BATCH_MAX_EVENTS: usize = 32;
/// Leave envelope and digest headroom below the 65,536-byte wire frame limit.
pub const EVENT_BATCH_MAX_BYTES: usize = 60_000;
pub const ACK_FLUSH_AFTER: Duration = Duration::from_millis(100);
pub const ACK_MAX_PENDING: usize = 32;
/// Keep unchanged semantic health at the upper edge of the protocol's
/// five-to-ten-minute window.  WebSocket Ping/Pong remains the liveness
/// mechanism; this checkpoint is only for an unchanged semantic snapshot.
pub const DEFAULT_HEALTH_CHECKPOINT: Duration = Duration::from_secs(10 * 60);

#[derive(Debug, thiserror::Error)]
pub enum BatchError {
    #[error("event batch event must be a JSON object")]
    InvalidEvent,
    #[error("event batch exceeds {EVENT_BATCH_MAX_BYTES} encoded bytes")]
    TooLarge,
    #[error("event batch encoding failed")]
    Encoding,
}

/// One normalized event waiting for cloud transport.  `priority` is a
/// transport policy bit; it never changes the event itself or its local
/// sequence.
#[derive(Debug, Clone, PartialEq)]
pub struct BufferedEvent {
    pub sequence: u64,
    pub event: Value,
    pub priority: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EventBatch {
    pub run_id: String,
    pub operation_id: Option<String>,
    pub from_sequence: u64,
    pub through_sequence: u64,
    pub source_range_digest: String,
    pub priority: bool,
    pub events: Vec<Value>,
    pub payload: Value,
    pub encoded_bytes: usize,
}

impl EventBatch {
    pub fn from_events(
        run_id: impl Into<String>,
        operation_id: Option<String>,
        events: Vec<BufferedEvent>,
    ) -> Result<Self, BatchError> {
        if events.is_empty() {
            return Err(BatchError::InvalidEvent);
        }
        let run_id = run_id.into();
        let from_sequence = events
            .first()
            .map(|event| event.sequence)
            .ok_or(BatchError::InvalidEvent)?;
        let through_sequence = events
            .last()
            .map(|event| event.sequence)
            .ok_or(BatchError::InvalidEvent)?;
        let priority = events.iter().any(|event| event.priority);
        let values = events
            .into_iter()
            .map(|event| event.event)
            .collect::<Vec<_>>();
        let payload = build_payload(&run_id, from_sequence, through_sequence, values.clone())?;
        let encoded_bytes = serde_jcs::to_vec(&payload)
            .map_err(|_| BatchError::Encoding)?
            .len();
        if encoded_bytes > EVENT_BATCH_MAX_BYTES {
            return Err(BatchError::TooLarge);
        }
        let source_range_digest = payload["sourceRangeDigest"]
            .as_str()
            .ok_or(BatchError::Encoding)?
            .to_owned();
        Ok(Self {
            run_id,
            operation_id,
            from_sequence,
            through_sequence,
            source_range_digest,
            priority,
            events: values,
            payload,
            encoded_bytes,
        })
    }
}

/// Accumulates one Run's normalized events.  Adjacent assistant deltas stay
/// as separate normalized records inside the same batch: this is a wire-level
/// coalesce, so concatenating their visible text is byte-for-byte identical to
/// the local stream and every source sequence/digest remains auditable.
#[derive(Debug, Clone)]
pub struct EventAccumulator {
    run_id: String,
    operation_id: Option<String>,
    events: Vec<BufferedEvent>,
    first_event_at: Option<Instant>,
}

impl EventAccumulator {
    pub fn new(run_id: impl Into<String>, operation_id: Option<String>) -> Self {
        Self {
            run_id: run_id.into(),
            operation_id,
            events: Vec::new(),
            first_event_at: None,
        }
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn operation_id(&self) -> Option<&str> {
        self.operation_id.as_deref()
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn first_event_at(&self) -> Option<Instant> {
        self.first_event_at
    }

    /// Add an event and return any batches that became ready.  The normal
    /// path flushes at 32 events, 60,000 encoded payload bytes, or 100ms.  A
    /// priority event flushes the preceding normal events and itself in the
    /// same call, so approvals, terminal/error, tool, command, and file
    /// effects never wait behind a timer.
    pub fn push(
        &mut self,
        sequence: u64,
        event: Value,
        priority: bool,
        now: Instant,
    ) -> Result<Vec<EventBatch>, BatchError> {
        if !event.is_object() {
            return Err(BatchError::InvalidEvent);
        }
        let mut ready = Vec::new();
        if self
            .first_event_at
            .is_some_and(|started| now.duration_since(started) >= EVENT_BATCH_FLUSH_AFTER)
            && let Some(batch) = self.flush()?
        {
            ready.push(batch);
        }

        let candidate = BufferedEvent {
            sequence,
            event,
            priority,
        };
        if !self.events.is_empty() {
            let count_full = self.events.len() >= EVENT_BATCH_MAX_EVENTS;
            let mut trial = self.events.clone();
            trial.push(candidate.clone());
            let too_large = !fits(&self.run_id, &trial)?;
            if (count_full || too_large)
                && let Some(batch) = self.flush()?
            {
                ready.push(batch);
            }
        }

        if self.events.is_empty() {
            self.first_event_at = Some(now);
        }
        self.events.push(candidate);

        let full = self.events.len() >= EVENT_BATCH_MAX_EVENTS;
        let size_full = !fits(&self.run_id, &self.events)?;
        if size_full {
            // A single normalized event must fit the bounded event payload.
            // If it does not, retaining it in memory would only postpone a
            // deterministic failure and could lose the run's progress.
            if self.events.len() == 1 {
                self.events.clear();
                self.first_event_at = None;
                return Err(BatchError::TooLarge);
            }
            let last = self.events.pop().ok_or(BatchError::InvalidEvent)?;
            if let Some(batch) = self.flush()? {
                ready.push(batch);
            }
            self.first_event_at = Some(now);
            self.events.push(last);
        }
        if (full || priority)
            && let Some(batch) = self.flush()?
        {
            ready.push(batch);
        }
        Ok(ready)
    }

    pub fn flush_due(&mut self, now: Instant) -> Result<Option<EventBatch>, BatchError> {
        if self
            .first_event_at
            .is_some_and(|started| now.duration_since(started) >= EVENT_BATCH_FLUSH_AFTER)
        {
            self.flush()
        } else {
            Ok(None)
        }
    }

    pub fn flush(&mut self) -> Result<Option<EventBatch>, BatchError> {
        if self.events.is_empty() {
            self.first_event_at = None;
            return Ok(None);
        }
        let events = std::mem::take(&mut self.events);
        self.first_event_at = None;
        EventBatch::from_events(&self.run_id, self.operation_id.clone(), events).map(Some)
    }
}

/// Build a replay batch from already persisted normalized events.  Replay uses
/// the same source range/digest contract as live accumulation.
pub fn replay_batch(
    run_id: impl Into<String>,
    events: Vec<(u64, Value)>,
) -> Result<EventBatch, BatchError> {
    EventBatch::from_events(
        run_id,
        None,
        events
            .into_iter()
            .map(|(sequence, event)| BufferedEvent {
                sequence,
                event,
                priority: false,
            })
            .collect(),
    )
}

fn fits(run_id: &str, events: &[BufferedEvent]) -> Result<bool, BatchError> {
    if events.is_empty() || events.len() > EVENT_BATCH_MAX_EVENTS {
        return Ok(false);
    }
    let values = events
        .iter()
        .map(|event| event.event.clone())
        .collect::<Vec<_>>();
    Ok(serde_jcs::to_vec(&build_payload(
        run_id,
        events[0].sequence,
        events.last().ok_or(BatchError::InvalidEvent)?.sequence,
        values,
    )?)
    .map_err(|_| BatchError::Encoding)?
    .len()
        <= EVENT_BATCH_MAX_BYTES)
}

fn build_payload(
    run_id: &str,
    from_sequence: u64,
    through_sequence: u64,
    events: Vec<Value>,
) -> Result<Value, BatchError> {
    if events.is_empty() || events.len() > EVENT_BATCH_MAX_EVENTS {
        return Err(BatchError::InvalidEvent);
    }
    if events.iter().any(|event| !event.is_object()) {
        return Err(BatchError::InvalidEvent);
    }
    let source_range_digest =
        source_range_digest(run_id, from_sequence, through_sequence, &events)?;
    Ok(json!({
        "runId": run_id,
        "fromSequence": from_sequence.to_string(),
        "throughSequence": through_sequence.to_string(),
        "sourceSequenceRange": {
            "from": from_sequence.to_string(),
            "through": through_sequence.to_string(),
        },
        "sourceRangeDigest": source_range_digest,
        "traceSchema": "conduit.trace/1",
        "events": events,
    }))
}

/// The range digest commits the exact local range and each normalized event's
/// immutable digest.  A fallback digest over the complete canonical event is
/// used for test/replay callers that do not have an eventDigest field.
pub fn source_range_digest(
    run_id: &str,
    from_sequence: u64,
    through_sequence: u64,
    events: &[Value],
) -> Result<String, BatchError> {
    let commitments = events
        .iter()
        .enumerate()
        .map(|(index, event)| {
            let object = event.as_object().ok_or(BatchError::InvalidEvent)?;
            let sequence = object
                .get("sequence")
                .cloned()
                .unwrap_or_else(|| Value::String((from_sequence + index as u64).to_string()));
            let event_digest = object
                .get("eventDigest")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or_else(|| {
                    serde_jcs::to_vec(event)
                        .map(|bytes| hex::encode(Sha256::digest(bytes)))
                        .unwrap_or_default()
                });
            Ok(json!({"sequence": sequence, "eventDigest": event_digest}))
        })
        .collect::<Result<Vec<_>, BatchError>>()?;
    let commitment = json!({
        "runId": run_id,
        "fromSequence": from_sequence.to_string(),
        "throughSequence": through_sequence.to_string(),
        "events": commitments,
    });
    let bytes = serde_jcs::to_vec(&commitment).map_err(|_| BatchError::Encoding)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

/// Cumulative ACK policy used by the service.  ACKs are emitted after at most
/// 100ms or 32 received frames, while callers may force a flush at a durable
/// boundary such as reconciliation completion.
#[derive(Debug, Clone, Default)]
pub struct AckAccumulator {
    through: Option<u64>,
    pending: usize,
    first_at: Option<Instant>,
}

impl AckAccumulator {
    pub fn note(&mut self, sequence: u64, now: Instant) {
        self.through = Some(self.through.map_or(sequence, |value| value.max(sequence)));
        self.pending = self.pending.saturating_add(1);
        self.first_at.get_or_insert(now);
    }

    pub fn is_empty(&self) -> bool {
        self.through.is_none()
    }

    pub fn through(&self) -> Option<u64> {
        self.through
    }

    pub fn should_flush(&self, now: Instant) -> bool {
        self.pending >= ACK_MAX_PENDING
            || self
                .first_at
                .is_some_and(|started| now.duration_since(started) >= ACK_FLUSH_AFTER)
    }

    pub fn take(&mut self) -> Option<u64> {
        self.pending = 0;
        self.first_at = None;
        self.through.take()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthState {
    pub node_state: String,
    pub journal_state: String,
    pub storage_state: String,
    pub active_commands: usize,
    pub active_agent_runs: usize,
    pub active_runtimes: usize,
}

#[derive(Debug, Clone)]
pub struct HealthTracker {
    checkpoint: Duration,
    last_state: Option<HealthState>,
    last_sent_at: Option<Instant>,
}

impl Default for HealthTracker {
    fn default() -> Self {
        Self::new(DEFAULT_HEALTH_CHECKPOINT)
    }
}

impl HealthTracker {
    pub fn new(checkpoint: Duration) -> Self {
        Self {
            checkpoint,
            last_state: None,
            last_sent_at: None,
        }
    }

    pub fn checkpoint(&self) -> Duration {
        self.checkpoint
    }

    pub fn last_state(&self) -> Option<&HealthState> {
        self.last_state.as_ref()
    }

    pub fn last_sent_at(&self) -> Option<Instant> {
        self.last_sent_at
    }

    /// Returns true only for an unchanged state whose semantic checkpoint is
    /// due.  Callers can use this to replay the exact durable health envelope
    /// instead of allocating another transport sequence and outbox row.
    pub fn unchanged_checkpoint_due(&self, state: &HealthState, now: Instant) -> bool {
        self.last_state.as_ref() == Some(state)
            && self
                .last_sent_at
                .is_some_and(|last| now.duration_since(last) >= self.checkpoint)
    }

    pub fn should_emit(&self, state: &HealthState, now: Instant, force: bool) -> bool {
        force
            || self.last_state.as_ref() != Some(state)
            || self
                .last_sent_at
                .is_none_or(|last| now.duration_since(last) >= self.checkpoint)
    }

    pub fn record(&mut self, state: HealthState, now: Instant) {
        self.last_state = Some(state);
        self.last_sent_at = Some(now);
    }

    pub fn consider(&mut self, state: HealthState, now: Instant, force: bool) -> bool {
        if !self.should_emit(&state, now, force) {
            return false;
        }
        self.record(state, now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY_SECONDS: u64 = 24 * 60 * 60;
    const ACTIVE_RUN_SECONDS: u64 = 8 * 60 * 60;
    const CONTROL_PLANE_HEALTH_CHECKPOINT_SECONDS: u64 = 15 * 60;
    const DELTA_COUNT: u64 = 10_000;
    const PRIORITY_EVENT_COUNT: u64 = 500;

    // These are the DeviceRoom owner's measured steady-state counters used
    // by the cross-component budget model.  A new semantic health projection
    // takes the existing nine-row upper bound; an exact unchanged-health
    // replay only updates the health marker at the 15-minute D1 checkpoint.
    // The replay path does not create an ACK or an alarm.
    const DEVICE_ROOM_D1_ROWS_PER_NEW_HEALTH: u64 = 2;
    const DEVICE_ROOM_D1_ROWS_PER_HEALTH_CHECKPOINT: u64 = 1;
    const DEVICE_ROOM_D1_ROWS_PER_CONNECTION: u64 = 1;
    const DEVICE_ROOM_DO_ROWS_PER_NEW_HEALTH: u64 = 9;
    const DEVICE_ROOM_DO_ROWS_PER_HEALTH_CHECKPOINT: u64 = 1;
    const DEVICE_ROOM_DO_ROWS_PER_CONNECTION: u64 = 8;
    const DEVICE_ROOM_IDLE_ALARMS: u64 = 0;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct DailyFreeEstimate {
        worker_requests: u64,
        d1_rows_read: u64,
        d1_rows_written: u64,
        durable_object_requests: u64,
        durable_object_rows_read: u64,
        durable_object_rows_written: u64,
        free_queue_operations: u64,
        queue_mode_operations: u64,
        log_trace_events: u64,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct IdleDeviceEstimate {
        health_frames: u64,
        health_projections: u64,
        d1_rows_written: u64,
        durable_object_rows_written: u64,
        alarm_invocations: u64,
    }

    fn ceil_div(value: u64, divisor: u64) -> u64 {
        value.saturating_add(divisor.saturating_sub(1)) / divisor
    }

    fn delta_probe() -> (Vec<EventBatch>, String) {
        let start = Instant::now();
        let mut accumulator = EventAccumulator::new("run_delta_budget01", None);
        let mut batches = Vec::new();
        let mut expected = String::new();
        for sequence in 1..=DELTA_COUNT {
            let text = if sequence % 97 == 0 {
                "漢字🦀"
            } else {
                "delta\n"
            };
            expected.push_str(text);
            batches.extend(
                accumulator
                    .push(
                        sequence,
                        event(sequence, text),
                        false,
                        start + Duration::from_millis(sequence),
                    )
                    .unwrap(),
            );
        }
        if let Some(batch) = accumulator.flush().unwrap() {
            batches.push(batch);
        }
        (batches, expected)
    }

    fn health_probe_emissions() -> usize {
        let start = Instant::now();
        let state = HealthState {
            node_state: "ready".into(),
            journal_state: "healthy".into(),
            storage_state: "healthy".into(),
            active_commands: 0,
            active_agent_runs: 0,
            active_runtimes: 0,
        };
        let mut tracker = HealthTracker::new(Duration::from_secs(5 * 60));
        let mut emitted = 0;
        emitted += tracker.consider(state.clone(), start, false) as usize;
        emitted += tracker.consider(state.clone(), start + Duration::from_secs(60), false) as usize;
        emitted +=
            tracker.consider(state.clone(), start + Duration::from_secs(5 * 60), false) as usize;
        let mut changed = state;
        changed.node_state = "degraded".into();
        emitted +=
            tracker.consider(changed, start + Duration::from_secs(5 * 60 + 1), false) as usize;
        emitted
    }

    fn idle_device_estimate() -> IdleDeviceEstimate {
        let health_frames = 1 + ceil_div(DAY_SECONDS, DEFAULT_HEALTH_CHECKPOINT.as_secs());
        // D1's 15-minute throttle is observed only when the Node sends its
        // ten-minute exact checkpoint, so unchanged state projects every
        // second checkpoint (20 minutes), not on an independent timer.
        let observable_projection_seconds = ceil_div(
            CONTROL_PLANE_HEALTH_CHECKPOINT_SECONDS,
            DEFAULT_HEALTH_CHECKPOINT.as_secs(),
        ) * DEFAULT_HEALTH_CHECKPOINT.as_secs();
        let health_projections = 1 + ceil_div(DAY_SECONDS, observable_projection_seconds);
        IdleDeviceEstimate {
            health_frames,
            health_projections,
            d1_rows_written: DEVICE_ROOM_D1_ROWS_PER_NEW_HEALTH
                .saturating_add(
                    health_projections
                        .saturating_sub(1)
                        .saturating_mul(DEVICE_ROOM_D1_ROWS_PER_HEALTH_CHECKPOINT),
                )
                .saturating_add(DEVICE_ROOM_D1_ROWS_PER_CONNECTION),
            durable_object_rows_written: DEVICE_ROOM_DO_ROWS_PER_NEW_HEALTH
                .saturating_add(
                    health_projections
                        .saturating_sub(1)
                        .saturating_mul(DEVICE_ROOM_DO_ROWS_PER_HEALTH_CHECKPOINT),
                )
                .saturating_add(DEVICE_ROOM_DO_ROWS_PER_CONNECTION),
            alarm_invocations: DEVICE_ROOM_IDLE_ALARMS,
        }
    }

    /// Conservative daily model for the review's fleet scenario. This is a
    /// quota projection, not a Cloudflare account measurement. Node health
    /// application frames are charged as one Worker/DO request and six DO row
    /// reads. Idle health writes use the DeviceRoom counter above: only the
    /// initial semantic frame uses the nine-row upper bound, while unchanged
    /// exact replays incur the measured one-row 15-minute marker checkpoint.
    /// Active health and event frames retain the nine-row upper bound. D1 event
    /// work is charged at three reads per write. The Free profile keeps event
    /// batches in the durable inbox, so Queue operations remain zero. The
    /// queue-mode column is included to guard the alternate one-batch path.
    fn estimate_daily_free_usage(
        idle_devices: u64,
        measured_delta_batches: u64,
        measured_max_batch_bytes: u64,
    ) -> DailyFreeEstimate {
        assert!(measured_max_batch_bytes < 65_536);
        let idle_device = idle_device_estimate();
        let idle_health_frames = idle_devices.saturating_mul(idle_device.health_frames);
        let active_health_frames =
            1 + ceil_div(ACTIVE_RUN_SECONDS, DEFAULT_HEALTH_CHECKPOINT.as_secs());
        let active_event_batches = measured_delta_batches + PRIORITY_EVENT_COUNT;
        let application_frames = idle_health_frames + active_health_frames + active_event_batches;
        let connection_count = idle_devices + 1;
        let normalized_events = DELTA_COUNT + PRIORITY_EVENT_COUNT;
        let active_health_projections =
            1 + ceil_div(ACTIVE_RUN_SECONDS, CONTROL_PLANE_HEALTH_CHECKPOINT_SECONDS);
        let worker_requests = application_frames
            .saturating_add(288)
            .saturating_add(connection_count.saturating_mul(3));
        let d1_rows_written = normalized_events
            .saturating_add(active_event_batches)
            .saturating_add(idle_devices.saturating_mul(idle_device.d1_rows_written))
            .saturating_add(
                active_health_projections.saturating_mul(DEVICE_ROOM_D1_ROWS_PER_NEW_HEALTH),
            )
            .saturating_add(DEVICE_ROOM_D1_ROWS_PER_CONNECTION)
            .saturating_add(4);
        let d1_rows_read = d1_rows_written.saturating_mul(3);
        let durable_object_requests = worker_requests;
        let durable_object_rows_written = idle_devices
            .saturating_mul(idle_device.durable_object_rows_written)
            .saturating_add(
                active_health_frames
                    .saturating_add(active_event_batches)
                    .saturating_mul(DEVICE_ROOM_DO_ROWS_PER_NEW_HEALTH),
            )
            .saturating_add(DEVICE_ROOM_DO_ROWS_PER_CONNECTION);
        let durable_object_rows_read = application_frames
            .saturating_mul(6)
            .saturating_add(connection_count.saturating_mul(8));
        let queue_mode_operations = active_event_batches.saturating_mul(3);
        let observations = normalized_events
            .saturating_add(application_frames)
            .saturating_add(connection_count.saturating_mul(3))
            .saturating_add(288);
        let log_trace_events = ceil_div(observations.saturating_mul(20), 100)
            .saturating_add(ceil_div(observations, 100));
        DailyFreeEstimate {
            worker_requests,
            d1_rows_read,
            d1_rows_written,
            durable_object_requests,
            durable_object_rows_read,
            durable_object_rows_written,
            free_queue_operations: 0,
            queue_mode_operations,
            log_trace_events,
        }
    }

    fn event(sequence: u64, text: &str) -> Value {
        json!({
            "schemaVersion": 1,
            "kind": "normalized_event",
            "eventId": format!("evt_{sequence:016}"),
            "sequence": sequence.to_string(),
            "eventDigest": hex::encode(Sha256::digest(text.as_bytes())),
            "payload": {"text": text},
        })
    }

    #[test]
    fn priority_flushes_and_timer_bounds_normal_events() {
        let start = Instant::now();
        let mut accumulator =
            EventAccumulator::new("run_batch_test01", Some("op_batch_test01".into()));
        assert!(
            accumulator
                .push(1, event(1, "a"), false, start)
                .unwrap()
                .is_empty()
        );
        assert!(
            accumulator
                .push(2, event(2, "b"), false, start + Duration::from_millis(99))
                .unwrap()
                .is_empty()
        );
        let batches = accumulator
            .push(3, event(3, "!"), true, start + Duration::from_millis(99))
            .unwrap();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].from_sequence, 1);
        assert_eq!(batches[0].through_sequence, 3);
        assert_eq!(batches[0].events.len(), 3);
        assert!(
            accumulator
                .push(
                    4,
                    event(4, "later"),
                    false,
                    start + Duration::from_millis(100)
                )
                .unwrap()
                .is_empty()
        );
        let due = accumulator
            .flush_due(start + Duration::from_millis(200))
            .unwrap()
            .unwrap();
        assert_eq!(due.from_sequence, 4);
    }

    #[test]
    fn ten_thousand_deltas_reconstruct_and_stay_within_batch_budget() {
        let (batches, expected) = delta_probe();
        assert!(batches.len() <= 400, "{} batches", batches.len());
        assert!(
            batches
                .iter()
                .all(|batch| batch.events.len() <= EVENT_BATCH_MAX_EVENTS)
        );
        assert!(
            batches
                .iter()
                .all(|batch| batch.encoded_bytes <= EVENT_BATCH_MAX_BYTES)
        );
        let reconstructed = batches
            .iter()
            .flat_map(|batch| batch.events.iter())
            .filter_map(|item| item["payload"]["text"].as_str())
            .collect::<String>();
        assert_eq!(reconstructed.as_bytes(), expected.as_bytes());
        for batch in &batches {
            assert_eq!(
                batch.payload["sourceRangeDigest"],
                batch.source_range_digest
            );
            assert_eq!(
                batch.payload["sourceSequenceRange"]["from"],
                batch.payload["fromSequence"]
            );
            assert_eq!(
                batch.payload["sourceSequenceRange"]["through"],
                batch.payload["throughSequence"]
            );
        }
    }

    #[test]
    fn unchanged_health_checkpoint_is_replayable_but_change_and_force_are_new() {
        let start = Instant::now();
        let state = HealthState {
            node_state: "ready".into(),
            journal_state: "healthy".into(),
            storage_state: "healthy".into(),
            active_commands: 0,
            active_agent_runs: 0,
            active_runtimes: 0,
        };
        let mut tracker = HealthTracker::default();
        assert!(tracker.should_emit(&state, start, true));
        tracker.record(state.clone(), start);
        assert!(tracker.unchanged_checkpoint_due(&state, start + DEFAULT_HEALTH_CHECKPOINT));

        let mut changed = state.clone();
        changed.node_state = "degraded".into();
        assert!(tracker.should_emit(&changed, start + Duration::from_secs(1), false));
        assert!(!tracker.unchanged_checkpoint_due(&changed, start + DEFAULT_HEALTH_CHECKPOINT));
        assert!(tracker.should_emit(&state, start + Duration::from_secs(1), true));
    }

    #[test]
    fn idle_health_checkpoint_reuses_one_allocation_over_24h() {
        let start = Instant::now();
        let state = HealthState {
            node_state: "ready".into(),
            journal_state: "healthy".into(),
            storage_state: "healthy".into(),
            active_commands: 0,
            active_agent_runs: 0,
            active_runtimes: 0,
        };
        let mut tracker = HealthTracker::default();
        let mut allocations = 0;
        let mut replays = 0;
        for checkpoint in 0..=ceil_div(DAY_SECONDS, DEFAULT_HEALTH_CHECKPOINT.as_secs()) {
            let at = start + Duration::from_secs(checkpoint * DEFAULT_HEALTH_CHECKPOINT.as_secs());
            let force = checkpoint == 0;
            if !tracker.should_emit(&state, at, force) {
                continue;
            }
            if !force && tracker.unchanged_checkpoint_due(&state, at) {
                replays += 1;
            } else {
                allocations += 1;
            }
            tracker.record(state.clone(), at);
        }
        assert_eq!(allocations, 1, "initial health envelope allocation");
        assert_eq!(replays, 144, "ten-minute unchanged checkpoints in 24h");
    }

    #[test]
    fn free_profile_fleet_budget_stays_below_quarter_daily_quotas() {
        let (batches, expected) = delta_probe();
        let measured_batches = batches.len() as u64;
        let measured_max_batch_bytes = batches
            .iter()
            .map(|batch| batch.encoded_bytes)
            .max()
            .unwrap_or_default() as u64;
        assert_eq!(expected.len(), 103 * 10 + (10_000 - 103) * 6);
        assert_eq!(measured_batches, 313);
        assert_eq!(measured_max_batch_bytes, 6_889);
        assert_eq!(health_probe_emissions(), 3);

        let idle_device = idle_device_estimate();
        assert_eq!(idle_device.health_frames, 145);
        assert_eq!(idle_device.health_projections, 73);
        assert_eq!(idle_device.d1_rows_written, 75);
        assert_eq!(idle_device.durable_object_rows_written, 89);
        assert_eq!(idle_device.alarm_invocations, 0);
        assert!(
            idle_device.d1_rows_written <= 300,
            "idle Device D1 write budget exceeded: {idle_device:?}"
        );
        assert!(
            idle_device.durable_object_rows_written <= 1_000,
            "idle Device DO write budget exceeded: {idle_device:?}"
        );
        assert!(
            idle_device.alarm_invocations <= 10,
            "idle Device alarm budget exceeded: {idle_device:?}"
        );

        // Review 5085026404's 25% daily ceilings for the Free profile.
        // These are deliberately integer ceilings so the test cannot hide a
        // quota overrun in floating-point rounding.
        let target = DailyFreeEstimate {
            worker_requests: 25_000,
            d1_rows_read: 1_250_000,
            d1_rows_written: 25_000,
            durable_object_requests: 25_000,
            durable_object_rows_read: 1_250_000,
            durable_object_rows_written: 25_000,
            free_queue_operations: 2_500,
            queue_mode_operations: 2_500,
            log_trace_events: 50_000,
        };
        let expected = [
            (
                1,
                DailyFreeEstimate {
                    worker_requests: 1_301,
                    d1_rows_read: 34_377,
                    d1_rows_written: 11_459,
                    durable_object_requests: 1_301,
                    durable_object_rows_read: 6_058,
                    durable_object_rows_written: 7_855,
                    free_queue_operations: 0,
                    queue_mode_operations: 2_439,
                    log_trace_events: 2_480,
                },
            ),
            (
                5,
                DailyFreeEstimate {
                    worker_requests: 1_893,
                    d1_rows_read: 35_277,
                    d1_rows_written: 11_759,
                    durable_object_requests: 1_893,
                    durable_object_rows_read: 9_570,
                    durable_object_rows_written: 8_211,
                    free_queue_operations: 0,
                    queue_mode_operations: 2_439,
                    log_trace_events: 2_603,
                },
            ),
            (
                10,
                DailyFreeEstimate {
                    worker_requests: 2_633,
                    d1_rows_read: 36_402,
                    d1_rows_written: 12_134,
                    durable_object_requests: 2_633,
                    durable_object_rows_read: 13_960,
                    durable_object_rows_written: 8_656,
                    free_queue_operations: 0,
                    queue_mode_operations: 2_439,
                    log_trace_events: 2_759,
                },
            ),
        ];
        for (idle_devices, expected_estimate) in expected {
            let estimate =
                estimate_daily_free_usage(idle_devices, measured_batches, measured_max_batch_bytes);
            assert_eq!(estimate, expected_estimate);
            assert!(estimate.worker_requests <= target.worker_requests);
            assert!(estimate.d1_rows_read <= target.d1_rows_read);
            assert!(estimate.d1_rows_written <= target.d1_rows_written);
            assert!(estimate.durable_object_requests <= target.durable_object_requests);
            assert!(estimate.durable_object_rows_read <= target.durable_object_rows_read);
            assert!(
                estimate.durable_object_rows_written <= target.durable_object_rows_written,
                "{idle_devices} idle devices: {:?}",
                estimate
            );
            assert!(estimate.free_queue_operations <= target.free_queue_operations);
            assert!(estimate.queue_mode_operations <= target.queue_mode_operations);
            assert!(estimate.log_trace_events <= target.log_trace_events);
            assert!(estimate.queue_mode_operations / 3 <= measured_batches + PRIORITY_EVENT_COUNT);
        }
    }

    #[test]
    fn acknowledgement_and_health_policies_are_bounded() {
        let start = Instant::now();
        let mut acks = AckAccumulator::default();
        for sequence in 1..=31 {
            acks.note(sequence, start);
        }
        assert!(!acks.should_flush(start + Duration::from_millis(99)));
        acks.note(32, start);
        assert!(acks.should_flush(start));
        assert_eq!(acks.take(), Some(32));
        assert!(acks.is_empty());

        let state = HealthState {
            node_state: "ready".into(),
            journal_state: "healthy".into(),
            storage_state: "healthy".into(),
            active_commands: 0,
            active_agent_runs: 0,
            active_runtimes: 0,
        };
        let mut tracker = HealthTracker::new(Duration::from_secs(5 * 60));
        let mut emitted = 0;
        emitted += tracker.consider(state.clone(), start, false) as usize;
        emitted += tracker.consider(state.clone(), start + Duration::from_secs(60), false) as usize;
        emitted +=
            tracker.consider(state.clone(), start + Duration::from_secs(5 * 60), false) as usize;
        let mut changed = state;
        changed.node_state = "degraded".into();
        emitted +=
            tracker.consider(changed, start + Duration::from_secs(5 * 60 + 1), false) as usize;
        assert_eq!(
            emitted, 3,
            "initial, unchanged checkpoint, and state change"
        );
        assert_eq!(
            HealthTracker::default().checkpoint(),
            DEFAULT_HEALTH_CHECKPOINT
        );
        assert_eq!(DEFAULT_HEALTH_CHECKPOINT, Duration::from_secs(10 * 60));
        assert_eq!(health_probe_emissions(), emitted);
    }
}
