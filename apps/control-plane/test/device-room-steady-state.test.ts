import { env, exports } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { parseWireDocumentText, schemaIds } from "@conduit/schema";
import { base64url, canonicalJson, sha256Hex } from "../src/crypto.ts";

interface DeviceRoomProbe {
  incomingApplicationMessages: number;
  sqlStatements: number;
  sqlRowsRead: number;
  sqlRowsWritten: number;
  setAlarm: number;
  deleteAlarm: number;
  alarmInvocations: number;
}

function emptyProbe(): DeviceRoomProbe {
  return { incomingApplicationMessages: 0, sqlStatements: 0, sqlRowsRead: 0, sqlRowsWritten: 0, setAlarm: 0, deleteAlarm: 0, alarmInvocations: 0 };
}

async function instrumentRoom(room: DurableObjectStub, probe: DeviceRoomProbe): Promise<void> {
  await runInDurableObject(room, (_instance, durable) => {
    const sql = durable.storage.sql;
    const originalExec = sql.exec.bind(sql);
    sql.exec = ((query: string, ...bindings: any[]) => {
      probe.sqlStatements += query.split(";").filter((part) => part.trim().length > 0).length;
      const cursor = originalExec(query, ...bindings);
      probe.sqlRowsRead += cursor.rowsRead;
      probe.sqlRowsWritten += cursor.rowsWritten;
      return cursor;
    }) as typeof sql.exec;
    const originalSetAlarm = durable.storage.setAlarm.bind(durable.storage);
    durable.storage.setAlarm = ((scheduledTime: number | Date, options?: DurableObjectSetAlarmOptions) => {
      probe.setAlarm += 1;
      return originalSetAlarm(scheduledTime, options);
    }) as typeof durable.storage.setAlarm;
    const originalDeleteAlarm = durable.storage.deleteAlarm.bind(durable.storage);
    durable.storage.deleteAlarm = ((options?: DurableObjectSetAlarmOptions) => {
      probe.deleteAlarm += 1;
      return originalDeleteAlarm(options);
    }) as typeof durable.storage.deleteAlarm;
  });
}

function eventFixture(deviceId: string, runId: string, sequence: number): Record<string, unknown> {
  const hex = sequence.toString(16).padStart(64, "0");
  return {
    schemaVersion: 1,
    kind: "normalized_event",
    eventId: `evt_room_batch_${sequence.toString().padStart(8, "0")}`,
    runId,
    deviceId,
    sequence: String(sequence),
    eventType: "skill.script_completed",
    source: "adapter.test",
    observedAt: new Date().toISOString(),
    nodeBootId: "node-boot-room-batch-0001",
    evidenceLevel: "observed",
    sensitivity: "metadata",
    retentionClass: "R1",
    payloadDigest: hex,
    eventDigest: hex,
    previousChainHash: (sequence - 1).toString(16).padStart(64, "0"),
    chainHash: (sequence + 1).toString(16).padStart(64, "0"),
    payload: { text: `event-${sequence}` },
  };
}

interface AcceptedTransport {
  connectionId: string;
  connectionEpoch: string;
}

interface ConnectedDevice {
  socket: WebSocket;
  next: () => Promise<string>;
  send: (sequence: number, type: string, payload: Record<string, unknown>, correlationId?: string, controlAppliedThrough?: string) => Promise<void>;
  accepted: AcceptedTransport;
}

async function seedDevice(deviceId: string, keyId: string, enrollmentId: string, runId: string): Promise<CryptoKeyPair> {
  const keyPair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]) as CryptoKeyPair;
  const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const now = new Date().toISOString();
  const expires = new Date(Date.now() + 86_400_000).toISOString();
  const deviceCodeHash = await sha256Hex(`${deviceId}:device-code`);
  const userCodeHash = await sha256Hex(`${deviceId}:user-code`);
  const fingerprint = await sha256Hex(`${deviceId}:fingerprint`);
  await env.DB.batch([
    env.DB.prepare("INSERT INTO device_enrollments(id,state,device_code_hash,user_code_hash,claims_json,requested_key_id,requested_public_jwk_json,requested_fingerprint,possession_challenge,possession_signature,assigned_device_id,created_at,expires_at,terminal_at) VALUES (?1,'completed',?2,?3,'{}',?4,?5,?6,'challenge','signature',?7,?8,?9,?8)").bind(enrollmentId, deviceCodeHash, userCodeHash, keyId, JSON.stringify(publicJwk), fingerprint, deviceId, now, expires),
    env.DB.prepare("INSERT INTO devices(id,enrollment_id,display_label,os,arch,node_version,protocol_version,status,created_at,updated_at) VALUES (?1,?2,'steady-state-test','linux','x86_64','0.1.0','conduit.node/1','active',?3,?3)").bind(deviceId, enrollmentId, now),
    env.DB.prepare("INSERT INTO device_keys(id,device_id,public_jwk_json,fingerprint,status,created_at) VALUES (?1,?2,?3,?4,'active',?5)").bind(keyId, deviceId, JSON.stringify(publicJwk), fingerprint, now),
    env.DB.prepare("INSERT INTO runs(id,device_id,runtime_kind,access_scope,approval_mode,state,created_at,updated_at) VALUES (?1,?2,'native','project_full','always','queued',?3,?3)").bind(runId, deviceId, now),
  ]);
  return keyPair;
}

async function connectDevice(deviceId: string, keyId: string, keyPair: CryptoKeyPair, bootId: string, probe?: DeviceRoomProbe): Promise<ConnectedDevice> {
  const response = await exports.default.fetch(new Request(`https://conduit.example.com/v1/devices/${deviceId}/connect`, { headers: { upgrade: "websocket" } }));
  expect(response.status).toBe(101);
  expect(response.webSocket).not.toBeNull();
  const socket = response.webSocket!;
  socket.accept();
  const queued: string[] = [];
  const waiters: Array<(message: string) => void> = [];
  socket.addEventListener("message", (event) => {
    const waiter = waiters.shift();
    if (waiter === undefined) queued.push(String(event.data));
    else waiter(String(event.data));
  });
  const next = () => queued.length > 0 ? Promise.resolve(queued.shift()!) : new Promise<string>((resolve) => waiters.push(resolve));
  const clientNonce = base64url(crypto.getRandomValues(new Uint8Array(24)));
  const challengePending = next();
  socket.send(JSON.stringify({ type: "device.hello", deviceId, keyId, supportedProtocols: ["conduit.node/1"], capabilityDigest: "a".repeat(64), clientNonce, nodeBootId: bootId }));
  const challenge = parseWireDocumentText(schemaIds.nodeV1, await challengePending);
  if (challenge.type !== "device.challenge") throw new Error("expected device.challenge");
  const transcript = canonicalJson({ domain: "conduit.device-auth.v1", origin: "https://conduit.example.com", clientNonce, connectionId: challenge.connectionId, deviceId, keyId, protocol: challenge.selectedProtocol, serverNonce: challenge.serverNonce, serverTime: challenge.serverTime });
  const signature = base64url(new Uint8Array(await crypto.subtle.sign("Ed25519", keyPair.privateKey, new TextEncoder().encode(transcript))));
  const acceptedPending = next();
  socket.send(JSON.stringify({ type: "device.proof", connectionId: challenge.connectionId, deviceId, keyId, signature }));
  const acceptedMessage = parseWireDocumentText(schemaIds.nodeV1, await acceptedPending);
  if (acceptedMessage.type !== "transport.accepted") throw new Error("expected transport.accepted");
  const accepted: AcceptedTransport = { connectionId: acceptedMessage.connectionId, connectionEpoch: acceptedMessage.connectionEpoch };
  const send = async (sequence: number, type: string, payload: Record<string, unknown>, correlationId?: string, controlAppliedThrough?: string): Promise<void> => {
    if (probe !== undefined && type !== "transport.ack") probe.incomingApplicationMessages += 1;
    socket.send(JSON.stringify({ protocol: "conduit.node/1", messageId: `nmsg_room_steady_${deviceId}_${sequence.toString().padStart(4, "0")}`, deviceId, connectionEpoch: accepted.connectionEpoch, direction: "node_to_control", sequence: String(sequence), type, ...(correlationId === undefined ? {} : { correlationId }), ...(controlAppliedThrough === undefined ? {} : { controlAppliedThrough }), payloadDigest: await sha256Hex(canonicalJson(payload)), payload }));
  };
  return { socket, next, send, accepted };
}

async function completeReconciliation(device: ConnectedDevice, bootId: string): Promise<number> {
  await device.send(1, "reconcile.summary", { nodeBootId: bootId, journalGeneration: "1", capabilityDigest: "a".repeat(64), lastControlSequenceApplied: "0", lastNodeSequenceAcknowledged: "0", lastNodeSequenceRetained: "1", runs: [], retainedEventRanges: [], unresolvedCount: 0, truncated: false, storageHealth: "healthy" }, device.accepted.connectionId);
  const first = [parseWireDocumentText(schemaIds.nodeV1, await device.next()), parseWireDocumentText(schemaIds.nodeV1, await device.next())];
  const plan = first.find((frame) => frame.type === "reconcile.plan");
  if (plan?.type !== "reconcile.plan") throw new Error("expected reconcile.plan");
  await device.send(2, "reconcile.complete", { reconciliationId: plan.payload.reconciliationId, lastControlSequenceApplied: "2", lastNodeSequenceAcknowledged: "1", unresolvedRunIds: [] }, plan.payload.reconciliationId);
  const completeAck = parseWireDocumentText(schemaIds.nodeV1, await device.next());
  if (completeAck.type !== "transport.ack") throw new Error("expected reconciliation ACK");
  await device.send(3, "transport.ack", { direction: "control_to_node", throughSequence: "3" });
  return Number(plan.sequence);
}

describe.sequential("DeviceRoom steady-state custody", () => {
  it("does not reserve an alarm for an idle room", async () => {
    const room = env.DEVICE_ROOMS.getByName("dev_room_idle_marker_01");
    const state = await runInDurableObject(room, async (_instance, durable) => ({
      marker: durable.storage.sql.exec<{ pending: number; min_due_at: number | null }>("SELECT pending,min_due_at FROM room_work_marker WHERE singleton=1").one(),
      alarm: await durable.storage.getAlarm(),
      inbound: durable.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM inbound_frames").one().count,
      outbound: durable.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM outbound_frames").one().count,
    }));
    expect(state).toEqual({ marker: { pending: 0, min_due_at: null }, alarm: null, inbound: 0, outbound: 0 });
  });

  it("custodies one WebSocket event.batch in a bounded alarm and keeps the auto-response probe write-free", async () => {
    const deviceId = "dev_room_batch_e2e01";
    const keyId = "dkey_room_batch_e2e01";
    const enrollmentId = "enroll_room_batch_e2e01";
    const runId = "run_room_batch_e2e01";
    const keyPair = await seedDevice(deviceId, keyId, enrollmentId, runId);
    const room = env.DEVICE_ROOMS.getByName(deviceId);
    const probe = emptyProbe();
    await instrumentRoom(room, probe);
    const connected = await connectDevice(deviceId, keyId, keyPair, "node-boot-room-batch-0001", probe);
    await completeReconciliation(connected, "node-boot-room-batch-0001");

    const events = [eventFixture(deviceId, runId, 1), eventFixture(deviceId, runId, 2)];
    const eventPayload = {
      runId,
      fromSequence: "1",
      throughSequence: "2",
      sourceSequenceRange: { from: "1", through: "2" },
      sourceRangeDigest: await sha256Hex(canonicalJson({ runId, fromSequence: "1", throughSequence: "2", events: events.map((event) => ({ sequence: String(event.sequence), eventDigest: String(event.eventDigest) })) })),
      traceSchema: "conduit.trace/1",
      events,
    };
    await connected.send(4, "event.batch", eventPayload);
    await expect.poll(async () => runInDurableObject(room, (_instance, durable) => durable.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM inbound_frames WHERE sequence=4").one().count)).toBe(1);

    // Force the same bounded alarm worker used after a DO wake-up. The event
    // batch must be projected from durable custody before its cumulative ACK.
    await runInDurableObject(room, async (instance) => {
      probe.alarmInvocations += 1;
      await instance.alarm();
    });
    await expect.poll(async () => ({
      events: (await env.DB.prepare("SELECT COUNT(*) AS count FROM normalized_events WHERE run_id=?").bind(runId).first<{ count: number }>())?.count ?? 0,
      projected: await runInDurableObject(room, (_instance, durable) => durable.storage.sql.exec<{ projected: number }>("SELECT projected FROM inbound_frames WHERE sequence=4").one().projected),
    })).toEqual({ events: 2, projected: 1 });
    const ack = parseWireDocumentText(schemaIds.nodeV1, await Promise.race([
      connected.next(),
      new Promise<string>((_resolve, reject) => setTimeout(() => reject(new Error("event.batch ACK timeout")), 2_000)),
    ]));
    expect(ack).toMatchObject({ type: "transport.ack", payload: { direction: "node_to_control", throughSequence: "4" } });
    expect(probe.incomingApplicationMessages).toBe(3);
    expect(probe.alarmInvocations).toBeGreaterThanOrEqual(1);
    expect(probe.sqlStatements).toBeGreaterThan(0);
    expect(probe.sqlRowsWritten).toBeGreaterThanOrEqual(0);
    console.info("[device-room-steady-state] event.batch counters", JSON.stringify(probe));

    // `WebSocket.send("ping")` is a text application probe in this test
    // runtime, not a WebSocket control Ping. Production control Ping/Pong is
    // handled by DeviceRoom's `setWebSocketAutoResponse` without entering the
    // application handler; the Rust protocol probe covers that control frame.
    const beforeProbe = { ...probe };
    const pong = new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error("protocol pong timeout")), 2_000);
      connected.socket.addEventListener("message", (event) => {
        if (String(event.data) !== "pong") return;
        clearTimeout(timeout);
        resolve();
      }, { once: true });
    });
    connected.socket.send("ping");
    await pong;
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(probe.sqlStatements).toBe(beforeProbe.sqlStatements);
    expect(probe.sqlRowsRead).toBe(beforeProbe.sqlRowsRead);
    expect(probe.sqlRowsWritten).toBe(beforeProbe.sqlRowsWritten);
    expect(probe.setAlarm).toBe(beforeProbe.setAlarm);
    expect(probe.deleteAlarm).toBe(beforeProbe.deleteAlarm);
    expect(probe.alarmInvocations).toBe(beforeProbe.alarmInvocations);
    connected.socket.close(1000, "steady_state_complete");
  });

  it("treats an unchanged health checkpoint as an exact replay with bounded D1/DO/alarm cost", async () => {
    const deviceId = "dev_room_health_replay_01";
    const keyId = "dkey_room_health_replay_01";
    const enrollmentId = "enroll_room_health_replay_01";
    const runId = "run_room_health_replay_01";
    const keyPair = await seedDevice(deviceId, keyId, enrollmentId, runId);
    const room = env.DEVICE_ROOMS.getByName(deviceId);
    const probe = emptyProbe();
    await instrumentRoom(room, probe);
    const connected = await connectDevice(deviceId, keyId, keyPair, "node-boot-room-health-0001", probe);
    await completeReconciliation(connected, "node-boot-room-health-0001");

    const healthPayload = {
      observedAt: new Date().toISOString(),
      nodeState: "ready",
      journalState: "healthy",
      storageState: "healthy",
      controlAppliedThrough: "3",
      activeCommands: 0,
      activeAgentRuns: 0,
      activeRuntimes: 0,
    } satisfies Record<string, unknown>;
    await connected.send(4, "device.health", healthPayload);
    const firstAck = parseWireDocumentText(schemaIds.nodeV1, await Promise.race([
      connected.next(),
      new Promise<string>((_resolve, reject) => setTimeout(() => reject(new Error("health ACK timeout")), 2_000)),
    ]));
    expect(firstAck).toMatchObject({ type: "transport.ack", payload: { direction: "node_to_control", throughSequence: "4" } });
    const first = await env.DB.prepare("SELECT last_observed_at,health_sequence FROM devices WHERE id=?1").bind(deviceId).first<{ last_observed_at: string; health_sequence: string }>();
    expect(first).toMatchObject({ health_sequence: "4" });
    expect(first?.last_observed_at).toBeTruthy();
    const firstInbound = await runInDurableObject(room, (_instance, durable) => durable.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM inbound_frames").one().count);
    const firstOutboundAcks = await runInDurableObject(room, (_instance, durable) => durable.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM outbound_message_receipts WHERE kind='ack'").one().count);

    const afterFirst = { ...probe };
    await connected.send(4, "device.health", healthPayload);
    await new Promise((resolve) => setTimeout(resolve, 10));
    const immediateReplay = await runInDurableObject(room, async (_instance, durable) => ({
      position: durable.storage.sql.exec<{ durable_sequence: number }>("SELECT durable_sequence FROM transport_positions WHERE direction='node_to_control'").one().durable_sequence,
      inbound: durable.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM inbound_frames").one().count,
      marker: durable.storage.sql.exec<{ health_last_projected_at: number | null }>("SELECT health_last_projected_at FROM room_work_marker WHERE singleton=1").one().health_last_projected_at,
      alarm: await durable.storage.getAlarm(),
    }));
    expect(immediateReplay.position).toBe(4);
    expect(immediateReplay.inbound).toBe(firstInbound);
    expect(immediateReplay.marker).not.toBeNull();
    expect(immediateReplay.alarm).toBeNull(); // future retention alone must not reserve an idle alarm.
    expect(probe.sqlRowsWritten - afterFirst.sqlRowsWritten).toBe(0);
    expect(probe.setAlarm - afterFirst.setAlarm).toBe(0);

    // Advance only the local checkpoint marker. The next exact replay should
    // refresh D1 observation once, without a new transport/inbox/ACK row.
    await runInDurableObject(room, (_instance, durable) => {
      durable.storage.sql.exec("UPDATE room_work_marker SET health_last_projected_at=? WHERE singleton=1", Date.now() - 15 * 60_000 - 1);
    });
    const beforeCheckpoint = { ...probe };
    await new Promise((resolve) => setTimeout(resolve, 10));
    await connected.send(4, "device.health", healthPayload);
    await expect.poll(async () => (await env.DB.prepare("SELECT last_observed_at FROM devices WHERE id=?1").bind(deviceId).first<{ last_observed_at: string }>())?.last_observed_at).not.toBe(first?.last_observed_at);
    const afterCheckpoint = await env.DB.prepare("SELECT last_observed_at,health_sequence FROM devices WHERE id=?1").bind(deviceId).first<{ last_observed_at: string; health_sequence: string }>();
    expect(afterCheckpoint).toMatchObject({ health_sequence: "4" });
    expect(afterCheckpoint?.last_observed_at).not.toBe(first?.last_observed_at);
    const checkpointState = await runInDurableObject(room, async (_instance, durable) => ({
      position: durable.storage.sql.exec<{ durable_sequence: number }>("SELECT durable_sequence FROM transport_positions WHERE direction='node_to_control'").one().durable_sequence,
      inbound: durable.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM inbound_frames").one().count,
      marker: durable.storage.sql.exec<{ health_last_projected_at: number | null }>("SELECT health_last_projected_at FROM room_work_marker WHERE singleton=1").one().health_last_projected_at,
      outboundAcks: durable.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM outbound_message_receipts WHERE kind='ack'").one().count,
      alarm: await durable.storage.getAlarm(),
    }));
    expect(checkpointState.position).toBe(4);
    expect(checkpointState.inbound).toBe(firstInbound);
    expect(checkpointState.outboundAcks).toBe(firstOutboundAcks);
    expect(checkpointState.marker).not.toBeNull();
    expect(checkpointState.alarm).toBeNull();
    expect(probe.sqlRowsWritten - beforeCheckpoint.sqlRowsWritten).toBeLessThanOrEqual(1);
    expect(probe.setAlarm - beforeCheckpoint.setAlarm).toBe(0);

    // The release budget uses the configured ten-minute unchanged-health
    // replay cadence (144 replays/day) and the independent fifteen-minute D1
    // observation throttle (96 projections/day). Exact replay performs no DO
    // write; only the 15-minute local marker checkpoint is charged.
    const unchangedReplayPerDay = Math.ceil((24 * 60) / 10);
    const unchangedD1ProjectionPerDay = Math.ceil((24 * 60) / 15);
    const checkpointDoRows = Math.max(0, probe.sqlRowsWritten - beforeCheckpoint.sqlRowsWritten);
    const unchangedDoRowsPerDay = checkpointDoRows * unchangedD1ProjectionPerDay;
    const unchangedD1RowsPerDay = 1 * unchangedD1ProjectionPerDay;
    expect(unchangedDoRowsPerDay).toBeLessThanOrEqual(1_000);
    expect(unchangedD1RowsPerDay).toBeLessThanOrEqual(300);
    expect(probe.setAlarm - afterFirst.setAlarm).toBeLessThanOrEqual(10);
    expect(probe.alarmInvocations).toBeLessThanOrEqual(10);
    console.info("[device-room-steady-state] unchanged health replay", JSON.stringify({ unchangedReplayPerDay, unchangedD1ProjectionPerDay, checkpointDoRows, unchangedDoRowsPerDay, unchangedD1RowsPerDay, alarmInvocations: probe.alarmInvocations, counters: probe }));
    connected.socket.close(1000, "health_replay_complete");
  });

  it("resends the existing cumulative health ACK write-free after a send-loss fault", async () => {
    const deviceId = "dev_room_health_ack_retry_01";
    const keyId = "dkey_room_health_ack_retry_01";
    const enrollmentId = "enroll_room_health_ack_retry_01";
    const runId = "run_room_health_ack_retry_01";
    const keyPair = await seedDevice(deviceId, keyId, enrollmentId, runId);
    const room = env.DEVICE_ROOMS.getByName(deviceId);
    const probe = emptyProbe();
    await instrumentRoom(room, probe);
    const first = await connectDevice(deviceId, keyId, keyPair, "node-boot-room-health-ack-0001", probe);
    await completeReconciliation(first, "node-boot-room-health-ack-0001");
    const healthPayload = {
      observedAt: new Date().toISOString(),
      nodeState: "ready",
      journalState: "healthy",
      storageState: "healthy",
      controlAppliedThrough: "3",
      activeCommands: 0,
      activeAgentRuns: 0,
      activeRuntimes: 0,
    } satisfies Record<string, unknown>;
    await first.send(4, "device.health", healthPayload);
    await expect.poll(async () => runInDurableObject(room, (_instance, durable) => durable.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM outbound_frames WHERE kind='ack' AND state='sent' AND json_extract(frame_json,'$.payload.throughSequence')='4'").one().count)).toBe(1);
    const beforeReplay = { ...probe };
    const beforeState = await runInDurableObject(room, async (_instance, durable) => ({
      position: durable.storage.sql.exec<{ durable_sequence: number }>("SELECT durable_sequence FROM transport_positions WHERE direction='node_to_control'").one().durable_sequence,
      inbound: durable.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM inbound_frames").one().count,
      outboundAcks: durable.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM outbound_message_receipts WHERE kind='ack'").one().count,
      alarm: await durable.storage.getAlarm(),
    }));
    // Fault injection: leave the first ACK unobserved, then replay the exact
    // health envelope on the still-authenticated socket. This is the
    // send-loss branch of disconnect-before-observation; the full reconnect
    // handshake/reconciliation path remains covered by core.test.ts.
    await first.send(4, "device.health", healthPayload);
    const firstDelivery = parseWireDocumentText(schemaIds.nodeV1, await Promise.race([
      first.next(),
      new Promise<string>((_resolve, reject) => setTimeout(() => reject(new Error("initial health ACK timeout")), 2_000)),
    ]));
    const replayedAck = parseWireDocumentText(schemaIds.nodeV1, await Promise.race([
      first.next(),
      new Promise<string>((_resolve, reject) => setTimeout(() => reject(new Error("replayed health ACK timeout")), 2_000)),
    ]));
    expect(firstDelivery).toMatchObject({ type: "transport.ack", payload: { direction: "node_to_control", throughSequence: "4" } });
    expect(replayedAck).toMatchObject({ type: "transport.ack", payload: { direction: "node_to_control", throughSequence: "4" } });
    const afterReplay = await runInDurableObject(room, async (_instance, durable) => ({
      position: durable.storage.sql.exec<{ durable_sequence: number }>("SELECT durable_sequence FROM transport_positions WHERE direction='node_to_control'").one().durable_sequence,
      inbound: durable.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM inbound_frames").one().count,
      outboundAcks: durable.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM outbound_message_receipts WHERE kind='ack'").one().count,
      alarm: await durable.storage.getAlarm(),
    }));
    expect(afterReplay).toEqual(beforeState);
    expect(probe.sqlRowsWritten - beforeReplay.sqlRowsWritten).toBe(0);
    expect(probe.setAlarm - beforeReplay.setAlarm).toBe(0);
    expect(probe.alarmInvocations).toBe(0);
    first.socket.close(1000, "health_ack_retry_complete");
  });

  it("accepts the shared control frontier on an ordinary node frame", async () => {
    const deviceId = "dev_room_frontier_frame_01";
    const keyId = "dkey_room_frontier_frame_01";
    const enrollmentId = "enroll_room_frontier_frame_01";
    const runId = "run_room_frontier_frame_01";
    const keyPair = await seedDevice(deviceId, keyId, enrollmentId, runId);
    const room = env.DEVICE_ROOMS.getByName(deviceId);
    const connected = await connectDevice(deviceId, keyId, keyPair, "node-boot-room-frontier-frame-0001");
    await completeReconciliation(connected, "node-boot-room-frontier-frame-0001");
    const healthPayload = {
      observedAt: new Date().toISOString(),
      nodeState: "ready",
      journalState: "healthy",
      storageState: "healthy",
      controlAppliedThrough: "3",
      activeCommands: 0,
      activeAgentRuns: 0,
      activeRuntimes: 0,
    } satisfies Record<string, unknown>;
    await connected.send(4, "device.health", healthPayload, undefined, "3");
    const healthAck = parseWireDocumentText(schemaIds.nodeV1, await connected.next());
    if (healthAck.type !== "transport.ack") throw new Error("expected health ACK");
    const acknowledgedControlSequence = healthAck.sequence;
    await expect.poll(async () => runInDurableObject(room, (_instance, durable) => durable.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM outbound_frames WHERE sequence=?", Number(acknowledgedControlSequence)).one().count)).toBe(1);

    await connected.send(5, "transport.error", { code: "diagnostic", retryable: false, details: { messageType: "health.frontier_probe" } }, undefined, acknowledgedControlSequence);
    await expect.poll(async () => runInDurableObject(room, (_instance, durable) => ({
      acknowledged: durable.storage.sql.exec<{ acknowledged_sequence: number }>("SELECT acknowledged_sequence FROM transport_positions WHERE direction='control_to_node'").one().acknowledged_sequence,
      retained: durable.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM outbound_frames WHERE sequence=?", Number(acknowledgedControlSequence)).one().count,
    }))).toEqual({ acknowledged: Number(acknowledgedControlSequence), retained: 0 });
    connected.socket.close(1000, "frontier_frame_complete");
  });

  it("retains one latest health proof and ACK across 25h hot-row compaction", async () => {
    const deviceId = "dev_room_health_retention_01";
    const keyId = "dkey_room_health_retention_01";
    const enrollmentId = "enroll_room_health_retention_01";
    const runId = "run_room_health_retention_01";
    const keyPair = await seedDevice(deviceId, keyId, enrollmentId, runId);
    const room = env.DEVICE_ROOMS.getByName(deviceId);
    const probe = emptyProbe();
    await instrumentRoom(room, probe);
    const connected = await connectDevice(deviceId, keyId, keyPair, "node-boot-room-health-retention-0001", probe);
    await completeReconciliation(connected, "node-boot-room-health-retention-0001");
    const healthPayload = {
      observedAt: new Date().toISOString(),
      nodeState: "ready",
      journalState: "healthy",
      storageState: "healthy",
      controlAppliedThrough: "3",
      activeCommands: 0,
      activeAgentRuns: 0,
      activeRuntimes: 0,
    } satisfies Record<string, unknown>;
    await connected.send(4, "device.health", healthPayload);
    const firstAck = parseWireDocumentText(schemaIds.nodeV1, await Promise.race([
      connected.next(),
      new Promise<string>((_resolve, reject) => setTimeout(() => reject(new Error("retention health ACK timeout")), 2_000)),
    ]));
    expect(firstAck).toMatchObject({ type: "transport.ack", payload: { direction: "node_to_control", throughSequence: "4" } });

    const agedAt = new Date(Date.now() - 25 * 60 * 60_000).toISOString();
    await runInDurableObject(room, (_instance, durable) => {
      durable.storage.transactionSync(() => {
        durable.storage.sql.exec("UPDATE inbound_frames SET created_at=?", agedAt);
        // Keep a large projected hot set so the bounded retention worker must
        // compact it. Sequence 4 is the last exact health proof and is the
        // only health row intentionally exempt from this delete pass.
        for (let sequence = 5; sequence <= 700; sequence += 1) {
          durable.storage.sql.exec(
            "INSERT INTO inbound_frames(sequence,message_id,correlation_id,payload_digest,frame_json,projected,kind,created_at) VALUES (?,?,?,?,?,1,'app',?)",
            sequence,
            `nmsg_room_health_retention_${sequence.toString().padStart(4, "0")}`,
            null,
            "f".repeat(64),
            JSON.stringify({ protocol: "conduit.node/1", type: "event.batch" }),
            agedAt,
          );
        }
        durable.storage.sql.exec("UPDATE transport_positions SET durable_sequence=700 WHERE direction='node_to_control'");
        // Simulate a 25h-old latest ACK. Its row is still the newest
        // unacknowledged cumulative proof and must remain replayable.
        durable.storage.sql.exec("UPDATE outbound_frames SET expires_at=? WHERE kind='ack' AND json_extract(frame_json,'$.payload.throughSequence')='4'", agedAt);
        durable.storage.sql.exec("UPDATE outbound_message_receipts SET expires_at=? WHERE kind='ack' AND sequence=(SELECT sequence FROM outbound_frames WHERE kind='ack' AND json_extract(frame_json,'$.payload.throughSequence')='4')", agedAt);
        durable.storage.sql.exec("UPDATE outbound_message_receipts SET expires_at=?", agedAt);
        durable.storage.sql.exec("UPDATE auth_challenges SET expires_at=?", agedAt);
        durable.storage.sql.exec("UPDATE reconciliation_sessions SET created_at=?,completed_at=?", agedAt, agedAt);
        durable.storage.sql.exec("UPDATE room_work_marker SET pending=1,min_due_at=?,retention_pending=1,retention_due_at=?,health_last_projected_at=?,updated_at=? WHERE singleton=1", Date.now(), Date.now(), Date.now() - 15 * 60_000 - 1, agedAt);
      });
      return durable.storage.setAlarm(Date.now() - 1);
    });
    for (let attempt = 0; attempt < 20; attempt += 1) await runInDurableObject(room, async (instance) => { probe.alarmInvocations += 1; await instance.alarm(); });

    const compacted = await runInDurableObject(room, async (_instance, durable) => ({
      inbound: durable.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM inbound_frames").one().count,
      healthProof: durable.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM inbound_frames WHERE sequence=4 AND json_extract(frame_json,'$.type')='device.health'").one().count,
      latestAck: durable.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM outbound_frames WHERE kind='ack' AND json_extract(frame_json,'$.payload.throughSequence')='4'").one().count,
      compactedThrough: durable.storage.sql.exec<{ compacted_through: number }>("SELECT compacted_through FROM transport_compaction WHERE direction='node_to_control'").one().compacted_through,
      marker: durable.storage.sql.exec<{ pending: number; retention_pending: number }>("SELECT pending,retention_pending FROM room_work_marker WHERE singleton=1").one(),
      alarm: await durable.storage.getAlarm(),
    }));
    expect(compacted.inbound).toBeLessThanOrEqual(512);
    expect(compacted.healthProof).toBe(1);
    expect(compacted.latestAck).toBe(1);
    expect(compacted.compactedThrough).toBeGreaterThanOrEqual(4);
    expect(compacted.marker).toEqual({ pending: 0, retention_pending: 0 });
    expect(compacted.alarm).toBeNull();

    const beforeReplay = { ...probe };
    await connected.send(4, "device.health", healthPayload);
    const replayAck = parseWireDocumentText(schemaIds.nodeV1, await Promise.race([
      connected.next(),
      new Promise<string>((_resolve, reject) => setTimeout(() => reject(new Error("25h health replay ACK timeout")), 2_000)),
    ]));
    expect(replayAck).toMatchObject({ type: "transport.ack", payload: { direction: "node_to_control", throughSequence: "4" } });
    const afterReplay = await runInDurableObject(room, async (_instance, durable) => ({
      inbound: durable.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM inbound_frames").one().count,
      healthProof: durable.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM inbound_frames WHERE sequence=4").one().count,
      latestAck: durable.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM outbound_frames WHERE kind='ack' AND json_extract(frame_json,'$.payload.throughSequence')='4'").one().count,
      alarm: await durable.storage.getAlarm(),
    }));
    expect(afterReplay.inbound).toBeLessThanOrEqual(512);
    expect(afterReplay.healthProof).toBe(1);
    expect(afterReplay.latestAck).toBe(1);
    expect(afterReplay.alarm).toBeNull();
    expect(probe.sqlRowsWritten - beforeReplay.sqlRowsWritten).toBeLessThanOrEqual(1);
    expect(probe.setAlarm - beforeReplay.setAlarm).toBe(0);
    connected.socket.close(1000, "health_retention_complete");
  });

  it("keeps 1, 5, and 10 idle rooms at zero pending work and below the 24h release budget", async () => {
    const idleRooms: Array<{ deviceId: string; probe: DeviceRoomProbe }> = [];
    const idleMeasurements: Array<{ fleetSize: number; rooms: number; incomingApplicationMessages: number; sqlStatements: number; sqlRowsRead: number; sqlRowsWritten: number; setAlarm: number; alarmInvocations: number }> = [];
    for (const fleetSize of [1, 5, 10]) {
      const fleetStart = idleRooms.length;
      for (let index = 0; index < fleetSize; index += 1) {
        const deviceId = `dev_room_idle_${fleetSize}_${index.toString().padStart(2, "0")}`;
        const room = env.DEVICE_ROOMS.getByName(deviceId);
        const probe = emptyProbe();
        await instrumentRoom(room, probe);
        idleRooms.push({ deviceId, probe });
        const state = await runInDurableObject(room, async (_instance, durable) => ({
          marker: durable.storage.sql.exec<{ pending: number; min_due_at: number | null }>("SELECT pending,min_due_at FROM room_work_marker WHERE singleton=1").one(),
          alarm: await durable.storage.getAlarm(),
          inbound: durable.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM inbound_frames").one().count,
          outbound: durable.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM outbound_frames").one().count,
        }));
        expect(state).toEqual({ marker: { pending: 0, min_due_at: null }, alarm: null, inbound: 0, outbound: 0 });
        expect(probe.incomingApplicationMessages).toBe(0);
        expect(probe.sqlRowsWritten).toBe(0);
        expect(probe.setAlarm).toBe(0);
        expect(probe.alarmInvocations).toBe(0);
      }
      const fleetProbes = idleRooms.slice(fleetStart).map((entry) => entry.probe);
      idleMeasurements.push({
        fleetSize,
        rooms: fleetProbes.length,
        incomingApplicationMessages: fleetProbes.reduce((total, probe) => total + probe.incomingApplicationMessages, 0),
        sqlStatements: fleetProbes.reduce((total, probe) => total + probe.sqlStatements, 0),
        sqlRowsRead: fleetProbes.reduce((total, probe) => total + probe.sqlRowsRead, 0),
        sqlRowsWritten: fleetProbes.reduce((total, probe) => total + probe.sqlRowsWritten, 0),
        setAlarm: fleetProbes.reduce((total, probe) => total + probe.setAlarm, 0),
        alarmInvocations: fleetProbes.reduce((total, probe) => total + probe.alarmInvocations, 0),
      });
    }

    // The 8h active workload combines the measured Node batch probe (313
    // assistant batches + 500 priority frames) with the configured ten-minute
    // health cadence (49 observations, including the initial sample). The
    // following are conservative arithmetic estimates, not account analytics;
    // the real WebSocket event.batch counters above are reported separately.
    const activeEightHourBudget = [
      { idleDevices: 1, activeHealthObservations: 49, activeD1HealthProjections: 33, workerRequests: 1_301, d1RowsRead: 34_737, d1RowsWritten: 11_579, doRequests: 1_301, doRowsRead: 6_058, doRowsWritten: 7_879, queueOperations: 0 },
      { idleDevices: 5, activeHealthObservations: 49, activeD1HealthProjections: 33, workerRequests: 1_893, d1RowsRead: 37_077, d1RowsWritten: 12_359, doRequests: 1_893, doRowsRead: 9_570, doRowsWritten: 8_331, queueOperations: 0 },
      { idleDevices: 10, activeHealthObservations: 49, activeD1HealthProjections: 33, workerRequests: 2_633, d1RowsRead: 40_002, d1RowsWritten: 13_334, doRequests: 2_633, doRowsRead: 13_960, doRowsWritten: 8_896, queueOperations: 0 },
    ] as const;
    for (const budget of activeEightHourBudget) {
      expect(budget.activeHealthObservations).toBe(49);
      expect(budget.activeD1HealthProjections).toBe(33);
      expect(budget.workerRequests).toBeLessThanOrEqual(25_000);
      expect(budget.d1RowsRead).toBeLessThanOrEqual(1_250_000);
      expect(budget.d1RowsWritten).toBeLessThanOrEqual(25_000);
      expect(budget.doRequests).toBeLessThanOrEqual(25_000);
      expect(budget.doRowsRead).toBeLessThanOrEqual(1_250_000);
      expect(budget.doRowsWritten).toBeLessThanOrEqual(25_000);
      expect(budget.queueOperations).toBeLessThanOrEqual(2_500);
    }
    expect(idleRooms).toHaveLength(16);
    console.info("[device-room-steady-state] idle 24h counters", JSON.stringify(idleMeasurements));
    console.info("[device-room-steady-state] active 8h budget model", JSON.stringify(activeEightHourBudget));
  });

  it("compacts a sent ACK backlog through the shared control frontier", async () => {
    const room = env.DEVICE_ROOMS.getByName("dev_room_ack_frontier_01");
    await runInDurableObject(room, (_instance, durable) => {
      const now = new Date().toISOString();
      durable.storage.transactionSync(() => {
        durable.storage.sql.exec("UPDATE transport_positions SET durable_sequence=600,acknowledged_sequence=600 WHERE direction='control_to_node'");
        for (let sequence = 1; sequence <= 600; sequence += 1) {
          durable.storage.sql.exec(
            "INSERT INTO outbound_message_receipts(message_id,correlation_id,payload_digest,sequence,state,kind,expires_at,created_at,updated_at) VALUES (?,?,?,?,'sent','ack',?,?,?)",
            `cmsg_ack_frontier_${sequence}`,
            null,
            `${sequence.toString(16).padStart(64, "0")}`,
            sequence,
            new Date(Date.now() + 86_400_000).toISOString(),
            now,
            now,
          );
        }
        durable.storage.sql.exec("UPDATE room_work_marker SET pending=1,min_due_at=?,retention_pending=1,retention_due_at=?,updated_at=? WHERE singleton=1", Date.now(), Date.now(), now);
      });
      return durable.storage.setAlarm(Date.now() - 1);
    });

    for (let attempt = 0; attempt < 6; attempt += 1) await runInDurableObject(room, async (instance) => instance.alarm());
    const state = await runInDurableObject(room, async (_instance, durable) => ({
      receipts: durable.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM outbound_message_receipts").one().count,
      tombstones: durable.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM outbound_message_tombstones").one().count,
      compactedThrough: durable.storage.sql.exec<{ compacted_through: number }>("SELECT compacted_through FROM transport_compaction WHERE direction='control_to_node'").one().compacted_through,
      marker: durable.storage.sql.exec<{ pending: number; retention_pending: number }>("SELECT pending,retention_pending FROM room_work_marker WHERE singleton=1").one(),
      alarm: await durable.storage.getAlarm(),
    }));
    expect(state.receipts).toBe(0);
    expect(state.tombstones).toBeLessThanOrEqual(512);
    expect(state.compactedThrough).toBe(600);
    expect(state.marker).toEqual({ pending: 0, retention_pending: 0 });
    expect(state.alarm).toBeNull();
  });
});
