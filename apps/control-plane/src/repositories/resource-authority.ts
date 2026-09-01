import { PublicError } from "../errors.ts";
import type { ResourceName } from "./domain.ts";

export interface ResourceAuthority {
  projectId?: string;
  deviceId?: string;
}

export function combineResourceAuthorities(...values: ResourceAuthority[]): ResourceAuthority {
  const projectId = authority(values.map((value) => value.projectId), "Project");
  const deviceId = authority(values.map((value) => value.deviceId), "Device");
  return { ...(projectId === undefined ? {} : { projectId }), ...(deviceId === undefined ? {} : { deviceId }) };
}

type AuthorityRow = Record<string, string | null>;

function authority(values: Array<string | null | undefined>, label: "Project" | "Device"): string | undefined {
  const distinct = [...new Set(values.filter((value): value is string => typeof value === "string" && value.length > 0))];
  if (distinct.length > 1) throw new PublicError("invalid_request", 409, `Resource ${label} bindings disagree`);
  return distinct[0];
}

function fromRow(row: AuthorityRow): ResourceAuthority {
  const projectId = authority(Object.entries(row).filter(([key]) => key.startsWith("project_")).map(([, value]) => value), "Project");
  const deviceId = authority(Object.entries(row).filter(([key]) => key.startsWith("device_")).map(([, value]) => value), "Device");
  return { ...(projectId === undefined ? {} : { projectId }), ...(deviceId === undefined ? {} : { deviceId }) };
}

const authorityQueries: Record<ResourceName, string> = {
  projects: "SELECT p.id, p.id AS project_direct FROM projects p WHERE p.id=?1 LIMIT 1",
  sources: "SELECT s.id, s.project_id AS project_direct FROM sources s WHERE s.id=?1 LIMIT 1",
  locations: "SELECT l.id, s.project_id AS project_source, l.device_id AS device_direct FROM locations l JOIN sources s ON s.id=l.source_id WHERE l.id=?1 LIMIT 1",
  sessions: "SELECT s.id, s.project_id AS project_direct FROM collaboration_sessions s WHERE s.id=?1 LIMIT 1",
  messages: "SELECT m.id, s.project_id AS project_session FROM messages m JOIN collaboration_sessions s ON s.id=m.session_id WHERE m.id=?1 LIMIT 1",
  project_agents: "SELECT a.id, a.project_id AS project_direct FROM project_agents a WHERE a.id=?1 LIMIT 1",
  assignments: "SELECT a.id, a.project_id AS project_direct, s.project_id AS project_session, ms.project_id AS project_message FROM assignments a LEFT JOIN collaboration_sessions s ON s.id=a.session_id LEFT JOIN messages m ON m.id=a.source_message_id LEFT JOIN collaboration_sessions ms ON ms.id=m.session_id WHERE a.id=?1 LIMIT 1",
  runs: "SELECT r.id, r.project_id AS project_direct, a.project_id AS project_assignment, sa.project_id AS project_assignment_session, sr.project_id AS project_session, r.device_id AS device_direct FROM runs r LEFT JOIN assignments a ON a.id=r.assignment_id LEFT JOIN collaboration_sessions sa ON sa.id=a.session_id LEFT JOIN collaboration_sessions sr ON sr.id=r.session_id WHERE r.id=?1 LIMIT 1",
  approvals: "SELECT ap.id, o.project_id AS project_operation, so.project_id AS project_operation_session, r.project_id AS project_run, sr.project_id AS project_run_session, ar.project_id AS project_run_assignment, ap.device_id AS device_direct, o.device_id AS device_operation, r.device_id AS device_run FROM approvals ap LEFT JOIN operation_journal o ON o.id=ap.operation_id LEFT JOIN collaboration_sessions so ON so.id=o.session_id LEFT JOIN runs r ON r.id=ap.run_id LEFT JOIN collaboration_sessions sr ON sr.id=r.session_id LEFT JOIN assignments ar ON ar.id=r.assignment_id WHERE ap.id=?1 LIMIT 1",
  tasks: "SELECT t.id, t.project_id AS project_direct, st.project_id AS project_session, a.project_id AS project_assignment, sa.project_id AS project_assignment_session FROM tasks t LEFT JOIN collaboration_sessions st ON st.id=t.session_id LEFT JOIN assignments a ON a.id=t.assignment_id LEFT JOIN collaboration_sessions sa ON sa.id=a.session_id WHERE t.id=?1 LIMIT 1",
  artifacts: "SELECT ar.id, ar.project_id AS project_direct, r.project_id AS project_run, a.project_id AS project_assignment, sr.project_id AS project_run_session, sa.project_id AS project_assignment_session, r.device_id AS device_run FROM artifacts ar LEFT JOIN runs r ON r.id=ar.run_id LEFT JOIN assignments a ON a.id=r.assignment_id LEFT JOIN collaboration_sessions sr ON sr.id=r.session_id LEFT JOIN collaboration_sessions sa ON sa.id=a.session_id WHERE ar.id=?1 LIMIT 1",
  devices: "SELECT d.id, d.id AS device_direct FROM devices d WHERE d.id=?1 LIMIT 1",
  traces: "SELECT t.run_id AS id, r.project_id AS project_run, a.project_id AS project_assignment, sr.project_id AS project_run_session, sa.project_id AS project_assignment_session, t.device_id AS device_direct, r.device_id AS device_run FROM trace_indexes t JOIN runs r ON r.id=t.run_id LEFT JOIN assignments a ON a.id=r.assignment_id LEFT JOIN collaboration_sessions sr ON sr.id=r.session_id LEFT JOIN collaboration_sessions sa ON sa.id=a.session_id WHERE t.run_id=?1 LIMIT 1",
  evidence: "SELECT e.id, r.project_id AS project_run, a.project_id AS project_assignment, sr.project_id AS project_run_session, sa.project_id AS project_assignment_session, r.device_id AS device_run FROM evidence_summaries e JOIN runs r ON r.id=e.run_id LEFT JOIN assignments a ON a.id=r.assignment_id LEFT JOIN collaboration_sessions sr ON sr.id=r.session_id LEFT JOIN collaboration_sessions sa ON sa.id=a.session_id WHERE e.id=?1 LIMIT 1",
  operations: "SELECT o.id, o.project_id AS project_direct, so.project_id AS project_session, ao.project_id AS project_assignment, sao.project_id AS project_assignment_session, r.project_id AS project_run, sr.project_id AS project_run_session, ar.project_id AS project_run_assignment, o.device_id AS device_direct, r.device_id AS device_run FROM operation_journal o LEFT JOIN collaboration_sessions so ON so.id=o.session_id LEFT JOIN assignments ao ON ao.id=o.assignment_id LEFT JOIN collaboration_sessions sao ON sao.id=ao.session_id LEFT JOIN runs r ON r.id=o.run_id LEFT JOIN collaboration_sessions sr ON sr.id=r.session_id LEFT JOIN assignments ar ON ar.id=r.assignment_id WHERE o.id=?1 LIMIT 1",
};

export async function resolveResourceAuthority(db: D1Database, resource: ResourceName, recordId: string): Promise<ResourceAuthority> {
  const row = await db.prepare(authorityQueries[resource]).bind(recordId).first<AuthorityRow>();
  if (row === null) throw new PublicError("not_found", 404, "Record not found");
  return fromRow(row);
}

async function verifyProject(db: D1Database, projectId: string): Promise<void> {
  const row = await db.prepare("SELECT id FROM projects WHERE id=?1 LIMIT 1").bind(projectId).first<{ id: string }>();
  if (row === null) throw new PublicError("not_found", 404, "Referenced Project not found");
}

async function verifyDevice(db: D1Database, deviceId: string): Promise<void> {
  const row = await db.prepare("SELECT id FROM devices WHERE id=?1 LIMIT 1").bind(deviceId).first<{ id: string }>();
  if (row === null) throw new PublicError("not_found", 404, "Referenced Device not found");
}

export async function resolveInputAuthority(db: D1Database, resource: ResourceName, input: Record<string, unknown>): Promise<ResourceAuthority> {
  const projects: Array<string | undefined> = [];
  const devices: Array<string | undefined> = [];
  const addReference = async (field: string, target: ResourceName): Promise<void> => {
    const value = input[field];
    if (typeof value !== "string") return;
    const resolved = await resolveResourceAuthority(db, target, value);
    projects.push(resolved.projectId);
    devices.push(resolved.deviceId);
  };

  if (typeof input.project_id === "string") {
    await verifyProject(db, input.project_id);
    projects.push(input.project_id);
  }
  if (typeof input.device_id === "string") {
    await verifyDevice(db, input.device_id);
    devices.push(input.device_id);
  }

  if (resource === "locations") await addReference("source_id", "sources");
  if (["messages", "assignments", "runs", "tasks", "operations"].includes(resource)) await addReference("session_id", "sessions");
  if (["runs", "tasks", "operations"].includes(resource)) await addReference("assignment_id", "assignments");
  if (["artifacts", "operations", "approvals", "traces", "evidence"].includes(resource)) await addReference("run_id", "runs");
  if (resource === "assignments") await addReference("source_message_id", "messages");
  if (resource === "approvals") await addReference("operation_id", "operations");

  const projectId = authority(projects, "Project");
  const deviceId = authority(devices, "Device");
  return { ...(projectId === undefined ? {} : { projectId }), ...(deviceId === undefined ? {} : { deviceId }) };
}
