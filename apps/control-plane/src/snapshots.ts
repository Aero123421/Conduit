import { nowIso } from "./crypto.ts";

type Row = Record<string, unknown>;

function resultRows(result: D1Result<unknown> | undefined): Row[] {
  return (result?.results ?? []).filter((row): row is Row => row !== null && typeof row === "object" && !Array.isArray(row));
}

function snapshotRevision(groups: readonly Row[][]): number {
  let revision = 0;
  for (const rows of groups) for (const row of rows) if (typeof row.revision === "number" && Number.isSafeInteger(row.revision)) revision = Math.max(revision, row.revision);
  return revision;
}

export async function sessionCompositeSnapshot(db: D1Database, sessionId: string): Promise<Record<string, unknown> | null> {
  const [sessionResult, messagesResult, assignmentsResult, runsResult, approvalsResult, tasksResult, devicesResult] = await db.batch([
    db.prepare("SELECT id,project_id,title,revision,accepted_baseline_id,status,created_at,updated_at FROM collaboration_sessions WHERE id=?1 LIMIT 1").bind(sessionId),
    db.prepare("SELECT id,author_principal_id,origin,substr(body,1,4096) AS body,CASE WHEN length(body)>4096 THEN 1 ELSE 0 END AS body_truncated,revision,created_at FROM messages WHERE session_id=?1 ORDER BY created_at DESC,id DESC LIMIT 50").bind(sessionId),
    db.prepare("SELECT id,project_id,source_message_id,title,state,revision,created_at,updated_at FROM assignments WHERE session_id=?1 ORDER BY updated_at DESC,id DESC LIMIT 100").bind(sessionId),
    db.prepare("SELECT id,assignment_id,project_id,device_id,runtime_kind,state,revision,created_at,updated_at FROM runs WHERE session_id=?1 ORDER BY updated_at DESC,id DESC LIMIT 100").bind(sessionId),
    db.prepare("SELECT approval.id,approval.operation_id,approval.device_id,approval.run_id,approval.operation_type,approval.decision,approval.expires_at,approval.resolved_at,approval.created_at FROM approvals AS approval JOIN operation_journal AS operation ON operation.id=approval.operation_id WHERE operation.session_id=?1 ORDER BY approval.created_at DESC,approval.id DESC LIMIT 100").bind(sessionId),
    db.prepare("SELECT id,project_id,assignment_id,title,status,revision,created_at,updated_at FROM tasks WHERE session_id=?1 ORDER BY updated_at DESC,id DESC LIMIT 100").bind(sessionId),
    db.prepare("SELECT device.id,device.display_label,device.os,device.arch,device.node_version,device.protocol_version,device.status,device.revision,device.connection_epoch,device.last_observed_at,device.updated_at FROM devices AS device WHERE EXISTS (SELECT 1 FROM runs WHERE runs.session_id=?1 AND runs.device_id=device.id) ORDER BY device.id LIMIT 64").bind(sessionId),
  ]);
  const session = resultRows(sessionResult)[0];
  if (session === undefined) return null;
  const messages = resultRows(messagesResult).reverse();
  const assignments = resultRows(assignmentsResult);
  const runs = resultRows(runsResult);
  const approvals = resultRows(approvalsResult);
  const tasks = resultRows(tasksResult);
  const devices = resultRows(devicesResult);
  return {
    kind: "session_snapshot",
    snapshotAt: nowIso(),
    session,
    messages,
    assignments,
    runs,
    approvals,
    tasks,
    devices,
    revision: snapshotRevision([[session], messages, assignments, runs, tasks, devices]),
  };
}

export async function projectCompositeSnapshot(db: D1Database, projectId: string): Promise<Record<string, unknown> | null> {
  const [projectResult, sessionsResult, assignmentsResult, runsResult, approvalsResult, tasksResult, devicesResult] = await db.batch([
    db.prepare("SELECT id,name,description,revision,status,created_at,updated_at FROM projects WHERE id=?1 LIMIT 1").bind(projectId),
    db.prepare("SELECT id,title,revision,accepted_baseline_id,status,created_at,updated_at FROM collaboration_sessions WHERE project_id=?1 ORDER BY updated_at DESC,id DESC LIMIT 100").bind(projectId),
    db.prepare("SELECT id,session_id,source_message_id,title,state,revision,created_at,updated_at FROM assignments WHERE project_id=?1 ORDER BY updated_at DESC,id DESC LIMIT 100").bind(projectId),
    db.prepare("SELECT id,assignment_id,session_id,device_id,runtime_kind,state,revision,created_at,updated_at FROM runs WHERE project_id=?1 ORDER BY updated_at DESC,id DESC LIMIT 100").bind(projectId),
    db.prepare("SELECT approval.id,approval.operation_id,approval.device_id,approval.run_id,approval.operation_type,approval.decision,approval.expires_at,approval.resolved_at,approval.created_at FROM approvals AS approval JOIN operation_journal AS operation ON operation.id=approval.operation_id WHERE operation.project_id=?1 ORDER BY approval.created_at DESC,approval.id DESC LIMIT 100").bind(projectId),
    db.prepare("SELECT id,session_id,assignment_id,title,status,revision,created_at,updated_at FROM tasks WHERE project_id=?1 ORDER BY updated_at DESC,id DESC LIMIT 100").bind(projectId),
    db.prepare("SELECT device.id,device.display_label,device.os,device.arch,device.node_version,device.protocol_version,device.status,device.revision,device.connection_epoch,device.last_observed_at,device.updated_at FROM devices AS device WHERE EXISTS (SELECT 1 FROM locations JOIN sources ON sources.id=locations.source_id WHERE sources.project_id=?1 AND locations.device_id=device.id) OR EXISTS (SELECT 1 FROM runs WHERE runs.project_id=?1 AND runs.device_id=device.id) ORDER BY device.id LIMIT 64").bind(projectId),
  ]);
  const project = resultRows(projectResult)[0];
  if (project === undefined) return null;
  const sessions = resultRows(sessionsResult);
  const assignments = resultRows(assignmentsResult);
  const runs = resultRows(runsResult);
  const approvals = resultRows(approvalsResult);
  const tasks = resultRows(tasksResult);
  const devices = resultRows(devicesResult);
  return {
    kind: "project_snapshot",
    snapshotAt: nowIso(),
    project,
    sessions,
    assignments,
    runs,
    approvals,
    tasks,
    devices,
    revision: snapshotRevision([[project], sessions, assignments, runs, tasks, devices]),
  };
}
