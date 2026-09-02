import type { ControlPlaneEnv } from "./types.ts";

export type RetryWorkKind = "operation" | "approval" | "realtime" | "retention";

export interface RetryWork {
  kind: RetryWorkKind;
  targetId: string;
  dueAt: string;
}

const SCHEDULER_NAME = "control-plane";

export async function scheduleRetryWork(env: ControlPlaneEnv, work: RetryWork): Promise<void> {
  await env.RETRY_SCHEDULER.getByName(SCHEDULER_NAME).schedule(work);
}

export async function clearRetryWork(env: ControlPlaneEnv, kind: RetryWorkKind, targetId: string): Promise<void> {
  await env.RETRY_SCHEDULER.getByName(SCHEDULER_NAME).clear(kind, targetId);
}

export async function reconcileRetryScheduler(env: ControlPlaneEnv, now = new Date()): Promise<void> {
  await env.RETRY_SCHEDULER.getByName(SCHEDULER_NAME).backstop(now.toISOString());
}
