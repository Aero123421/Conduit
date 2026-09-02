import type { ControlPlaneEnv } from "./types.ts";

export type CloudflareUsageProfileName = "free" | "standard";
export type EventIngestionMode = "durable_inbox" | "queue";

export interface CloudflareUsageProfile {
  name: CloudflareUsageProfileName;
  eventIngestionMode: EventIngestionMode;
  healthCheckpointMs: number;
  d1HealthTouchMs: number;
  ackCoalesceMs: number;
  ackCoalesceFrames: number;
  eventFlushMs: number;
  eventBatchEvents: number;
  eventBatchBytes: number;
  realtimeBatchRows: number;
  retentionBatchRows: number;
  cronBackstopMinutes: number;
  logSamplingRate: number;
  traceSamplingRate: number;
}

const profiles: Record<CloudflareUsageProfileName, Readonly<CloudflareUsageProfile>> = {
  free: Object.freeze({
    name: "free",
    eventIngestionMode: "durable_inbox",
    healthCheckpointMs: 10 * 60_000,
    d1HealthTouchMs: 15 * 60_000,
    ackCoalesceMs: 100,
    ackCoalesceFrames: 32,
    eventFlushMs: 100,
    eventBatchEvents: 32,
    eventBatchBytes: 60_000,
    realtimeBatchRows: 32,
    retentionBatchRows: 250,
    cronBackstopMinutes: 5,
    logSamplingRate: 0.2,
    traceSamplingRate: 0.01,
  }),
  standard: Object.freeze({
    name: "standard",
    eventIngestionMode: "queue",
    healthCheckpointMs: 5 * 60_000,
    d1HealthTouchMs: 5 * 60_000,
    ackCoalesceMs: 50,
    ackCoalesceFrames: 32,
    eventFlushMs: 50,
    eventBatchEvents: 32,
    eventBatchBytes: 60_000,
    realtimeBatchRows: 32,
    retentionBatchRows: 500,
    cronBackstopMinutes: 5,
    logSamplingRate: 1,
    traceSamplingRate: 1,
  }),
};

export function cloudflareUsageProfile(value: string | undefined): Readonly<CloudflareUsageProfile> {
  if (value === undefined || value === "") return profiles.free;
  if (value !== "free" && value !== "standard") throw new Error(`Unsupported CLOUDFLARE_USAGE_PROFILE: ${value}`);
  return profiles[value];
}

export function usageProfileForEnv(env: Pick<ControlPlaneEnv, "CLOUDFLARE_USAGE_PROFILE">): Readonly<CloudflareUsageProfile> {
  return cloudflareUsageProfile(env.CLOUDFLARE_USAGE_PROFILE);
}

