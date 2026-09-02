/**
 * Opt-in local/test instrumentation. Production request paths do not create or
 * persist these counters; remote measurements come from Cloudflare Analytics.
 */
export interface D1UsageSnapshot {
  statements: number;
  bindingCalls: number;
  boundParameters: number[];
  maxBoundParameters: number;
  rowsRead: number;
  rowsWritten: number;
}

export interface InstrumentedD1 {
  db: D1Database;
  snapshot(): D1UsageSnapshot;
  reset(): void;
}

interface MutableD1Usage {
  statements: number;
  bindingCalls: number;
  boundParameters: number[];
  rowsRead: number;
  rowsWritten: number;
}

function addMeta(usage: MutableD1Usage, result: unknown): void {
  if (result === null || typeof result !== "object") return;
  const meta = (result as { meta?: Record<string, unknown> }).meta;
  if (meta === undefined) return;
  const read = meta.rows_read;
  const written = meta.rows_written;
  if (typeof read === "number" && Number.isFinite(read)) usage.rowsRead += read;
  if (typeof written === "number" && Number.isFinite(written)) usage.rowsWritten += written;
}

/** Wrap a D1 binding without changing query results or transaction semantics. */
export function instrumentD1(database: D1Database): InstrumentedD1 {
  const usage: MutableD1Usage = { statements: 0, bindingCalls: 0, boundParameters: [], rowsRead: 0, rowsWritten: 0 };
  const rawStatements = new WeakMap<object, D1PreparedStatement>();
  const statementParameterCounts = new WeakMap<object, number>();

  const wrapStatement = (statement: D1PreparedStatement, boundCount = 0): D1PreparedStatement => {
    const proxy = new Proxy(statement, {
      get(target, property, receiver) {
        if (property === "bind") {
          return (...values: unknown[]) => {
            usage.bindingCalls += 1;
            return wrapStatement(target.bind(...values), values.length);
          };
        }
        if (property === "run" || property === "all" || property === "raw" || property === "first") {
          return async (...args: unknown[]) => {
            usage.statements += 1;
            usage.boundParameters.push(boundCount);
            const result = await (Reflect.get(target, property, receiver) as (...inner: unknown[]) => Promise<unknown>).apply(target, args);
            addMeta(usage, result);
            return result;
          };
        }
        return Reflect.get(target, property, receiver);
      },
    });
    rawStatements.set(proxy, statement);
    statementParameterCounts.set(proxy, boundCount);
    return proxy;
  };

  const db = new Proxy(database, {
    get(target, property, receiver) {
      if (property === "prepare") return (query: string) => wrapStatement(target.prepare(query));
      if (property === "batch") {
        return async (statements: D1PreparedStatement[]) => {
          usage.statements += statements.length;
          for (const statement of statements) {
            const raw = rawStatements.get(statement as object);
            if (raw === undefined) throw new Error("instrumented D1 batch received an unwrapped statement");
            usage.boundParameters.push(statementParameterCounts.get(statement as object) ?? 0);
          }
          const results = await target.batch(statements.map((statement) => rawStatements.get(statement as object)!));
          for (const result of results) addMeta(usage, result);
          return results;
        };
      }
      if (property === "exec") {
        return async (query: string) => {
          const count = query.split(";").filter((part) => part.trim().length > 0).length;
          usage.statements += Math.max(1, count);
          const result = await target.exec(query);
          addMeta(usage, result);
          return result;
        };
      }
      return Reflect.get(target, property, receiver);
    },
  });

  return {
    db,
    snapshot: () => ({
      statements: usage.statements,
      bindingCalls: usage.bindingCalls,
      boundParameters: [...usage.boundParameters],
      maxBoundParameters: Math.max(0, ...usage.boundParameters),
      rowsRead: usage.rowsRead,
      rowsWritten: usage.rowsWritten,
    }),
    reset: () => {
      usage.statements = 0;
      usage.bindingCalls = 0;
      usage.boundParameters.length = 0;
      usage.rowsRead = 0;
      usage.rowsWritten = 0;
    },
  };
}

export function assertFreeD1Ceilings(snapshot: D1UsageSnapshot): void {
  if (snapshot.statements > 40) throw new Error(`D1 statement budget exceeded: ${snapshot.statements} > 40`);
  if (snapshot.bindingCalls > 40) throw new Error(`D1 binding-call budget exceeded: ${snapshot.bindingCalls} > 40`);
  if (snapshot.maxBoundParameters > 90) throw new Error(`D1 parameter budget exceeded: ${snapshot.maxBoundParameters} > 90`);
}

const QUEUE_CHUNK_BYTES = 64 * 1024;

export interface QueueUsageSnapshot {
  messages: number;
  chunks: number;
  writeOperations: number;
  readOperations: number;
  deleteOperations: number;
  retryReadOperations: number;
  deadLetterOperations: number;
  totalOperations: number;
}

export function queueUsage(bytes: readonly number[], options: { retries?: number; deadLetter?: boolean } = {}): QueueUsageSnapshot {
  const chunks = bytes.reduce((sum, size) => {
    if (!Number.isInteger(size) || size < 0) throw new Error("Queue message size must be a non-negative integer");
    return sum + Math.max(1, Math.ceil(size / QUEUE_CHUNK_BYTES));
  }, 0);
  const retries = options.retries ?? 0;
  if (!Number.isInteger(retries) || retries < 0) throw new Error("Queue retries must be a non-negative integer");
  const writeOperations = chunks;
  const readOperations = chunks;
  const deleteOperations = options.deadLetter === true ? 0 : chunks;
  const retryReadOperations = chunks * retries;
  const deadLetterOperations = options.deadLetter === true ? chunks * 2 : 0;
  return {
    messages: bytes.length,
    chunks,
    writeOperations,
    readOperations,
    deleteOperations,
    retryReadOperations,
    deadLetterOperations,
    totalOperations: writeOperations + readOperations + deleteOperations + retryReadOperations + deadLetterOperations,
  };
}

export interface CloudflareUsageSnapshot {
  workerInvocations: number;
  workerCpuMs: number;
  logEvents: number;
  traceSpans: number;
  durableObjectRpc: number;
  durableObjectIncomingMessages: number;
  durableObjectSqlMutations: number;
  durableObjectSetAlarms: number;
  durableObjectAlarmInvocations: number;
  r2ClassA: number;
  r2ClassB: number;
  r2BytesStored: number;
  r2BytesServed: number;
}

export function projectedObservabilityEvents(invocations: number, options: { logSamplingRate: number; traceSamplingRate: number; spansPerTrace?: number }): { logEvents: number; traceSpans: number; total: number } {
  const spans = options.spansPerTrace ?? 1;
  const logEvents = Math.ceil(invocations * options.logSamplingRate);
  const traceSpans = Math.ceil(invocations * options.traceSamplingRate * spans);
  return { logEvents, traceSpans, total: logEvents + traceSpans };
}

export class CloudflareUsageRecorder {
  readonly value: CloudflareUsageSnapshot = {
    workerInvocations: 0,
    workerCpuMs: 0,
    logEvents: 0,
    traceSpans: 0,
    durableObjectRpc: 0,
    durableObjectIncomingMessages: 0,
    durableObjectSqlMutations: 0,
    durableObjectSetAlarms: 0,
    durableObjectAlarmInvocations: 0,
    r2ClassA: 0,
    r2ClassB: 0,
    r2BytesStored: 0,
    r2BytesServed: 0,
  };

  worker(cpuMs: number, logs = 0, spans = 0): void {
    this.value.workerInvocations += 1;
    this.value.workerCpuMs += cpuMs;
    this.value.logEvents += logs;
    this.value.traceSpans += spans;
  }

  durableObject(values: Partial<Pick<CloudflareUsageSnapshot, "durableObjectRpc" | "durableObjectIncomingMessages" | "durableObjectSqlMutations" | "durableObjectSetAlarms" | "durableObjectAlarmInvocations">>): void {
    for (const [key, amount] of Object.entries(values) as Array<[keyof typeof values, number]>) {
      if (!Number.isFinite(amount) || amount < 0) throw new Error(`Invalid Durable Object usage for ${key}`);
      this.value[key] += amount;
    }
  }

  r2(values: Partial<Pick<CloudflareUsageSnapshot, "r2ClassA" | "r2ClassB" | "r2BytesStored" | "r2BytesServed">>): void {
    for (const [key, amount] of Object.entries(values) as Array<[keyof typeof values, number]>) {
      if (!Number.isFinite(amount) || amount < 0) throw new Error(`Invalid R2 usage for ${key}`);
      this.value[key] += amount;
    }
  }

  snapshot(): Readonly<CloudflareUsageSnapshot> {
    return Object.freeze({ ...this.value });
  }
}

export interface CpuProfile {
  samplesMs: number[];
  medianMs: number;
  p95Ms: number;
  maxMs: number;
}

/** Local/CI CPU probe. Warm-up samples are intentionally excluded. */
export function measureCpu(run: () => void, options: { samples?: number; warmup?: number } = {}): CpuProfile {
  const samples = Math.max(20, Math.min(options.samples ?? 100, 1_000));
  const warmup = Math.max(1, Math.min(options.warmup ?? 10, 100));
  for (let index = 0; index < warmup; index += 1) run();
  const values: number[] = [];
  for (let index = 0; index < samples; index += 1) {
    const started = performance.now();
    run();
    values.push(performance.now() - started);
  }
  values.sort((left, right) => left - right);
  const percentile = (fraction: number) => values[Math.min(values.length - 1, Math.ceil(values.length * fraction) - 1)] ?? 0;
  return { samplesMs: values, medianMs: percentile(0.5), p95Ms: percentile(0.95), maxMs: values.at(-1) ?? 0 };
}
