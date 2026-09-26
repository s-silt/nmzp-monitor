import { monitorEventLoopDelay, performance, type IntervalHistogram } from "node:perf_hooks";

/**
 * Bounded process counters for capacity observation.
 * Labels are a fixed set. Samples are histogram buckets, not per-request arrays.
 * Payloads, commands, and device identifiers are not stored.
 */

const EDGES_MS = [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000] as const;

const REQUEST_STATUS = ["200", "400", "401", "403", "404", "405", "409", "413", "429", "500", "502", "503"] as const;

export type RequestStatusKey = (typeof REQUEST_STATUS)[number];

export type WorkerErrorKind = "queue_full" | "timeout" | "task_failed";

/** Fixed route labels. Query strings, device ids, and bodies are not labels. */
export type RouteLatencyLabel = "state" | "evaluate";

export interface HistogramSnapshot {
  edgesMs: number[];
  counts: number[];
  count: number;
  sumMs: number;
  maxMs: number;
}

export interface CapacitySnapshot {
  mutex: {
    waitMs: HistogramSnapshot;
    holdMs: HistogramSnapshot;
    queuedCurrent: number;
    queuedMax: number;
    queueSamples: number;
  };
  worker: {
    queueCurrent: number;
    queueMax: number;
    errors: Record<WorkerErrorKind, number>;
  };
  eventLoop: { delayMs: HistogramSnapshot };
  requests: { status: Record<RequestStatusKey, number>; other: number };
  routes: Record<RouteLatencyLabel, HistogramSnapshot>;
}

interface Histogram {
  counts: number[];
  count: number;
  sumMs: number;
  maxMs: number;
}

interface MetricsState {
  mutexWait: Histogram;
  mutexHold: Histogram;
  queuedCurrent: number;
  queuedMax: number;
  queueSamples: number;
  workerQueueCurrent: number;
  workerQueueMax: number;
  workerErrors: Record<WorkerErrorKind, number>;
  eventLoop: Histogram;
  requests: Record<RequestStatusKey, number>;
  requestOther: number;
  routes: Record<RouteLatencyLabel, Histogram>;
}

function emptyHistogram(): Histogram {
  return { counts: Array.from({ length: EDGES_MS.length + 1 }, () => 0), count: 0, sumMs: 0, maxMs: 0 };
}

function emptyRequests(): Record<RequestStatusKey, number> {
  return {
    "200": 0,
    "400": 0,
    "401": 0,
    "403": 0,
    "404": 0,
    "405": 0,
    "409": 0,
    "413": 0,
    "429": 0,
    "500": 0,
    "502": 0,
    "503": 0,
  };
}

function emptyState(): MetricsState {
  return {
    mutexWait: emptyHistogram(),
    mutexHold: emptyHistogram(),
    queuedCurrent: 0,
    queuedMax: 0,
    queueSamples: 0,
    workerQueueCurrent: 0,
    workerQueueMax: 0,
    workerErrors: { queue_full: 0, timeout: 0, task_failed: 0 },
    eventLoop: emptyHistogram(),
    requests: emptyRequests(),
    requestOther: 0,
    routes: { state: emptyHistogram(), evaluate: emptyHistogram() },
  };
}

let state: MetricsState = emptyState();

function finiteMs(value: number): number | undefined {
  if (!Number.isFinite(value) || value < 0) return undefined;
  return value;
}

function pushHistogram(hist: Histogram, ms: number): void {
  const value = finiteMs(ms);
  if (value === undefined) return;
  let index = EDGES_MS.findIndex((edge) => value <= edge);
  if (index < 0) index = EDGES_MS.length;
  hist.counts[index] = (hist.counts[index] ?? 0) + 1;
  hist.count += 1;
  hist.sumMs += value;
  if (value > hist.maxMs) hist.maxMs = value;
}

function copyHistogram(hist: Histogram): HistogramSnapshot {
  return {
    edgesMs: [...EDGES_MS],
    counts: [...hist.counts],
    count: hist.count,
    sumMs: hist.sumMs,
    maxMs: hist.maxMs,
  };
}

export function observeMutexWait(ms: number): void {
  pushHistogram(state.mutexWait, ms);
}

export function observeMutexHold(ms: number): void {
  pushHistogram(state.mutexHold, ms);
}

export function observeMutexQueued(depth: number): void {
  if (!Number.isSafeInteger(depth) || depth < 0) return;
  state.queuedCurrent = depth;
  if (depth > state.queuedMax) state.queuedMax = depth;
  state.queueSamples += 1;
}

export function observeWorkerQueue(depth: number): void {
  if (!Number.isSafeInteger(depth) || depth < 0) return;
  state.workerQueueCurrent = depth;
  if (depth > state.workerQueueMax) state.workerQueueMax = depth;
}

export function observeWorkerError(kind: WorkerErrorKind): void {
  state.workerErrors[kind] += 1;
}

export function observeRequest(status: number): void {
  if (!Number.isSafeInteger(status)) return;
  const key = String(status);
  if ((REQUEST_STATUS as readonly string[]).includes(key)) {
    state.requests[key as RequestStatusKey] += 1;
    return;
  }
  state.requestOther += 1;
}

let loopMonitor: IntervalHistogram | undefined;
let lastLoopSample = 0;

function eventLoopMonitor(): IntervalHistogram {
  if (!loopMonitor) {
    const histogram = monitorEventLoopDelay({ resolution: 20 });
    histogram.enable();
    loopMonitor = histogram;
  }
  return loopMonitor;
}

/** Records one event-loop delay sample. The value is milliseconds, not a capacity claim. */
export function sampleEventLoop(now = Date.now()): number {
  const histogram = eventLoopMonitor();
  const ms = histogram.mean / 1e6;
  const value = finiteMs(ms) ?? 0;
  pushHistogram(state.eventLoop, value);
  histogram.reset();
  lastLoopSample = now;
  return value;
}

function maybeSampleEventLoop(): void {
  const now = Date.now();
  if (now - lastLoopSample < 1000) return;
  sampleEventLoop(now);
}

export function observeRequestOutcome(status: number): void {
  observeRequest(status);
  maybeSampleEventLoop();
}

export function observeRouteLatency(label: RouteLatencyLabel, ms: number): void {
  pushHistogram(state.routes[label], ms);
}

/** Call the returned function once when the labeled request finishes, including failures. */
export function beginRouteLatency(label: RouteLatencyLabel): () => void {
  const start = performance.now();
  let finished = false;
  return () => {
    if (finished) return;
    finished = true;
    observeRouteLatency(label, performance.now() - start);
  };
}

export function histogramPercentile(hist: HistogramSnapshot, ratio: number): number | null {
  if (!hist.count || !Number.isFinite(ratio) || ratio <= 0 || ratio > 1) return null;
  const target = Math.max(1, Math.ceil(hist.count * ratio));
  let seen = 0;
  for (let index = 0; index < hist.counts.length; index += 1) {
    seen += hist.counts[index] ?? 0;
    if (seen >= target) {
      if (index >= hist.edgesMs.length) return hist.maxMs;
      return hist.edgesMs[index] ?? hist.maxMs;
    }
  }
  return hist.maxMs;
}

export function snapshotCapacity(): CapacitySnapshot {
  maybeSampleEventLoop();
  return {
    mutex: {
      waitMs: copyHistogram(state.mutexWait),
      holdMs: copyHistogram(state.mutexHold),
      queuedCurrent: state.queuedCurrent,
      queuedMax: state.queuedMax,
      queueSamples: state.queueSamples,
    },
    worker: {
      queueCurrent: state.workerQueueCurrent,
      queueMax: state.workerQueueMax,
      errors: { ...state.workerErrors },
    },
    eventLoop: { delayMs: copyHistogram(state.eventLoop) },
    requests: { status: { ...state.requests }, other: state.requestOther },
    routes: {
      state: copyHistogram(state.routes.state),
      evaluate: copyHistogram(state.routes.evaluate),
    },
  };
}

export function resetCapacityMetrics(): void {
  state = emptyState();
  lastLoopSample = 0;
}
