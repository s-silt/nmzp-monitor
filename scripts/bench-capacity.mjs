// Synthetic capacity harness. It never deletes a caller-supplied directory.
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

function fail(message) {
  process.stderr.write(`${message}\n`);
  const error = new Error(message);
  error.harness = true;
  throw error;
}

function flag(name) {
  const index = process.argv.indexOf(name);
  if (index < 0) return undefined;
  const value = process.argv[index + 1];
  if (!value || value.startsWith("--")) fail(`missing value for ${name}`);
  return value;
}

function boundedInt(name, fallback, min, max) {
  const raw = flag(name);
  if (raw === undefined) return fallback;
  if (!/^[0-9]+$/.test(raw)) fail(`${name} must be an integer ${min}..${max}`);
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < min || value > max) fail(`${name} must be an integer ${min}..${max}`);
  return value;
}

const here = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const dryRun = args.includes("--dry-run");
const synthetic = args.includes("--run-synthetic");
if (flag("--data-dir") !== undefined) {
  fail("supplied --data-dir is rejected; the harness creates its own temporary directory");
}
if (dryRun === synthetic) fail("explicit --dry-run or --run-synthetic required; this harness does not run a load by default");
const bind = flag("--bind") ?? "127.0.0.1";
if (bind !== "127.0.0.1" && bind !== "::1" && bind !== "localhost") fail("non-loopback bind rejected");

const devices = boundedInt("--devices", 1, 1, 100);
const durationMs = boundedInt("--duration-ms", 200, 50, 45 * 60 * 1000);
const concurrency = boundedInt("--concurrency", 1, 1, 16);
const pollMs = boundedInt("--poll-ms", 50, 20, 60_000);
const storage = flag("--storage") ?? "window";
if (storage !== "window" && storage !== "sqlite") fail("--storage must be window or sqlite");

function percentile(hist, ratio) {
  if (!hist || !hist.count) return null;
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

function latency(hist) {
  return {
    count: hist?.count ?? 0,
    p50: percentile(hist, 0.5),
    p95: percentile(hist, 0.95),
    p99: percentile(hist, 0.99),
    maxMs: hist?.maxMs ?? 0,
  };
}

const matrix = {
  devices: [10, 25, 50, 100],
  activeRatio: [0, 0.2, 0.5, 1],
  evaluatePerSecond: [0.2, 1, 3],
  storage: ["window", "sqlite"],
  heartbeat: ["jitter", "synchronized"],
  warmupMin: 5,
  steadyMin: 30,
  recoveryMin: 10,
  executed: false,
};

let dir;
let server;
try {
  dir = await mkdtemp(join(tmpdir(), synthetic ? "nmzp-capacity-synth-" : "nmzp-capacity-dry-"));
  if (dryRun) {
    const persistUrl = pathToFileURL(join(here, "..", "core", "persist.ts")).href;
    const metricsUrl = pathToFileURL(join(here, "..", "core", "metrics.ts")).href;
    const { NmzpStore } = await import(persistUrl);
    const { snapshotCapacity } = await import(metricsUrl);
    const store = new NmzpStore(dir);
    await store.load();
    let release;
    const gate = new Promise((done) => {
      release = done;
    });
    const first = store.withMutex(async () => {
      await gate;
    });
    const second = store.withMutex(async () => "second");
    await new Promise((done) => setTimeout(done, 40));
    release();
    await first;
    await second;
    const metrics = snapshotCapacity();
    await store.close();
    process.stdout.write(`${JSON.stringify({
      mode: "dry-run",
      synthetic: true,
      bind,
      dataDir: dir,
      validatesRoutes: false,
      routeCapacity: false,
      extrapolation: "not_performed",
      productionCapacity: null,
      claimsProductionCapacity: false,
      matrix,
      metrics,
    })}\n`);
  } else {
    const serveUrl = pathToFileURL(join(here, "..", "core", "serve.ts")).href;
    const httpsUrl = pathToFileURL(join(here, "..", "core", "https-client.ts")).href;
    const metricsUrl = pathToFileURL(join(here, "..", "core", "metrics.ts")).href;
    const { startServer } = await import(serveUrl);
    const { pinnedHttps } = await import(httpsUrl);
    const { resetCapacityMetrics, snapshotCapacity } = await import(metricsUrl);
    server = await startServer({
      dataDir: dir,
      host: "127.0.0.1",
      port: 0,
      coreDir: join(here, "..", "core"),
      uiDir: null,
      storageMode: storage,
    });
    resetCapacityMetrics();
    const pin = { caPem: server.tls.certPem, fingerprintSha256: server.tls.fingerprintSha256 };
    const outcomes = {
      state: { "200": 0, other: 0 },
      evaluate: { "200": 0, other: 0 },
      heartbeat: { "200": 0, other: 0 },
    };
    async function hit(route, request) {
      try {
        const response = await pinnedHttps({ ...pin, timeoutMs: 8000, maxBodyBytes: 2_000_000, ...request });
        if (response.status === 200) outcomes[route]["200"] += 1;
        else outcomes[route].other += 1;
      } catch {
        outcomes[route].other += 1;
      }
    }
    const joined = [];
    for (let index = 0; index < devices; index += 1) {
      const ticketResponse = await pinnedHttps({
        ...pin,
        url: `${server.url}/api/v1/ticket`,
        method: "POST",
        body: "{}",
        headers: { authorization: `Bearer ${server.adminToken}`, "content-type": "application/json" },
        timeoutMs: 8000,
      });
      if (ticketResponse.status !== 200) fail("synthetic ticket was rejected");
      const ticket = JSON.parse(ticketResponse.body).ticket;
      const response = await pinnedHttps({
        ...pin,
        url: `${server.url}/api/v1/join`,
        method: "POST",
        body: JSON.stringify({ ticket, hostname: `synth-${index}`, os: "linux", user: "fixture" }),
        headers: { "content-type": "application/json" },
        timeoutMs: 8000,
      });
      if (response.status !== 200) fail("synthetic join was rejected");
      joined.push(JSON.parse(response.body).deviceToken);
    }
    for (const token of joined) {
      await hit("heartbeat", {
        url: `${server.url}/api/v1/heartbeat`,
        method: "POST",
        body: JSON.stringify({ hostname: "synth", user: "fixture", ip: "127.0.0.1", policyVersion: 1 }),
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      });
    }
    const deadline = Date.now() + durationMs;
    let sequence = 0;
    let nextPoll = 0;
    while (Date.now() < deadline) {
      const batch = [];
      for (let slot = 0; slot < concurrency; slot += 1) {
        const token = joined[sequence % joined.length];
        const eventId = `synth-${sequence}`;
        sequence += 1;
        batch.push(hit("evaluate", {
          url: `${server.url}/api/v1/evaluate`,
          method: "POST",
          body: JSON.stringify({
            eventId,
            agent: "grok",
            tool_name: "Read",
            tool_input: { file_path: "README.md" },
          }),
          headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        }));
      }
      await Promise.all(batch);
      const now = Date.now();
      if (now >= nextPoll) {
        await hit("state", {
          url: `${server.url}/api/v1/state`,
          method: "GET",
          headers: { authorization: `Bearer ${server.adminToken}` },
        });
        nextPoll = now + pollMs;
      }
    }
    const metrics = snapshotCapacity();
    process.stdout.write(`${JSON.stringify({
      mode: "run-synthetic",
      synthetic: true,
      bind: "127.0.0.1",
      dataDir: dir,
      validatesRoutes: true,
      routeCapacity: "synthetic-loopback-only",
      extrapolation: "not_performed",
      productionCapacity: null,
      claimsProductionCapacity: false,
      params: { devices, durationMs, storage, concurrency, pollMs },
      outcomes,
      latency: {
        state: latency(metrics.routes.state),
        evaluate: latency(metrics.routes.evaluate),
      },
      matrix,
      metrics,
    })}\n`);
  }
} finally {
  if (server) await server.close().catch(() => undefined);
  if (dir) await rm(dir, { recursive: true, force: true });
}
