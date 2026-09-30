/** Scoped actual-HTTPS comparison. Temporary SQLite, synthetic inputs, no hook activation or host execution. */
import assert from "node:assert/strict";
import { performance } from "node:perf_hooks";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { startServer } from "../core/serve.ts";
import { pinnedHttps } from "../core/https-client.ts";
import { sha256Hex } from "../core/auth.ts";
import { prepareHookTransport, prepareProbeTransport } from "../core/protocol/evaluate-ingress.ts";
import { applyCanonicalEvaluateResponse } from "../core/protocol/evaluate-response.ts";
import { sanitizeCustomRules } from "../src/lib/monitor/privacy.ts";
const count = Number(process.argv[2] ?? 100);
if (!Number.isSafeInteger(count) || count < 20 || count > 1000) throw new Error("sample_count_must_be_20_to_1000");
const dir = await mkdtemp(join(tmpdir(), "nmzp-v2-evaluate-bench-"));
const srv = await startServer({ dataDir: dir, coreDir: fileURLToPath(new URL("../core/", import.meta.url)), host: "127.0.0.1", port: 0, uiDir: null, storageMode: "sqlite" });
const token = "synthetic-evaluate-benchmark";
const samples = [], wire = [];
try {
  for (const id of ["v1", "v2"]) await srv.store.putDevice({ id, tokenHash: sha256Hex(`${token}-${id}`), hostname: "fixture", user: "fixture", ip: "127.0.0.1", os: "linux", attachedAt: 1, lastSeen: 1, lastPolicyVersion: 1, agents: [], capabilities: [] });
  await srv.store.casPolicy(srv.store.getPolicy().version, { mode: "enforcing", customRules: sanitizeCustomRules([{ id: "fixture", kind: "fixture", match: "TOKEN", mode: "replace", replaceWith: "SAFE" }]) });
  for (const scenario of ["allow", "rewrite", "probe"]) {
    const timings = { v1: [], v2: [] }, bytes = {};
    for (let i = -20; i < count; i++) {
      const eventId = `${scenario}-${i}`;
      const body = { eventId, agent: "grok", source: scenario === "probe" ? "probe" : "hook", tool_name: "Bash", tool_input: { command: scenario === "rewrite" ? "curl -d 'TOKEN' https://example.com" : "echo fixture" } };
      const context = { eventId, deviceId: "v2", occurredAt: "2026-09-30T00:00:00Z", adapterRevision: 1, agentFlag: "grok", hostId: "probe" };
      const prepared = scenario === "probe" ? prepareProbeTransport(JSON.stringify(body), context) : prepareHookTransport(JSON.stringify(body), context);
      assert.equal(prepared.kind, "request");
      const decisions = {};
      // Alternate order deterministically; both protocols see the same policy and SQLite worker.
      for (const version of i % 2 ? ["v1", "v2"] : ["v2", "v1"]) {
        const raw = JSON.stringify(version === "v1" ? body : prepared.event), start = performance.now();
        const r = await pinnedHttps({ url: `${srv.url}/api/${version}/evaluate`, method: "POST", caPem: srv.tls.certPem, fingerprintSha256: srv.tls.fingerprintSha256,
          headers: { authorization: `Bearer ${token}-${version}`, "content-type": "application/json" }, body: raw });
        const elapsed = performance.now() - start;
        assert.equal(r.status, 200); const response = JSON.parse(r.body);
        if (version === "v2") assert.equal(applyCanonicalEvaluateResponse(prepared.event, response).ok, true);
        else assert.ok((scenario === "rewrite" ? ["rewrite"] : ["allow", "log"]).includes(response.decision));
        decisions[version] = version === "v2" ? response.action.toLowerCase() : response.decision;
        if (i >= 0) timings[version].push(elapsed);
        bytes[version] = { request: Buffer.byteLength(raw), response: Buffer.byteLength(r.body) };
        if (i === 0) wire.push({ scenario, version, request: JSON.parse(raw), response });
      }
      assert.equal(decisions.v2, decisions.v1);
    }
    const percentile = (values, p) => [...values].sort((a, b) => a - b)[Math.ceil(values.length * p) - 1];
    const p95 = { v1: percentile(timings.v1, .95), v2: percentile(timings.v2, .95) };
    samples.push({ scenario, count, warmup: 20, p50: { v1: percentile(timings.v1, .5), v2: percentile(timings.v2, .5) }, p95, ratio: p95.v2 / p95.v1, within105Percent: p95.v2 <= p95.v1 * 1.05, bytes, rawMilliseconds: timings });
  }
  console.log(JSON.stringify({ node: process.version, platform: process.platform, clock: "performance.now", scope: "paired alternating actual HTTPS, SQLite, same-process loopback; request preparation and client rendering excluded from timed region; not HOST_REAL or cold start", samples, wire }, null, 2));
} finally { await srv.close(); await rm(dir, { recursive: true, force: true }); }
