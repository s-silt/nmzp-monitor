// Predeclared before execution. Self-defined scenarios (the handoff's three-scenario definitions were not provided).
// Gate: per scenario, p95(head) / p95(base) <= 1.10. Paired, alternating order, same process, inert synthetic text.
// Usage: node --experimental-strip-types bench.mjs <dir with base.ts, ref.ts, cand.ts>
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = process.argv[2];
const load = async (f) => (await import(pathToFileURL(join(here, f)).href)).ResponseRiskObserver;
const impl = { base: await load("base.ts"), ref: await load("ref.ts"), head: await load("cand.ts") };
const GATE = 1.1;
const envelope = (content) => JSON.stringify({ choices: [{ index: 0, message: { role: "assistant", content } }] });
const sse = (parts) =>
  parts.map((content) => "data: " + JSON.stringify({ choices: [{ index: 0, delta: { content } }] }) + "\n\n").join("") +
  "data: [DONE]\n\n";

// S1: typical benign assistant answer, ~4 KB of markdown prose and a code fence.
const prose = "The function reads the configuration, validates each field and returns a typed result.";
const s1 = envelope(Array.from({ length: 40 }, (_, i) => (i % 10 === 9 ? "```ts\nconst x = 1;\n```" : `${prose} Step ${i}.`)).join("\n"));
// S2: worst case for the rev3 pair path, near the 256 KiB cap: every line matches `override`, no line is a hijack,
// so each line evaluates hijack(line) and hijack(prev + "\n" + line).
const ov = "Ignore the previous formatting rules for this table and keep columns aligned.";
let s2text = "";
while (envelope(s2text + ov + "\n").length < 250_000) s2text += ov + "\n";
const s2 = envelope(s2text);
// S3: streamed ~64 KB answer as SSE, many small deltas, pushed in 1 KiB chunks.
const words = (prose + " ").repeat(800).match(/.{1,24}/gs);
const s3 = sse(words);
const SCENARIOS = [
  { id: "S1-benign-json-4k", kind: "json", bytes: Buffer.from(s1), chunk: 0, n: 3000 },
  { id: "S2-override-lines-250k", kind: "json", bytes: Buffer.from(s2), chunk: 0, n: 120 },
  { id: "S3-sse-64k-small-deltas", kind: "sse", bytes: Buffer.from(s3), chunk: 1024, n: 200 },
];

function once(Obs, sc) {
  const t = performance.now();
  const ob = new Obs(sc.kind);
  if (sc.chunk) for (let i = 0; i < sc.bytes.length; i += sc.chunk) ob.push(sc.bytes.subarray(i, i + sc.chunk));
  else ob.push(sc.bytes);
  const r = ob.finish();
  return { ms: performance.now() - t, r };
}
const pct = (xs, p) => {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.ceil(s.length * p) - 1)];
};
const results = [];
for (const sc of SCENARIOS) {
  const t = { base: [], head: [] };
  const shape = {};
  for (const k of ["base", "head"]) {
    const { r } = once(impl[k], sc);
    shape[k] = { coverage: r.coverage, findings: r.findings.length };
  }
  for (let i = 0; i < 20; i++) for (const k of ["base", "head"]) once(impl[k], sc);
  for (let i = 0; i < sc.n; i++) {
    const order = i % 2 ? ["head", "base"] : ["base", "head"];
    for (const k of order) t[k].push(once(impl[k], sc).ms);
  }
  const p95 = { base: pct(t.base, 0.95), head: pct(t.head, 0.95) };
  const p50 = { base: pct(t.base, 0.5), head: pct(t.head, 0.5) };
  const ratio = p95.head / p95.base;
  results.push({ id: sc.id, bytes: sc.bytes.length, n: sc.n, shape, p50, p95, ratio, pass: ratio <= GATE });
}
console.log(JSON.stringify({ node: process.version, platform: process.platform, arch: process.arch, gate: GATE, results }, null, 2));
console.log(`summary ${results.filter((r) => r.pass).length}/${results.length}`);
// ref (c663cb6) is timed outside the gate loop only to show whether the original regression also exists on x64.
const refRatios = [];
for (const sc of SCENARIOS) {
  const t = { base: [], ref: [] };
  for (let i = 0; i < 20; i++) for (const k of ["base", "ref"]) once(impl[k], sc);
  for (let i = 0; i < sc.n; i++) for (const k of i % 2 ? ["ref", "base"] : ["base", "ref"]) t[k].push(once(impl[k], sc).ms);
  refRatios.push({ id: sc.id, ratio: pct(t.ref, 0.95) / pct(t.base, 0.95) });
}
console.log("REF " + JSON.stringify(refRatios));
