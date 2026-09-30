import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { collectContentLeaves, contentLeavesToV1, toolInputToEvalFields } from "../../core/hook-alias-keys.ts";
import { HOOK_AGENTS, parseHookEvent } from "../../core/hook-protocol.ts";
import { runHook } from "../../core/hook.ts";
import { writePolicyCache } from "../../core/policy-cache.ts";
import { ENGINE_REVISION } from "../../core/policy/engine-revision.ts";
import { evaluate } from "../../src/lib/monitor/engine.ts";
import { parseHookPayload } from "../../src/lib/monitor/ingest.ts";
import {
  canonicalToEvalInput, d8TrimAuditWarnings, d8TrimObservations, toCanonicalToolEvent,
  renderCanonicalDecision, toCanonicalDecision, sha256Prefixed, ADAPTER_BODY_LIMIT, toCanonicalToolEventFromBytes,
} from "../../core/protocol/v2-adapter.ts";
import { contentLeafAccountingOk, lookup, createAjv, compileAll, loadSchemas } from "./protocol-checks.mjs";

const ctx = { eventId: "evt-leaves", occurredAt: "2026-09-30T00:00:00Z", deviceId: "local", adapterRevision: 1, agentFlag: "claude" };
const envelope = (bag, key = "tool_input") => ({ tool_name: "Write", [key]: bag, eventId: ctx.eventId });
const parse = (raw, opts) => {
  const result = toCanonicalToolEvent(JSON.stringify(raw), ctx, opts);
  assert.equal(result.ok, true, JSON.stringify(result.failure));
  assert.equal(contentLeafAccountingOk(result.event, raw), true);
  for (const leaf of result.event.fields.contents?.leaves ?? []) {
    assert.equal(lookup(raw, leaf.provenance), leaf.value);
    assert.equal(result.event.extraFields.some((extra) => extra.path === leaf.provenance), false);
  }
  return result;
};
const values = (result) => result.event.fields.contents?.leaves.map((leaf) => leaf.value);
const pointers = (result) => result.event.fields.contents?.leaves.map((leaf) => leaf.provenance);

test("content exactness: preserve empty, whitespace, padded and equal leaves; bridge alone projects", () => {
  const raw = envelope({ contents: "", content: " \t", body: " a ", input: ["a", " a ", "b", ""] });
  const result = parse(raw);
  assert.deepEqual(values(result), ["", " \t", " a ", "a", " a ", "b", ""]);
  assert.equal(canonicalToEvalInput(result.event).contents, "a\nb");
  assert.equal(toolInputToEvalFields("Write", raw.tool_input).contents, "a\nb");
  assert.equal(contentLeavesToV1([{ value: " a " }, { value: "a" }, { value: "" }, { value: "b" }]), "a\nb");
  assert.equal(parse(envelope({})).event.fields.contents, undefined);
  const empty = parse(envelope({ contents: "" }));
  assert.deepEqual(values(empty), [""]);
  assert.equal(canonicalToEvalInput(empty.event).contents, undefined);
  const observations = d8TrimObservations(result.event).filter((row) => row.field === "contents");
  assert.deepEqual(observations.map((row) => row.leafIndex), [0, 1, 2, 4, 6]);
  assert.deepEqual(d8TrimAuditWarnings(result.event), []);
});

test("content order: key priority, edit rows, then recursive insertion and array order", () => {
  const bag = { z: ["z0", { z1: "z1", z2: "z2" }], patch: "patch", content: "same", contents: "same", body: "body",
    edits: [{ body: "e-body", old_string: "e-old", new_string: "e-new" }, { content: "e2" }], a: "last" };
  const result = parse(envelope(bag));
  assert.deepEqual(values(result), ["same", "same", "body", "patch", "e-new", "e-old", "e-body", "e2", "z0", "z1", "z2", "last"]);
  assert.equal(canonicalToEvalInput(result.event).contents, "same\nbody\npatch\ne-new\ne-old\ne-body\ne2\nz0\nz1\nz2\nlast");
});

test("content exclusions: edits are not general recursive bags; root operational keys only", () => {
  const bag = { command: "echo ignored", directory: "ignored-dir", file_path: "/tmp/ignored", cwd: "/tmp/ignored-cwd",
    edits: [{ contents: "keep", other: "ignored", body: { nested: "ignored-object" } }, "ignored-row"],
    patch: [{ contents: "patch-leaf", command: "nested-command" }], input: { path: "nested-path" } };
  const result = parse(envelope(bag));
  assert.deepEqual(values(result), ["keep", "patch-leaf", "nested-command", "nested-path"]);
  assert.ok(result.event.extraFields.some((item) => item.path === "/tool_input/edits/0/other"));
  assert.ok(result.event.extraFields.some((item) => item.path === "/tool_input/edits/0/body/nested"));
});

test("content metadata: canonical bags retain metadata-looking leaves; ingest envelope filtering stays separate", () => {
  const bag = { contents: "body", session_id: "bag-session", eventId: "bag-event", hookBlind: "bag-flag", workdir: "/b" };
  const result = parse({ ...envelope(bag), session_id: "envelope-session", note: "envelope-note" });
  assert.deepEqual(values(result), ["body", "bag-session", "bag-event", "bag-flag", "/b"]);
  assert.equal(result.event.fields.cwd, undefined);
  assert.equal(parseHookPayload(JSON.stringify({ tool_name: "Write", contents: "body", session_id: "envelope-session" }))?.contents, "body");
  assert.equal(canonicalToEvalInput(result.event).contents, "body\nbag-session\nbag-event\nbag-flag\n/b");
});

test("content pointers: bag aliases, empty and escaped raw keys resolve exactly", () => {
  const bag = { input: { "": "empty-key", "a/b": { "~x": "slash-tilde" }, "~1": "literal-escape", "白": ["zero", "one"] } };
  for (const key of ["tool_input", "toolInput", "input"]) {
    const result = parse(envelope(bag, key));
    assert.deepEqual(pointers(result), [`/${key}/input/`, `/${key}/input/a~1b/~0x`, `/${key}/input/~01`, `/${key}/input/白/0`, `/${key}/input/白/1`]);
  }
});

test("content Antigravity: remap only first token; unclaimed raw host members remain resolvable", () => {
  const raw = { toolCall: { name: "write_to_file", args: { CodeContent: " padded ", ReplacementContent: "replace", TargetFile: "/tmp/a", AbsolutePath: "/tmp/a", input: { contents: "nested", CodeContent: "raw-nested" } } }, eventId: ctx.eventId };
  const result = parse(raw);
  assert.deepEqual(values(result), [" padded ", "replace", "/tmp/a", "nested", "raw-nested"]);
  assert.deepEqual(pointers(result), ["/toolCall/args/CodeContent", "/toolCall/args/ReplacementContent", "/toolCall/args/AbsolutePath", "/toolCall/args/input/contents", "/toolCall/args/input/CodeContent"]);
});

test("content accounting: query may share scalar provenance, but extras and duplicate leaf pointers cannot", () => {
  const raw = envelope({ query: "query-text", input: ["same", "same"] });
  const result = parse(raw);
  assert.equal(result.event.fields.query.provenance, "/tool_input/query");
  assert.ok(pointers(result).includes("/tool_input/query"));
  const duplicate = structuredClone(result.event);
  duplicate.fields.contents.leaves.push(duplicate.fields.contents.leaves[0]);
  assert.equal(contentLeafAccountingOk(duplicate, raw), false);
  const extra = structuredClone(result.event);
  extra.extraFields.push({ path: "/tool_input/query", value: "query-text" });
  assert.equal(contentLeafAccountingOk(extra, raw), false);
  const mismatch = structuredClone(result.event);
  mismatch.fields.contents.leaves[0].value = "wrong";
  assert.equal(contentLeafAccountingOk(mismatch, raw), false);
});

test("content schema is one closed shape, not legacy/new union or a second aggregate value", () => {
  const schemas = loadSchemas();
  const valid = compileAll(createAjv(schemas), schemas)["canonical-tool-event.schema.json"];
  const event = parse(envelope({ contents: "" })).event;
  assert.equal(valid(event), true);
  for (const contents of [null, { value: "", provenance: "/x" }, { leaves: [] }, { leaves: event.fields.contents.leaves, value: "" }, { leaves: [{ value: "", provenance: "/x", extra: true }] }]) {
    assert.equal(valid({ ...event, fields: { contents } }), false);
    if (contents === null) assert.equal(contentLeafAccountingOk({ ...event, fields: { contents } }), false);
  }
});

test("content strict pointers: every mapped leaf participates at 1024/1025 UTF-8 bytes", () => {
  for (const count of [1024, 1025]) {
    const key = "k".repeat(count - "/tool_input/".length);
    const raw = envelope({ [key]: "leaf" });
    const off = parse(raw);
    assert.equal(Buffer.byteLength(pointers(off)[0]), count);
    const strict = toCanonicalToolEvent(JSON.stringify(raw), ctx, { strictIngress: true });
    assert.equal(strict.ok, count === 1024);
    if (!strict.ok) assert.equal(strict.failure.failureClass, "pointer_too_long");
  }
});

test("content canonical ceiling remains IC-10 default-off after exact-leaf wire expansion", () => {
  const bag = { contents: "x".repeat(ADAPTER_BODY_LIMIT - 450), a: "", b: "", c: "" };
  const raw = JSON.stringify(envelope(bag));
  assert.ok(Buffer.byteLength(raw) < ADAPTER_BODY_LIMIT);
  const off = toCanonicalToolEvent(raw, ctx);
  assert.equal(off.ok, true);
  assert.ok(Buffer.byteLength(JSON.stringify(off.event)) > ADAPTER_BODY_LIMIT);
  const strict = toCanonicalToolEvent(raw, ctx, { strictIngress: true });
  assert.equal(strict.ok, false);
  assert.equal(strict.failure.failureClass, "canonical_over_limit");
});

test("content collector is iterative and keeps existing graph cycle handling", () => {
  let nested = "leaf";
  for (let i = 0; i < 1000; i += 1) nested = [nested];
  assert.equal(collectContentLeaves({ input: nested })[0].value, "leaf");
  const cycle = { keep: "kept" };
  cycle.self = cycle;
  assert.deepEqual(collectContentLeaves({ input: cycle }).map((leaf) => leaf.value), ["kept"]);
});

test("content 13-host bytes: exact multi-leaf storage preserves real v1 hook output", async () => {
  const coreDir = fileURLToPath(new URL("../../core/", import.meta.url));
  for (const agent of HOOK_AGENTS) {
    const raw = JSON.stringify(envelope({ contents: " SAFE ", input: ["SAFE", "", " nested "], file_path: "/tmp/a" }));
    const canonical = toCanonicalToolEvent(raw, { ...ctx, agentFlag: agent });
    assert.equal(canonical.ok, true);
    assert.deepEqual(values(canonical), [" SAFE ", "SAFE", "", " nested "]);
    const parsed = parseHookEvent(raw);
    assert.equal(canonicalToEvalInput(canonical.event).contents, toolInputToEvalFields(parsed.toolName, parsed.toolInput).contents);
    const evaluated = evaluate(canonicalToEvalInput(canonical.event), "enforcing", []);
    const rendered = renderCanonicalDecision(agent, toCanonicalDecision({ eventId: ctx.eventId, v1Result: evaluated, policyVersion: 1, rulesHash: sha256Prefixed(""), engineRevision: ENGINE_REVISION, origin: "OFFLINE_CACHE" }));
    const home = await mkdtemp(join(tmpdir(), "nmzp-content-host-"));
    try {
      await writePolicyCache(join(home, ".nmzp", "policy-cache.json"), { version: 1, mode: "enforcing", stopped: false, customRules: [], updatedAt: 1 });
      const v1 = await runHook({ argv: ["--agent", agent], stdin: raw, home, coreDir, env: {} });
      const bytes = (value) => ({ stdout: value.stdout, stderr: value.stderr ?? "", exitCode: value.exitCode });
      assert.deepEqual(bytes(rendered), bytes(v1), agent);
    } finally { await rm(home, { recursive: true, force: true }); }
  }
});


test("content Unicode pointer limit counts bytes after RFC6901 encoding", () => {
  for (const limit of [1024, 1025]) {
    const budget = limit - Buffer.byteLength("/tool_input/");
    const key = "汉".repeat(Math.floor(budget / 3)) + "x".repeat(budget % 3);
    const raw = envelope({ [key]: "😀\n exact " });
    const result = parse(raw);
    assert.equal(Buffer.byteLength(pointers(result)[0]), limit);
    assert.deepEqual(values(result), ["😀\n exact "]);
    const strict = toCanonicalToolEvent(JSON.stringify(raw), ctx, { strictIngress: true });
    assert.equal(strict.ok, limit === 1024);
    if (!strict.ok) assert.equal(strict.failure.failureClass, "pointer_too_long");
  }
});

test("content Antigravity shadowed and unclaimed blank raw keys are accounted separately", () => {
  const raw = { toolCall: { name: "write_to_file", args: { CodeContent: "source", contents: "shadow", TargetFile: "", AbsolutePath: "/tmp/a", input: { contents: "nested" } } } };
  const result = parse(raw);
  assert.deepEqual(values(result), ["source", "", "nested"]);
  assert.deepEqual(pointers(result), ["/toolCall/args/CodeContent", "/toolCall/args/TargetFile", "/toolCall/args/input/contents"]);
  assert.deepEqual(result.event.fields.filePath, { value: "/tmp/a", provenance: "/toolCall/args/AbsolutePath" });
  assert.ok(result.event.extraFields.some((extra) => extra.path === "/toolCall/args/contents" && extra.value === "shadow"));
  assert.equal(canonicalToEvalInput(result.event).contents, "source\nnested");
});

test("content leaf count is not the IC-10 extras count; only actual unmapped strings consume it", () => {
  const bag = Object.fromEntries(Array.from({ length: 300 }, (_, i) => [`leaf${i}`, `value${i}`]));
  const raw = envelope(bag);
  const result = parse(raw, { strictIngress: true });
  assert.equal(result.event.fields.contents.leaves.length, 300);
  assert.equal(result.event.extraFields.length, 0);
  for (let i = 0; i < 257; i += 1) raw[`extra${i}`] = `outside${i}`;
  const off = parse(raw);
  assert.equal(off.event.extraFields.length, 257);
  const strict = toCanonicalToolEvent(JSON.stringify(raw), ctx, { strictIngress: true });
  assert.equal(strict.ok, false);
  assert.equal(strict.failure.failureClass, "extras_exceeded");
});

test("content raw bytes preserve decoded strings and whole-payload hash; IC-10 duplicates stay gated", () => {
  const raw = '\uFEFF{"tool_name":"Write","tool_input":{"contents":"first","contents":" last ","input":{"a/b":"\\u4f60\\n"}}}';
  const result = toCanonicalToolEventFromBytes(Buffer.from(raw, "utf8"), ctx);
  assert.equal(result.ok, true);
  assert.deepEqual(values(result), [" last ", "你\n"]);
  assert.equal(result.event.rawPayloadHash, sha256Prefixed(raw));
  assert.equal(contentLeafAccountingOk(result.event, JSON.parse(raw.slice(1))), true);
  const strict = toCanonicalToolEventFromBytes(Buffer.from(raw, "utf8"), ctx, { strictIngress: true });
  assert.equal(strict.ok, false);
  assert.equal(strict.failure.failureClass, "duplicate_member");
});


test("content Antigravity prototype-looking raw keys are ordinary exact leaves", () => {
  const args = JSON.parse('{"constructor":"root-constructor","toString":"root-toString","__proto__":"root-proto","input":{"constructor":"nested-constructor","toString":"nested-toString","__proto__":"nested-proto"}}');
  const raw = { toolCall: { name: "write_to_file", args } };
  let result;
  assert.doesNotThrow(() => { result = parse(raw); });
  assert.deepEqual(values(result), ["root-constructor", "root-toString", "root-proto", "nested-constructor", "nested-toString", "nested-proto"]);
  assert.deepEqual(pointers(result), ["/toolCall/args/constructor", "/toolCall/args/toString", "/toolCall/args/__proto__", "/toolCall/args/input/constructor", "/toolCall/args/input/toString", "/toolCall/args/input/__proto__"]);
});
