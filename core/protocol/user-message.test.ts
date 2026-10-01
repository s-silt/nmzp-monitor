// D13: userMessage is the fixed per-action table in evaluate-response.ts.
// Payloads below are the rewrite / privacy fixtures already built by
// tests/contract/evaluate-schema.test.mjs (`response`) and
// tests/contract/evaluate-routes.test.mjs (`hook`, probe examples, residue, projection).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it, type TestContext } from "node:test";
import { fileURLToPath } from "node:url";
import {
  EvaluationApplicationError,
  canonicalRequestHash,
  evaluateDurably,
  type DecisionProjection,
} from "../evaluation-application.ts";
import { HOOK_AGENTS } from "../hook-protocol.ts";
import { loadMonitor, resolveRepoRoot } from "../paths.ts";
import { NmzpStore } from "../persist.ts";
import type { DeviceRecord } from "../schema.ts";
import { buildRenderedRewriteEvidence, rewriteReplayWitness } from "./rendered-rewrite.ts";
import type { PrivacyFns } from "../rewrite.ts";
import { prepareCanonicalEvaluation, prepareHookTransport, prepareProbeTransport } from "./evaluate-ingress.ts";
import {
  applyCanonicalEvaluateResponse,
  canonicalEvaluateResponse,
  type CanonicalEvaluateResponseV2,
} from "./evaluate-response.ts";
import type { CanonicalToolEvent } from "./v2-adapter.ts";
import {
  REDACT_TAG,
  cloakPersona,
  sanitizeCustomRules,
  scanCustom,
  scanSecrets,
  shouldCloakPersona,
} from "../../src/lib/monitor/privacy.ts";

const ACTIONS = ["ALLOW", "LOG", "ASK", "BLOCK", "REWRITE"] as const;
type Action = (typeof ACTIONS)[number];
type MessageTable = Record<Action, string>;
type FixtureRules = NonNullable<ReturnType<typeof sanitizeCustomRules>>;

const coreDir = dirname(fileURLToPath(new URL("../nmzp.mjs", import.meta.url)));
const repoRoot = resolveRepoRoot(coreDir);
const monitor = await loadMonitor(coreDir);
const privacyFns: PrivacyFns = { REDACT_TAG, scanSecrets, scanCustom, cloakPersona, shouldCloakPersona };
const TOKEN_SECRET = "TOKEN";
const schemaCtx = {
  deviceId: "schema-device",
  eventId: "schema-event",
  occurredAt: "2026-09-30T12:00:00Z",
  adapterRevision: 1,
};
const routeCtx = (id: string, agentFlag = "grok", deviceId = "a") => ({
  deviceId,
  eventId: id,
  occurredAt: "2026-09-30T00:00:00Z",
  adapterRevision: 1,
  agentFlag,
});

const tokenRules = rulesFrom([
  { id: "fixture", kind: "fixture_kind", match: TOKEN_SECRET, mode: "replace", replaceWith: "SAFE" },
]);
const schemaRules = rulesFrom([
  { id: "schema_rule", kind: "schema_kind", match: TOKEN_SECRET, mode: "replace", replaceWith: "SAFE" },
]);
const residueMatch = 'TOKEN|"flag":true';
const residueRules = rulesFrom([
  { id: "fixture", kind: "fixture_kind", match: residueMatch, mode: "replace", replaceWith: "SAFE" },
]);

type Fixture = {
  label: string;
  rules: FixtureRules;
  event: CanonicalToolEvent;
  forbidden: string[];
  action?: Action;
  tooLarge?: boolean;
  replay?: boolean;
};

function rulesFrom(input: unknown): FixtureRules {
  const rules = sanitizeCustomRules(input);
  if (!rules || rules.length !== 1) assert.fail(`sanitizeCustomRules dropped fixture rule ${JSON.stringify(input)}`);
  return rules;
}

function forbidden(...parts: string[]): string[] {
  return [...new Set(parts.filter((part) => part.length > 0))];
}

function readSourceMessages(): MessageTable {
  const source = readFileSync(join(repoRoot, "core/protocol/evaluate-response.ts"), "utf8");
  const body = source.match(/const messages = \{([\s\S]*?)\} as const;/);
  if (!body?.[1]) assert.fail("evaluate-response.ts: could not read `const messages = { ... } as const`");
  const found = new Map<string, string>();
  for (const item of body[1].matchAll(/([A-Z]+):\s*"([^"]*)"/g)) found.set(item[1] ?? "", item[2] ?? "");
  return tableFrom("evaluate-response.ts", found);
}

function readSchemaMessages(schema: unknown, label: string): MessageTable {
  if (!schema || typeof schema !== "object" || !("allOf" in schema) || !Array.isArray(schema.allOf)) {
    assert.fail(`${label}: canonical evaluate response schema has no allOf`);
  }
  const found = new Map<string, string>();
  for (const clause of schema.allOf) {
    if (!clause || typeof clause !== "object") continue;
    const action = (clause as { if?: { properties?: { action?: { const?: unknown } } } }).if?.properties?.action?.const;
    const message = (clause as { then?: { properties?: { userMessage?: { const?: unknown } } } }).then?.properties
      ?.userMessage?.const;
    if (typeof action !== "string" || typeof message !== "string") continue;
    if (found.has(action)) assert.fail(`${label}: duplicate userMessage const for ${action}`);
    found.set(action, message);
  }
  return tableFrom(label, found);
}

function tableFrom(label: string, found: Map<string, string>): MessageTable {
  const table = {} as MessageTable;
  const missing = ACTIONS.filter((action) => !found.has(action));
  if (missing.length) assert.fail(`${label}: missing pinned userMessage for ${missing.join(", ")}`);
  const extra = [...found.keys()].filter((action) => !ACTIONS.includes(action as Action));
  if (extra.length) assert.fail(`${label}: unexpected userMessage action ${extra.join(", ")}`);
  for (const action of ACTIONS) table[action] = found.get(action)!;
  if (new Set(Object.values(table)).size !== ACTIONS.length) {
    assert.fail(`${label}: userMessage constants are not distinct: ${JSON.stringify(table)}`);
  }
  return table;
}

function embeddedResponseSchema(source: string): unknown {
  const id = '"$id":"https://nmzp.local/contract-candidate/canonical-evaluate-response-v2.schema.json"';
  const at = source.indexOf(id);
  if (at < 0) assert.fail("evaluate-validator.ts: embedded canonical-evaluate-response-v2 schema is missing");
  const brace = source.lastIndexOf("{", at);
  if (brace < 0) assert.fail("evaluate-validator.ts: embedded response schema object did not start");
  let depth = 0;
  let inString = false;
  let escape = false;
  for (let i = brace; i < source.length; i++) {
    const ch = source[i];
    if (inString) {
      if (escape) escape = false;
      else if (ch === "\\") escape = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') inString = true;
    else if (ch === "{") depth += 1;
    else if (ch === "}") {
      depth -= 1;
      if (depth === 0) return JSON.parse(source.slice(brace, i + 1)) as unknown;
    }
  }
  assert.fail("evaluate-validator.ts: embedded response schema object did not close");
}

function assertSameTable(label: string, actual: MessageTable, expected: MessageTable): void {
  for (const action of ACTIONS) {
    assert.equal(
      actual[action],
      expected[action],
      `${label} ${action} userMessage drifted from evaluate-response.ts: ${JSON.stringify(actual[action])} !== ${JSON.stringify(expected[action])}`,
    );
  }
}

function assertUserMessage(json: string, messages: MessageTable, secrets: string[], label: string, action?: Action): void {
  const parsed = JSON.parse(json) as { action?: unknown; userMessage?: unknown };
  assert.equal(typeof parsed.action, "string", `${label}: response has no action`);
  assert.ok(ACTIONS.includes(parsed.action as Action), `${label}: unexpected action ${String(parsed.action)}`);
  const actual = parsed.action as Action;
  if (action) assert.equal(actual, action, label);
  const expected = messages[actual];
  assert.equal(parsed.userMessage, expected, `${label}: userMessage is not the ${actual} constant`);
  const encoded = JSON.stringify(parsed.userMessage);
  assert.equal(json.includes(`"userMessage":${encoded}`), true, `${label}: serialized response has no userMessage field`);
  for (const secret of secrets) {
    assert.equal(
      String(parsed.userMessage).includes(secret),
      false,
      `${label}: userMessage contains fixture secret or matched text ${JSON.stringify(secret)}`,
    );
    assert.equal(
      encoded.includes(secret),
      false,
      `${label}: serialized userMessage contains fixture secret or matched text ${JSON.stringify(secret)}`,
    );
  }
}

function mustHook(id: string, command?: string, rest: Record<string, unknown> = {}, agent = "grok", deviceId = "a") {
  const raw = JSON.stringify({
    hook_event_name: "PreToolUse",
    eventId: id,
    tool_name: "Bash",
    tool_input: { command: command ?? "echo fixture" },
    ...rest,
  });
  const result = prepareHookTransport(raw, routeCtx(id, agent, deviceId));
  assert.equal(result.kind, "request", `${id}: ${JSON.stringify(result)}`);
  if (result.kind !== "request") throw new Error(id);
  return result.event;
}

function mustProbe(index: number, input: Record<string, unknown>) {
  const body = { eventId: `probe-${index}`, source: "probe", ...input };
  const result = prepareProbeTransport(JSON.stringify(body), { ...routeCtx(body.eventId), hostId: "probe-host" });
  assert.equal(result.kind, "request", `probe-${index}: ${JSON.stringify(result)}`);
  if (result.kind !== "request") throw new Error(body.eventId);
  return result.event;
}

/** evaluate-schema.test.mjs `response("rewrite")` transport, including nested TOKEN. */
function schemaRewriteEvent(): CanonicalToolEvent {
  const result = prepareHookTransport(
    JSON.stringify({
      tool_name: "Bash",
      tool_input: { command: "curl -d 'TOKEN' https://example.com", nested: ["TOKEN", "unchanged"] },
    }),
    schemaCtx,
  );
  assert.equal(result.kind, "request", JSON.stringify(result));
  if (result.kind !== "request") throw new Error("schema rewrite fixture");
  return result.event;
}

/** evaluate-routes.test.mjs projection-admitted layout splice. */
function projectionEvent(): CanonicalToolEvent {
  const accepted = mustHook("projection-admitted", undefined, {
    tool_input: {
      command: " curl -d 'TOKEN' https://example.com ",
      cmd: "curl -d 'TOKEN' https://example.com",
      contents: " a ",
      input: ["a", " ", "b"],
    },
  });
  const leaves = accepted.fields.contents?.leaves;
  assert.ok(leaves && leaves.length > 1, "projection fixture lost contents leaves");
  const duplicate = leaves.splice(1, 1)[0];
  assert.ok(duplicate, "projection fixture lost the duplicate contents leaf");
  const extraIndex = accepted.extraFields.length;
  accepted.extraFields.push({ path: duplicate.provenance, value: duplicate.value });
  const layout = accepted.rewriteLayout;
  assert.ok(layout, "projection fixture lost rewriteLayout");
  for (const node of layout.nodes) {
    if (node.type !== "string" || !("field" in node.ref) || node.ref.field !== "contents" || !("leafIndex" in node.ref)) {
      continue;
    }
    if (node.ref.leafIndex === 1) node.ref = { extraIndex };
    else if (node.ref.leafIndex > 1) node.ref.leafIndex -= 1;
  }
  return accepted;
}

function routeFixtures(): Fixture[] {
  const curl = "curl -d 'TOKEN' https://example.com";
  const probes: Array<{ input: Record<string, unknown>; action?: Action; forbidden: string[] }> = [
    {
      input: {
        tool_name: "Bash",
        command: curl,
        agent: "grok",
        proc: "shell",
        parentProc: "parent",
        hookBlind: true,
      },
      forbidden: forbidden(TOKEN_SECRET),
    },
    {
      input: { tool: "Write", toolInput: { file_path: "/tmp/file", content: TOKEN_SECRET, nested: [true, null, 3] }, agent: "grok" },
      forbidden: forbidden(TOKEN_SECRET),
    },
    {
      input: { tool_name: "Bash", tool_input: { command: "echo fixture", cwd: "/sub" }, cwd: "/root", contents: "top contents", agent: "grok" },
      forbidden: forbidden(TOKEN_SECRET),
    },
    { input: { tool_name: "Read", filePath: "/tmp/file", agent: "" }, forbidden: forbidden(TOKEN_SECRET) },
    {
      input: { tool_name: "Bash", tool_input: { command: " echo fixture ", cmd: "echo fixture", host: " example.com " }, agent: "grok" },
      forbidden: forbidden(TOKEN_SECRET),
    },
  ];
  return [
    ...HOOK_AGENTS.map((agent) => ({
      label: `evaluate-routes ${agent} TOKEN curl`,
      rules: tokenRules,
      event: mustHook(`host-${agent}`, curl, {}, agent),
      forbidden: forbidden(TOKEN_SECRET),
      action: "REWRITE" as const,
    })),
    ...probes.map((probe, index) => ({
      label: `evaluate-routes probe-${index}`,
      rules: tokenRules,
      event: mustProbe(index, probe.input),
      forbidden: probe.forbidden,
      action: probe.action,
    })),
    {
      label: "evaluate-routes replay TOKEN curl",
      rules: tokenRules,
      event: mustHook("replay", curl),
      forbidden: forbidden(TOKEN_SECRET),
      action: "REWRITE",
      replay: true,
    },
    {
      label: "evaluate-routes response budget",
      rules: tokenRules,
      event: mustHook("response-budget", undefined, {
        tool_input: { command: curl, nested: Array(650).fill(TOKEN_SECRET) },
      }),
      forbidden: forbidden(TOKEN_SECRET),
      action: "REWRITE",
      tooLarge: true,
    },
    {
      label: "evaluate-routes projection admitted",
      rules: tokenRules,
      event: projectionEvent(),
      forbidden: forbidden(TOKEN_SECRET),
      action: "REWRITE",
    },
    {
      label: "evaluate-routes default echo fixture",
      rules: tokenRules,
      event: mustHook("echo-fixture"),
      forbidden: forbidden(TOKEN_SECRET, "echo fixture"),
      action: "LOG",
    },
    {
      label: "evaluate-schema nested TOKEN",
      rules: schemaRules,
      event: schemaRewriteEvent(),
      forbidden: forbidden(TOKEN_SECRET, "unchanged"),
      action: "REWRITE",
    },
    {
      label: "evaluate-routes residue flag true",
      rules: residueRules,
      event: mustHook("residue-true", undefined, {
        tool_input: { command: curl, cmd: " curl -d 'TOKEN' https://example.com ", flag: true },
      }),
      forbidden: forbidden(TOKEN_SECRET, residueMatch, '"flag":true'),
      action: "BLOCK",
    },
    {
      label: "evaluate-routes residue flag false",
      rules: residueRules,
      event: mustHook("residue-false", undefined, {
        tool_input: { command: curl, cmd: " curl -d 'TOKEN' https://example.com ", flag: false },
      }),
      forbidden: forbidden(TOKEN_SECRET, residueMatch, '"flag":true'),
      action: "REWRITE",
    },
  ];
}

const wire = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

/** evaluate-schema.test.mjs `response()` for allow, block, and the TOKEN rewrite fixture. */
function schemaResponse(decision: "allow" | "block" | "rewrite"): { event: CanonicalToolEvent; response: CanonicalEvaluateResponseV2 } {
  const opened = prepareHookTransport(JSON.stringify({ tool_name: "Bash", tool_input: { command: "echo safe" } }), schemaCtx);
  assert.equal(opened.kind, "request", JSON.stringify(opened));
  if (opened.kind !== "request") throw new Error("schema request");
  const event = wire(opened.event);
  let rewrite: DecisionProjection["rewrite"];
  if (decision === "rewrite") {
    Object.assign(event, wire(schemaRewriteEvent()));
    const rules = rulesFrom([
      { id: "schema_rule", kind: "schema_kind", match: TOKEN_SECRET, mode: "replace", replaceWith: "SAFE" },
    ]);
    const rendered = buildRenderedRewriteEvidence(event, rules, privacyFns);
    assert.equal(rendered.ok, true, JSON.stringify(rendered));
    if (!rendered.ok) throw new Error("schema rewrite evidence");
    rewrite = rendered.evidence;
  }
  const hash = `sha256:${"a".repeat(64)}`;
  const record = {
    id: event.eventId,
    requestHash: canonicalRequestHash(event),
    policyVersion: 7,
    binding: { rulesHash: hash },
    outcome: {
      decision,
      reason: decision,
      ruleIndex: null,
      risk: "info",
      threat: null,
      rewriteStatus: decision === "rewrite" ? "APPLIED" : "NONE",
      secretKindIndices: [],
      enforcement: "delivered",
    },
    ...(rewrite ? { rewrite: rewriteReplayWitness(rewrite, []) } : {}),
  };
  const projected = canonicalEvaluateResponse({
    record: record as unknown as DecisionProjection["record"],
    catalog: { rules: ["schema_rule"], kinds: ["schema_kind"], exemptions: [] },
    rewrite,
    duplicate: false,
  });
  return { event, response: wire(projected) };
}

function device(id: string): DeviceRecord {
  return {
    id,
    tokenHash: "fixture",
    hostname: "fixture",
    user: "fixture",
    ip: "127.0.0.1",
    os: "linux",
    attachedAt: 1,
    lastSeen: 1,
    lastPolicyVersion: 1,
    agents: [],
    capabilities: [],
  };
}

async function openStore(t: TestContext): Promise<NmzpStore> {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-user-message-"));
  t.after(async () => {
    await rm(dir, { recursive: true, force: true });
  });
  const store = new NmzpStore(dir);
  t.after(async () => {
    await store.close();
  });
  await store.load({ storageMode: "sqlite", policySource: monitor, auditRetention: { minFreeBytes: 0 } });
  await store.putDevice(device("a"));
  await store.putDevice(device("schema-device"));
  return store;
}

describe("D13 userMessage", () => {
  it("pins the same five action constants in evaluate-response.ts, the response schema, and the generated validator", () => {
    const source = readSourceMessages();
    const schema = JSON.parse(
      readFileSync(join(repoRoot, "contract/protocol/schemas/canonical-evaluate-response-v2.schema.json"), "utf8"),
    ) as unknown;
    const validator = readFileSync(join(repoRoot, "core/protocol/generated/evaluate-validator.ts"), "utf8");
    assertSameTable("canonical-evaluate-response-v2.schema.json", readSchemaMessages(schema, "canonical-evaluate-response-v2.schema.json"), source);
    assertSameTable(
      "core/protocol/generated/evaluate-validator.ts",
      readSchemaMessages(embeddedResponseSchema(validator), "evaluate-validator.ts"),
      source,
    );
  });

  it("keeps server-built userMessage on the action constant and out of fixture secrets", async (t) => {
    const messages = readSourceMessages();
    const schemaBuilt = schemaResponse("rewrite");
    assertUserMessage(JSON.stringify(schemaBuilt.response), messages, forbidden(TOKEN_SECRET), "evaluate-schema response() rewrite", "REWRITE");
    const store = await openStore(t);
    let active = "";
    const fixtures = routeFixtures();
    const ids = fixtures.map((fixture) => fixture.event.eventId);
    assert.equal(new Set(ids).size, ids.length, `duplicate fixture event ids: ${ids.join(",")}`);
    for (const fixture of fixtures) {
      const key = JSON.stringify(fixture.rules);
      if (key !== active) {
        const next = await store.casPolicy(store.getPolicy().version, { mode: "enforcing", customRules: fixture.rules });
        if ("conflict" in next) assert.fail(`${fixture.label}: policy cas conflict at version ${next.version}`);
        active = key;
      }
      const ingress = prepareCanonicalEvaluation(fixture.event, fixture.event.device.id);
      assert.equal(ingress.ok, true, `${fixture.label}: ${JSON.stringify(ingress)}`);
      if (!ingress.ok) throw new Error(fixture.label);
      let built: CanonicalEvaluateResponseV2 | undefined;
      const run = () =>
        evaluateDurably({
          store,
          monitor,
          windows: new monitor.SessionWindows(),
          snapshot: store.capturePolicy(),
          deviceId: fixture.event.device.id,
          event: ingress.event,
          prepared: ingress.prepared,
          project: (decision) => {
            built = canonicalEvaluateResponse(decision);
            return built;
          },
        });
      let json: string;
      try {
        const result = await run();
        if (fixture.tooLarge) assert.fail(`${fixture.label}: expected evaluation_result_too_large`);
        json = result.json;
      } catch (error) {
        if (fixture.tooLarge && error instanceof EvaluationApplicationError && error.code === "evaluation_result_too_large" && built) {
          json = JSON.stringify(built);
        } else {
          const code = error instanceof EvaluationApplicationError ? error.code : error instanceof Error ? error.message : String(error);
          assert.fail(`${fixture.label}: server evaluation failed: ${code}`);
        }
      }
      assertUserMessage(json, messages, fixture.forbidden, fixture.label, fixture.action);
      const applied = applyCanonicalEvaluateResponse(fixture.event, JSON.parse(json) as unknown);
      assert.equal(applied.ok, true, `${fixture.label}: ${JSON.stringify(applied)}`);
      if (fixture.replay) {
        const again = await run();
        const body = JSON.parse(again.json) as { duplicate?: unknown };
        assert.equal(body.duplicate, true, `${fixture.label} duplicate`);
        assertUserMessage(again.json, messages, fixture.forbidden, `${fixture.label} duplicate`, fixture.action);
      }
    }
  });

  it("rejects a userMessage that appends the fixture secret, is empty, or belongs to another action", () => {
    const messages = readSourceMessages();
    const baselines = [
      ["ALLOW", schemaResponse("allow")],
      ["BLOCK", schemaResponse("block")],
      ["REWRITE", schemaResponse("rewrite")],
    ] as const;
    for (const [action, built] of baselines) {
      const accepted = applyCanonicalEvaluateResponse(built.event, built.response);
      assert.equal(accepted.ok, true, `${action} baseline: ${JSON.stringify(accepted)}`);
      assert.equal(built.response.action, action);
      assert.equal(built.response.userMessage, messages[action]);
      const other: Action = action === "ALLOW" ? "BLOCK" : "ALLOW";
      const replacements = [
        ["secret appended", messages[action] + TOKEN_SECRET],
        ["empty", ""],
        ["other action", messages[other]],
      ] as const;
      for (const [name, userMessage] of replacements) {
        const mutated = structuredClone(built.response) as { userMessage: string };
        mutated.userMessage = userMessage;
        assert.deepEqual(
          applyCanonicalEvaluateResponse(built.event, mutated),
          { ok: false, code: "evaluation_response_invalid" },
          `${action} ${name}`,
        );
      }
    }
  });
});
