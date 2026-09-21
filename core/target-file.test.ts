import assert from "node:assert/strict";
import { dirname } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { applyEvaluate, reconstructRewrite } from "./eval-bridge.ts";
import { structuredRewrite, type PrivacyFns } from "./rewrite.ts";
import type { DeviceRecord, PolicyState } from "./schema.ts";
import { loadMonitor } from "./paths.ts";
import { parseHookPayload } from "../src/lib/monitor/ingest.ts";
import { REDACT_TAG, scanCustom, scanSecrets } from "../src/lib/monitor/privacy.ts";

const coreDir = dirname(fileURLToPath(import.meta.url));
const device: DeviceRecord = {
  id: "dev_tf",
  tokenHash: "x",
  hostname: "h",
  ip: "127.0.0.1",
  user: "u",
  os: "win32",
  attachedAt: 0,
  lastSeen: 0,
  lastPolicyVersion: 1,
  capabilities: [],
  agents: [],
};
const policy: PolicyState = {
  version: 1,
  mode: "enforcing",
  customRules: [],
  stopped: false,
  updatedAt: 0,
};
const windows = { apply: (_input: unknown, result: unknown) => result };

const p: PrivacyFns = { REDACT_TAG, scanSecrets, scanCustom };
const idCard = "110101199001011237";
const grokPath = "C:\\Users\\dev\\Desktop\\NMZP\\nmzp-monitor\\core\\hook-protocol.ts";

describe("target_file ingest alias", () => {
  it("maps Grok read_file/write_file/search_replace target_file to filePath", () => {
    const read = parseHookPayload(
      JSON.stringify({
        hookEventName: "pre_tool_use",
        toolName: "read_file",
        toolInput: { target_file: grokPath, limit: 80 },
      }),
    );
    assert.ok(read);
    assert.equal(read!.nativeTool, "read_file");
    assert.equal(read!.filePath, grokPath);
    assert.equal(read!.contents, undefined);

    const write = parseHookPayload(
      JSON.stringify({
        toolName: "write_file",
        toolInput: { target_file: "core/out.ts", contents: "export const x = 1;" },
      }),
    );
    assert.ok(write);
    assert.equal(write!.nativeTool, "write_file");
    assert.equal(write!.filePath, "core/out.ts");
    assert.equal(write!.contents, "export const x = 1;");

    const sr = parseHookPayload(
      JSON.stringify({
        toolName: "search_replace",
        toolInput: { target_file: "core/hook.ts", old_string: "a", new_string: "b" },
      }),
    );
    assert.ok(sr);
    assert.equal(sr!.nativeTool, "search_replace");
    assert.equal(sr!.filePath, "core/hook.ts");
    assert.equal(sr!.contents?.includes("a"), true);
    assert.equal(sr!.contents?.includes("b"), true);
  });

  it("rejects conflicting target_file aliases and accepts matching ones", () => {
    assert.equal(
      parseHookPayload(JSON.stringify({ toolName: "read_file", toolInput: { target_file: "/tmp/a.txt", file_path: "/tmp/b.txt" } })),
      null,
    );
    assert.equal(
      parseHookPayload(JSON.stringify({ toolName: "read_file", toolInput: { target_file: "/tmp/a.txt", filePath: "/tmp/c.txt" } })),
      null,
    );
    assert.equal(
      parseHookPayload(JSON.stringify({ file_path: "/tmp/a.txt", toolInput: { target_file: "/tmp/b.txt" } })),
      null,
    );
    const same = parseHookPayload(
      JSON.stringify({
        toolName: "read_file",
        toolInput: { target_file: "/tmp/a.txt", path: "/tmp/a.txt" },
      }),
    );
    assert.ok(same);
    assert.equal(same!.filePath, "/tmp/a.txt");
  });

  it("does not forge a nested path into the operation target", () => {
    const pld = parseHookPayload(
      JSON.stringify({
        toolName: "read_file",
        toolInput: { target_file: "core/hook.ts", meta: { path: "/etc/shadow" } },
      }),
    );
    assert.ok(pld);
    assert.equal(pld!.filePath, "core/hook.ts");
    assert.notEqual(pld!.filePath, "/etc/shadow");

    const nestedOnly = parseHookPayload(
      JSON.stringify({
        toolName: "read_file",
        toolInput: { meta: { path: "/etc/shadow" } },
      }),
    );
    assert.ok(nestedOnly);
    assert.equal(nestedOnly!.filePath, undefined);
  });
});

describe("target_file rewrite path preservation", () => {
  it("keeps Grok target_file and still privacy-replaces non-path content", () => {
    const write = structuredRewrite({ target_file: grokPath, contents: `id=${idCard}` }, [], p);
    assert.equal(write.ok, true);
    if (write.ok) {
      assert.equal(write.updatedInput.target_file, grokPath);
      assert.equal(write.updatedInput.contents, `id=${REDACT_TAG}`);
    }

    const sr = structuredRewrite(
      { target_file: "core/hook.ts", old_string: idCard, new_string: `x=${idCard}` },
      [],
      p,
    );
    assert.equal(sr.ok, true);
    if (sr.ok) {
      assert.equal(sr.updatedInput.target_file, "core/hook.ts");
      assert.equal(sr.updatedInput.old_string, REDACT_TAG);
      assert.equal(sr.updatedInput.new_string, `x=${REDACT_TAG}`);
    }
  });

  it("does not rewrite target_file into another file; residue still denies", () => {
    const r = structuredRewrite(
      {
        target_file: `/tmp/${idCard}.txt`,
        contents: `id=${idCard}`,
      },
      [],
      p,
    );
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "sensitive_residue");
  });

  it("rewrites nested non-path content without promoting nested path to the op target", () => {
    const r = structuredRewrite(
      {
        target_file: "core/out.ts",
        contents: "ok",
        nested: { path: "/etc/shadow", note: idCard },
      },
      [],
      p,
    );
    assert.equal(r.ok, true);
    if (r.ok) {
      assert.equal(r.updatedInput.target_file, "core/out.ts");
      const nested = r.updatedInput.nested as { path: string; note: string };
      assert.equal(nested.path, "/etc/shadow");
      assert.equal(nested.note, REDACT_TAG);
      assert.notEqual(r.updatedInput.target_file, "/etc/shadow");
    }
  });
});

describe("target_file eval-bridge rewriteSource", () => {
  it("reconstructRewrite keeps target_file and does not inject file_path", () => {
    const write = reconstructRewrite(
      {
        agent: "grok",
        toolName: "write_file",
        toolInput: { target_file: grokPath, contents: `id=${idCard}` },
      },
      [],
      p,
    );
    assert.equal(write.ok, true);
    if (write.ok) {
      assert.equal(write.updatedInput.target_file, grokPath);
      assert.equal("file_path" in write.updatedInput, false);
      assert.equal("filePath" in write.updatedInput, false);
      assert.equal(write.updatedInput.contents, `id=${REDACT_TAG}`);
    }

    const sr = reconstructRewrite(
      {
        agent: "grok",
        toolName: "search_replace",
        toolInput: { target_file: "core/hook.ts", old_string: "x", new_string: `id=${idCard}` },
      },
      [],
      p,
    );
    assert.equal(sr.ok, true);
    if (sr.ok) {
      assert.equal(sr.updatedInput.target_file, "core/hook.ts");
      assert.equal("file_path" in sr.updatedInput, false);
      assert.equal(sr.updatedInput.new_string, `id=${REDACT_TAG}`);
    }
  });

  it("applyEvaluate rewrite keeps Grok target_file without adding file_path", async () => {
    const monitor = await loadMonitor(coreDir);
    const body = {
      eventId: "tf-write",
      sessionId: "s",
      agent: "grok" as const,
      toolName: "write_file",
      toolInput: { target_file: grokPath, contents: `id=${idCard}` },
    };
    const bridged = reconstructRewrite(body, policy.customRules, {
      REDACT_TAG: monitor.privacy.REDACT_TAG as string,
      scanSecrets: monitor.privacy.scanSecrets,
      scanCustom: monitor.privacy.scanCustom,
      cloakPersona: monitor.privacy.cloakPersona,
      shouldCloakPersona: monitor.privacy.shouldCloakPersona,
    });
    assert.equal(bridged.ok, true);
    if (bridged.ok) {
      assert.equal(bridged.updatedInput.target_file, grokPath);
      assert.equal("file_path" in bridged.updatedInput, false);
      assert.equal(bridged.updatedInput.contents, `id=${REDACT_TAG}`);
    }

    const out = applyEvaluate({
      monitor,
      windows,
      policy,
      device,
      body,
      eventId: "tf-write",
    });
    assert.notEqual(out.response.reason, "conflicting_aliases");
    assert.equal(out.hookDeny, false);
    if (out.response.updatedInput) {
      assert.equal(out.response.updatedInput.target_file, grokPath);
      assert.equal("file_path" in out.response.updatedInput, false);
      assert.equal(String(out.response.updatedInput.contents).includes(idCard), false);
    }
  });
});

