import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, test } from "node:test";
import { fileURLToPath } from "node:url";
import { checkContract } from "./check-error-codes.mjs";

const repo = dirname(dirname(fileURLToPath(import.meta.url)));

function openapi(members) {
  const lines = ["", "    ErrorCode:", "      oneOf:"];
  for (const member of members) {
    lines.push(`        - const: ${member.name}`);
    if (member.description !== undefined) lines.push(`          description: ${member.description}`);
    if (member.remediation !== undefined) lines.push(`          x-remediation: ${member.remediation}`);
  }
  lines.push("    NextSchema:");
  return `${lines.join("\n")}\n`;
}

function envelope(codes) {
  return `${JSON.stringify({
    properties: { error: { properties: { code: { enum: codes } } } },
  })}\n`;
}

async function withFixture(run) {
  const root = await mkdtemp(join(tmpdir(), "nmzp-lint-contract-"));
  try {
    await mkdir(join(root, "contract", "protocol", "schemas"), { recursive: true });
    await mkdir(join(root, "core"), { recursive: true });
    await run(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

async function writeContract(root, members, codes) {
  await writeFile(join(root, "contract", "protocol", "openapi.yaml"), openapi(members));
  await writeFile(join(root, "contract", "protocol", "schemas", "error-envelope.schema.json"), envelope(codes));
}

const KNOWN = { name: "bad_json", description: "not json", remediation: "send json" };

describe("lint:contract", () => {
  test("the repository contract passes, including generated types", () => {
    const result = checkContract(repo);
    assert.equal(result.ok, true, result.errors.join("\n"));
  });

  test("a known literal code passes", async () => {
    await withFixture(async (root) => {
      await writeContract(root, [KNOWN], ["bad_json"]);
      await writeFile(join(root, "core", "ok.ts"), 'v2Error("bad_json");\n');
      const result = checkContract(root, { skipTypes: true });
      assert.equal(result.ok, true, result.errors.join("\n"));
    });
  });

  test("an unknown literal code fails", async () => {
    await withFixture(async (root) => {
      await writeContract(root, [KNOWN], ["bad_json"]);
      await writeFile(join(root, "core", "bad.ts"), 'v2Error("not_a_code");\n');
      const result = checkContract(root, { skipTypes: true });
      assert.equal(result.ok, false);
      assert.match(result.errors.join("\n"), /not an ErrorCode/);
    });
  });

  test("a non-literal code fails", async () => {
    await withFixture(async (root) => {
      await writeContract(root, [KNOWN], ["bad_json"]);
      await writeFile(join(root, "core", "dynamic.ts"), 'const code = "bad_json";\nv2Error(code);\n');
      const result = checkContract(root, { skipTypes: true });
      assert.equal(result.ok, false);
      assert.match(result.errors.join("\n"), /must be a string literal/);
    });
  });

  test("a member without x-remediation fails", async () => {
    await withFixture(async (root) => {
      await writeContract(root, [{ name: "bad_json", description: "not json" }], ["bad_json"]);
      const result = checkContract(root, { skipTypes: true });
      assert.equal(result.ok, false);
      assert.match(result.errors.join("\n"), /bad_json is missing x-remediation/);
    });
  });

  test("a code enum that differs in order fails", async () => {
    await withFixture(async (root) => {
      await writeContract(
        root,
        [
          { name: "bad_json", description: "not json", remediation: "send json" },
          { name: "unauthorized", description: "auth", remediation: "send a token" },
        ],
        ["unauthorized", "bad_json"],
      );
      const result = checkContract(root, { skipTypes: true });
      assert.equal(result.ok, false);
      assert.match(result.errors.join("\n"), /out of sync/);
    });
  });
});
