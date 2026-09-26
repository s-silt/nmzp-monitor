import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { it } from "node:test";
import { NMZP_VERSION } from "../../../core/constants.ts";
import * as hookConfig from "./hooks-config.ts";

const packageJson: { version: string } = JSON.parse(
  readFileSync(new URL("../../../package.json", import.meta.url), "utf8"),
);
const packageVersion = packageJson.version;

function serializedExport(value: unknown): string {
  if (typeof value === "string") return value;
  const text = JSON.stringify(value);
  if (typeof text !== "string") assert.fail("exported example did not serialize");
  return text;
}

it("hook config examples reference the current package runtime version", () => {
  let runtimePaths = 0;
  for (const [name, value] of Object.entries(hookConfig)) {
    const serialized = serializedExport(value);
    assert.equal(
      serialized.includes("runtime/0.1.0") || serialized.includes("runtime\\0.1.0"),
      false,
      `${name} contains stale runtime/0.1.0`,
    );
    for (const found of serialized.matchAll(/runtime[/\\]([^/\\]+)[/\\]nmzp\.mjs/g)) {
      runtimePaths += 1;
      assert.equal(found[1], packageVersion, `${name} runtime path version`);
    }
    if (serialized.includes("nmzp.mjs hook")) {
      const forward = `runtime/${packageVersion}/nmzp.mjs`;
      const backward = `runtime\\${packageVersion}\\nmzp.mjs`;
      assert.equal(
        serialized.includes(forward) || serialized.includes(backward),
        true,
        `${name} runtime path must use package version ${packageVersion}`,
      );
    }
  }
  assert.ok(runtimePaths > 0, "examples include a versioned runtime path");
});

it("core NMZP_VERSION matches package.json version", () => {
  assert.equal(NMZP_VERSION, packageVersion);
});

it("hook config module stays browser-safe", () => {
  const hookSrc = readFileSync(new URL("./hooks-config.ts", import.meta.url), "utf8");
  const constantsSrc = readFileSync(new URL("../../../core/constants.ts", import.meta.url), "utf8");
  const specifiers = [
    ...hookSrc.matchAll(/(?:\bfrom\s*|\bimport\s*\(\s*|\bimport\s+)["']([^"']+)["']/g),
  ].map((match) => match[1] ?? "");
  for (const spec of specifiers) {
    const parts = spec.split(/[/\\]/);
    if (parts.includes("core")) assert.equal(spec, "../../../core/constants.ts");
  }
  assert.doesNotMatch(constantsSrc, /^\s*import\s/m);
});
