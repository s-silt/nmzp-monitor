// Real offline hook oracle. The fixture-only observer delegates to the unchanged
// evaluator; it never constructs EvalInput, evaluates an alternate input, or changes
// production source. runHook -> applyEvaluate -> resolveEvalBody/buildEvalInput owns it.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const hookBytes = (result) => ({
  stdout: result.stdout,
  stderr: result.stderr ?? "",
  exitCode: result.exitCode,
});
const root = fileURLToPath(new URL("../../", import.meta.url));
const enginePath = "src/lib/monitor/engine.ts";
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");

export async function createRealHookOracle() {
  const fixture = await mkdtemp(join(tmpdir(), "nmzp-real-hook-oracle-"));
  const original = await readFile(join(root, enginePath), "utf8");
  try {
    await cp(join(root, "core"), join(fixture, "core"), { recursive: true });
    await mkdir(join(fixture, "src", "lib"), { recursive: true });
    await cp(join(root, "src", "lib", "monitor"), join(fixture, "src", "lib", "monitor"), {
      recursive: true,
    });
    await cp(join(root, "package.json"), join(fixture, "package.json"));
    await mkdir(join(fixture, "node_modules"), { recursive: true });
    await cp(join(root, "node_modules", "acorn"), join(fixture, "node_modules", "acorn"), {
      recursive: true,
    });
    const needle = "export function evaluate(";
    assert.equal(original.split(needle).length, 2, "unique real evaluator observer anchor");
    const observed =
      original.replace(needle, "function oracleOriginalEvaluate(") +
      `
// Fixture-only transparent observer; the original evaluator above is unchanged.
const oracleObservations: Array<{ input: unknown; result: unknown }> = [];
export function evaluate(...args: Parameters<typeof oracleOriginalEvaluate>): ReturnType<typeof oracleOriginalEvaluate> {
  const result = oracleOriginalEvaluate(...args);
  oracleObservations.push({ input: structuredClone(args[0]), result: structuredClone(result) });
  return result;
}
export function takeOracleObservations() { return oracleObservations.splice(0); }
`;
    await writeFile(join(fixture, enginePath), observed);
    const { runHook } = await import(pathToFileURL(join(fixture, "core", "hook.ts")).href);
    const { writePolicyCache } = await import(
      pathToFileURL(join(fixture, "core", "policy-cache.ts")).href
    );
    const { takeOracleObservations } = await import(pathToFileURL(join(fixture, enginePath)).href);
    let packedDir;
    return {
      async run(stdin, agent) {
        const home = await mkdtemp(join(fixture, "home-"));
        try {
          takeOracleObservations();
          await writePolicyCache(join(home, ".nmzp", "policy-cache.json"), {
            version: 1,
            mode: "enforcing",
            stopped: false,
            customRules: [],
            updatedAt: 1,
          });
          // No credentials => offline only. Every case gets fresh session state.
          const hook = await runHook({
            argv: ["--agent", agent],
            stdin,
            home,
            coreDir: join(fixture, "core"),
            now: 1,
            env: {},
          });
          const observations = takeOracleObservations();
          assert.ok(observations.length <= 1, "one real engine call per hook fixture");
          return { hook, ...observations[0], evaluated: observations.length === 1 };
        } finally {
          await rm(home, { recursive: true, force: true });
        }
      },
      async packed(item, stdin) {
        // Byte-limit handling and bootstrap failures belong to the real packed
        // entrypoint/hookMain, not runHook (whose input is already a JS string).
        if (!packedDir) {
          const { packRelease } = await import("../../scripts/release-archive.mjs");
          const packRoot = join(fixture, "packed-source");
          await cp(join(root, "core"), join(packRoot, "core"), { recursive: true });
          await cp(join(root, "src", "lib", "monitor"), join(packRoot, "src", "lib", "monitor"), {
            recursive: true,
          });
          await cp(join(root, "dist"), join(packRoot, "dist"), { recursive: true });
          packedDir = (await packRelease(packRoot)).dir;
        }
        const home = await mkdtemp(join(fixture, "packed-home-"));
        let broken;
        try {
          await writePolicyCache(join(home, ".nmzp", "policy-cache.json"), {
            version: 1,
            mode: "enforcing",
            stopped: false,
            customRules: [],
            updatedAt: 1,
          });
          let entry = join(packedDir, "nmzp.mjs");
          if (item.kind === "bootstrap") {
            broken = await mkdtemp(join(fixture, "broken-runtime-"));
            await cp(packedDir, broken, { recursive: true });
            await writeFile(join(broken, "nmzp-main.cjs"), "throw new Error('bootstrap');\n");
            entry = join(broken, "nmzp.mjs");
          }
          const env = { ...process.env, HOME: home, USERPROFILE: home, NODE_OPTIONS: "" };
          for (const key of Object.keys(env)) {
            if (/^(GROK_|CLAUDE_|CURSOR_|CODEX_|ZCODE_|GEMINI_|NMZP_)/.test(key)) delete env[key];
          }
          delete env.NODE_TEST_CONTEXT;
          env.NMZP_HOME = home;
          const child = spawnSync(
            process.execPath,
            ["--experimental-strip-types", entry, ...item.argv],
            {
              env,
              input: stdin,
              encoding: "utf8",
              timeout: 15000,
              maxBuffer: 1024 * 1024,
              windowsHide: true,
            },
          );
          assert.equal(child.error, undefined, `${item.id}: packed hook must terminate`);
          assert.equal(child.signal, null);
          return { stdout: child.stdout, stderr: child.stderr, exitCode: child.status };
        } finally {
          if (broken) await rm(broken, { recursive: true, force: true });
          await rm(home, { recursive: true, force: true });
        }
      },
      async close() {
        assert.equal(
          hash(await readFile(join(root, enginePath))),
          hash(original),
          "oracle never changes checkout engine",
        );
        await rm(fixture, { recursive: true, force: true });
      },
    };
  } catch (error) {
    await rm(fixture, { recursive: true, force: true });
    throw error;
  }
}
