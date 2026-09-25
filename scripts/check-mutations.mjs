// Mutate a temp copy, then run the repository test. The checkout is never written.
// M20-15 is not in this table. Removing the commit() catch ROLLBACK in
// core/policy/history.ts is semantically equivalent: #withDb opens a
// DatabaseSync per operation and closes it in finally, which rolls back an
// uncommitted transaction. Durable state and the next writer match the
// explicit ROLLBACK. Do not assert on the ROLLBACK source text.
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { cp, mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const repo = join(dirname(fileURLToPath(import.meta.url)), "..");
const COPY_DIRS = ["core", "src", "tests", "scripts"];
const COPY_FILES = ["package.json", "tsconfig.json"];

const tlsBlock = (mode) =>
  [
    `    await writeFile(keyPath, material.keyPem, { mode: ${mode} });`,
    `    await writeFile(certPath, material.certPem, { mode: ${mode} });`,
    "    await writeFile(",
    "      pinPath,",
    "      JSON.stringify({ fingerprintSha256: material.fingerprintSha256, hosts: material.hosts }, null, 2),",
    `      { mode: ${mode} },`,
    "    );",
  ].join("\r\n");

const mutants = [
  {
    id: "M20-01",
    source: "core/admin-proxy.ts",
    oldText: "if (!token || !safeEqualStr(token, opts.adminToken)) {",
    newText: "if (!token) {",
    testFile: "core/admin-proxy.test.ts",
    target: "rejects a wrong admin token on POST /api/v1/session",
  },
  {
    id: "M20-02",
    source: "core/hook.ts",
    oldText: 'return stamped(deny(agent, "no_policy_cache", argMap));',
    newText: 'return stamped(pass(agent, "no_policy_cache", undefined, argMap));',
    testFile: "core/hook.test.ts",
    target: "denies a Bash-class tool with no policy cache",
  },
  {
    id: "M20-03a",
    source: "core/hook.ts",
    oldText: 'if (status === 401 || status === 403) return { action: "deny", reason: "unauthorized", evaluation: "block" };',
    newText:
      'if (status === 401) return { action: "fallback" };\r\n  if (status === 403) return { action: "deny", reason: "unauthorized", evaluation: "block" };',
    testFile: "core/hook.test.ts",
    target: "401 from the evaluate server is deny not cache fallback",
  },
  {
    id: "M20-03b",
    source: "core/hook.ts",
    oldText: 'if (status === 401 || status === 403) return { action: "deny", reason: "unauthorized", evaluation: "block" };',
    newText:
      'if (status === 401) return { action: "deny", reason: "unauthorized", evaluation: "block" };\r\n  if (status === 403) return { action: "fallback" };',
    testFile: "core/hook.test.ts",
    target: "403 from the evaluate server is deny not cache fallback",
  },
  {
    id: "M20-04a",
    source: "core/hook.ts",
    oldText: 'if (status === 413) return { action: "deny", reason: "payload_too_large", evaluation: "block" };',
    newText: 'if (status === 413) return { action: "fallback" };',
    testFile: "core/hook.test.ts",
    target: "413 from the evaluate server is deny not cache fallback",
  },
  {
    id: "M20-04b",
    source: "core/hook.ts",
    oldText: 'if (status === 409) return { action: "deny", reason: "event_conflict", evaluation: "block" };',
    newText: 'if (status === 409) return { action: "fallback" };',
    testFile: "core/hook.test.ts",
    target: "409 from the evaluate server is deny not cache fallback",
  },
  {
    id: "M20-05",
    source: "core/hook.ts",
    oldText: 'if (opts.stdin.length > BODY_LIMIT) return failStatus("payload_too_large");',
    newText: 'if (false && opts.stdin.length > BODY_LIMIT) return failStatus("payload_too_large");',
    testFile: "core/hook.test.ts",
    target: "denies valid JSON stdin over the hook body limit",
  },
  {
    id: "M20-06",
    source: "core/http-util.ts",
    oldText: "if (!abs.startsWith(normalize(uiDir) + sep) && abs !== normalize(uiDir)) return false;",
    newText: "if (false) return false;",
    testFile: "core/http-util.test.ts",
    target: "does not serve files outside the static root via dot-dot traversal",
  },
  {
    id: "M20-07",
    source: "core/audit/store.ts",
    oldText: 'if (createHash("sha256").update(bytes).digest("hex") !== row.body_hash) throw new Error("audit_corrupt");',
    newText: 'if (false && createHash("sha256").update(bytes).digest("hex") !== row.body_hash) throw new Error("audit_corrupt");',
    testFile: "core/audit/store.test.mjs",
    target: "rejects a decodable body whose hash does not match",
  },
  {
    id: "M20-08",
    source: "core/audit/store.ts",
    oldText: "if (ev.id !== row.id || ev.machineId !== row.machine_id || ev.ts !== row.ts || ev.policyVersion !== row.policy_version) {",
    newText: "if (ev.id !== row.id || ev.machineId !== row.machine_id) {",
    testFile: "core/audit/store.test.mjs",
    target: "rejects a decodable body when ts or policyVersion differs",
  },
  {
    id: "M20-09",
    source: "core/audit/outbox.ts",
    oldText: "const acknowledged=result.status===200 && result.body.ok===true && result.body.eventId===item.eventId;",
    newText: "const acknowledged=result.status===200 && result.body.ok===true;",
    testFile: "core/audit/outbox.test.mjs",
    target: "does not accept an acknowledgement carrying a different eventId",
  },
  {
    id: "M20-10",
    source: "core/audit/outbox.ts",
    oldText: "if([401,403,409].includes(result.status)){state.items.splice(index,1);state.quarantined++;return;}",
    newText: "if(false && [401,403,409].includes(result.status)){state.items.splice(index,1);state.quarantined++;return;}",
    testFile: "core/audit/outbox.test.mjs",
    target: "quarantines an outbox item when the server returns",
  },
  {
    id: "M20-11",
    source: "core/admin-proxy.ts",
    oldText: "if (!exp || exp < Date.now()) {",
    newText: "if (!exp) {",
    testFile: "core/admin-proxy.test.ts",
    target: "rejects an expired proxy session",
  },
  {
    id: "M20-12",
    source: "src/lib/monitor/self-protection.ts",
    oldText: "      stack.pop();",
    newText: "",
    testFile: "core/self-protection.test.ts",
    target: "protects a home install path that climbs through dot-dot",
  },
  {
    id: "M20-13",
    source: "core/model-gateway.ts",
    oldText: "if (code >= 300 && code < 400) {",
    newText: "if (code === 302) {",
    testFile: "core/model-gateway.test.ts",
    target: "does not follow upstream 301, 303, 307, or 308 or leak Location",
  },
  {
    id: "M20-14a",
    source: "core/install-fs.ts",
    oldText: "chmodSync(target, st.isDirectory() ? 0o700 : 0o600);",
    newText: "chmodSync(target, st.isDirectory() ? 0o755 : 0o644);",
    testFile: "core/install-fs.test.ts",
    target: "restrictPath clears group and other permission bits",
    platform: "posix",
  },
  {
    id: "M20-14b",
    source: "core/tls.ts",
    oldText: tlsBlock("0o600"),
    newText: tlsBlock("0o644"),
    testFile: "core/tls.test.ts",
    target: "writes tls key, cert, and pin without group or other permissions",
    platform: "posix",
  },
  {
    id: "backfill-extra-fields",
    source: "core/audit/backfill.ts",
    oldText: '!keys(raw,["kind","eventId","payload"])',
    newText: "false",
    testFile: "core/audit/backfill.test.mjs",
    target: "rejects an envelope with extra top-level fields",
  },
  {
    id: "M20-16",
    source: "core/audit/backfill.ts",
    oldText: '!keys(raw,["kind","eventId","payload"])',
    newText: "false",
    testFile: "core/audit/backfill.test.mjs",
    target: "rejects an envelope with extra top-level fields",
  },
  {
    id: "M20-17a",
    source: "src/lib/monitor/overrides.ts",
    oldText: "if (ex.expiresAt !== undefined && ex.expiresAt <= now) continue;",
    newText: "if (ex.expiresAt !== undefined && ex.expiresAt < now) continue;",
    testFile: "src/lib/monitor/policy-overrides.test.ts",
    target: "treats an exemption expiring at the current instant as expired",
  },
  {
    id: "M20-17b",
    source: "src/lib/monitor/correlate.ts",
    oldText: "const next = [...(prev ?? []).filter((h) => h.ts >= cut), hit];",
    newText: "const next = [...(prev ?? []).filter((h) => h.ts > cut), hit];",
    testFile: "src/lib/monitor/guard.test.ts",
    target: "retains a pushHit exactly on the correlate window boundary",
  },
  {
    id: "compression-without-benefit",
    source: "core/audit/json-codec.ts",
    oldText: "compressed.length < rawBytes && rawBytes - compressed.length >= minSavings",
    newText: "true",
    testFile: "core/audit/json-codec.test.ts",
    target: "retains plain JSON when compression does not meet savings threshold",
  },
  {
    id: "policy-pointer",
    source: "core/policy/history.ts",
    oldText: 'db.prepare("UPDATE policy_current SET version=? WHERE singleton=1").run(next.policy.version);',
    newText: "/* mutant omits current pointer update */",
    testFile: "core/policy/history.test.mjs",
    target: "commits current pointer and immutable history in one transaction across reopen",
  },
];

const INVALID = /SyntaxError|ERR_MODULE_NOT_FOUND|ERR_UNKNOWN_FILE_EXTENSION|Cannot find module|Cannot find package|ERR_TEST_TIMEOUT|failureType:\s*'testTimeout'|failureType:\s*'cancelled'|cancelledByParent|timed out after/;

function posixSkipped(mutant) {
  return mutant.platform === "posix" && process.platform === "win32";
}

function timeoutFor(file) {
  if (file.endsWith("model-gateway.test.ts") || file.endsWith("guard.test.ts")) return 300_000;
  if (file.endsWith("policy-overrides.test.ts") || file.endsWith("self-protection.test.ts")) return 240_000;
  return 180_000;
}

function cleanEnv() {
  const env = { ...process.env };
  for (const key of Object.keys(env)) {
    if (key.startsWith("NODE_TEST_") || key === "NODE_CHANNEL_FD" || key === "NMZP_TEST_REAL_ACL") delete env[key];
  }
  return env;
}

function tapFailures(output) {
  const lines = output.split(/\r?\n/);
  const items = [];
  for (let i = 0; i < lines.length; i++) {
    const matched = /^(\s*)not ok\s+\d+\s+-\s(.*)$/.exec(lines[i]);
    if (!matched) continue;
    let yaml = "";
    let cursor = i + 1;
    if (cursor < lines.length && /^\s+---\s*$/.test(lines[cursor])) {
      const yamlLines = [];
      cursor += 1;
      for (; cursor < lines.length; cursor++) {
        if (/^\s+\.\.\.\s*$/.test(lines[cursor])) break;
        yamlLines.push(lines[cursor]);
      }
      yaml = yamlLines.join("\n");
    }
    items.push({ title: matched[2].trim(), yaml });
  }
  return items;
}

function classify(exitCode, output, target, timedOut) {
  if (timedOut) return { status: "invalid", detected: false, reason: "timeout" };
  const leaves = tapFailures(output).filter((item) => item.title.includes(target) && !/type:\s*'suite'/.test(item.yaml));
  const assertion = leaves.find((item) => /ERR_ASSERTION|AssertionError/.test(item.yaml) && !INVALID.test(item.yaml));
  if (exitCode !== 0 && assertion) return { status: "detected", detected: true, reason: "target_assertion" };
  if (INVALID.test(output)) return { status: "invalid", detected: false, reason: "syntax_import_timeout_or_cancel" };
  return { status: "survived", detected: false, reason: exitCode === 0 ? "exit_0" : "no_target_assertion" };
}

function killTree(child) {
  if (!child.pid) return;
  if (process.platform === "win32") {
    spawn("taskkill", ["/PID", String(child.pid), "/T", "/F"], { windowsHide: true, stdio: "ignore" });
    return;
  }
  try {
    process.kill(-child.pid, "SIGKILL");
  } catch {
    child.kill("SIGKILL");
  }
}

function runNodeTest(root, file, timeoutMs) {
  return new Promise((resolve) => {
    const child = spawn(
      process.execPath,
      ["--experimental-strip-types", "--test", "--test-reporter=tap", "--test-concurrency=1", file],
      {
        cwd: root,
        env: cleanEnv(),
        windowsHide: true,
        detached: process.platform !== "win32",
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    let output = "";
    let timedOut = false;
    const take = (chunk) => {
      if (output.length < 8_000_000) output += chunk.toString("utf8");
    };
    child.stdout.on("data", take);
    child.stderr.on("data", take);
    const timer = setTimeout(() => {
      timedOut = true;
      killTree(child);
    }, timeoutMs);
    child.on("error", (error) => {
      clearTimeout(timer);
      resolve({ exitCode: 1, output: `${output}\n${error.message}`, timedOut: false });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ exitCode: timedOut ? null : code, output, timedOut });
    });
  });
}

function resolveSpec(fromFile, spec) {
  if (!spec.startsWith(".")) return null;
  const base = join(dirname(fromFile), spec);
  const candidates = [base, `${base}.ts`, `${base}.tsx`, `${base}.mjs`, `${base}.js`, `${base}.json`, join(base, "index.ts")];
  return candidates.find((candidate) => existsSync(candidate)) ?? base;
}

async function inventory(files) {
  const pending = files.map((file) => join(repo, file));
  const seen = new Set();
  const outside = [];
  const importRe = /(?:from\s+|import\s*\(\s*|import\s+)["']([^"']+)["']/g;
  while (pending.length) {
    const file = pending.pop();
    if (!file || seen.has(file) || !existsSync(file)) continue;
    seen.add(file);
    const text = await readFile(file, "utf8");
    for (const match of text.matchAll(importRe)) {
      const spec = match[1];
      if (!spec.startsWith(".")) continue;
      const resolved = resolveSpec(file, spec);
      if (!resolved || !existsSync(resolved)) {
        outside.push(`${relative(repo, file)} -> ${spec}`);
        continue;
      }
      const rel = relative(repo, resolved);
      if (rel.startsWith("..") || rel.split(sep).some((part) => part === "node_modules")) {
        outside.push(rel);
        continue;
      }
      const rooted = COPY_DIRS.some((dir) => rel === dir || rel.startsWith(`${dir}${sep}`) || rel.startsWith(`${dir}/`));
      if (!rooted) outside.push(rel);
      else pending.push(resolved);
    }
  }
  if (outside.length) throw new Error(`test import is outside the copied layout: ${[...new Set(outside)].join(", ")}`);
}

async function copyLayout(root) {
  await inventory([...new Set(mutants.filter((mutant) => !posixSkipped(mutant)).map((mutant) => mutant.testFile))]);
  for (const dir of COPY_DIRS) await cp(join(repo, dir), join(root, dir), { recursive: true });
  for (const file of COPY_FILES) {
    if (existsSync(join(repo, file))) await cp(join(repo, file), join(root, file));
  }
  const extras = await readdir(repo);
  for (const name of extras) {
    if (!name.startsWith("tsconfig.") || name === "tsconfig.json" || !name.endsWith(".json")) continue;
    await cp(join(repo, name), join(root, name));
  }
  await symlink(join(repo, "node_modules"), join(root, "node_modules"), process.platform === "win32" ? "junction" : "dir");
}

async function main() {
  const root = await mkdtemp(join(tmpdir(), "nmzp-mutations-"));
  const baselines = [];
  const outcomes = [];
  try {
    await copyLayout(root);
    const groups = new Map();
    for (const mutant of mutants) {
      if (posixSkipped(mutant)) {
        outcomes.push({
          id: mutant.id,
          source: mutant.source,
          testFile: mutant.testFile,
          target: mutant.target,
          status: "unexercised",
          detected: false,
          exitCode: null,
          reason: "posix_only",
        });
        continue;
      }
      const list = groups.get(mutant.testFile) ?? [];
      list.push(mutant);
      groups.set(mutant.testFile, list);
    }
    for (const [file, list] of groups) {
      const timeoutMs = Math.max(...list.map((mutant) => timeoutFor(mutant.testFile)));
      const baseline = await runNodeTest(root, file, timeoutMs);
      const baselineOk = baseline.exitCode === 0 && !baseline.timedOut;
      baselines.push({ file, exitCode: baseline.exitCode, status: baselineOk ? "pass" : "fail", timedOut: baseline.timedOut });
      for (const mutant of list) {
        const row = {
          id: mutant.id,
          source: mutant.source,
          testFile: mutant.testFile,
          target: mutant.target,
          status: "invalid",
          detected: false,
          exitCode: null,
          reason: "baseline_failure",
        };
        if (!baselineOk) {
          outcomes.push(row);
          continue;
        }
        const sourcePath = join(root, mutant.source);
        const original = await readFile(sourcePath, "utf8");
        const count = original.split(mutant.oldText).length - 1;
        if (count !== 1) {
          row.reason = "target_not_unique";
          outcomes.push(row);
          continue;
        }
        await writeFile(sourcePath, original.replace(mutant.oldText, mutant.newText));
        try {
          const run = await runNodeTest(root, mutant.testFile, timeoutMs);
          const verdict = classify(run.exitCode, run.output, mutant.target, run.timedOut);
          outcomes.push({ ...row, ...verdict, exitCode: run.exitCode });
        } finally {
          await writeFile(sourcePath, original);
        }
      }
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
  const ordered = mutants.map((mutant) => outcomes.find((row) => row.id === mutant.id));
  const summary = { platform: process.platform, baselines, outcomes: ordered };
  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
  const baselineFailed = baselines.some((row) => row.status !== "pass");
  const undetected = ordered.some((row) => row.status !== "unexercised" && row.detected !== true);
  if (baselineFailed || undetected) process.exitCode = 1;
}

await main();
