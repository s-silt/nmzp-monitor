import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { existsSync, readFileSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { load as parseWorkflowYaml } from "js-yaml";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, test } from "node:test";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const CHECKOUT = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262";
const SETUP_NODE = "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020";
const STABILITY_PATHS = [
  "core/audit/**",
  "core/schema.ts",
  "scripts/run-stability-tests.mjs",
  ".github/workflows/core-stability.yml",
];
const silent = { write() {} };
const SELF_EXPIRE_MS = 15_000;

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function processAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error.code !== "ESRCH";
  }
}

async function stopped(pid) {
  const start = Date.now();
  while (Date.now() - start < 1_500) {
    if (!processAlive(pid)) return true;
    await delay(50);
  }
  return !processAlive(pid);
}

const TREE_FIXTURE = [
  "import { spawn } from 'node:child_process';",
  "import { writeFileSync } from 'node:fs';",
  "const grand = spawn(process.execPath, ['-e', 'setTimeout(() => process.exit(0), 15000)'], { stdio: 'ignore', windowsHide: true });",
  "writeFileSync(process.argv[2], JSON.stringify({ parent: process.pid, grand: grand.pid }));",
  "setTimeout(() => process.exit(0), 15000);",
  "",
].join("\n");

function readRepo(rel, label) {
  const path = join(root, rel);
  assert.equal(existsSync(path), true, label);
  return readFileSync(path, "utf8");
}

function loadQuality() {
  return readRepo(".github/workflows/quality.yml", "quality workflow is required");
}

async function loadPreflight() {
  assert.equal(existsSync(join(root, "scripts/release-preflight.mjs")), true, "scripts/release-preflight.mjs is required");
  const mod = await import("./release-preflight.mjs");
  assert.equal(typeof mod.runReleasePreflight, "function", "runReleasePreflight is required");
  assert.equal(typeof mod.defaultSpawn, "function", "defaultSpawn is required");
  assert.equal(typeof mod.resolveNpmLaunch, "function", "resolveNpmLaunch is required");
  return mod;
}

describe("quality gates", { concurrency: false }, () => {
  test("quality workflow is required", () => {
    const doc = parseWorkflowYaml(loadQuality());
    assert.ok(doc.jobs && Object.hasOwn(doc.jobs, "quality"), "quality job is required");
  });

  test("workflow parser retains path filters", () => {
    const filtered = parseWorkflowYaml(
      [
        "on:",
        "  pull_request:",
        "    paths:",
        "      - 'core/hook.ts'",
        "  push:",
        "    branches: [main]",
        "    paths-ignore:",
        "      - 'docs/**'",
        "  workflow_dispatch:",
        "jobs:",
        "  sample:",
        "    steps:",
        "      - name: Run",
        "        run: |",
        "          node --version",
        "          npm test",
      ].join("\n"),
    );
    assert.deepEqual(filtered.on.pull_request.paths, ["core/hook.ts"]);
    assert.deepEqual(filtered.on.push.branches, ["main"]);
    assert.deepEqual(filtered.on.push["paths-ignore"], ["docs/**"]);
    assert.equal(filtered.on.workflow_dispatch, null);
    assert.equal(filtered.jobs.sample.steps[0].run, "node --version\nnpm test\n");
  });

  test("quality workflow has no path, branch, or tag filter", () => {
    const text = loadQuality();
    const onAt = text.indexOf("\non:");
    const permissionsAt = text.indexOf("\npermissions:");
    assert.ok(onAt !== -1 && permissionsAt > onAt, "quality workflow is required");
    const onBlock = text.slice(onAt + 1, permissionsAt);
    assert.doesNotMatch(onBlock, /^\s*(paths|paths-ignore|branches|branches-ignore|tags|tags-ignore)\s*:/m);
    assert.deepEqual(parseWorkflowYaml(text).on, {
      pull_request: null,
      push: null,
      workflow_dispatch: {
        inputs: {
          baseline: {
            description: "Full 40-hex trusted baseline commit; empty uses merge-base with origin/<default branch>",
            required: false,
            default: "",
            type: "string",
          },
        },
      },
    });
  });

  test("quality workflow pins the Node 24 Linux and Windows matrix", () => {
    const text = loadQuality();
    const stability = readRepo(".github/workflows/core-stability.yml", "narrow stability workflow is required");
    const doc = parseWorkflowYaml(text);
    const job = doc.jobs.quality;
    assert.equal(doc.name, "Quality");
    assert.deepEqual(Object.keys(doc).sort(), ["concurrency", "jobs", "name", "on", "permissions"]);
    assert.deepEqual(doc.permissions, { contents: "read" });
    assert.deepEqual(doc.concurrency, {
      group: "quality-${{ github.workflow }}-${{ github.ref }}",
      "cancel-in-progress": true,
    });
    assert.deepEqual(Object.keys(doc.jobs), ["quality"]);
    assert.equal(job.name, "Quality / ${{ matrix.os }} / Node 24");
    assert.deepEqual(job.strategy, {
      "fail-fast": false,
      matrix: { os: ["ubuntu-latest", "windows-latest"] },
    });
    assert.equal(job["runs-on"], "${{ matrix.os }}");
    assert.equal(job["timeout-minutes"], 30);
    assert.deepEqual(Object.keys(job).sort(), ["if", "name", "runs-on", "steps", "strategy", "timeout-minutes"]);
    assert.equal(job.if, "github.event_name != 'push' || github.event.deleted != true");
    assert.equal(job.steps[0].uses, CHECKOUT);
    assert.equal(job.steps[1].uses, SETUP_NODE);
    assert.ok(stability.includes(`${CHECKOUT} # v4`), "checkout pin is copied from the stability workflow");
    assert.ok(stability.includes(`${SETUP_NODE} # v4`), "setup-node pin is copied from the stability workflow");
    assert.ok(text.includes(`${CHECKOUT} # v4`));
    assert.ok(text.includes(`${SETUP_NODE} # v4`));
  });

  test("quality workflow runs the required checks without publish permissions", () => {
    const text = loadQuality();
    const steps = parseWorkflowYaml(text).jobs.quality.steps;
    const allowed = new Set(["name", "uses", "run", "with", "env", "if"]);
    for (const step of steps) {
      for (const key of Object.keys(step)) assert.ok(allowed.has(key), `unexpected step key ${key}`);
    }
    const fetchDefaultBranch =
      "node --input-type=commonjs -e \"const {spawnSync}=require('node:child_process'); const branch=process.env.NMZP_DEFAULT_BRANCH||''; if(!branch){console.error('default branch missing'); process.exit(1);} const have=spawnSync('git',['rev-parse','--verify','--end-of-options','refs/remotes/origin/'+branch+'^{commit}'],{stdio:'ignore'}); if(have.status===0) process.exit(0); const fetched=spawnSync('git',['fetch','--no-tags','origin',branch],{stdio:'inherit'}); process.exit(fetched.status===0?0:fetched.status||1);\"";
    assert.deepEqual(
      steps.map((step) => ({
        name: step.name,
        uses: step.uses ?? null,
        run: step.run ?? null,
        with: step.with ?? null,
        env: step.env ?? null,
        if: step.if ?? null,
      })),
      [
        {
          name: "Checkout",
          uses: CHECKOUT,
          run: null,
          with: { "fetch-depth": 0, "persist-credentials": false },
          env: null,
          if: null,
        },
        {
          name: "Node 24",
          uses: SETUP_NODE,
          run: null,
          with: { "node-version": "24" },
          env: null,
          if: null,
        },
        { name: "Install", uses: null, run: "npm ci --ignore-scripts", with: null, env: null, if: null },
        {
          name: "Fetch default branch",
          uses: null,
          run: fetchDefaultBranch,
          with: null,
          env: { NMZP_DEFAULT_BRANCH: "${{ github.event.repository.default_branch }}" },
          if: "github.event_name == 'workflow_dispatch' || (github.event_name == 'push' && github.event.before == '0000000000000000000000000000000000000000')",
        },
        {
          name: "Policy compatibility",
          uses: null,
          run: "node --experimental-strip-types scripts/policy-compat-guard.mjs",
          with: null,
          env: null,
          if: null,
        },
        { name: "Current version", uses: null, run: "node scripts/check-current-version.mjs", with: null, env: null, if: null },
        { name: "Typecheck", uses: null, run: "npm run typecheck", with: null, env: null, if: null },
        { name: "Lint", uses: null, run: "npm run lint -- --max-warnings 0", with: null, env: null, if: null },
        { name: "Layers", uses: null, run: "npm run lint:layers", with: null, env: null, if: null },
        { name: "Contract", uses: null, run: "npm run lint:contract", with: null, env: null, if: null },
        { name: "Build", uses: null, run: "npm run build", with: null, env: null, if: null },
        { name: "Test", uses: null, run: "npm test", with: null, env: null, if: null },
        { name: "H-03 semantic mutation checks", uses: null, run: "npm run test:mutations:h03", with: null, env: null, if: null },
      ],
    );
    assert.equal(text.match(/npm\s+ci\b/g)?.length, 1);
    for (const pattern of [
      /pull_request_target/,
      /self-hosted/,
      /NMZP_TEST_REAL_ACL/,
      /\$\{\{\s*secrets\b/,
      /contents\s*:\s*write/,
      /packages\s*:/,
      /id-token\s*:/,
      /persist-credentials\s*:\s*true/,
      /npm\s+publish/,
    ]) {
      assert.doesNotMatch(text, pattern, pattern.source);
    }
  });

  test("narrow stability workflow keeps its path filter", () => {
    const text = readRepo(".github/workflows/core-stability.yml", "narrow stability workflow is required");
    const doc = parseWorkflowYaml(text);
    assert.deepEqual(doc.on.pull_request.paths, STABILITY_PATHS);
    assert.deepEqual(doc.on.push.branches, ["main"]);
    assert.deepEqual(doc.on.push.paths, STABILITY_PATHS);
    assert.equal(doc.on.workflow_dispatch, null);
    assert.deepEqual(doc.permissions, { contents: "read" });
    assert.deepEqual(doc.jobs.audit.strategy.matrix.os, ["ubuntu-latest", "windows-latest"]);
    assert.equal(doc.jobs.audit.steps[0].uses, CHECKOUT);
    assert.equal(doc.jobs.audit.steps[0].with["persist-credentials"], false);
    assert.equal(doc.jobs.audit.steps[1].uses, SETUP_NODE);
    assert.equal(doc.jobs.audit.steps[1].with["node-version"], "24");
    const runs = doc.jobs.audit.steps.map((step) => step.run).filter((run) => run != null);
    assert.deepEqual(runs, [
      "node --version\nnode scripts/run-stability-tests.mjs --list\n",
      "node scripts/run-stability-tests.mjs",
    ]);
  });

  test("stability docs describe the unfiltered gate and its limits", () => {
    const zh = readRepo("docs/testing-stability.md", "docs/testing-stability.md is required");
    const en = readRepo("docs/testing-stability.en.md", "docs/testing-stability.en.md is required");
    for (const text of [zh, en]) {
      for (const needle of [
        "quality.yml",
        "release-preflight.mjs",
        "NMZP_TEST_REAL_ACL",
        "Quality / ubuntu-latest / Node 24",
        "Quality / windows-latest / Node 24",
        CHECKOUT,
        SETUP_NODE,
        "ubuntu-latest",
        "windows-latest",
      ]) {
        assert.ok(text.includes(needle), needle);
      }
    }
    assert.match(zh, /本机通过不是托管 Linux 作业的证据，也不是宿主认证。/);
    assert.match(zh, /workflow 文件和本地脚本不能代替仓库规则。/);
    assert.match(en, /A local pass is not evidence from the hosted Linux job and is not host certification\./);
    assert.match(en, /The workflow file and the local script cannot replace repository rules\./);
    assert.doesNotMatch(zh, /已经启用分支保护|托管门禁已经通过|已经强制全绿/);
    assert.doesNotMatch(en, /branch protection is enabled|hosted gate has passed|tags are automatically blocked/);
  });

  test("release preflight module is required", async () => {
    const mod = await loadPreflight();
    assert.deepEqual(mod.RELEASE_CHECKS, [
      ["npm", ["run", "typecheck"]],
      ["npm", ["run", "lint"]],
      ["npm", ["test"]],
      ["npm", ["run", "build"]],
    ]);
    assert.throws(() => {
      mod.RELEASE_CHECKS.push(["npm", ["publish"]]);
    }, TypeError);
    assert.equal(mod.npmArgsAllowed(["--version"]), true);
    assert.equal(mod.npmArgsAllowed(["run", "typecheck"]), true);
    assert.equal(mod.npmArgsAllowed(["publish"]), false);
    assert.equal(mod.npmArgsAllowed(["ci", "--ignore-scripts"]), false);
    assert.deepEqual(await mod.resolveNpmLaunch(["test"], { platform: "linux" }), {
      file: "npm",
      args: ["test"],
    });
    assert.deepEqual(await mod.resolveNpmLaunch(["run", "build"], { platform: "darwin" }), {
      file: "npm",
      args: ["run", "build"],
    });
  });

  test("preflight propagates a failing child status and stops later checks", async () => {
    const mod = await loadPreflight();
    const calls = [];
    const code = await mod.runReleasePreflight({
      stderr: silent,
      spawnImpl(command, args, options) {
        calls.push({ command, args, cwd: options.cwd });
        return { status: 1 };
      },
    });
    assert.equal(code, 1, "failing child status is propagated");
    assert.deepEqual(calls, [{ command: "npm", args: ["run", "typecheck"], cwd: root }]);
  });

  test("preflight propagates a later nonzero status and stops the remaining checks", async () => {
    const mod = await loadPreflight();
    const calls = [];
    const code = await mod.runReleasePreflight({
      stderr: silent,
      spawnImpl(command, args) {
        calls.push([command, ...args]);
        return { status: calls.length === 2 ? 4 : 0 };
      },
    });
    assert.equal(code, 4, "later nonzero status is propagated");
    assert.deepEqual(calls, [
      ["npm", "run", "typecheck"],
      ["npm", "run", "lint"],
    ]);
  });

  test("preflight runs typecheck, lint, test, and build in order", async () => {
    const mod = await loadPreflight();
    const calls = [];
    const code = await mod.runReleasePreflight({
      stderr: silent,
      spawnImpl(command, args) {
        calls.push([command, ...args]);
        return { status: 0, signal: null };
      },
    });
    assert.equal(code, 0);
    assert.deepEqual(calls, [
      ["npm", "run", "typecheck"],
      ["npm", "run", "lint"],
      ["npm", "test"],
      ["npm", "run", "build"],
    ]);
  });

  test("preflight keeps spawn failures nonzero and does not continue", async () => {
    const mod = await loadPreflight();
    assert.equal(mod.statusOf(null), 1);
    assert.equal(mod.statusOf({}), 1);
    assert.equal(mod.statusOf({ status: null }), 1);
    assert.equal(mod.statusOf({ status: 0, signal: "SIGTERM" }), 1);
    assert.equal(mod.statusOf({ status: 0, signal: null }), 0);
    let calls = 0;
    const thrown = await mod.runReleasePreflight({
      stderr: silent,
      spawnImpl() {
        calls += 1;
        throw new Error("spawn failed");
      },
    });
    assert.equal(thrown, 1, "spawn failure is nonzero");
    assert.equal(calls, 1);
    const signaled = await mod.runReleasePreflight({
      stderr: silent,
      spawnImpl() {
        calls += 1;
        return { status: 0, signal: "SIGTERM" };
      },
    });
    assert.equal(signaled, 1, "signaled child is nonzero");
    assert.equal(calls, 2);
    const missing = await mod.runReleasePreflight({
      stderr: silent,
      spawnImpl() {
        calls += 1;
        return null;
      },
    });
    assert.equal(missing, 1, "missing child status is nonzero");
    assert.equal(calls, 3);
  });

  test("preflight does not install, tag, or publish", async () => {
    const source = readRepo("scripts/release-preflight.mjs", "scripts/release-preflight.mjs is required");
    const self = readFileSync(fileURLToPath(import.meta.url), "utf8");
    assert.match(source, /function invokedDirectly\(/);
    assert.match(source, /if \(invokedDirectly\(\)\)/);
    assert.match(source, /NODE_TEST_CONTEXT/);
    assert.match(source, /refused inside a node:test process/);
    assert.match(source, /shell:\s*false/);
    assert.doesNotMatch(source, /shell:\s*true/);
    assert.doesNotMatch(source, /process\.exit\(0\)/);
    for (const pattern of [/npm\s+ci\b/, /\bgit\b/, /npm\s+publish\b/, /\bgh\b/, /NMZP_TEST_REAL_ACL/, /pull_request_target/]) {
      assert.doesNotMatch(source, pattern, pattern.source);
    }
    assert.doesNotMatch(self, /release-preflight\.mjs["']\s*\]/);
    assert.doesNotMatch(self, /spawn\(\s*["']npm["']/);
    const mod = await loadPreflight();
    assert.equal(
      mod.RELEASE_CHECKS.some((entry) => entry[1].includes("ci") || entry[1].includes("publish")),
      false,
    );
  });

  test("default spawn reports the child status", { timeout: 15_000 }, async () => {
    const mod = await loadPreflight();
    const result = await mod.defaultSpawn(process.execPath, ["-e", "process.exit(2)"], { cwd: root });
    assert.equal(result.status, 2);
    assert.equal(result.signal, null);
  });

  test("default spawn launches npm --version", { timeout: 20_000 }, async () => {
    const mod = await loadPreflight();
    await assert.rejects(
      () => mod.defaultSpawn("npm", ["publish"], { cwd: root, stdio: "pipe" }),
      /fixed preflight set/,
    );
    const launch = await mod.resolveNpmLaunch(["--version"], { cwd: root });
    if (process.platform === "win32") {
      assert.equal(launch.file.toLowerCase().endsWith(".cmd"), false);
      if (launch.file === process.execPath) {
        assert.match(launch.args[0].replaceAll("\\", "/"), /\/node_modules\/npm\/bin\/npm-cli\.js$/i);
        assert.deepEqual(launch.args.slice(1), ["--version"]);
      } else {
        assert.match(launch.file.replaceAll("\\", "/"), /\/npm\.exe$/i);
        assert.deepEqual(launch.args, ["--version"]);
      }
    } else {
      assert.deepEqual(launch, { file: "npm", args: ["--version"] });
    }
    const result = await mod.defaultSpawn("npm", ["--version"], { cwd: root, stdio: "pipe" });
    assert.equal(result.signal, null);
    assert.equal(result.status, 0, "npm --version exits 0");
    assert.match(result.stdout, /\d+\.\d+\.\d+/);
  });

  test("owned signal target is a process group only off Windows", async () => {
    const mod = await loadPreflight();
    assert.deepEqual(mod.ownedSignalTarget(42, "linux"), { pid: -42, direct: false });
    assert.deepEqual(mod.ownedSignalTarget(42, "darwin"), { pid: -42, direct: false });
    assert.deepEqual(mod.ownedSignalTarget(42, "win32"), { pid: 42, direct: true });
    assert.equal(mod.ownedSignalTarget(0, "linux"), null);
    assert.equal(mod.ownedSignalTarget(-7, "win32"), null);
  });

  test("timed out child is not success", { timeout: 20_000 }, async () => {
    const mod = await loadPreflight();
    const before = process.listenerCount("exit");
    let pid = null;
    try {
      const result = await mod.spawnOwned(process.execPath, ["-e", `setTimeout(() => process.exit(0), ${SELF_EXPIRE_MS})`], {
        cwd: root,
        stdio: "ignore",
        timeoutMs: 300,
        onChild(child) {
          pid = child.pid;
        },
      });
      assert.notEqual(result.status, 0, "timed out child is not success");
      assert.equal(result.timedOut, true);
      assert.equal(await stopped(pid), true, "timed out child was stopped");
      assert.equal(process.listenerCount("exit"), before, "exit listener was removed");
    } finally {
      if (pid && processAlive(pid)) {
        try {
          process.kill(pid);
        } catch {
          // The fixture also expires on its own timer.
        }
      }
    }
  });

  test("explicit cancellation is nonzero", { timeout: 20_000 }, async () => {
    const mod = await loadPreflight();
    const before = process.listenerCount("exit");
    const dir = await mkdtemp(join(tmpdir(), "nmzp-cancel-"));
    const marker = join(dir, "pids.txt");
    const script = join(dir, "tree.mjs");
    let pids = null;
    try {
      await writeFile(script, TREE_FIXTURE);
      const done = mod.spawnOwned(process.execPath, [script, marker], { cwd: dir, stdio: "ignore" });
      const started = Date.now();
      while (!existsSync(marker)) {
        if (Date.now() - started > 3_000) break;
        await delay(30);
      }
      assert.equal(existsSync(marker), true, "synthetic tree reported its pids");
      pids = JSON.parse(readFileSync(marker, "utf8"));
      const code = await mod.cancelOwnedChildren("SIGTERM");
      assert.notEqual(code, 0, "cancellation is nonzero");
      await done;
      assert.equal(await stopped(pids.parent), true, "owned child was stopped");
      assert.equal(await stopped(pids.grand), true, "owned descendant was stopped");
      assert.equal(process.listenerCount("exit"), before, "exit listener was removed");
    } finally {
      for (const pid of [pids?.parent, pids?.grand]) {
        if (pid && processAlive(pid)) {
          try {
            process.kill(pid);
          } catch {
            // The fixture also expires on its own timer.
          }
        }
      }
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("cancellation listeners are removed", async () => {
    const mod = await loadPreflight();
    const fake = new EventEmitter();
    let exited = null;
    mod.installCancellation({
      process: fake,
      exit(code) {
        exited = code;
      },
    });
    assert.equal(fake.listenerCount("SIGTERM"), 1);
    assert.equal(fake.listenerCount("SIGINT"), 1);
    fake.emit("SIGINT");
    await mod.whenCancellationSettled();
    assert.notEqual(exited, 0, "cancellation is nonzero");
    assert.equal(fake.listenerCount("SIGTERM"), 0, "cancellation listeners were removed");
    assert.equal(fake.listenerCount("SIGINT"), 0, "cancellation listeners were removed");
  });
});
