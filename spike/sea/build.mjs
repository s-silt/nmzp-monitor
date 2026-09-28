/**
 * WP-10 SEA producer. Uses coordinator-installed esbuild/postject via absolute
 * paths. Copies producer node.exe into wp10-out before injection. No npm/pnpm.
 */
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { spawn } from "node:child_process";
import { copyFileSync, mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { basename, dirname, join, normalize, sep } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const HERE = dirname(fileURLToPath(import.meta.url));
const CHECKOUT = normalize(join(HERE, "..", ".."));
const OUT = "C:\\Users\\sxl\\Desktop\\NMZP\\wp10-out";
const TOOLS = "C:\\Users\\sxl\\Desktop\\NMZP\\wp10-tools\\node_modules";
const PRODUCER_NODE = "C:\\Program Files\\nodejs\\node.exe";
const ESBUILD_BIN = join(TOOLS, "@esbuild", "win32-arm64", "esbuild.exe");
const POSTJECT_CLI = join(TOOLS, "postject", "dist", "cli.js");
const SIGNTOOL =
  "C:\\Program Files (x86)\\Windows Kits\\10\\bin\\10.0.22621.0\\arm64\\signtool.exe";
// Observed in producer node.exe (v24.15.0 win32 arm64), not the 481702 string
// from some doc copies. Sentinel is ASCII `NODE_SEA_FUSE_...1996b2:0`.
const FUSE = "NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2";
const CORE_PATHS = normalize(join(CHECKOUT, "core", "paths.ts"));
const CORE_RUNTIME = normalize(join(CHECKOUT, "core", "audit", "runtime.ts"));
const MONITOR_LOADER = join(HERE, "monitor-loader.ts");
const ENTRY = join(HERE, "sea-entry.ts");
const WORKER_ENTRY = join(CHECKOUT, "core", "audit", "runtime-worker.ts");
const DEFAULT_SPAWN_RE =
  /function defaultSpawn\(workerData: AuditWorkerData\): AuditWorkerPort \{\r?\n {2}return new Worker\(new URL\("\.\/runtime-worker\.ts", import\.meta\.url\), \{\r?\n {4}execArgv: \["--experimental-strip-types"\],\r?\n {4}workerData,\r?\n {2}\}\);\r?\n\}/;

process.env.ESBUILD_BINARY_PATH = ESBUILD_BIN;

function sha256File(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function ensureDirs() {
  for (const dir of [
    OUT,
    join(OUT, "bin"),
    join(OUT, "staging"),
    join(OUT, "bundle"),
    join(OUT, "logs"),
    join(OUT, "results"),
    join(OUT, "d-prime"),
  ]) {
    mkdirSync(dir, { recursive: true });
  }
}

function scanText(label, text, checkoutNeedle) {
  const importCalls = [...text.matchAll(/(?<!["'`])\bimport\s*\(/g)].length;
  const runtimeImportCalls = [...text.matchAll(/\bimport\s*\(\s*["'`]/g)].length;
  const workerTs = /new URL\(\s*["']\.\/runtime-worker\.ts["']/.test(text);
  const stripInSpawn = /new Worker\([\s\S]{0,200}strip-types/.test(text);
  const absHits = [];
  const needles = [
    checkoutNeedle,
    checkoutNeedle.replaceAll("\\", "/"),
    checkoutNeedle.replaceAll("/", "\\"),
    CHECKOUT,
    CHECKOUT.replaceAll("\\", "/"),
  ];
  for (const n of new Set(needles)) {
    if (n && text.includes(n)) absHits.push(n);
  }
  return {
    label,
    importCalls,
    runtimeImportCalls,
    workerTs,
    stripInSpawn,
    absCheckoutHits: absHits,
  };
}

function rewriteImportMeta(src) {
  return src
    .replaceAll("import.meta.url", "NMZP_IMPORT_META_URL")
    .replaceAll("import.meta.dirname", "__dirname");
}

function plugins(kind) {
  return [
    {
      name: "nmzp-sea-paths",
      setup(build) {
        build.onResolve({ filter: /paths\.ts$/ }, (args) => {
          const resolved = normalize(
            join(args.resolveDir || dirname(args.importer || ""), args.path),
          );
          if (resolved === CORE_PATHS) return { path: MONITOR_LOADER };
          return undefined;
        });
      },
    },
    {
      name: "nmzp-sea-cjs-shims",
      setup(build) {
        build.onLoad({ filter: /\.[cm]?[jt]sx?$/ }, async (args) => {
          if (
            args.path.includes(`${sep}node_modules${sep}`) ||
            args.path.includes("/node_modules/")
          ) {
            return undefined;
          }
          const fs = await import("node:fs/promises");
          let src = await fs.readFile(args.path, "utf8");
          if (kind === "main" && normalize(args.path) === CORE_RUNTIME) {
            if (!DEFAULT_SPAWN_RE.test(src)) {
              throw new Error(
                "defaultSpawn source pattern mismatch; refusing to bundle a guessed spawn",
              );
            }
            src = src.replace(
              DEFAULT_SPAWN_RE,
              `function defaultSpawn(workerData: AuditWorkerData): AuditWorkerPort {
  return spawnSeaAuditWorker(workerData);
}`,
            );
            src = `import { spawnSeaAuditWorker } from "../../spike/sea/sea-audit-worker-spawn.ts";\n${src}`;
          }
          if (!src.includes("import.meta") && normalize(args.path) !== CORE_RUNTIME)
            return undefined;
          const loader = args.path.endsWith(".ts") || args.path.endsWith(".tsx") ? "ts" : "js";
          return { contents: rewriteImportMeta(src), loader, resolveDir: dirname(args.path) };
        });
      },
    },
  ];
}

async function bundleOne(kind, outfile) {
  const esbuild = require(join(TOOLS, "esbuild", "lib", "main.js"));
  const result = await esbuild.build({
    absWorkingDir: CHECKOUT,
    entryPoints: [kind === "main" ? ENTRY : WORKER_ENTRY],
    outfile,
    bundle: true,
    format: "cjs",
    platform: "node",
    target: "node24",
    sourcemap: false,
    legalComments: "none",
    minify: false,
    keepNames: true,
    logLevel: "info",
    metafile: true,
    write: true,
    packages: "bundle",
    supported: { "dynamic-import": false },
    banner: {
      js:
        kind === "main"
          ? '/* NMZP_SEA_MAIN entry=spike/sea/sea-entry.ts */\nvar NMZP_IMPORT_META_URL = require("node:url").pathToFileURL(__filename).href;\n'
          : '/* NMZP_SEA_AUDIT_WORKER */\nvar NMZP_IMPORT_META_URL = require("node:url").pathToFileURL(__filename).href;\n',
    },
    plugins: plugins(kind),
    nodePaths: [join(CHECKOUT, "node_modules")],
  });
  const text = readFileSync(outfile, "utf8");
  const scan = scanText(kind, text, CHECKOUT);
  const metaPath = join(OUT, "bundle", `${kind}-metafile.json`);
  writeFileSync(metaPath, JSON.stringify(result.metafile, null, 2));
  const inputs = Object.keys(result.metafile.inputs);
  const nonBuiltin = inputs.filter((p) => !p.startsWith("node:") && !p.includes("node_modules/"));
  const nodeModules = inputs.filter((p) => p.includes("node_modules"));
  const acorn = nodeModules.filter((p) => p.replaceAll("\\", "/").includes("/acorn/"));
  return {
    outfile,
    sha256: sha256File(outfile),
    bytes: readFileSync(outfile).length,
    scan,
    inputCount: inputs.length,
    sourceInputs: nonBuiltin.length,
    nodeModuleInputs: nodeModules,
    acornInputs: acorn,
    warnings: result.warnings,
    metaPath,
  };
}

function run(cmd, args, opts = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
      ...opts,
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (c) => {
      stdout += c;
    });
    child.stderr.on("data", (c) => {
      stderr += c;
    });
    child.on("error", reject);
    child.on("close", (code) => resolve({ code: code ?? 1, stdout, stderr }));
  });
}

async function makeBlob(mainJs, blobPath, useCodeCache) {
  const configPath = join(
    OUT,
    "staging",
    useCodeCache ? "sea-config-cache.json" : "sea-config-nocache.json",
  );
  const workerJs = join(OUT, "bundle", "audit-runtime-worker.cjs");
  const config = {
    main: mainJs,
    output: blobPath,
    disableExperimentalSEAWarning: true,
    useSnapshot: false,
    useCodeCache,
    execArgv: [],
    assets: {
      "audit-runtime-worker.cjs": workerJs,
    },
  };
  writeFileSync(configPath, JSON.stringify(config, null, 2));
  const r = await run(PRODUCER_NODE, ["--experimental-sea-config", configPath], { cwd: OUT });
  writeFileSync(
    join(OUT, "logs", useCodeCache ? "sea-config-cache.log" : "sea-config-nocache.log"),
    `${r.stdout}\n${r.stderr}`,
  );
  if (r.code !== 0) {
    const err = new Error(`sea-config failed code=${r.code}`);
    err.result = r;
    throw err;
  }
  return {
    configPath,
    blobPath,
    sha256: sha256File(blobPath),
    bytes: readFileSync(blobPath).length,
    log: r,
  };
}

async function inject(blobPath, exePath) {
  copyFileSync(PRODUCER_NODE, exePath);
  const copiedHash = sha256File(exePath);
  let unsign = { skipped: true };
  if (existsSync(SIGNTOOL)) {
    const u = await run(SIGNTOOL, ["remove", "/s", exePath]);
    unsign = { skipped: false, code: u.code, stdout: u.stdout, stderr: u.stderr };
  }
  const inj = await run(PRODUCER_NODE, [
    POSTJECT_CLI,
    exePath,
    "NODE_SEA_BLOB",
    blobPath,
    "--sentinel-fuse",
    FUSE,
    "--overwrite",
  ]);
  writeFileSync(
    join(OUT, "logs", `${basename(exePath)}.inject.log`),
    `${inj.stdout}\n${inj.stderr}`,
  );
  return {
    exePath,
    copiedProducerSha256: copiedHash,
    injectedSha256: existsSync(exePath) ? sha256File(exePath) : null,
    bytes: existsSync(exePath) ? readFileSync(exePath).length : 0,
    unsign,
    inject: { code: inj.code, stdout: inj.stdout, stderr: inj.stderr },
    ok: inj.code === 0,
  };
}

function dprimeLauncher(bundleJs) {
  const dir = join(OUT, "d-prime");
  const nodeCopy = join(dir, "node.exe");
  const script = join(dir, "sea-main.cjs");
  copyFileSync(PRODUCER_NODE, nodeCopy);
  copyFileSync(bundleJs, script);
  const cmd = `@echo off\r\n"${nodeCopy}" "${script}" %*\r\n`;
  writeFileSync(join(dir, "nmzp.cmd"), cmd);
  return {
    nodeCopy,
    nodeSha256: sha256File(nodeCopy),
    script,
    scriptSha256: sha256File(script),
    launcher: join(dir, "nmzp.cmd"),
  };
}

async function mainBuild() {
  ensureDirs();
  const producer = {
    path: PRODUCER_NODE,
    sha256: sha256File(PRODUCER_NODE),
    esbuildBin: ESBUILD_BIN,
    esbuildSha256: sha256File(ESBUILD_BIN),
    postjectCli: POSTJECT_CLI,
    postjectSha256: sha256File(POSTJECT_CLI),
  };
  const mainBundle = await bundleOne("main", join(OUT, "bundle", "sea-main.cjs"));
  const workerBundle = await bundleOne("worker", join(OUT, "bundle", "audit-runtime-worker.cjs"));
  const transforms = [
    {
      id: "T1_monitor_loader",
      source: "core/paths.ts loadMonitor/loadPolicyProposal dynamic import(file URL)",
      output: "spike/sea/monitor-loader.ts static ESM imports of src/lib/monitor/*",
      test: "serve+hook+health on injected exe with checkout renamed/absent from env",
    },
    {
      id: "T2_defaultSpawn",
      source:
        "core/audit/runtime.ts defaultSpawn Worker(new URL('./runtime-worker.ts'), execArgv strip-types)",
      output:
        "defaultSpawn -> spawnSeaAuditWorker; worker CJS asset audit-runtime-worker.cjs from runtime-worker.ts+store.ts",
      test: "sea-selftest audit-worker persist/close/reopen; serve /health audit=ready; never auditWorkerSpawn option",
    },
    {
      id: "T3_entry_shim",
      source: "core/nmzp.mjs strip-types respawn + core/cli.ts main",
      output:
        "spike/sea/sea-entry.ts CJS SEA main; --version; sea-selftest; emergency hook deny; no strip-types respawn loop",
      test: "--version/help; respawn child execPath equals SEA exe",
    },
    {
      id: "T4_dynamic_import_cjs",
      source: "core/cli.ts and others await import('./x.ts')",
      output: "esbuild format:cjs supported.dynamic-import=false converts to require",
      test: "bundle scan importCalls; useCodeCache=true blob generation",
    },
  ];
  writeFileSync(
    join(OUT, "results", "bundle.json"),
    JSON.stringify({ producer, mainBundle, workerBundle, transforms }, null, 2),
  );
  let cacheBlob;
  let nocacheBlob;
  let cacheInject;
  let nocacheInject;
  let seaError = null;
  try {
    cacheBlob = await makeBlob(
      mainBundle.outfile,
      join(OUT, "staging", "sea-prep-cache.blob"),
      true,
    );
    nocacheBlob = await makeBlob(
      mainBundle.outfile,
      join(OUT, "staging", "sea-prep-nocache.blob"),
      false,
    );
    cacheInject = await inject(cacheBlob.blobPath, join(OUT, "bin", "nmzp.exe"));
    nocacheInject = await inject(nocacheBlob.blobPath, join(OUT, "bin", "nmzp-nocache.exe"));
  } catch (error) {
    seaError = {
      message: error instanceof Error ? error.message : String(error),
      result: error.result ?? null,
    };
  }
  const dprime = dprimeLauncher(mainBundle.outfile);
  const summary = {
    producer,
    mainBundle,
    workerBundle,
    transforms,
    cacheBlob,
    nocacheBlob,
    cacheInject,
    nocacheInject,
    seaError,
    dprime,
    checkout: CHECKOUT,
  };
  writeFileSync(join(OUT, "results", "build.json"), JSON.stringify(summary, null, 2));
  process.stdout.write(
    `${JSON.stringify({ ok: cacheInject?.ok === true, cacheInject: cacheInject?.ok, nocacheInject: nocacheInject?.ok, seaError, mainScan: mainBundle.scan, workerScan: workerBundle.scan }, null, 2)}\n`,
  );
  if (cacheInject?.ok !== true) process.exitCode = 2;
}

await mainBuild();
