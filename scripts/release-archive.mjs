import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { cp, mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, join, resolve, win32 } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { gzipSync } from "node:zlib";
import { rolldown } from "rolldown";

const scriptRepo = dirname(dirname(fileURLToPath(import.meta.url)));
const require = createRequire(pathToFileURL(join(scriptRepo, "package.json")));

const MAIN_ENTRY = ["nmzp-main.cjs", "core/cli.ts"];
const WORKER_ENTRIES = [
  ["audit/runtime-worker.cjs", "core/audit/runtime-worker.ts"],
  ["agent-discovery-worker.cjs", "core/agent-discovery-worker.ts"],
  ["snapshot-status-worker.cjs", "core/snapshot-status-worker.ts"],
  ["probe-mailbox-worker.cjs", "core/probe-mailbox-worker.ts"],
];

const ASSET_EXT = new Set([
  ".ps1", ".json", ".cmd", ".bat", ".service", ".sh", ".md", ".txt", ".yaml", ".yml", ".toml",
  ".html", ".css", ".svg", ".bin",
]);
const LICENSE_NAMES = new Set(["license", "licence", "copying", "notice"]);
const EXPERIMENTAL = /^(?:native-|model-gateway|protected-session|model-response)/;
const PRODUCT_HOME = "|~|/home/";

function normalizeCmp(s) {
  return resolve(s).replace(/\\/g, "/").replace(/\/+$/, "").toLowerCase();
}

export function resolveInsidePackDir(repoRoot, target) {
  const packRoot = resolve(repoRoot, ".pack");
  const resolved = resolve(target);
  const rootCmp = normalizeCmp(packRoot);
  const targetCmp = normalizeCmp(resolved);
  if (targetCmp !== rootCmp && !targetCmp.startsWith(`${rootCmp}/`)) {
    throw new Error(`pack_rm_outside_pack_dir:${resolved}`);
  }
  return resolved;
}

function windowsFileUrlPath(metaUrl) {
  let url;
  try {
    url = new URL(metaUrl);
  } catch {
    return undefined;
  }
  if (url.protocol !== "file:") return undefined;
  let pathname = url.pathname;
  try {
    pathname = decodeURIComponent(pathname);
  } catch {
    return undefined;
  }
  const match = /^\/([A-Za-z]:\/.*)$/.exec(pathname);
  return match?.[1];
}

function isWindowsPath(p) {
  return /^[A-Za-z]:[\\/]/.test(p) || p.startsWith("\\\\");
}

function foldWin(p) {
  return win32.normalize(p).replace(/[/\\]+$/, "").toLowerCase();
}

export function isPackEntrypoint(metaUrl, argv1, cwd = process.cwd()) {
  if (!argv1) return false;
  const winSelf = windowsFileUrlPath(metaUrl);
  if (winSelf && (isWindowsPath(argv1) || isWindowsPath(cwd) || argv1.includes("\\"))) {
    const invoked = isWindowsPath(argv1) ? argv1 : win32.resolve(isWindowsPath(cwd) ? cwd : win32.dirname(winSelf), argv1);
    return foldWin(winSelf) === foldWin(invoked);
  }
  let self;
  try {
    self = fileURLToPath(metaUrl);
  } catch {
    return false;
  }
  const invoked = resolve(cwd, argv1);
  return normalizeCmp(self) === normalizeCmp(invoked);
}

function octal(n, width) {
  return n.toString(8).padStart(width - 1, "0") + "\0";
}

function compareCodeUnit(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

const CHECKSUM_SEPARATOR = "  ";

function entryBase(name) {
  const trimmed = name.endsWith("/") ? name.slice(0, -1) : name;
  const slash = trimmed.lastIndexOf("/");
  return slash >= 0 ? trimmed.slice(slash + 1) : trimmed;
}

function startsWithShebang(buf) {
  return buf.length >= 2 && buf[0] === 0x23 && buf[1] === 0x21;
}

const SHIPPED_TEXT_EXTENSIONS = new Set([
  ".ts", ".js", ".mjs", ".cjs", ".json", ".md", ".txt", ".yaml", ".yml", ".toml",
  ".html", ".css", ".svg", ".ps1", ".cmd", ".bat", ".service", ".sh",
]);

const SHIPPED_LICENSE_NAMES = new Set(["license", "licence", "copying", "notice"]);

function isShippedText(relPath) {
  const base = entryBase(relPath).toLowerCase();
  if (SHIPPED_LICENSE_NAMES.has(base) || base.endsWith(".license") || base.endsWith(".licence")) return true;
  const dot = base.lastIndexOf(".");
  return dot >= 0 && SHIPPED_TEXT_EXTENSIONS.has(base.slice(dot));
}

function crlfToLf(buf) {
  if (!buf.includes(0x0d)) return buf;
  const out = Buffer.alloc(buf.length);
  let written = 0;
  let changed = false;
  for (let index = 0; index < buf.length; index++) {
    const byte = buf[index];
    if (byte === 0x0d && buf[index + 1] === 0x0a) {
      changed = true;
      continue;
    }
    out[written++] = byte;
  }
  if (!changed) return buf;
  return Buffer.from(out.subarray(0, written));
}

export function normalizeShippedText(relPath, buf) {
  if (buf.includes(0)) return buf;
  if (!isShippedText(relPath) && !startsWithShebang(buf)) return buf;
  return crlfToLf(buf);
}

function executableTarMode(name, data) {
  const base = entryBase(name);
  if (base === "nmzp" || base === "nmzp.mjs" || base.endsWith(".sh") || startsWithShebang(data)) return 0o755;
  return 0o644;
}

const TAR_MTIME_MAX = 0o77777777777;

export function archiveTimestamp() {
  const raw = process.env.SOURCE_DATE_EPOCH;
  if (raw === undefined) return 0;
  const value = Number(raw);
  if (!/^\d{1,11}$/.test(raw) || !Number.isSafeInteger(value) || value > TAR_MTIME_MAX) {
    throw new Error("pack_invalid_source_date_epoch");
  }
  return value;
}

function archivePath(entry) {
  if (entry.dir && !entry.name.endsWith("/")) return `${entry.name}/`;
  return entry.name;
}

function tarHeader(name, size, type, mode, mtime) {
  const buf = Buffer.alloc(512);
  let nameField = name;
  let prefix = "";
  const nameBytes = Buffer.byteLength(name, "utf8");
  if (nameBytes > 100) {
    const slash = name.lastIndexOf("/", name.length - 1);
    if (slash > 0 && slash < 155 && nameBytes - slash - 1 <= 100) {
      prefix = name.slice(0, slash);
      nameField = name.slice(slash + 1);
    } else {
      throw new Error(`pack_name_too_long:${name}`);
    }
  }
  Buffer.from(nameField, "utf8").copy(buf, 0);
  buf.write(octal(mode, 8), 100, 8, "utf8");
  buf.write(octal(0, 8), 108, 8, "utf8");
  buf.write(octal(0, 8), 116, 8, "utf8");
  buf.write(octal(size, 12), 124, 12, "utf8");
  buf.write(octal(mtime, 12), 136, 12, "utf8");
  buf.fill(0x20, 148, 156);
  buf.write(type, 156, 1, "utf8");
  buf.write("ustar\0", 257, 6, "utf8");
  buf.write("00", 263, 2, "utf8");
  if (prefix) Buffer.from(prefix, "utf8").copy(buf, 345);
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += buf[i];
  const chk = `${sum.toString(8).padStart(6, "0")}\0 `;
  Buffer.from(chk, "utf8").copy(buf, 148);
  return buf;
}

function pad512(data) {
  const rem = data.length % 512;
  if (rem === 0) return data;
  return Buffer.concat([data, Buffer.alloc(512 - rem)]);
}

export function createTarGz(entries, mtime = archiveTimestamp()) {
  const parts = [];
  const ordered = entries.slice().sort((a, b) => compareCodeUnit(archivePath(a), archivePath(b)));
  for (const e of ordered) {
    if (e.dir) {
      const n = e.name.endsWith("/") ? e.name : `${e.name}/`;
      parts.push(tarHeader(n, 0, "5", 0o755, mtime));
      continue;
    }
    parts.push(tarHeader(e.name, e.data.length, "0", executableTarMode(e.name, e.data), mtime));
    parts.push(pad512(e.data));
  }
  parts.push(Buffer.alloc(1024));
  const gz = gzipSync(Buffer.concat(parts), { level: 9 });
  gz[4] = 0;
  gz[5] = 0;
  gz[6] = 0;
  gz[7] = 0;
  gz[9] = 255;
  return gz;
}

function readNmzpVersion() {
  const text = readFileSync(join(scriptRepo, "core", "constants.ts"), "utf8");
  const match = /export const NMZP_VERSION = "([^"]+)"/.exec(text);
  if (!match?.[1]) throw new Error("pack_missing_version");
  return match[1];
}

export function readAcornVersion() {
  const pkg = JSON.parse(readFileSync(require.resolve("acorn/package.json"), "utf8"));
  return typeof pkg.version === "string" ? pkg.version : "";
}

function acornPackageRoot() {
  return dirname(require.resolve("acorn/package.json"));
}

function installedResolver() {
  return {
    name: "nmzp-installed-deps",
    resolveId(source) {
      if (typeof source !== "string") return null;
      if (
        source.startsWith("\0") ||
        source.startsWith(".") ||
        source.startsWith("/") ||
        source.startsWith("node:") ||
        source.includes(":") ||
        /^[A-Za-z]:[\\/]/.test(source)
      ) {
        return null;
      }
      try {
        return require.resolve(source);
      } catch {
        return null;
      }
    },
  };
}

function packageNameFromId(id) {
  const norm = id.replaceAll("\\", "/");
  const mark = "/node_modules/";
  const at = norm.lastIndexOf(mark);
  if (at < 0) return "";
  const rest = norm.slice(at + mark.length);
  if (rest.startsWith("@")) {
    const [scope, name] = rest.split("/");
    return scope && name ? `${scope}/${name}` : "";
  }
  return rest.split("/")[0] || "";
}

function assertNotExperimental(id) {
  const norm = id.replaceAll("\\", "/");
  if (/(^|\/)(?:native-|model-gateway|protected-session|model-response)/.test(norm)) {
    throw new Error(`pack_experimental_in_bundle:${norm}`);
  }
}

export function hasImportMetaSyntax(code) {
  const re = /import\.meta/g;
  let match;
  while ((match = re.exec(code))) {
    const prev = code[match.index - 1];
    if (prev === "'" || prev === '"' || prev === "`") continue;
    return true;
  }
  return false;
}

function assertBundleClean(code, label) {
  if (hasImportMetaSyntax(code)) throw new Error(`pack_import_meta:${label}`);
  const stripped = code.split(PRODUCT_HOME).join("");
  for (const pattern of ["C:/Users", "C:\\Users", "C:\\\\Users", "/home/"]) {
    const at = stripped.indexOf(pattern);
    if (at >= 0) {
      const sample = stripped.slice(Math.max(0, at - 48), at + pattern.length + 48).replaceAll("\n", "\\n");
      throw new Error(`pack_absolute_path:${label}:${pattern}:${sample}`);
    }
  }
}

// rolldown 在每个模块前后写入 `//#region <相对 cwd 的模块路径>` 注释；路径取决于检出布局
// （node_modules junction、CI runner 目录），会让产物不可复现并泄露本机路径。这里只删除
// 整行的 region 标记，不触碰任何代码行。
const REGION_MARKER = /^[ \t]*\/\/#(?:region|endregion)\b[^\n]*\n/gm;

export function stripRegionMarkers(code) {
  return code.replace(REGION_MARKER, "");
}

async function bundleOne(repoRoot, inputRel) {
  const input = join(repoRoot, inputRel);
  const moduleIds = new Set();
  const warnings = [];
  const build = await rolldown({
    input,
    platform: "node",
    cwd: repoRoot,
    treeshake: true,
    transform: { define: { NMZP_BUNDLE: "true" } },
    plugins: [
      installedResolver(),
      {
        name: "nmzp-module-ids",
        moduleParsed(info) {
          if (info?.id) moduleIds.add(info.id);
        },
      },
    ],
    onwarn(warning, warn) {
      const message = `${warning.code || ""} ${warning.message || ""}`;
      if (/unresolved/i.test(message)) {
        warnings.push(message);
        return;
      }
      warn(warning);
    },
  });
  let generated;
  try {
    generated = await build.generate({
      format: "cjs",
      codeSplitting: false,
      sourcemap: false,
      exports: "auto",
    });
  } finally {
    await build.close();
  }
  if (warnings.length > 0) throw new Error(`pack_unresolved_import:${inputRel}:${warnings[0]}`);
  const chunks = generated.output.filter((item) => item.type === "chunk");
  if (chunks.length !== 1) throw new Error(`pack_bundle_not_single:${inputRel}`);
  const chunk = chunks[0];
  for (const id of Object.keys(chunk.modules || {})) moduleIds.add(id);
  const deps = new Set();
  for (const id of moduleIds) {
    assertNotExperimental(id);
    const name = packageNameFromId(id);
    if (name && name !== "rolldown") deps.add(name);
  }
  const code = stripRegionMarkers(chunk.code);
  assertBundleClean(code, inputRel);
  return { code, deps };
}

function isTestName(name) {
  return /\.(?:test|spec)\.(?:[cm]?[jt]s|ps1)$/.test(name);
}

function shouldCopyAsset(name) {
  if (isTestName(name) || name === "Dockerfile") return false;
  if (name === "nmzp.mjs" || name === "hook-emergency-deny.mjs") return true;
  const base = name.toLowerCase();
  if (LICENSE_NAMES.has(base) || base.endsWith(".license") || base.endsWith(".licence")) return true;
  const dot = base.lastIndexOf(".");
  return dot >= 0 && ASSET_EXT.has(base.slice(dot));
}

async function copyRuntimeAssets(coreDir, packDir) {
  async function walk(dir, rel) {
    for (const ent of await readdir(dir, { withFileTypes: true })) {
      if (EXPERIMENTAL.test(ent.name) || isTestName(ent.name)) continue;
      const abs = join(dir, ent.name);
      const next = rel ? `${rel}/${ent.name}` : ent.name;
      if (ent.isDirectory()) {
        await walk(abs, next);
        continue;
      }
      if (!shouldCopyAsset(ent.name)) continue;
      const dest = join(packDir, next);
      await mkdir(dirname(dest), { recursive: true });
      await cp(abs, dest);
    }
  }
  await walk(coreDir, "");
}

export async function packRelease(repoRoot, hooks = {}) {
  const archivedAt = archiveTimestamp();
  if (!existsSync(join(repoRoot, "dist", "index.html"))) throw new Error("pack_missing_ui_dist");
  if (!existsSync(join(repoRoot, "core", "nmzp.mjs"))) throw new Error("pack_missing_core_entry");
  const acornVersion = hooks.readAcornVersion ? hooks.readAcornVersion() : readAcornVersion();
  if (acornVersion !== "8.18.0") throw new Error("pack_acorn_version_mismatch");

  const bundles = [];
  const runtimeDeps = new Set();
  if (existsSync(join(repoRoot, MAIN_ENTRY[1]))) {
    const bundled = await bundleOne(repoRoot, MAIN_ENTRY[1]);
    bundles.push({ rel: MAIN_ENTRY[0], code: bundled.code });
    for (const dep of bundled.deps) runtimeDeps.add(dep);
  }
  for (const [rel, sourceRel] of WORKER_ENTRIES) {
    if (!existsSync(join(repoRoot, sourceRel))) continue;
    const bundled = await bundleOne(repoRoot, sourceRel);
    bundles.push({ rel, code: bundled.code });
    for (const dep of bundled.deps) runtimeDeps.add(dep);
  }

  const packRoot = resolveInsidePackDir(repoRoot, join(repoRoot, ".pack"));
  const packDir = resolveInsidePackDir(repoRoot, join(repoRoot, ".pack", "nmzp"));
  if (existsSync(packDir)) await rm(packDir, { recursive: true, force: true });
  await mkdir(packDir, { recursive: true });
  await copyRuntimeAssets(join(repoRoot, "core"), packDir);
  for (const bundle of bundles) {
    const dest = join(packDir, bundle.rel);
    await mkdir(dirname(dest), { recursive: true });
    await writeFile(dest, bundle.code);
  }
  const license = crlfToLf(await readFile(join(acornPackageRoot(), "LICENSE")));
  await writeFile(join(packDir, "THIRD_PARTY_LICENSES"), Buffer.concat([Buffer.from("acorn 8.18.0\n\n"), license]));
  await cp(join(repoRoot, "dist"), join(packDir, "ui"), { recursive: true });
  await writeFile(join(packDir, "VERSION"), `${readNmzpVersion()}\nnode>=24\n`);
  await cp(join(packDir, "nmzp.mjs"), join(packDir, "nmzp"));

  const files = [];
  const tarEntries = [{ name: "nmzp", data: Buffer.alloc(0), dir: true }];
  async function walk(dir, rel) {
    const ents = await readdir(dir, { withFileTypes: true });
    ents.sort((a, b) => compareCodeUnit(a.name, b.name));
    for (const ent of ents) {
      const abs = join(dir, ent.name);
      const r = rel ? `${rel}/${ent.name}` : ent.name;
      if (ent.isDirectory()) {
        tarEntries.push({ name: `nmzp/${r}`, data: Buffer.alloc(0), dir: true });
        await walk(abs, r);
      } else {
        const raw = await readFile(abs);
        const buf = normalizeShippedText(r, raw);
        if (!buf.equals(raw)) await writeFile(abs, buf);
        files.push({
          path: r,
          sha256: createHash("sha256").update(buf).digest("hex"),
          bytes: buf.length,
        });
        tarEntries.push({ name: `nmzp/${r}`, data: buf });
      }
    }
  }
  await walk(packDir, "");
  files.sort((a, b) => compareCodeUnit(a.path, b.path));
  const tgzBuf = createTarGz(tarEntries, archivedAt);
  const tgzPack = join(packRoot, "nmzp-core.tgz");
  const tgz = join(repoRoot, "nmzp-core.tgz");
  writeFileSync(tgzPack, tgzBuf);
  writeFileSync(tgz, tgzBuf);
  const tgzHash = createHash("sha256").update(tgzBuf).digest("hex");
  const releaseChecksum = join(packRoot, "SHA256SUMS.txt");
  const fileManifest = join(packRoot, "nmzp-files.sha256");
  await writeFile(releaseChecksum, `${tgzHash}${CHECKSUM_SEPARATOR}nmzp-core.tgz\n`);
  const manifest = files.map((file) => `${file.sha256}${CHECKSUM_SEPARATOR}nmzp/${file.path}`).join("\n");
  await writeFile(fileManifest, manifest.length > 0 ? `${manifest}\n` : "");
  const staleSums = join(packRoot, "SHA256SUMS");
  if (existsSync(staleSums)) await rm(staleSums);
  return {
    dir: packDir,
    tgz,
    files,
    releaseChecksum,
    fileManifest,
    runtimeDeps: [...runtimeDeps].sort(compareCodeUnit),
  };
}
