import { cp, mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { existsSync, writeFileSync } from "node:fs";
import { dirname, join, resolve, win32 } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";
import { NMZP_VERSION } from "./constants.ts";

function normalizeCmp(s: string): string {
  return resolve(s).replace(/\\/g, "/").replace(/\/+$/, "").toLowerCase();
}

export function resolveInsidePackDir(repoRoot: string, target: string): string {
  const packRoot = resolve(repoRoot, ".pack");
  const resolved = resolve(target);
  const rootCmp = normalizeCmp(packRoot);
  const targetCmp = normalizeCmp(resolved);
  if (targetCmp !== rootCmp && !targetCmp.startsWith(`${rootCmp}/`)) {
    throw new Error(`pack_rm_outside_pack_dir:${resolved}`);
  }
  return resolved;
}

function windowsFileUrlPath(metaUrl: string): string | undefined {
  let url: URL;
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

function isWindowsPath(p: string): boolean {
  return /^[A-Za-z]:[\\/]/.test(p) || p.startsWith("\\\\");
}

function foldWin(p: string): string {
  return win32.normalize(p).replace(/[/\\]+$/, "").toLowerCase();
}

export function isPackEntrypoint(metaUrl: string, argv1?: string, cwd = process.cwd()): boolean {
  if (!argv1) return false;
  const winSelf = windowsFileUrlPath(metaUrl);
  if (winSelf && (isWindowsPath(argv1) || isWindowsPath(cwd) || argv1.includes("\\"))) {
    const invoked = isWindowsPath(argv1) ? argv1 : win32.resolve(isWindowsPath(cwd) ? cwd : win32.dirname(winSelf), argv1);
    return foldWin(winSelf) === foldWin(invoked);
  }
  let self: string;
  try {
    self = fileURLToPath(metaUrl);
  } catch {
    return false;
  }
  const invoked = resolve(cwd, argv1);
  return normalizeCmp(self) === normalizeCmp(invoked);
}

function octal(n: number, width: number): string {
  return n.toString(8).padStart(width - 1, "0") + "\0";
}

function compareCodeUnit(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

const CHECKSUM_SEPARATOR = "  ";

function entryBase(name: string): string {
  const trimmed = name.endsWith("/") ? name.slice(0, -1) : name;
  const slash = trimmed.lastIndexOf("/");
  return slash >= 0 ? trimmed.slice(slash + 1) : trimmed;
}

function startsWithShebang(buf: Buffer): boolean {
  return buf.length >= 2 && buf[0] === 0x23 && buf[1] === 0x21;
}

const SHIPPED_TEXT_EXTENSIONS = new Set([
  ".ts",
  ".js",
  ".mjs",
  ".json",
  ".md",
  ".txt",
  ".yaml",
  ".yml",
  ".toml",
  ".html",
  ".css",
  ".svg",
  ".ps1",
  ".cmd",
  ".bat",
  ".service",
  ".sh",
]);

const SHIPPED_LICENSE_NAMES = new Set(["license", "licence", "copying", "notice"]);

function isShippedText(relPath: string): boolean {
  const base = entryBase(relPath).toLowerCase();
  if (SHIPPED_LICENSE_NAMES.has(base) || base.endsWith(".license") || base.endsWith(".licence")) return true;
  const dot = base.lastIndexOf(".");
  return dot >= 0 && SHIPPED_TEXT_EXTENSIONS.has(base.slice(dot));
}

function crlfToLf(buf: Buffer): Buffer {
  if (!buf.includes(0x0d)) return buf;
  const out = Buffer.alloc(buf.length);
  let written = 0;
  let changed = false;
  for (let index = 0; index < buf.length; index++) {
    const byte = buf[index]!;
    if (byte === 0x0d && buf[index + 1] === 0x0a) {
      changed = true;
      continue;
    }
    out[written++] = byte;
  }
  if (!changed) return buf;
  return Buffer.from(out.subarray(0, written));
}

// Stage recognized UTF-8 text as LF before hashes and the archive. A NUL byte stays binary.
function normalizeShippedText(relPath: string, buf: Buffer): Buffer {
  if (buf.includes(0)) return buf;
  if (!isShippedText(relPath) && !startsWithShebang(buf)) return buf;
  return crlfToLf(buf);
}

function executableTarMode(name: string, data: Buffer): number {
  const base = entryBase(name);
  if (base === "nmzp" || base === "nmzp.mjs" || base.endsWith(".sh") || startsWithShebang(data)) return 0o755;
  return 0o644;
}

const TAR_MTIME_MAX = 0o77777777777;

function archiveTimestamp(): number {
  const raw = process.env.SOURCE_DATE_EPOCH;
  if (raw === undefined) return 0;
  const value = Number(raw);
  if (!/^\d{1,11}$/.test(raw) || !Number.isSafeInteger(value) || value > TAR_MTIME_MAX) {
    throw new Error("pack_invalid_source_date_epoch");
  }
  return value;
}

function archivePath(entry: { name: string; dir?: boolean }): string {
  if (entry.dir && !entry.name.endsWith("/")) return `${entry.name}/`;
  return entry.name;
}

function tarHeader(name: string, size: number, type: string, mode: number, mtime: number): Buffer {
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
  for (let i = 0; i < 512; i++) sum += buf[i]!;
  const chk = `${sum.toString(8).padStart(6, "0")}\0 `;
  Buffer.from(chk, "utf8").copy(buf, 148);
  return buf;
}

function pad512(data: Buffer): Buffer {
  const rem = data.length % 512;
  if (rem === 0) return data;
  return Buffer.concat([data, Buffer.alloc(512 - rem)]);
}

export function createTarGz(
  entries: Array<{ name: string; data: Buffer; dir?: boolean }>,
  mtime = archiveTimestamp(),
): Buffer {
  const parts: Buffer[] = [];
  const ordered = entries
    .slice()
    .sort((a, b) => compareCodeUnit(archivePath(a), archivePath(b)));
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
  // Bytes 4-7 are MTIME and byte 9 is OS; both vary by clock and host.
  gz[4] = 0;
  gz[5] = 0;
  gz[6] = 0;
  gz[7] = 0;
  gz[9] = 255;
  return gz;
}

export type PackReleaseResult = {
  dir: string;
  tgz: string;
  files: Array<{ path: string; sha256: string; bytes: number }>;
  releaseChecksum: string;
  fileManifest: string;
};

export async function packRelease(repoRoot: string): Promise<PackReleaseResult> {
  const archivedAt = archiveTimestamp();
  if (!existsSync(join(repoRoot, "dist", "index.html"))) {
    throw new Error("pack_missing_ui_dist");
  }
  if (!existsSync(join(repoRoot, "core", "nmzp.mjs"))) {
    throw new Error("pack_missing_core_entry");
  }
  const packRoot = resolveInsidePackDir(repoRoot, join(repoRoot, ".pack"));
  const packDir = resolveInsidePackDir(repoRoot, join(repoRoot, ".pack", "nmzp"));
  if (existsSync(packDir)) await rm(packDir, { recursive: true, force: true });
  await mkdir(packDir, { recursive: true });
  const coreDir = join(repoRoot, "core");
  const names = await readdir(coreDir);
  for (const name of names) {
    if (name.endsWith(".test.ts")||name.endsWith(".test.ps1")) continue;
    // Experimental native/gateway components are reviewed separately, never shipped implicitly.
    if (name.startsWith("native-") || name.startsWith("model-gateway") || name.startsWith("protected-session") || name.startsWith("model-response")) continue;
    if (name === "Dockerfile") continue;
    await cp(join(coreDir, name), join(packDir, name), {
      recursive: true,
      filter: (src) => !/\.(?:test|spec)\.(?:[cm]?[jt]s|ps1)$/.test(src),
    });
  }
  await cp(join(repoRoot, "src", "lib", "monitor"), join(packDir, "monitor"), {
    recursive: true,
    filter: (src) => !src.endsWith(".test.ts"),
  });
  // The shipped Hook has no npm install step. Include the locked parser and license.
  const acornRoot = dirname(dirname(fileURLToPath(import.meta.resolve("acorn"))));
  const acornPackage = JSON.parse(await readFile(join(acornRoot, "package.json"), "utf8"));
  if (acornPackage.version !== "8.18.0") throw new Error("pack_acorn_version_mismatch");
  const vendor = join(packDir, "monitor", "vendor");
  await mkdir(vendor, { recursive: true });
  await cp(join(acornRoot, "dist", "acorn.mjs"), join(vendor, "acorn.mjs"));
  await cp(join(acornRoot, "LICENSE"), join(vendor, "acorn.LICENSE"));
  const nodeData = join(packDir, "monitor", "node-data.ts");
  if (existsSync(nodeData)) await writeFile(nodeData, (await readFile(nodeData, "utf8")).replace('from "acorn"', 'from "./vendor/acorn.mjs"'));
  for (const name of ["probe-protection.ts", "zcode-hooks.ts", "zcode-events.ts"]) {
    const file = join(packDir, name);
    if (existsSync(file)) await writeFile(file, (await readFile(file, "utf8")).replaceAll("../src/lib/monitor/", "./monitor/"));
  }
  const bridge = join(packDir, "monitor", "network-evidence.ts");
  if (existsSync(bridge)) {
    const source = await readFile(bridge, "utf8");
    await writeFile(bridge, source.replaceAll('"../../../core/network-evidence.ts"', '"../network-evidence.ts"').replaceAll('"../../../core/schema.ts"', '"../schema.ts"'));
  }
  for (const name of ["response-evidence", "evidence-window", "agent-discovery-schema", "agent-catalog", "egress-schema", "policy-schema"]) {
    const file=join(packDir,"monitor",name+".ts");
    if (existsSync(file)) await writeFile(file,(await readFile(file,"utf8")).replaceAll("../../../core/"+name+".ts","../"+name+".ts"));
  }
  const eg=join(packDir,"monitor","egress-evidence.ts");if(existsSync(eg))await writeFile(eg,(await readFile(eg,"utf8")).replaceAll("../../../core/egress-schema.ts","../egress-schema.ts"));
  await cp(join(repoRoot, "dist"), join(packDir, "ui"), { recursive: true });
  await writeFile(join(packDir, "VERSION"), `${NMZP_VERSION}\nnode>=24\n`);
  await cp(join(packDir, "nmzp.mjs"), join(packDir, "nmzp"));

  const files: Array<{ path: string; sha256: string; bytes: number }> = [];
  const tarEntries: Array<{ name: string; data: Buffer; dir?: boolean }> = [{ name: "nmzp", data: Buffer.alloc(0), dir: true }];
  async function walk(dir: string, rel: string) {
    for (const ent of await readdir(dir, { withFileTypes: true })) {
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
  return { dir: packDir, tgz, files, releaseChecksum, fileManifest };
}

export async function packMain(): Promise<void> {
  const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
  const r = await packRelease(repoRoot);
  process.stdout.write(`packed ${r.dir} files=${r.files.length} tgz=${r.tgz}\n`);
}

if (isPackEntrypoint(import.meta.url, process.argv[1])) {
  await packMain();
}
