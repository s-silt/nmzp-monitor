import { cp, mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { existsSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
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

export function isPackEntrypoint(metaUrl: string, argv1?: string, cwd = process.cwd()): boolean {
  if (!argv1) return false;
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

function tarHeader(name: string, size: number, type: string, mode: number): Buffer {
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
  buf.write(octal(Math.floor(Date.now() / 1000), 12), 136, 12, "utf8");
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

export function createTarGz(entries: Array<{ name: string; data: Buffer; dir?: boolean }>): Buffer {
  const parts: Buffer[] = [];
  for (const e of entries) {
    if (e.dir) {
      const n = e.name.endsWith("/") ? e.name : `${e.name}/`;
      parts.push(tarHeader(n, 0, "5", 0o755));
      continue;
    }
    parts.push(tarHeader(e.name, e.data.length, "0", 0o644));
    parts.push(pad512(e.data));
  }
  parts.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(parts));
}

export async function packRelease(
  repoRoot: string,
): Promise<{ dir: string; tgz: string; files: Array<{ path: string; sha256: string; bytes: number }> }> {
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
    await cp(join(coreDir, name), join(packDir, name), { recursive: true });
  }
  await cp(join(repoRoot, "src", "lib", "monitor"), join(packDir, "monitor"), {
    recursive: true,
    filter: (src) => !src.endsWith(".test.ts"),
  });
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
        const buf = await readFile(abs);
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
  files.sort((a, b) => a.path.localeCompare(b.path));
  const tgzBuf = createTarGz(tarEntries);
  const tgzPack = join(packRoot, "nmzp-core.tgz");
  const tgz = join(repoRoot, "nmzp-core.tgz");
  writeFileSync(tgzPack, tgzBuf);
  writeFileSync(tgz, tgzBuf);
  const tgzHash = createHash("sha256").update(tgzBuf).digest("hex");
  const sums = [`${tgzHash}  nmzp-core.tgz`, ...files.map((f) => `${f.sha256}  ${f.path}`)].join("\n") + "\n";
  await writeFile(join(packRoot, "SHA256SUMS"), sums);
  return { dir: packDir, tgz, files };
}

export async function packMain(): Promise<void> {
  const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
  const r = await packRelease(repoRoot);
  process.stdout.write(`packed ${r.dir} files=${r.files.length} tgz=${r.tgz}\n`);
}

if (isPackEntrypoint(import.meta.url, process.argv[1])) {
  await packMain();
}
