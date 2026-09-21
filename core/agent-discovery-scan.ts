import {
  existsSync,
  lstatSync,
  readdirSync,
  realpathSync,
  openSync,
  fstatSync,
  readSync,
  closeSync,
} from "node:fs";
import { join, dirname, resolve, relative, isAbsolute, basename } from "node:path";
import { createHmac } from "node:crypto";
import { AGENT_CATALOG, type AgentAdapter } from "./agent-catalog.ts";
import {
  DISCOVERY_SOURCES,
  discoveryProtections,
  safeVersion,
  type DiscoverySnapshot,
  type DiscoverySource,
  type DiscoveredAgent,
  type ScanStatus,
} from "./agent-discovery-schema.ts";
export interface ScanInput {
  home: string;
  pathDirs: string[];
  packageRoots: string[];
  extensionRoots: string[];
  pythonRoots: string[];
  manual: ManualPath[];
  key: string;
  os: OsMetadata;
  now: number;
}
export interface ManualPath {
  kind: "executable" | "npm-prefix" | "extensions" | "python-env";
  path: string;
}
export interface OsMetadata {
  records: Array<{
    adapterId: string;
    version?: string;
    path?: string;
    location?: string;
    source: "registry" | "appx";
    sourceId?: string; entryCandidates?: string[];
  }>;
  files: Array<{
    path: string;
    product?: string;
    description?: string;
    version?: string;
    signature?: string;
    error?: string;
  }>;
  processes: Array<{ pid: number; path: string; startedAt: number }>;
  states: Partial<Record<DiscoverySource, ScanStatus>>;
}
const norm = (p: string) => resolve(p).replaceAll("\\", "/").toLowerCase();
const within = (p: string, root: string) => {
  const r = relative(root, p);
  return !r.startsWith("..") && !isAbsolute(r);
};
export function scanMetadata(input: ScanInput): DiscoverySnapshot {
  const states = new Map<DiscoverySource, ScanStatus>(
    DISCOVERY_SOURCES.map((id) => [id, input.os.states[id] ?? "ok"]),
  );
  const items = new Map<string, DiscoveredAgent>();
  let reads = 0;
  const budget = () => {
    if (++reads > 6000) throw Error("budget");
  };
  const failed = (s: DiscoverySource, e: unknown) => {
    const code = (e as NodeJS.ErrnoException)?.code;
    states.set(s, code === "EACCES" || code === "EPERM" ? "permission" : "partial");
  };
  const file = (p: string, s: DiscoverySource, max = 256_000): Buffer | undefined => {
    budget();
    let fd: number | undefined;
    try {
      const st = lstatSync(p);
      if (
        !st.isFile() ||
        st.isSymbolicLink() ||
        st.size > max ||
        norm(realpathSync(p)) !== norm(p)
      ) {
        states.set(s, "partial");
        return;
      }
      fd = openSync(p, "r");
      const actual = fstatSync(fd);
      if (!actual.isFile() || actual.size > max) {
        states.set(s, "partial");
        return;
      }
      const b = Buffer.alloc(max + 1);
      const n = readSync(fd, b, 0, b.length, 0);
      if (n > max) {
        states.set(s, "partial");
        return;
      }
      return b.subarray(0, n);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "ENOENT") failed(s, e);
    } finally {
      if (fd !== undefined) closeSync(fd);
    }
  };
  const json = (p: string, s: DiscoverySource): any => {
    const b = file(p, s);
    if (!b) return;
    try {
      return JSON.parse(b.toString("utf8"));
    } catch {
      states.set(s, "partial");
    }
  };
  const dirs = (p: string, s: DiscoverySource): string[] => {
    budget();
    try {
      const rows = readdirSync(p, { withFileTypes: true });
      if (rows.length > 500) states.set(s, "partial");
      return rows
        .slice(0, 500)
        .filter((e) => e.isDirectory() && !e.isSymbolicLink())
        .map((e) => e.name);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "ENOENT") failed(s, e);
      return [];
    }
  };
  const add = (
    a: AgentAdapter,
    p: string,
    source: DiscoverySource,
    evidence: DiscoveredAgent["evidence"],
    corroborated: boolean,
    version?: unknown,
    proc?: { pid: number; startedAt: number },
  ) => {
    if (a.unsupported) return;
    const instanceId =
      "di_" +
      createHmac("sha256", input.key)
        .update(a.id + "|" + (p.startsWith("registry:") ? p : norm(p)))
        .digest("hex")
        .slice(0, 32);
    let item = items.get(instanceId);
    if (!item) {
      if (items.size >= 128) {
        states.set(source, "partial");
        return;
      }
      item = {
        instanceId,
        adapterId: a.id,
        version: safeVersion(version),
        installation: corroborated ? "present" : "candidate",
        running: "unknown",
        identity: corroborated ? "corroborated" : "candidate",
        scopeEligible: false,
        evidence: [],
        reasons: [],
        sources: [],
        processes: [],
        firstSeen: input.now,
        lastSeen: input.now,
        lastChecked: input.now,
        integration: "not_bound",
        protection: "not_verified",
        protections: discoveryProtections(a.id),
      };
      items.set(instanceId, item);
    }
    item.evidence = [...new Set([...item.evidence, ...evidence])];
    item.sources = [...new Set([...item.sources, source])];
    if (corroborated) {
      item.installation = "present";
      item.identity = "corroborated";
    }
    if (safeVersion(version)) item.version = safeVersion(version);
    if (proc && !item.processes.some((p) => p.pid === proc.pid && p.startedAt === proc.startedAt)) {
      if (item.processes.length < 32) item.processes.push(proc);
      else states.set("processes", "partial");
    }
  };
  // Resolve only candidates enumerated beside actual installation metadata; ambiguity stays unresolved.
  input = {...input, os:{...input.os, records:input.os.records.map(r=>{
    if(r.path || !r.entryCandidates)return r;
    const a=AGENT_CATALOG.find(a=>a.id===r.adapterId);
    const matches=input.os.files.filter(f=>!f.error && r.entryCandidates!.some(p=>norm(p)===norm(f.path)) && a?.names?.some(n=>n.toLowerCase()===f.product?.toLowerCase()));
    return matches.length===1 ? {...r,path:matches[0].path} : r;
  })}};
  // Registry is a candidate until a corresponding actual file carries consistent product metadata.
  for (const r of input.os.records.slice(0, 500)) {
    const a = AGENT_CATALOG.find((a) => a.id === r.adapterId);
    if (!a) continue;
    const p = r.sourceId ? "registry:"+r.sourceId : r.path || r.location || "registry:unresolved:"+r.adapterId;
    const f = input.os.files.find((f) => r.path && norm(f.path) === norm(r.path));
    const consistent =
      !!f &&
      !f.error &&
      (a.names ?? []).some((n) => n.toLowerCase() === (f.product ?? "").toLowerCase());
    const appx = r.source === "appx" && !!r.path && existsSync(r.path);
    add(
      a,
      p,
      r.source,
      [
        r.source === "appx" ? "appx_record" : "uninstall_record",
        ...(consistent ? ["file_metadata" as const] : []),
      ],
      consistent || appx,
      r.version,
    );
  }
  for (const f of input.os.files.slice(0, 256)) {
    if (!f.path || f.path.replaceAll("\\", "/").toLowerCase().includes("/node_modules/")) continue;
    const record = input.os.records.find((r) => r.path && norm(r.path) === norm(f.path));
    // A registry identity already owns its entryCandidates; extra PE files in that group are not separate installs.
    if (
      !record &&
      input.os.records.some((r) => {
        if (!r.entryCandidates?.some((p) => norm(p) === norm(f.path))) return false;
        const adapter = AGENT_CATALOG.find((a) => a.id === r.adapterId);
        return !!adapter?.names?.some((n) => n.toLowerCase() === (f.product ?? "").toLowerCase());
      })
    )
      continue;
    const possible = AGENT_CATALOG.filter(
      (a) =>
        a.form !== "extension" &&
        !a.unsupported &&
        (record?.source === "appx"
          ? a.id === record.adapterId
          : (a.names ?? []).some((n) => n.toLowerCase() === (f.product ?? "").toLowerCase()) ||
            a.command?.toLowerCase() + ".exe" === basename(f.path).toLowerCase() ||
            a.id === record?.adapterId),
    );
    // Ambiguous CLI / desktop metadata cannot resolve a form by product name alone.
    for (const a of possible) {
      const productMatches = (a.names ?? []).some(
        (n) => n.toLowerCase() === (f.product ?? "").toLowerCase(),
      );
      const consistent =
        (productMatches || record?.source === "appx") && possible.length === 1 && !f.error;
      const processes = input.os.processes.filter((p) => norm(p.path) === norm(f.path));
      const src: DiscoverySource = processes.length
        ? "processes"
        : input.manual.some((m) => norm(m.path) === norm(f.path))
          ? "manual"
          : record
            ? "registry"
            : "path";
      const ev: DiscoveredAgent["evidence"] = [
        ...(productMatches ? ["file_metadata" as const] : []),
        f.signature === "Valid" ? "signature_valid" : "signature_unverified",
        ...(src === "manual"
          ? ["manual_path" as const]
          : src === "path"
            ? ["path_entry" as const]
            : []),
      ];
      const version = record?.version ?? (a.form === "cli" ? f.version : undefined); // Electron runtime version is not the app version.
      add(a, record?.sourceId ? "registry:"+record.sourceId : f.path, src, ev, consistent, version);
      for (const p of processes)
        add(a, record?.sourceId ? "registry:"+record.sourceId : f.path, "processes", [...ev, "process_identity"], consistent, version, {
          pid: p.pid,
          startedAt: p.startedAt,
        });
    }
  }
  // Unresolved registry groups skip extra PE files; still attach uniquely owned stable processes as candidate runtime.
  const recordKey = (r: ScanInput["os"]["records"][number]) =>
    r.sourceId ? "registry:" + r.sourceId : r.path || r.location || "registry:unresolved:" + r.adapterId;
  for (const proc of input.os.processes) {
    const file = input.os.files.find((f) => !f.error && f.path && norm(f.path) === norm(proc.path));
    if (!file) continue;
    const owners = input.os.records.filter((r) => {
      if (!r.entryCandidates?.some((p) => norm(p) === norm(file.path))) return false;
      const adapter = AGENT_CATALOG.find((a) => a.id === r.adapterId);
      return !!adapter?.names?.some((n) => n.toLowerCase() === (file.product ?? "").toLowerCase());
    });
    if (owners.length !== 1) continue;
    const r = owners[0]!;
    const a = AGENT_CATALOG.find((x) => x.id === r.adapterId);
    if (!a || a.unsupported) continue;
    add(a, recordKey(r), "processes", ["process_identity"], false, r.version, {
      pid: proc.pid,
      startedAt: proc.startedAt,
    });
  }
  const prefixes = [
    ...new Set([
      ...input.packageRoots,
      ...input.pathDirs,
      ...input.manual.filter((m) => m.kind === "npm-prefix").map((m) => m.path),
    ]),
  ].slice(0, 128);
  for (const prefix of prefixes) {
    if (!isAbsolute(prefix) || /(^|[\\/])node_modules([\\/]|$)/i.test(prefix)) continue;
    // Project package.json at a PATH directory means this is not a global installation root.
    if (existsSync(join(prefix, "package.json"))) continue;
    for (const a of AGENT_CATALOG.filter((a) => a.npm)) {
      const root = join(prefix, "node_modules", a.npm!);
      const p = join(root, "package.json");
      const m = json(p, "packages");
      if (!m || m.name !== a.npm) continue;
      const entry = typeof m.bin === "string" ? m.bin : m.bin?.[a.command!];
      if (typeof entry !== "string" || !within(resolve(root, entry), root)) {
        states.set("packages", "partial");
        continue;
      }
      try {
        if (
          !within(realpathSync(resolve(root, entry)), realpathSync(root)) ||
          !lstatSync(resolve(root, entry)).isFile()
        )
          continue;
      } catch {
        states.set("packages", "partial");
        continue;
      }
      add(a, root, "packages", ["npm_manifest"], true, m.version);
    }
  }
  // VS Code forks advertise their real data-folder name in installation product metadata.
  // Never infer an IDE's entire activity belongs to a plugin, and never read user settings.json.
  const ideRoots: string[] = [];
  for (const f of input.os.files) {
    const isIde =
      /^(Code|Code - Insiders)\.exe$/i.test(basename(f.path)) ||
      AGENT_CATALOG.some(
        (a) =>
          a.form === "desktop" &&
          !a.unsupported &&
          a.names?.some((n) => n.toLowerCase() === f.product?.toLowerCase()),
      );
    if (!isIde) continue;
    const product = json(join(dirname(f.path), "resources", "app", "product.json"), "extensions");
    if (
      typeof product?.dataFolderName === "string" &&
      /^\.[a-z][a-z0-9-]{1,40}$/i.test(product.dataFolderName)
    )
      ideRoots.push(join(input.home, product.dataFolderName, "extensions"));
    ideRoots.push(join(dirname(f.path), "data", "extensions"));
  }
  const extRoots = [
    ...new Set([
      ...input.extensionRoots,
      ...ideRoots,
      ...input.manual.filter((m) => m.kind === "extensions").map((m) => m.path),
    ]),
  ];
  for (const root of extRoots.slice(0, 32)) {
    // Read the installed extension index, never .vscode/extensions.json workspace recommendations.
    const index = json(join(root, "extensions.json"), "extensions");
    if (index === undefined) continue;
    if (!Array.isArray(index)) {
      states.set("extensions", "partial");
      continue;
    }
    if (index.length > 500) states.set("extensions", "partial");
    for (const row of index.slice(0, 500)) {
      const a = AGENT_CATALOG.find(
        (a) => a.extension?.toLowerCase() === String(row?.identifier?.id).toLowerCase(),
      );
      if (!a) continue;
      const rel = row.relativeLocation;
      if (typeof rel !== "string" || !within(resolve(root, rel), root)) {
        states.set("extensions", "partial");
        continue;
      }
      const dir = resolve(root, rel);
      const m = json(join(dir, "package.json"), "extensions");
      if (
        !m ||
        `${m.publisher}.${m.name}`.toLowerCase() !== a.extension!.toLowerCase() ||
        m.version !== row.version
      ) {
        states.set("extensions", "partial");
        continue;
      }
      add(a, dir, "extensions", ["extension_index", "extension_manifest"], true, m.version);
    }
  }
  // uv tool / pipx virtual environments. METADATA is read statically; Python is never started.
  for (const env of [
    ...input.pythonRoots,
    ...input.manual.filter((m) => m.kind === "python-env").map((m) => m.path),
  ].slice(0, 32)) {
    const site = join(env, "Lib", "site-packages");
    for (const d of dirs(site, "packages").filter((n) => /^aider_chat-.*\.dist-info$/i.test(n))) {
      const text = file(join(site, d, "METADATA"), "packages")?.toString("utf8");
      if (
        !text ||
        !/^Name: aider-chat\r?$/im.test(text) ||
        !existsSync(join(env, "Scripts", "aider.exe"))
      )
        continue;
      add(
        AGENT_CATALOG.find((a) => a.id === "aider-cli")!,
        env,
        "packages",
        ["python_metadata"],
        true,
        /^Version: (.+)\r?$/im.exec(text)?.[1]?.trim(),
      );
    }
  }
  for (const item of items.values()) {
    const a = AGENT_CATALOG.find((a) => a.id === item.adapterId)!;
    item.running = item.evidence.includes("uninstall_record") && !item.evidence.includes("file_metadata") && !item.processes.length ? "unknown" :
      a.form === "extension" || item.sources.includes("packages")
        ? "unknown"
        : item.processes.length
          ? "observed"
          : states.get("processes") === "ok"
            ? "not_observed"
            : "unknown";
    item.reasons = [
      item.identity === "candidate" ? "name_only" : "publisher_not_pinned",
      ...(item.evidence.includes("uninstall_record") && !item.evidence.includes("file_metadata") ? ["entry_unresolved" as const] : []),
      "instance_not_bound",
      ...(a.form === "extension"
        ? ["shared_host" as const]
        : item.running === "unknown"
          ? ["runtime_unattributed" as const]
          : []),
    ];
  }
  const sources = DISCOVERY_SOURCES.map((id) => ({ id, status: states.get(id)! }));
  return {
    schemaVersion: 1,
    platform: "win32",
    checkedAt: input.now,
    completedAt: Math.max(input.now, Date.now()),
    status: sources.every((s) => s.status === "ok") ? "ok" : "partial",
    sources,
    items: [...items.values()],
  };
}
