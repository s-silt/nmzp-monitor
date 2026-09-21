import assert from "node:assert/strict";
import { it, describe } from "node:test";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { AGENT_CATALOG } from "./agent-catalog.ts";
import { scanMetadata, type ScanInput } from "./agent-discovery-scan.ts";
import {
  DISCOVERY_TTL_MS,
  parseDiscovery,
  mergeDiscovery,
  discoveryStale,
} from "./agent-discovery-schema.ts";
import { validateManualPaths, scanWorker, refreshDiscovery } from "./agent-discovery.ts";
import { windowsDiscoveryScript } from "./agent-discovery-windows.ts";
import { collectAgentTcp } from "./network-collect.ts";
const now = Date.now();
function fixture() {
  const home = mkdtempSync(join(tmpdir(), "nmzp-discovery-test-"));
  const input: ScanInput = {
    home,
    key: "synthetic-not-a-real-key",
    now,
    os: { records: [], files: [], processes: [], states: {} },
    manual: [],
    pathDirs: [],
    packageRoots: [],
    extensionRoots: [],
    pythonRoots: [],
  };
  return { home, input, clean: () => rmSync(home, { recursive: true, force: true }) };
}
function write(p: string, value: unknown) {
  mkdirSync(join(p, ".."), { recursive: true });
  writeFileSync(p, typeof value === "string" ? value : JSON.stringify(value));
}
describe("bounded discovery and identity", () => {
  it("actual network sampler does not query OS without independently owned identities", async () => {
    const s = await collectAgentTcp({
      stopped: false,
      deps: { platform: "win32", now: () => 123 },
    });
    assert.deepEqual(s, {
      status: "not_sampled",
      observedAt: 123,
      connections: [],
      error: "no_confirmed_agent",
    });
  });
  it("installed, run, PID reuse, exit, upgrade, uninstall use distinct facts and preserve lastSeen", () => {
    const f = fixture();
    try {
      const p = join(f.home, "custom", "Cursor.exe");
      write(p, "synthetic");
      f.input.os.records = [
        { adapterId: "cursor-desktop", path: p, version: "3.21.0", source: "registry" },
      ];
      f.input.os.files = [{ path: p, product: "Cursor", version: "153.0.0", signature: "Valid" }];
      const installed = scanMetadata(f.input);
      assert.equal(installed.items[0].installation, "present");
      assert.equal(installed.items[0].running, "not_observed");
      assert.equal(installed.items[0].version, "3.21.0");
      f.input.os.processes = [{ pid: 10, path: p, startedAt: now - 1000 }];
      const running = mergeDiscovery(installed, scanMetadata(f.input));
      assert.equal(running.items[0].running, "observed");
      assert.equal(running.items[0].scopeEligible, false);
      f.input.os.processes = [{ pid: 10, path: join(f.home, "other.exe"), startedAt: now }];
      assert.equal(scanMetadata(f.input).items[0].running, "not_observed");
      f.input.os.processes = [];
      f.input.os.records[0].version = "3.22.0";
      const upgraded = mergeDiscovery(running, scanMetadata(f.input));
      assert.equal(upgraded.items[0].version, "3.22.0");
      assert.equal(upgraded.items[0].instanceId, installed.items[0].instanceId);
      f.input.os.records = [];
      f.input.os.files = [];
      const gone = mergeDiscovery(upgraded, scanMetadata(f.input));
      assert.equal(gone.items[0].installation, "not_found");
      assert.equal(gone.items[0].lastSeen, upgraded.items[0].lastSeen);
    } finally {
      f.clean();
    }
  });
  it("portable, custom path and multiple versions have independent identities", () => {
    const f = fixture();
    try {
      for (const v of ["1", "2"]) {
        const p = join(f.home, v, "TRAE.exe");
        write(p, "fake PE");
        f.input.os.files.push({ path: p, product: "TRAE", signature: "Valid" });
        f.input.os.processes.push({ pid: 10 + Number(v), startedAt: now - 100, path: p });
      }
      const s = scanMetadata(f.input);
      assert.equal(s.items.length, 2);
      assert.notEqual(s.items[0].instanceId, s.items[1].instanceId);
      assert.ok(
        s.items.every(
          (i) => i.running === "observed" && !i.scopeEligible && i.version === undefined,
        ),
      );
    } finally {
      f.clean();
    }
  });
  it("renamed executable, project node_modules, Node/Python and parent names cannot authorize identity", () => {
    const f = fixture();
    try {
      for (const name of ["grok.exe", "claude.exe", "node.exe", "python.exe", "Code.exe"]) {
        const p = join(f.home, name);
        f.input.os.files.push({ path: p, product: "Unrelated", signature: "Valid" });
        f.input.os.processes.push({ pid: 10, startedAt: now - 10, path: p });
      }
      f.input.os.files.push({
        path: join(f.home, "project", "node_modules", "codex.exe"),
        product: "Codex",
      });
      const s = scanMetadata(f.input);
      assert.deepEqual(s.items.map((i) => i.adapterId).sort(), ["claude-code-cli", "grok-cli"]);
      assert.ok(
        s.items.every(
          (i) => i.identity === "candidate" && i.installation === "candidate" && !i.scopeEligible,
        ),
      );
    } finally {
      f.clean();
    }
  });
  it("Claude CLI and Desktop forms remain separate even with a shared filename", () => {
    const f = fixture();
    try {
      f.input.os.files = [
        { path: join(f.home, "code", "claude.exe"), product: "Claude Code" },
        { path: join(f.home, "desktop", "Claude.exe"), product: "Claude" },
      ];
      const s = scanMetadata(f.input);
      const desktop = s.items.find((i) => i.adapterId === "claude-desktop");
      assert.ok(desktop);
      assert.equal(desktop.identity, "candidate"); // basename also suggests CLI: no silent promotion.
      assert.ok(s.items.some((i) => i.adapterId === "claude-code-cli"));
    } finally {
      f.clean();
    }
  });
  it("every supported desktop adapter detects metadata without granting scope", () => {
    const f = fixture();
    try {
      for (const a of AGENT_CATALOG.filter((a) => a.form === "desktop" && !a.unsupported)) {
        const p = join(f.home, a.id, "app.exe");
        write(p, "fixture");
        f.input.os.records = [{ adapterId: a.id, path: p, version: "1.2.3", source: "registry" }];
        f.input.os.files = [{ path: p, product: a.names![0] }];
        const s = scanMetadata(f.input);
        assert.ok(
          s.items.some((i) => i.adapterId === a.id && i.installation === "present"),
          a.id,
        );
        assert.ok(s.items.every((i) => !i.scopeEligible));
      }
    } finally {
      f.clean();
    }
  });
  it("all official npm identifiers require actual entry files; no candidate execution", () => {
    const f = fixture();
    try {
      const prefix = join(f.home, "global");
      f.input.packageRoots = [prefix];
      for (const a of AGENT_CATALOG.filter((a) => a.npm)) {
        const root = join(prefix, "node_modules", a.npm!);
        write(join(root, "package.json"), {
          name: a.npm,
          version: "1.2.3",
          bin: { [a.command!]: "bin.js" },
          scripts: { postinstall: "DO NOT RUN" },
        });
        write(join(root, "bin.js"), 'throw Error("must never execute")');
      }
      const s = scanMetadata(f.input);
      assert.equal(s.items.length, AGENT_CATALOG.filter((a) => a.npm).length);
      assert.ok(s.items.every((i) => i.running === "unknown" && i.installation === "present"));
      write(join(prefix, "package.json"), { private: true });
      assert.equal(scanMetadata(f.input).items.length, 0);
    } finally {
      f.clean();
    }
  });
  it("all extension IDs require installed index + matching manifest, never claim plugin is running", () => {
    const f = fixture();
    try {
      const root = join(f.home, "extensions");
      f.input.extensionRoots = [root];
      const index = [];
      for (const a of AGENT_CATALOG.filter((a) => a.extension)) {
        const [publisher, name] = a.extension!.split(".");
        const rel = a.extension + "-1.2.3";
        index.push({ identifier: { id: a.extension }, version: "1.2.3", relativeLocation: rel });
        write(join(root, rel, "package.json"), { publisher, name, version: "1.2.3" });
      }
      write(join(root, "extensions.json"), index);
      const s = scanMetadata(f.input);
      assert.equal(s.items.length, index.length);
      assert.ok(s.items.every((i) => i.running === "unknown" && i.processes.length === 0));
      write(join(root, "extensions.json"), { recommendations: index.map((i) => i.identifier.id) });
      const bad = scanMetadata(f.input);
      assert.equal(bad.items.length, 0);
      assert.equal(bad.status, "partial");
    } finally {
      f.clean();
    }
  });
  it("partial errors and timeout preserve history without invented absence or fresh lastSeen", () => {
    const f = fixture();
    try {
      f.input.os.files = [{ path: join(f.home, "grok.exe"), product: "Grok" }];
      const before = scanMetadata(f.input);
      for (const status of ["timeout", "permission", "error", "partial"] as const) {
        f.input.os.files = [];
        f.input.os.states = { path: status, processes: status };
        const after = mergeDiscovery(before, scanMetadata(f.input));
        assert.equal(after.items[0].installation, "unknown");
        assert.equal(after.items[0].running, "unknown");
        assert.equal(after.items[0].lastSeen, before.items[0].lastSeen);
      }
      assert.equal(discoveryStale(before, before.completedAt + DISCOVERY_TTL_MS + 1), true);
    } finally {
      f.clean();
    }
  });
  it("projection removes private paths, extra fields, and uploaded protection self-attestation", () => {
    const f = fixture();
    try {
      f.input.os.files = [{ path: join(f.home, "grok.exe"), product: "Grok" }];
      const s = scanMetadata(f.input);
      const raw = JSON.parse(JSON.stringify(s));
      raw.path = "PRIVATE_HOME";
      raw.items[0].path = "PRIVATE_HOME";
      raw.items[0].scopeEligible = true;
      raw.items[0].protection = "verified";
      const parsed = parseDiscovery(raw)!;
      assert.equal(parsed.items[0].scopeEligible, false);
      assert.equal(parsed.items[0].protection, "not_verified");
      assert.ok(!JSON.stringify(parsed).includes("PRIVATE_HOME"));
      assert.equal(parseDiscovery({ ...s, completedAt: now + 1e9 }), undefined);
      raw.items[0].evidence = ["PRIVATE_SECRET"];
      assert.equal(parseDiscovery(raw), undefined);
    } finally {
      f.clean();
    }
  });
  it("manual input rejects network paths, relative paths, traversal, excessive lists and project modules", () => {
    for (const p of [
      "x.exe",
      "\\\\host\\share\\grok.exe",
      "C:\\project\\node_modules\\grok.exe",
      "C:\\a\\..\\b",
    ])
      assert.throws(() => validateManualPaths([{ kind: "executable", path: p }]));
    assert.throws(() =>
      validateManualPaths(Array(25).fill({ kind: "extensions", path: "C:\\ext" })),
    );
  });
  it("OS script never requests command lines or invokes a candidate; queries exact process start time twice", () => {
    const s = windowsDiscoveryScript([], "C:\\synthetic");
    assert.doesNotMatch(s, /CommandLine|Start-Process|Invoke-Expression|Win32_Product/);
    assert.match(s, /CreationDate/);
    assert.match(s, /Get-AppxPackageManifest/);
    assert.match(s, /Get-AuthenticodeSignature/);
  });
  it("actual IDE product metadata locates installed extensions without promoting the host", () => {
    const f = fixture();
    try {
      const exe = join(f.home, "portable", "Antigravity.exe");
      write(exe, "fixture");
      f.input.os.files = [{ path: exe, product: "Antigravity" }];
      write(join(f.home, "portable", "resources", "app", "product.json"), {
        dataFolderName: ".synthetic-ide",
      });
      const root = join(f.home, ".synthetic-ide", "extensions");
      write(join(root, "extensions.json"), [
        { identifier: { id: "GitHub.copilot" }, version: "1.2.3", relativeLocation: "copilot" },
      ]);
      write(join(root, "copilot", "package.json"), {
        publisher: "GitHub",
        name: "copilot",
        version: "1.2.3",
      });
      const s = scanMetadata(f.input);
      assert.ok(s.items.some((i) => i.adapterId === "antigravity-desktop"));
      const ext = s.items.find((i) => i.adapterId === "copilot-extension")!;
      assert.equal(ext.installation, "present");
      assert.equal(ext.running, "unknown");
      assert.deepEqual(ext.processes, []);
      write(join(f.home, "portable", "resources", "app", "product.json"), {
        dataFolderName: "../../PRIVATE",
      });
      assert.ok(!scanMetadata(f.input).items.some((i) => i.adapterId === "copilot-extension"));
    } finally {
      f.clean();
    }
  });
  it("Appx application version wins over Electron runtime and bundled CLI remains separate", () => {
    const f = fixture();
    try {
      const exe = join(f.home, "app", "ChatGPT.exe");
      write(exe, "fixture");
      f.input.os.records = [
        { adapterId: "codex-desktop", path: exe, version: "26.915.4065.0", source: "appx" },
      ];
      f.input.os.files = [
        { path: exe, product: "Electron", version: "40.0.0" },
        { path: join(f.home, "app", "codex.exe"), product: "unrelated" },
      ];
      const s = scanMetadata(f.input);
      assert.equal(s.items.find((i) => i.adapterId === "codex-desktop")?.version, "26.915.4065.0");
      assert.equal(s.items.find((i) => i.adapterId === "codex-cli")?.identity, "candidate");
    } finally {
      f.clean();
    }
  });
  it("Python metadata requires exact distribution and entry; oversized metadata makes source incomplete", () => {
    const f = fixture();
    try {
      const env = join(f.home, "python");
      f.input.pythonRoots = [env];
      const meta = join(env, "Lib", "site-packages", "aider_chat-1.0.dist-info", "METADATA");
      write(meta, "Name: aider-chat\nVersion: 1.2.3\n");
      assert.equal(scanMetadata(f.input).items.length, 0);
      write(join(env, "Scripts", "aider.exe"), "never executed");
      let s = scanMetadata(f.input);
      assert.equal(s.items[0].version, "1.2.3");
      assert.equal(s.items[0].running, "unknown");
      write(meta, "Name: ordinary-python\nVersion: 1.2.3\n");
      assert.equal(scanMetadata(f.input).items.length, 0);
      write(meta, "x".repeat(256001));
      s = scanMetadata(f.input);
      assert.equal(s.status, "partial");
      assert.equal(s.items.length, 0);
    } finally {
      f.clean();
    }
  });
  it("worker timeout terminates own worker; refresh deduplicates overlapping calls", async () => {
    const f = fixture();
    try {
      const timed = await scanWorker(f.input, 1);
      assert.equal(timed.status, "timeout");
      let calls = 0;
      const deps = {
        platform: "win32",
        os: async () => {
          calls++;
          await new Promise((r) => setTimeout(r, 20));
          return f.input.os;
        },
        scan: async () => scanMetadata(f.input),
      };
      const [a, b] = await Promise.all([
        refreshDiscovery(f.home, true, deps),
        refreshDiscovery(f.home, true, deps),
      ]);
      assert.deepEqual(a, b);
      assert.equal(calls, 1);
      assert.ok(
        parseDiscovery(JSON.parse(readFileSync(join(f.home, ".nmzp", "discovery.json"), "utf8"))),
      );
      const failed = await refreshDiscovery(f.home, true, {
        platform: "win32",
        os: async () => {
          throw Error("PRIVATE_PATH");
        },
      });
      assert.equal(failed.status, "error");
      assert.equal(
        JSON.parse(readFileSync(join(f.home, ".nmzp", "discovery.json"), "utf8")).status,
        "error",
      );
      const inconsistent = { ...a, status: "ok", sources: [], items: [] };
      assert.equal(parseDiscovery(inconsistent)?.status, "partial");
    } finally {
      f.clean();
    }
  });
});
