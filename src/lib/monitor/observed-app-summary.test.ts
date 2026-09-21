import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { DISCOVERY_SOURCES, DISCOVERY_TTL_MS, discoveryProtections } from "./agent-discovery.ts";
import { formatDateTime } from "./format.ts";
import {
  legacyAuditIdentityTitle,
  summarizeObservedAppProcesses,
  type ObservedAppSummary,
} from "./observed-app-summary.ts";
import type { DiscoveredAgent, DiscoverySnapshot } from "./agent-discovery.ts";
import type { Machine } from "./types.ts";

const NOW = 1_700_000_180_000;
const STARTED = Date.UTC(2024, 0, 1, 0, 0, 0);

function item(over: Partial<DiscoveredAgent> & Pick<DiscoveredAgent, "instanceId" | "adapterId">): DiscoveredAgent {
  return {
    version: "0.1.0",
    installation: "present",
    running: "observed",
    identity: "corroborated",
    scopeEligible: false,
    evidence: ["process_identity"],
    reasons: ["publisher_not_pinned", "instance_not_bound"],
    sources: ["processes"],
    processes: [{ pid: 15912, startedAt: STARTED }],
    firstSeen: NOW,
    lastSeen: NOW,
    lastChecked: NOW,
    integration: "not_bound",
    protection: "not_verified",
    protections: discoveryProtections(over.adapterId),
    ...over,
  };
}

function snap(over: Partial<DiscoverySnapshot> = {}): DiscoverySnapshot {
  return {
    schemaVersion: 1,
    platform: "win32",
    checkedAt: NOW,
    completedAt: NOW,
    status: "ok",
    sources: DISCOVERY_SOURCES.map((id) => ({ id, status: "ok" })),
    items: [],
    ...over,
  };
}

function machine(over: Partial<Machine> = {}): Machine {
  return {
    id: "dev_a",
    hostname: "host-a",
    ip: "10.0.0.2",
    user: "u",
    os: "win32",
    lastSeen: NOW,
    attachedAt: NOW,
    status: "online",
    ...over,
  };
}

const CODEX_DESKTOP = item({
  instanceId: "di_e5c4fbbeacda8ce822e478277974ee42",
  adapterId: "codex-desktop",
  processes: [
    { pid: 15912, startedAt: STARTED },
    { pid: 7604, startedAt: STARTED + 200 },
  ],
});
const CODEX_CLI = item({
  instanceId: "di_1ac76104eeb227ff38e161e5178bc9c1",
  adapterId: "codex-cli",
  installation: "candidate",
  identity: "candidate",
  reasons: ["name_only", "instance_not_bound"],
  processes: [{ pid: 22376, startedAt: STARTED + 400 }],
});
const ZCODE = item({
  instanceId: "di_0d4932b53fb6d700868d7478772c56bb",
  adapterId: "zcode-desktop",
  installation: "candidate",
  identity: "candidate",
  reasons: ["name_only", "entry_unresolved", "instance_not_bound"],
  evidence: ["uninstall_record", "process_identity"],
  processes: [
    { pid: 4100, startedAt: STARTED + 10 },
    { pid: 4101, startedAt: STARTED + 11 },
  ],
});

function summaryOf(
  machines: Machine[],
  over: { host?: string; now?: number; disconnected?: boolean } = {},
): ObservedAppSummary {
  return summarizeObservedAppProcesses(machines, {
    host: over.host ?? "all",
    now: over.now ?? NOW,
    disconnected: over.disconnected ?? false,
  });
}

function leak(text: string) {
  assert.equal(/C:\\|C:\/|Users\\|cmd\.exe|commandLine|cwd/i.test(text), false, text);
}

describe("summarizeObservedAppProcesses", () => {
  it("shows Codex desktop/CLI and ZCode observed metadata without treating them as tasks or protection", () => {
    const s = summaryOf([
      machine({
        discovery: snap({ items: [CODEX_DESKTOP, CODEX_CLI, ZCODE] }),
      }),
    ]);
    assert.equal(s.status, "observed");
    assert.equal(s.count, 3);
    assert.match(s.headline, /已观察到应用进程/);
    assert.match(s.headline, /3/);
    assert.match(s.note, /不等于正在执行 Agent 任务/);
    assert.match(s.note, /不表示已保护/);
    const products = s.apps.map((a) => `${a.product}\t${a.form}`);
    assert.ok(products.some((p) => p.includes("Codex desktop") && p.includes("desktop")));
    assert.ok(products.some((p) => p.includes("Codex CLI") && p.includes("cli")));
    assert.ok(products.some((p) => p.includes("ZCode") && p.includes("desktop")));
    const z = s.apps.find((a) => a.adapterId === "zcode-desktop")!;
    assert.equal(z.candidate, true);
    assert.equal(z.runningLabel, "候选应用进程");
    assert.equal(z.processes.length, 2);
    const desktop = s.apps.find((a) => a.adapterId === "codex-desktop")!;
    assert.equal(desktop.candidate, false);
    assert.equal(desktop.runningLabel, "观察到应用进程");
    assert.equal(desktop.processes[0]?.startedAtText, `${formatDateTime(STARTED, "zh")} UTC+8`);
    leak(JSON.stringify(s));
  });

  it("counts one install for multiple subprocesses and dedupes PID by lifecycle", () => {
    const s = summaryOf([
      machine({
        discovery: snap({
          items: [
            item({
              instanceId: "di_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
              adapterId: "codex-desktop",
              processes: [
                { pid: 10, startedAt: STARTED },
                { pid: 10, startedAt: STARTED },
                { pid: 11, startedAt: STARTED + 1 },
              ],
            }),
          ],
        }),
      }),
    ]);
    assert.equal(s.status, "observed");
    assert.equal(s.count, 1);
    assert.equal(s.apps.length, 1);
    assert.deepEqual(
      s.apps[0]!.processes.map((p) => `${p.pid}:${p.startedAt}`),
      [`10:${STARTED}`, `11:${STARTED + 1}`],
    );
  });

  it("ignores records that are not currently observed with a real PID", () => {
    const s = summaryOf([
      machine({
        discovery: snap({
          items: [
            item({
              instanceId: "di_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
              adapterId: "codex-desktop",
              running: "unknown",
              processes: [{ pid: 15912, startedAt: STARTED }],
            }),
            item({
              instanceId: "di_cccccccccccccccccccccccccccccccc",
              adapterId: "codex-cli",
              running: "observed",
              processes: [],
            }),
            item({
              instanceId: "di_dddddddddddddddddddddddddddddddd",
              adapterId: "zcode-desktop",
              running: "observed",
              processes: [{ pid: 0, startedAt: STARTED }],
            }),
          ],
        }),
      }),
    ]);
    assert.equal(s.status, "none");
    assert.equal(s.count, 0);
    assert.equal(s.apps.length, 0);
    assert.equal(s.headline.includes("无程序运行"), false);
    assert.equal(/已观察到应用进程 \(0\)/.test(s.headline), false);
  });

  it("filters by host and does not mix another machine's observed processes", () => {
    const s = summaryOf(
      [
        machine({
          id: "dev_a",
          discovery: snap({ items: [CODEX_DESKTOP] }),
        }),
        machine({
          id: "dev_b",
          hostname: "host-b",
          discovery: snap({ items: [ZCODE] }),
        }),
      ],
      { host: "dev_a" },
    );
    assert.equal(s.status, "observed");
    assert.equal(s.count, 1);
    assert.equal(s.apps[0]?.adapterId, "codex-desktop");
    assert.equal(
      summaryOf(
        [
          machine({ id: "dev_a", discovery: snap({ items: [CODEX_DESKTOP] }) }),
          machine({ id: "dev_b", hostname: "host-b", discovery: snap({ items: [ZCODE] }) }),
        ],
        { host: "dev_b" },
      ).apps[0]?.adapterId,
      "zcode-desktop",
    );
  });

  it("expired, missing, disconnected, and partial-without-observation are unknown, not idle", () => {
    const fresh = [machine({ discovery: snap({ items: [CODEX_DESKTOP] }) })];
    const stale = summaryOf(fresh, { now: NOW + DISCOVERY_TTL_MS + 1 });
    assert.equal(stale.status, "unknown");
    assert.equal(stale.count, 0);
    assert.equal(stale.apps.length, 0);
    assert.match(stale.headline, /未知/);
    assert.equal(stale.headline.includes("无程序运行"), false);

    const missing = summaryOf([machine({ discovery: undefined })]);
    assert.equal(missing.status, "unknown");
    assert.match(missing.headline, /未知/);
    assert.equal(missing.headline.includes("无程序运行"), false);

    const disconnected = summaryOf(fresh, { disconnected: true });
    assert.equal(disconnected.status, "unknown");
    assert.equal(disconnected.apps.length, 0);
    assert.match(disconnected.headline, /未知/);

    const partial = summaryOf([
      machine({
        discovery: snap({
          status: "partial",
          sources: DISCOVERY_SOURCES.map((id) => ({
            id,
            status: id === "processes" ? "partial" : "ok",
          })),
          items: [
            item({
              instanceId: "di_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
              adapterId: "zcode-desktop",
              running: "unknown",
              installation: "candidate",
              processes: [],
            }),
          ],
        }),
      }),
    ]);
    assert.equal(partial.status, "unknown");
    assert.equal(partial.count, 0);
    assert.match(partial.headline, /未知/);
    assert.equal(partial.headline.includes("无程序运行"), false);
  });

  it("keeps observed rows from a partial scan that did report PIDs", () => {
    const s = summaryOf([
      machine({
        discovery: snap({
          status: "partial",
          sources: DISCOVERY_SOURCES.map((id) => ({
            id,
            status: id === "path" ? "partial" : "ok",
          })),
          items: [CODEX_CLI],
        }),
      }),
    ]);
    assert.equal(s.status, "observed");
    assert.equal(s.count, 1);
    assert.equal(s.apps[0]?.adapterId, "codex-cli");
    assert.equal(s.apps[0]?.product, "Codex CLI");
  });
});

describe("legacyAuditIdentityTitle", () => {
  it("does not advertise 进程身份 (0) when there are no audit process records", () => {
    const empty = legacyAuditIdentityTitle({ collectedCount: 0, identityLabel: "进程身份" });
    assert.equal(empty, "审计进程归属记录");
    assert.equal(empty.includes("进程身份 (0)"), false);
    assert.equal(empty.includes("(0)"), false);
    const filled = legacyAuditIdentityTitle({ collectedCount: 2, identityLabel: "进程身份" });
    assert.match(filled, /进程身份/);
    assert.match(filled, /审计进程归属记录/);
    assert.match(filled, /\(2\)/);
  });
});

describe("home wiring", () => {
  it("renders the discovery summary beside the audit identity heading helper", async () => {
    const { readFileSync } = await import("node:fs");
    const home = readFileSync(new URL("../../routes/index.tsx", import.meta.url), "utf8");
    assert.match(home, /ObservedAppProcessSection/);
    assert.match(home, /legacyAuditIdentityTitle/);
    assert.equal(home.includes("agentProcs"), false);
    assert.equal(/identities\s*=/.test(home) && home.includes("discovery.items"), false);
  });
});
