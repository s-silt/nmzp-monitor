import {networkOwnerCli} from "./network-owner.ts";
import {discoveryHome,readDiscovery,setManualPaths,refreshDiscovery} from "./agent-discovery.ts";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir, hostname as osHostname, userInfo } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ADMIN_BODY_LIMIT, BODY_LIMIT, JOIN_TICKET_TTL_MS, NMZP_VERSION } from "./constants.ts";
import { startServer } from "./serve.ts";
import { bootstrapAdmin, NmzpStore, readServePointer } from "./persist.ts";
import { loadOrCreateTls } from "./tls.ts";
import { parseJoinBundle, parseCtPin, joinDevice, leaveDevice, defaultHome, defaultProbeController } from "./install.ts";
import { startAdminProxy } from "./admin-proxy.ts";
import { parseViewerFlags, startLanViewer } from "./lan-viewer.ts";
import {
  parseSnapshotGuardCli,
  publicSnapshotGuardStatus,
  snapshotGuardApply,
  snapshotGuardRestore,
  snapshotGuardStatus,
} from "./snapshot-guard.ts";
import { hookMain } from "./hook.ts";
import { probeLoop } from "./probe.ts";
import { loadMonitor, resolveUiDir } from "./paths.ts";
import { newSecret, sha256Hex } from "./auth.ts";
import { exportBundleShape } from "./export.ts";
import { pinnedHttps } from "./https-client.ts";
import type { CustomPrivacyRule, Intervention } from "./schema.ts";

export function coreDirFromMeta(metaUrl = import.meta.url): string {
  return dirname(fileURLToPath(metaUrl));
}

function dataDir(): string {
  return process.env.NMZP_DATA || join(homedir(), ".nmzp", "ct-data");
}

function fail(msg: string): never {
  process.stderr.write(msg + "\n");
  process.exit(1);
}

function usage(): string {
  return `nmzp ${NMZP_VERSION}
nmzp serve
nmzp status
nmzp rules list|add|rm
nmzp rights export|wipe|stop|resume
nmzp ticket --out <bundle.json>
nmzp join <bundle.json>
nmzp stop
nmzp leave
nmzp uninstall
nmzp discover [refresh|status|paths <local-path-list.json>]
nmzp probe
nmzp network-owner status|approve <local-claim.json>|revoke <id> --token-file <admin.token>
nmzp hook --agent grok|claude|codex
nmzp board --bundle <join.json> --token-file <admin.token>
nmzp viewer --host <private-ip> --port 8789 --allow-cidr <CIDR>
nmzp snapshot status|apply|restore [--home <path>]
`;
}

interface LiveAdmin {
  url: string;
  pin: { caPem: string; fingerprintSha256: string };
  headers: Record<string, string>;
}

async function detectLiveAdmin(dir: string): Promise<LiveAdmin | "offline"> {
  let pointer;
  try {
    pointer = await readServePointer(dir);
  } catch (e) {
    fail(e instanceof Error ? e.message : "corrupt serve pointer");
  }
  if (!pointer) return "offline";
  let token = "";
  let certPem = "";
  try {
    token = (await readFile(join(dir, "admin.token"), "utf8")).trim();
    certPem = await readFile(join(dir, "tls", "server.crt"), "utf8");
  } catch {
    fail("serve is running but admin.token or tls cert is missing; refusing disk writes");
  }
  if (!token || !certPem) fail("serve is running but admin credentials are incomplete; refusing disk writes");
  const pin = { caPem: certPem, fingerprintSha256: pointer.fingerprintSha256 };
  try {
    const h = await pinnedHttps({ url: `${pointer.url}/health`, ...pin, timeoutMs: 1500 });
    if (h.status !== 200) fail("serve pointer exists but health failed; refusing disk writes");
  } catch {
    fail("serve pointer exists but is unreachable; refusing disk writes");
  }
  return {
    url: pointer.url,
    pin,
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
  };
}

function responseLimit(path: string): number {
  if (path.startsWith("/api/v1/state") || path.startsWith("/api/v1/export")) return ADMIN_BODY_LIMIT;
  return BODY_LIMIT;
}

export function formatJoinSuccess(r: { deviceId: string; autostart: string }): string {
  return `joined deviceId=${r.deviceId} autostart=${r.autostart}\ncodex=/hooks approve NMZP PreToolUse v1\n`;
}

export function snapshotCliExitCode(
  cmd: "status" | "apply" | "restore",
  status: { error?: string; active?: boolean },
): number {
  if (cmd === "status") return 0;
  if (cmd === "apply") return status.error || status.active !== true ? 1 : 0;
  return status.error ? 1 : 0;
}

async function liveJson<T>(
  live: LiveAdmin,
  method: string,
  path: string,
  body?: unknown,
): Promise<T> {
  const res = await pinnedHttps({
    url: `${live.url}${path}`,
    method,
    body: body === undefined ? undefined : JSON.stringify(body),
    headers: live.headers,
    ...live.pin,
    timeoutMs: 4000,
    maxBodyBytes: responseLimit(path),
  });
  let parsed: unknown = {};
  try {
    parsed = JSON.parse(res.body || "{}");
  } catch {
    fail("serve returned non-json");
  }
  if (res.status >= 400) {
    const err = parsed && typeof parsed === "object" && "error" in parsed ? String((parsed as { error: unknown }).error) : "";
    fail(`serve ${res.status}${err ? ` ${err}` : ""}`);
  }
  return parsed as T;
}

async function loadLocalStore(coreDir: string): Promise<{ store: NmzpStore; monitor: Awaited<ReturnType<typeof loadMonitor>> }> {
  const monitor = await loadMonitor(coreDir);
  const store = new NmzpStore(dataDir());
  const suggested = Array.isArray(monitor.privacy.SUGGESTED_PRIVACY) ? monitor.privacy.SUGGESTED_PRIVACY : [];
  await store.load({ defaultRules: suggested, defaultOverrides: monitor.SUGGESTED_OVERRIDES });
  return { store, monitor };
}

export async function main(argv: string[], coreDir = coreDirFromMeta()): Promise<void> {
  if(argv[0]==="network-owner"){await networkOwnerCli(argv.slice(1),discoveryHome());return;}
  if(argv[0]==="discover"){const home=discoveryHome();if(argv[1]==="paths"){if(!argv[2])throw Error("path_list_required");setManualPaths(home,JSON.parse(await readFile(argv[2],"utf8")));}
    const snapshot=argv[1]==="status"?readDiscovery(home):await refreshDiscovery(home,true);process.stdout.write(JSON.stringify({snapshot},null,2)+"\n");return;}
  const cmd = argv[0] ?? "help";
  if (cmd === "help" || cmd === "-h" || cmd === "--help") {
    process.stdout.write(usage());
    return;
  }
  if (cmd === "serve") {
    const host = process.env.NMZP_BIND ?? "0.0.0.0";
    const port = Number(process.env.NMZP_PORT ?? 8787);
    const extra = (process.env.NMZP_TLS_HOSTS ?? "").split(",").map((s) => s.trim()).filter(Boolean);
    const running = await startServer({
      dataDir: dataDir(),
      host,
      port,
      coreDir,
      extraHosts: extra.length ? extra : undefined,
    });
    process.stdout.write(`nmzp ${NMZP_VERSION} https://${host}:${running.port} (pinned TLS, no outbound)\n`);
    process.stdout.write(`admin token file: ${join(dataDir(), "admin.token")}\n`);
    return;
  }
  if (cmd === "board") {
    const bundleIdx = argv.indexOf("--bundle");
    const tokenIdx = argv.indexOf("--token-file");
    const portIdx = argv.indexOf("--port");
    const bundlePath = bundleIdx >= 0 ? argv[bundleIdx + 1] : "";
    const tokenPath = tokenIdx >= 0 ? argv[tokenIdx + 1] : join(dataDir(), "admin.token");
    if (!bundlePath) fail("usage: nmzp board --bundle <join.json> --token-file <admin.token>");
    const bundle = parseCtPin(await readFile(bundlePath, "utf8"));
    if (!bundle) fail("invalid pin bundle (https url, caPem, fingerprint)");
    const adminToken = (await readFile(tokenPath, "utf8")).trim();
    if (!adminToken) fail("empty admin token file");
    const proxy = await startAdminProxy({
      ctUrl: bundle.url,
      caPem: bundle.caPem,
      fingerprintSha256: bundle.fingerprintSha256,
      adminToken,
      host: "127.0.0.1",
      port: portIdx >= 0 ? Number(argv[portIdx + 1]) : 8788,
      uiDir: resolveUiDir(coreDir),
    });
    process.stdout.write(`nmzp board ${proxy.url} (loopback HTTP → pinned CT TLS)\n`);
    return;
  }
  if (cmd === "viewer") {
    let flags: ReturnType<typeof parseViewerFlags>;
    try {
      flags = parseViewerFlags(argv.slice(1));
    } catch (e) {
      fail(e instanceof Error ? e.message : "viewer flags invalid");
    }
    const live = await detectLiveAdmin(dataDir());
    if (live === "offline") fail("nmzp core is not running; viewer requires a live pinned core");
    const adminToken = (live.headers.authorization ?? "").replace(/^Bearer\s+/i, "").trim();
    if (!adminToken) fail("serve is running but admin credentials are incomplete; refusing disk writes");
    try {
      const probe = await pinnedHttps({
        url: `${live.url}/api/v1/state`,
        method: "GET",
        headers: live.headers,
        ...live.pin,
        timeoutMs: 4000,
        maxBodyBytes: ADMIN_BODY_LIMIT,
      });
      if (probe.status !== 200) fail("serve rejected viewer credentials; refusing to start");
    } catch {
      fail("serve pointer exists but is unreachable; refusing disk writes");
    }
    const running = await startLanViewer({
      host: flags.host,
      port: flags.port,
      allowedCidrs: flags.allowedCidrs,
      ctUrl: live.url,
      caPem: live.pin.caPem,
      fingerprintSha256: live.pin.fingerprintSha256,
      adminToken,
      uiDir: resolveUiDir(coreDir),
    });
    process.stdout.write(`nmzp viewer ${running.url} (LAN read-only HTTP, admin stays on TLS core)\n`);
    return;
  }
  if (cmd === "snapshot") {
    const parsed = parseSnapshotGuardCli(argv.slice(1));
    if (!parsed.ok) fail("usage: nmzp snapshot status|apply|restore [--home <path>]");
    const fn =
      parsed.cmd === "status" ? snapshotGuardStatus : parsed.cmd === "apply" ? snapshotGuardApply : snapshotGuardRestore;
    try {
      const status = await fn({ home: parsed.home });
      const pub = publicSnapshotGuardStatus(status);
      const text = JSON.stringify(pub);
      if (/sddl/i.test(text) || /\bO:[A-Z]{1,4}:/.test(text) || text.includes("D:(")) {
        fail(status.error || "snapshot_failed");
      }
      process.stdout.write(`${text}\n`);
      if (snapshotCliExitCode(parsed.cmd, status) !== 0) process.exit(1);
    } catch (e) {
      const msg = e instanceof Error ? e.message : "snapshot_failed";
      if (/sddl/i.test(msg) || /\bO:[A-Z]{1,4}:/.test(msg) || msg.includes("D:(")) fail("snapshot_failed");
      fail(msg);
    }
    return;
  }
  if (cmd === "hook") {
    await hookMain(argv.slice(1), coreDir);
    return;
  }
  if (cmd === "probe") {
    await probeLoop(coreDir);
    return;
  }
  if (cmd === "join") {
    const file = argv[1];
    if (!file) fail("usage: nmzp join <bundle.json>");
    const raw = await readFile(file, "utf8");
    const bundle = parseJoinBundle(raw);
    if (!bundle) fail("invalid join bundle (need https url, caPem, fingerprint, ticket)");
    const home = defaultHome();
    const result = await joinDevice({
      home,
      bundle,
      nodePath: process.execPath,
      coreDir,
      hostname: osHostname(),
      user: userInfo().username,
      os: process.platform === "darwin" || process.platform === "linux" ? process.platform : "win32",
    });
    process.stdout.write(formatJoinSuccess({ deviceId: result.deviceId, autostart: result.autostart }));
    return;
  }
  if (cmd === "stop") {
    const r = await defaultProbeController().stopOwn(defaultHome());
    if (r.stopped) process.stdout.write(`probe stopped pid=${r.pid}\n`);
    else process.stdout.write("probe not running\n");
    return;
  }
  if (cmd === "leave") {
    const r = await leaveDevice({ home: defaultHome() });
    process.stdout.write(`left (${r.removed.length} entries)\n`);
    return;
  }
  if (cmd === "uninstall" || cmd === "unistall") {
    const r = await leaveDevice({ home: defaultHome() });
    process.stdout.write(`uninstalled (${r.removed.length} entries)\n`);
    return;
  }

  const live = await detectLiveAdmin(dataDir());

  if (cmd === "ticket") {
    const outIdx = argv.indexOf("--out");
    const out = outIdx >= 0 ? argv[outIdx + 1] : join(dataDir(), "join-bundle.json");
    if (!out) fail("usage: nmzp ticket --out <file>");
    let bundle: { url: string; caPem: string; fingerprintSha256: string; ticket: string };
    if (live !== "offline") {
      const issued = await liveJson<{ ticket: string; caPem: string; fingerprintSha256: string }>(
        live,
        "POST",
        "/api/v1/ticket",
      );
      bundle = {
        url: process.env.NMZP_PUBLIC_URL || live.url,
        caPem: issued.caPem,
        fingerprintSha256: issued.fingerprintSha256,
        ticket: issued.ticket,
      };
    } else {
      const { store } = await loadLocalStore(coreDir);
      await bootstrapAdmin(store);
      const tls = await loadOrCreateTls(dataDir(), ["127.0.0.1", "localhost"]);
      const ticket = newSecret(24);
      await store.addTicket(sha256Hex(ticket), JOIN_TICKET_TTL_MS);
      bundle = {
        url: process.env.NMZP_PUBLIC_URL || `https://127.0.0.1:${process.env.NMZP_PORT ?? 8787}`,
        caPem: tls.certPem,
        fingerprintSha256: tls.fingerprintSha256,
        ticket,
      };
    }
    await mkdir(dirname(out), { recursive: true });
    await writeFile(out, JSON.stringify(bundle, null, 2), { mode: 0o600 });
    process.stdout.write(`bundle written (ticket not printed)\n`);
    return;
  }

  if (cmd === "status") {
    if (live !== "offline") {
      const st = await liveJson<{
        policyVersion: number;
        mode: string;
        stopped: boolean;
        devices: unknown[];
        events: unknown[];
      }>(live, "GET", "/api/v1/state");
      process.stdout.write(
        JSON.stringify(
          {
            version: NMZP_VERSION,
            policyVersion: st.policyVersion,
            mode: st.mode,
            stopped: st.stopped,
            devices: st.devices?.length ?? 0,
            events: st.events?.length ?? 0,
          },
          null,
          2,
        ) + "\n",
      );
      return;
    }
    const { store } = await loadLocalStore(coreDir);
    const p = store.getPolicy();
    const devices = store.listDevices();
    process.stdout.write(
      JSON.stringify(
        {
          version: NMZP_VERSION,
          policyVersion: p.version,
          mode: p.stopped ? "off" : p.mode,
          stopped: p.stopped,
          devices: devices.length,
          events: store.listEvents().length,
        },
        null,
        2,
      ) + "\n",
    );
    return;
  }

  if (cmd === "rules") {
    const sub = argv[1] ?? "list";
    const monitor = await loadMonitor(coreDir);
    if (live !== "offline") {
      const st = await liveJson<{
        policyVersion: number;
        customRules: CustomPrivacyRule[];
        mode: Intervention;
        stopped: boolean;
      }>(live, "GET", "/api/v1/state");
      if (sub === "list") {
        process.stdout.write(JSON.stringify(st.customRules ?? [], null, 2) + "\n");
        return;
      }
      if (sub === "add") {
        const draft = argv.slice(2).join(" ").trim().replace(/^['"]|['"]$/g, "");
        const rules = monitor.compilePrivacyDraft(draft);
        if (!rules.length) fail("pattern too broad or empty");
        const merged = [...(st.customRules ?? [])];
        for (const r of rules) {
          if (!merged.some((x) => x.match.toLowerCase() === r.match.toLowerCase())) merged.push(r);
        }
        const next = await liveJson<{ version: number; customRules: CustomPrivacyRule[] }>(live, "PUT", "/api/v1/policy", {
          expectedVersion: st.policyVersion,
          customRules: merged,
        });
        process.stdout.write(`ok version=${next.version} rules=${next.customRules.length}\n`);
        return;
      }
      if (sub === "rm" || sub === "remove") {
        const id = argv[2];
        if (!id) fail("usage: nmzp rules rm <id>");
        const next = await liveJson<{ version: number }>(live, "PUT", "/api/v1/policy", {
          expectedVersion: st.policyVersion,
          customRules: (st.customRules ?? []).filter((r) => r.id !== id),
        });
        process.stdout.write(`ok version=${next.version}\n`);
        return;
      }
      fail("usage: nmzp rules list|add|rm");
    }
    const { store } = await loadLocalStore(coreDir);
    if (sub === "list") {
      process.stdout.write(JSON.stringify(store.getPolicy().customRules, null, 2) + "\n");
      return;
    }
    if (sub === "add") {
      const draft = argv.slice(2).join(" ").trim().replace(/^['"]|['"]$/g, "");
      const rules = monitor.compilePrivacyDraft(draft);
      if (!rules.length) fail("pattern too broad or empty");
      const cur = store.getPolicy();
      const merged = [...cur.customRules];
      for (const r of rules) {
        if (!merged.some((x) => x.match.toLowerCase() === r.match.toLowerCase())) merged.push(r);
      }
      const next = await store.casPolicy(cur.version, { customRules: merged });
      if ("conflict" in next) fail("cas_conflict");
      process.stdout.write(`ok version=${next.version} rules=${next.customRules.length}\n`);
      return;
    }
    if (sub === "rm" || sub === "remove") {
      const id = argv[2];
      if (!id) fail("usage: nmzp rules rm <id>");
      const cur = store.getPolicy();
      const next = await store.casPolicy(cur.version, { customRules: cur.customRules.filter((r) => r.id !== id) });
      if ("conflict" in next) fail("cas_conflict");
      process.stdout.write(`ok version=${next.version}\n`);
      return;
    }
    fail("usage: nmzp rules list|add|rm");
  }

  if (cmd === "rights") {
    const sub = argv[1] ?? "export";
    if (live !== "offline") {
      if (sub === "export") {
        const bundle = await liveJson<unknown>(live, "GET", "/api/v1/export");
        process.stdout.write(JSON.stringify(bundle, null, 2) + "\n");
        return;
      }
      if (sub === "wipe") {
        await liveJson(live, "DELETE", "/api/v1/events");
        process.stdout.write("events cleared\n");
        return;
      }
      if (sub === "stop") {
        const st = await liveJson<{ policyVersion: number }>(live, "GET", "/api/v1/state");
        const p = await liveJson<{ version: number }>(live, "PUT", "/api/v1/policy", {
          expectedVersion: st.policyVersion,
          stopped: true,
        });
        process.stdout.write(`stopped version=${p.version}\n`);
        return;
      }
      if (sub === "resume") {
        const st = await liveJson<{ policyVersion: number }>(live, "GET", "/api/v1/state");
        const p = await liveJson<{ version: number; mode: string }>(live, "PUT", "/api/v1/policy", {
          expectedVersion: st.policyVersion,
          stopped: false,
        });
        process.stdout.write(`resumed version=${p.version} mode=${p.mode}\n`);
        return;
      }
      fail("usage: nmzp rights export|wipe|stop|resume");
    }
    const { store } = await loadLocalStore(coreDir);
    if (sub === "export") {
      process.stdout.write(JSON.stringify(exportBundleShape(store), null, 2) + "\n");
      return;
    }
    if (sub === "wipe") {
      await store.clearEvents();
      process.stdout.write("events cleared\n");
      return;
    }
    if (sub === "stop") {
      const p = await store.stop();
      process.stdout.write(`stopped version=${p.version}\n`);
      return;
    }
    if (sub === "resume") {
      const p = await store.resume();
      process.stdout.write(`resumed version=${p.version} mode=${p.mode}\n`);
      return;
    }
    fail("usage: nmzp rights export|wipe|stop|resume");
  }

  fail(usage());
}
