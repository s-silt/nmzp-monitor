import assert from "node:assert/strict";
import { createServer } from "node:net";
import { copyFile, mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { describe, it } from "node:test";
import {
  WINDOWS_NETWORK_IDENTITY_SCRIPT,
  WINDOWS_NETWORK_PROCESS_SCRIPT,
  WINDOWS_NETWORK_TCP_SCRIPT,
  agentTree,
  collectAgentTcp,
  confirmedAgentRoot,
  identityKey,
  parseIdentifiedProcs,
  type IdentifiedProc,
  type NetworkRunResult,
} from "./network-collect.ts";

const GROK_EXE = "C:\\Users\\Fixture\\.grok\\bin\\grok.exe";
const now = 1_700_000_100_000;

function grokProc(over: Partial<IdentifiedProc> = {}): IdentifiedProc {
  return {
    pid: 40,
    ppid: 1,
    name: "grok.exe",
    exe: GROK_EXE,
    startedAt: now - 10_000,
    ...over,
  };
}

describe("network scripts never request CommandLine", () => {
  it("cim and tcp scripts omit CommandLine", () => {
    assert.doesNotMatch(WINDOWS_NETWORK_PROCESS_SCRIPT, /CommandLine/);
    assert.match(WINDOWS_NETWORK_PROCESS_SCRIPT, /ExecutablePath/);
    assert.match(WINDOWS_NETWORK_PROCESS_SCRIPT, /StartedAtMs/);
    assert.doesNotMatch(WINDOWS_NETWORK_IDENTITY_SCRIPT([40, 41]), /CommandLine/);
    assert.doesNotMatch(WINDOWS_NETWORK_TCP_SCRIPT([40]), /CommandLine/);
    assert.match(WINDOWS_NETWORK_TCP_SCRIPT([40]), /Get-NetTCPConnection/);
    assert.doesNotMatch(WINDOWS_NETWORK_TCP_SCRIPT([40]), /SilentlyContinue/);
    assert.match(WINDOWS_NETWORK_TCP_SCRIPT([40]), /\[string\]\$_\.State/);
    assert.doesNotMatch(WINDOWS_NETWORK_TCP_SCRIPT([40]), /taskkill/i);
  });
});

describe("agent tree identity", () => {
  it("requires real exe; name-only grok is not a root", () => {
    assert.equal(confirmedAgentRoot({ pid: 1, ppid: 0, name: "grok.exe", exe: "", startedAt: now }), null);
    const parsed = parseIdentifiedProcs([{ ProcessId: 1, ParentProcessId: 0, Name: "grok.exe", ExecutablePath: "", StartedAtMs: now }]);
    assert.equal(parsed.length, 0);
    assert.ok(confirmedAgentRoot(grokProc()));
    assert.equal(confirmedAgentRoot({ pid: 100, ppid: 1, name: "grok.exe", exe: "C:\\Temp\\grok.exe", startedAt: now - 1000 }), null);
    assert.equal(
      confirmedAgentRoot({
        pid: 9,
        ppid: 1,
        name: "python.exe",
        exe: "C:\\Users\\u\\.codex\\python.exe",
        startedAt: now,
      }),
      null,
    );
  });

  it("rejects PID reuse when CreationDate changes", () => {
    const a = grokProc({ pid: 40, startedAt: 1000 });
    const b = grokProc({ pid: 40, startedAt: 2000, exe: "C:\\Windows\\System32\\notepad.exe" });
    assert.notEqual(identityKey(a), identityKey(b));
  });

  it("does not treat browsers or arbitrary node as agent roots", () => {
    const chrome: IdentifiedProc = {
      pid: 8,
      ppid: 1,
      name: "chrome.exe",
      exe: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
      startedAt: now,
    };
    const node: IdentifiedProc = {
      pid: 9,
      ppid: 1,
      name: "node.exe",
      exe: "C:\\Program Files\\nodejs\\node.exe",
      startedAt: now,
    };
    assert.equal(confirmedAgentRoot(chrome), null);
    assert.equal(confirmedAgentRoot(node), null);
    const child: IdentifiedProc = {
      pid: 50,
      ppid: 40,
      name: "node.exe",
      exe: "C:\\Program Files\\nodejs\\node.exe",
      startedAt: now - 1_000,
    };
    const tree = agentTree([grokProc(), child, chrome]);
    assert.equal(tree.has(40), true);
    assert.equal(tree.has(50), true);
    assert.equal(tree.has(8), false);
  });
});

describe("collectAgentTcp injected", () => {
  function json(v: unknown): string {
    return JSON.stringify(v);
  }

  it("stopped is not_sampled and does not run", async () => {
    let runs = 0;
    const r = await collectAgentTcp({
      stopped: true,
      homeKey: "t-stopped",
      deps: {
        now: () => now,
        platform: "win32",
        run: async () => {
          runs += 1;
          return { stdout: "[]" };
        },
      },
    });
    assert.equal(r.status, "not_sampled");
    assert.equal(runs, 0);
    assert.equal(r.connections.length, 0);
  });

  it("timeout is not a successful zero sample", async () => {
    const r = await collectAgentTcp({
      stopped: false,
      homeKey: "t-timeout",
      deps: {
        now: () => now,
        platform: "win32",
        run: async () => ({ stdout: "", timedOut: true, error: "timeout" }),
      },
    });
    assert.equal(r.status, "timeout");
    assert.notEqual(r.status, "ok");
    assert.equal(r.connections.length, 0);
  });

  it("truncated CIM is truncated, not ok", async () => {
    const r = await collectAgentTcp({
      stopped: false,
      homeKey: "t-trunc",
      deps: {
        now: () => now,
        platform: "win32",
        run: async () => ({ stdout: "[", truncated: true, error: "truncated" }),
      },
    });
    assert.equal(r.status, "truncated");
    assert.equal(r.connections.length, 0);
  });

  it("drops reused PID and Bound/Listen/zero-remote; keeps Established", async () => {
    const before = [
      { ProcessId: 40, ParentProcessId: 1, Name: "grok.exe", ExecutablePath: GROK_EXE, StartedAtMs: now - 10_000 },
      { ProcessId: 8, ParentProcessId: 1, Name: "chrome.exe", ExecutablePath: "C:\\Chrome\\chrome.exe", StartedAtMs: now - 10_000 },
    ];
    const tcp = [
      { LocalAddress: "10.0.0.2", LocalPort: 40000, RemoteAddress: "1.2.3.4", RemotePort: 443, State: 5, OwningProcess: 40 },
      { LocalAddress: "10.0.0.2", LocalPort: 80, RemoteAddress: "0.0.0.0", RemotePort: 0, State: "Bound", OwningProcess: 40 },
      { LocalAddress: "10.0.0.2", LocalPort: 443, RemoteAddress: "0.0.0.0", RemotePort: 0, State: "Listen", OwningProcess: 40 },
      { LocalAddress: "10.0.0.2", LocalPort: 40001, RemoteAddress: "9.9.9.9", RemotePort: 443, State: "Established", OwningProcess: 8 },
    ];
    const afterReuse = [
      { ProcessId: 40, ParentProcessId: 1, Name: "notepad.exe", ExecutablePath: "C:\\Windows\\notepad.exe", StartedAtMs: now - 100 },
    ];
    const reused = await collectAgentTcp({
      stopped: false,
      homeKey: "t-reuse",
      deps: {
        now: () => now,
        platform: "win32",
        run: async (kind) => {
          if (kind === "cim") return { stdout: json(before) };
          if (kind === "tcp") return { stdout: json(tcp) };
          return { stdout: json(afterReuse) };
        },
      },
    });
    assert.equal(reused.connections.length, 0);
    assert.equal(reused.status, "partial");

    const afterOk = [
      { ProcessId: 40, ParentProcessId: 1, Name: "grok.exe", ExecutablePath: GROK_EXE, StartedAtMs: now - 10_000 },
    ];
    const ok = await collectAgentTcp({
      stopped: false,
      homeKey: "t-ok",
      deps: {
        now: () => now,
        platform: "win32",
        run: async (kind) => {
          if (kind === "cim") return { stdout: json(before) };
          if (kind === "tcp") return { stdout: json(tcp) };
          return { stdout: json(afterOk) };
        },
      },
    });
    assert.equal(ok.status, "ok");
    assert.equal(ok.connections.length, 1);
    assert.equal(ok.connections[0]?.remoteIp, "1.2.3.4");
    assert.equal(ok.connections[0]?.state, "Established");
    assert.equal(ok.connections[0]?.agent, "grok");
    assert.equal(ok.connections.every((c) => c.role === "egress"), true);
    assert.equal(ok.connections[0]?.direction, "unknown");
  });

  it("rejects child sockets when ancestor root PID is reused", async () => {
    const root = {
      ProcessId: 100,
      ParentProcessId: 1,
      Name: "grok.exe",
      ExecutablePath: GROK_EXE,
      StartedAtMs: now - 10_000,
    };
    const child = {
      ProcessId: 101,
      ParentProcessId: 100,
      Name: "curl.exe",
      ExecutablePath: "C:\\Windows\\System32\\curl.exe",
      StartedAtMs: now - 5_000,
    };
    const tcp = {
      OwningProcess: 101,
      LocalAddress: "127.0.0.1",
      LocalPort: 41234,
      RemoteAddress: "203.0.113.7",
      RemotePort: 443,
      State: "Established",
    };
    const rep = await collectAgentTcp({
      stopped: false,
      homeKey: "t-ancestor",
      deps: {
        platform: "win32",
        now: () => now,
        run: async (kind) => ({
          stdout: JSON.stringify(
            kind === "cim" ? [root, child] : kind === "tcp" ? [tcp] : [{ ...root, StartedAtMs: now - 2000 }, child],
          ),
        }),
      },
    });
    assert.equal(rep.connections.length, 0);
  });

  it("non-windows without inject is unsupported, not ok-zero", async () => {
    const r = await collectAgentTcp({
      stopped: false,
      homeKey: "t-unsup",
      deps: { now: () => now, platform: "linux" },
    });
    assert.equal(r.status, "unsupported");
    assert.notEqual(r.status, "ok");
  });
});

describe("loopback TCP with injected install-layout identity", () => {
  it("observes real loopback sockets for a pid whose CIM identity is injected as .grok/bin/grok.exe", { timeout: 25_000 }, async () => {
    if (process.platform !== "win32") return;
    const dir = await mkdtemp(join(tmpdir(), "nmzp-net-"));
    const runtime = join(dir, ".grok", "runtime");
    const exe = join(runtime, "node.exe");
    let child: ReturnType<typeof spawn> | undefined;
    const server = createServer();
    try {
      await mkdir(runtime, { recursive: true });
      await copyFile(process.execPath, exe);
      server.on("error", () => undefined);
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
      const addr = server.address();
      if (!addr || typeof addr === "string") throw new Error("listen");
      const port = addr.port;
      await new Promise<void>((resolve) => {
        server.on("connection", (sock) => {
          sock.on("error", () => undefined);
          sock.resume();
          resolve();
        });
        child = spawn(
          exe,
          ["-e", `const c=require('net').connect(${port},'127.0.0.1');c.on('error',()=>{});setTimeout(()=>{},30000)`],
          { windowsHide: true, stdio: "ignore" },
        );
        child.on("error", () => undefined);
      });
      await new Promise((r) => setTimeout(r, 400));
      const pid = child?.pid ?? 0;
      assert.ok(pid > 0);
      const startedAt = Date.now() - 5_000;
      const identity = JSON.stringify({
        ProcessId: pid,
        ParentProcessId: 1,
        Name: "grok.exe",
        ExecutablePath: GROK_EXE,
        StartedAtMs: startedAt,
      });
      const { runPowershell, WINDOWS_NETWORK_TCP_SCRIPT } = await import("./network-collect.ts");
      let tcpOut = "";
      const r = await collectAgentTcp({
        stopped: false,
        timeoutMs: 12_000,
        homeKey: `t-live-${pid}`,
        deps: {
          platform: "win32",
          now: () => Date.now(),
          run: async (kind): Promise<NetworkRunResult> => {
            if (kind === "tcp") {
              const tcp = await runPowershell(WINDOWS_NETWORK_TCP_SCRIPT([pid]), 8_000);
              tcpOut = `${tcp.error ?? ""}:${tcp.stdout.slice(0, 400)}`;
              return tcp;
            }
            return { stdout: identity };
          },
        },
      });
      const mine = r.connections.filter(
        (c) => c.pid === pid && (c.remoteIp === "127.0.0.1" || c.remoteIp === "::1") && (c.remotePort === port || c.localPort === port),
      );
      assert.ok(
        mine.length >= 1,
        `expected loopback egress for pid ${pid} status=${r.status} n=${r.connections.length} tcp=${tcpOut} sample=${JSON.stringify(r.connections)}`,
      );
      assert.equal(mine[0]?.agent, "grok");
      assert.equal(mine.every((c) => c.role === "egress"), true);
    } finally {
      if (child && child.exitCode === null && child.signalCode === null) {
        try {
          child.kill();
        } catch {
          /* already gone */
        }
        await new Promise((r) => setTimeout(r, 400));
      }
      server.close();
      try {
        await rm(dir, { recursive: true, force: true });
      } catch {
        /* exe may stay locked until reboot; tmp leftover is ok */
      }
    }
  });
});

it("invalid process snapshots and lost identities never become successful zero TCP samples",async()=>{
 for(const bad of [42,null,[null],[{Name:"grok.exe",ProcessId:40,ParentProcessId:1,ExecutablePath:null}]]){
  const sample=await collectAgentTcp({stopped:false,homeKey:"invalid-before",deps:{platform:"win32",now:()=>now,run:async()=>({stdout:JSON.stringify(bad)})}});
  assert.equal(sample.status,"partial");
 }
 for(const after of [42,null,[]]){
  const sample=await collectAgentTcp({stopped:false,homeKey:"invalid-after",deps:{platform:"win32",now:()=>now,run:async(kind)=>({stdout:JSON.stringify(kind==="cim"?[grokProc()]:kind==="tcp"?[]:after)})}});
  assert.equal(sample.status,"partial");assert.equal(sample.connections.length,0);
 }
});
