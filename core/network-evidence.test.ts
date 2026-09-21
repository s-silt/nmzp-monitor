import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { describe, it } from "node:test";
import {
  extractDeclaredEndpoints,
  isEgressTcp,
  ossHostShape,
  parseEndpointList,
  parseHttpUrl,
  parseIp,
  mergeHeartbeatNetwork,
  parseNetworkSampleReport,
  publicNetworkSample,
  sanitizeAuditText,
  upsertNetworkHistory,
} from "./network-evidence.ts";

function tok(prefix: string): string {
  return `${prefix}_${randomBytes(8).toString("hex")}`;
}

describe("extractDeclaredEndpoints", () => {
  it("extracts multiple quoted http(s) urls, ipv6, ports, and powershell -Uri", () => {
    const command =
      `curl "https://Alpha.Example.TEST:8443/a" 'http://beta.example.test/b' ` +
      `Invoke-WebRequest -Uri https://[2001:db8::1]:9443/x`;
    const eps = extractDeclaredEndpoints({ command });
    assert.equal(eps.length, 3);
    assert.equal(eps[0]?.host, "alpha.example.test");
    assert.equal(eps[0]?.port, 8443);
    assert.equal(eps[0]?.scheme, "https");
    assert.equal(eps[0]?.source, "tool_command");
    assert.equal(eps[0]?.observation, "declared");
    assert.equal(eps[1]?.host, "beta.example.test");
    assert.equal(eps[1]?.scheme, "http");
    assert.equal(eps[2]?.host, "2001:db8::1");
    assert.equal(eps[2]?.port, 9443);
  });

  it("caps at 8 unique hosts and prefers tool_url over command duplicate", () => {
    const url = "https://one.example.test/path";
    const command = Array.from({ length: 12 }, (_, i) => `https://h${i}.example.test/x`).join(" ");
    const eps = extractDeclaredEndpoints({ url, command: `${url} ${command}` });
    assert.equal(eps.length, 8);
    assert.equal(eps[0]?.source, "tool_url");
    assert.equal(eps[0]?.host, "one.example.test");
  });

  it("does not execute or decode EncodedCommand / guessed hosts", () => {
    const eps = extractDeclaredEndpoints({
      command: "powershell -EncodedCommand aHR0cHM6Ly9ldmlsLmV4YW1wbGUudGVzdC9zZWNyZXQ=",
    });
    assert.equal(eps.length, 0);
  });
});

describe("URL credential stripping", () => {
  it("drops userinfo/path/query/fragment from parse and audit text", () => {
    const sig = tok("synsig");
    const user = tok("synuser");
    const path = tok("synpath");
    const oss = tok("syntok");
    const raw =
      `https://${user}:pw@bucket.oss-cn-hangzhou.aliyuncs.com/${path}/o?X-Amz-Signature=${sig}&x-oss-security-token=${oss}#frag`;
    const parsed = parseHttpUrl(raw);
    assert.ok(parsed);
    assert.equal(parsed!.host, "bucket.oss-cn-hangzhou.aliyuncs.com");
    assert.equal("user" in parsed!, false);
    const text = sanitizeAuditText(`curl ${raw}`);
    assert.equal(text.includes(sig), false);
    assert.equal(text.includes(user), false);
    assert.equal(text.includes(path), false);
    assert.equal(text.includes(oss), false);
    assert.match(text, /https:\/\/bucket\.oss-cn-hangzhou\.aliyuncs\.com/);
    assert.equal(ossHostShape(parsed!.host), true);
  });

  it("rejects embedded-secret hosts and spoof OSS suffixes", () => {
    const key = `sk-${"a".repeat(24)}`;
    const eps = extractDeclaredEndpoints({ url: `https://${key}.evil.example.test/x` });
    assert.equal(eps.length, 0);
    assert.equal(ossHostShape("bucket.aliyuncs.com.evil.example.test"), false);
    assert.equal(ossHostShape("oss-cn-hangzhou.aliyuncs.com"), true);
  });

  it("applies custom privacy host drop", () => {
    const eps = extractDeclaredEndpoints({
      dest: "db.prod.internal",
      scanCustom: (text, rules) => (rules.some((r) => text.includes(r.match)) ? [{ index: 0, length: 3 }] : []),
      customRules: [{ id: "p", enabled: true, mode: "block", match: "db.prod.internal", kind: "internal_host", replaceWith: "x" }],
    });
    assert.equal(eps.length, 0);
  });
});

describe("strict portable IP", () => {
  it("rejects invalid IPv6 and IPv4 masquerades", () => {
    assert.equal(parseIp("::::"), undefined);
    assert.equal(parseIp("1:2:3"), undefined);
    assert.equal(parseIp("1::2::3"), undefined);
    assert.equal(parseIp("999.2.3.4"), undefined);
    assert.equal(parseIp("2001:db8::1"), "2001:db8::1");
  });

  it("normalizes bracketed IPv6 URLs without peeling the host", () => {
    const ipv6 = parseHttpUrl("https://user:synthetic@[2001:db8::1]:8443/path?sig=synthetic");
    assert.equal(ipv6?.host, "2001:db8::1");
    assert.equal(ipv6?.port, 8443);
  });
});

describe("sample row completeness", () => {
  it("missing or invalid connections are not successful zero", () => {
    const now = Date.now();
    const missing = parseNetworkSampleReport({ status: "ok", observedAt: now });
    assert.ok(!missing || missing.status !== "ok");
    const badrows = parseNetworkSampleReport({ status: "ok", observedAt: now, connections: [{ pid: 99 }] });
    assert.ok(!badrows || badrows.status !== "ok");
  });
});

describe("historic endpoints", () => {
  it("missing endpoints stay undefined; empty array is collected-none", () => {
    assert.equal(parseEndpointList(undefined), undefined);
    assert.deepEqual(parseEndpointList([]), []);
    const parsed = parseEndpointList([{ host: "a.example.test", source: "tool_url", observation: "declared" }]);
    assert.equal(parsed?.[0]?.host, "a.example.test");
  });
});

describe("tcp role", () => {
  it("Bound/Listen/zero-remote are not egress; Established+real remote is", () => {
    assert.equal(isEgressTcp("Bound", "0.0.0.0", 0), false);
    assert.equal(isEgressTcp("Listen", "0.0.0.0", 443), false);
    assert.equal(isEgressTcp("Established", "0.0.0.0", 443), false);
    assert.equal(isEgressTcp("Established", "::", 443), false);
    assert.equal(isEgressTcp("Established", "1.2.3.4", 443), true);
    assert.equal(isEgressTcp("SynSent", "2001:db8::1", 443), true);
    assert.equal(isEgressTcp("Established", "127.0.0.1", 9), true);
  });

  it("timeout reports are not successful zero samples", () => {
    const ok = parseNetworkSampleReport({
      status: "timeout",
      observedAt: Date.now(),
      connections: [
        {
          remoteIp: "1.2.3.4",
          remotePort: 443,
          localIp: "10.0.0.1",
          localPort: 1234,
          state: "Established",
          role: "egress",
          observedAt: Date.now(),
          pid: 4,
          ppid: 1,
          processStartedAt: Date.now() - 1000,
          bin: "grok.exe",
          agent: "grok",
        },
      ],
    });
    assert.equal(ok?.status, "timeout");
    assert.equal(ok?.connections.length, 0);
  });
});

describe("receivedAt", () => {
  it("keeps server receivedAt and ignores client heartbeat timestamp", () => {
    const now = 1_700_000_000_000;
    const merged = mergeHeartbeatNetwork(
      undefined,
      { status: "ok", observedAt: now, receivedAt: 99, connections: [] },
      false,
      now + 80,
    );
    assert.equal(merged?.receivedAt, now + 80);
    assert.equal(publicNetworkSample(merged)?.receivedAt, now + 80);
  });
});

describe("history upsert", () => {
  it("keeps first/last seen and treats PID+start as a new key", () => {
    const now = 1_700_000_000_000;
    const conn = {
      remoteIp: "1.2.3.4",
      remotePort: 443,
      localIp: "10.0.0.2",
      localPort: 40000,
      state: "Established",
      role: "egress" as const,
      observedAt: now,
      pid: 9,
      ppid: 1,
      processStartedAt: now - 5_000,
      bin: "grok.exe",
      agent: "grok",
    };
    let rows = upsertNetworkHistory([], "dev_a", { status: "ok", observedAt: now, connections: [conn] }, () => "net_1");
    assert.equal(rows.length, 1);
    rows = upsertNetworkHistory(rows, "dev_a", { status: "ok", observedAt: now + 30_000, connections: [{ ...conn, observedAt: now + 30_000, state: "Established" }] }, () => "net_2");
    assert.equal(rows.length, 1);
    assert.equal(rows[0]?.firstSeen, now);
    assert.equal(rows[0]?.lastSeen, now + 30_000);
    rows = upsertNetworkHistory(rows, "dev_a", { status: "ok", observedAt: now + 40_000, connections: [{ ...conn, processStartedAt: now + 10_000, observedAt: now + 40_000 }] }, () => "net_3");
    assert.equal(rows.length, 2);
    rows = upsertNetworkHistory(rows, "dev_a", { status: "timeout", observedAt: now + 50_000, connections: [] }, () => "net_x");
    assert.equal(rows.length, 2);
  });
});
