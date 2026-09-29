/**
 * Append v1 hook failure bytes to tests/compat/fixtures/hook-bytes-golden.json.
 * Runs the packed nmzp.mjs the same way as tests/compat/hook-bytes-golden.test.mjs.
 * Does not rewrite the existing 65 cases. Over-limit stdin is stored compactly
 * (stdin + stdinPadTo + stdinPadChar) so the fixture stays reviewable.
 *
 *   node --experimental-strip-types scripts/gen-golden-failures.mjs
 */
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { copyFileSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { cp, mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { BODY_LIMIT } from "../core/constants.ts";
import { parseHookEvent } from "../core/hook-protocol.ts";
import { resolveGoldenStdin } from "../tests/compat/golden-stdin.mjs";
import { writePolicyCache } from "../core/policy-cache.ts";
import { packRelease } from "./release-archive.mjs";

const HOSTS = [
  "grok",
  "claude",
  "codex",
  "zcode",
  "antigravity",
  "kimi",
  "trae",
  "qwen",
  "qoder",
  "lingma",
  "codebuddy",
  "gemini",
  "cursor",
];
const KINDS = ["alias-conflict", "truncated", "over-limit"];
const PAD_TO = BODY_LIMIT + 1;
const GOLDEN_URL = new URL("../tests/compat/fixtures/hook-bytes-golden.json", import.meta.url);
const CLOSING = Buffer.from("\r\n  ]\r\n}\r\n");

function runHook(entry, home, argv, stdin) {
  return new Promise((resolve, reject) => {
    const env = { ...process.env, NMZP_HOME: home };
    for (const key of Object.keys(env)) {
      if (/^(GROK_|CLAUDE_|CURSOR_|CODEX_|ZCODE_|GEMINI_|NMZP_)/.test(key)) delete env[key];
    }
    env.NMZP_HOME = home;
    const child = spawn(process.execPath, ["--experimental-strip-types", entry, ...argv], {
      env,
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
    });
    const out = [];
    const err = [];
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`timeout ${argv.join(" ")}`));
    }, 20000);
    child.stdout.on("data", (data) => out.push(data));
    child.stderr.on("data", (data) => err.push(data));
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      if (signal) reject(new Error(`${argv.join(" ")}:${signal}`));
      else resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") });
    });
    child.stdin.end(stdin);
  });
}

async function freshHome(root, id) {
  const home = join(root, "homes", id);
  const cache = join(home, ".nmzp", "policy-cache.json");
  await mkdir(join(home, ".nmzp"), { recursive: true });
  await writePolicyCache(cache, { version: 1, mode: "enforcing", stopped: false, customRules: [], updatedAt: 1 });
  return home;
}

function denyByHost(cases) {
  const out = new Map();
  for (const item of cases) {
    if (item.kind === "deny" && !out.has(item.host)) out.set(item.host, item);
  }
  return out;
}

function aliasStdin(host, denyStdin) {
  const obj = JSON.parse(denyStdin);
  if (host === "antigravity") {
    obj.toolCall.args.TargetFile = "C:/repo/a.ts";
    obj.toolCall.args.AbsolutePath = "C:/repo/b.ts";
    if (obj.toolCall.args.TargetFile === obj.toolCall.args.AbsolutePath) {
      throw new Error("antigravity alias paths must differ");
    }
  } else {
    obj.tool_input.cmd = "echo distinct";
    if (obj.tool_input.command === obj.tool_input.cmd) throw new Error(`${host} command must differ from cmd`);
  }
  return JSON.stringify(obj);
}

function truncatedStdin(denyStdin) {
  const obj = JSON.parse(denyStdin);
  obj.toolInputTruncated = true;
  return JSON.stringify(obj);
}

function buildDrafts(cases) {
  const denies = denyByHost(cases);
  const drafts = [];
  for (const host of HOSTS) {
    const deny = denies.get(host);
    if (!deny) throw new Error(`missing deny case for ${host}`);
    const argv = [...deny.argv];
    for (const kind of KINDS) {
      const id = `${host}-${kind}`;
      if (kind === "alias-conflict") {
        const stdin = aliasStdin(host, deny.stdin);
        if (parseHookEvent(stdin) !== null) throw new Error(`${id} was parsed by v1`);
        drafts.push({ id, host, kind, argv, stdin });
      } else if (kind === "truncated") {
        const stdin = truncatedStdin(deny.stdin);
        if (parseHookEvent(stdin) !== null) throw new Error(`${id} was parsed by v1`);
        drafts.push({ id, host, kind, argv, stdin });
      } else {
        const draft = { id, host, kind, argv, stdin: deny.stdin, stdinPadTo: PAD_TO, stdinPadChar: "A" };
        const stdin = resolveGoldenStdin(draft);
        if (stdin.length !== PAD_TO) throw new Error(`${id} length ${stdin.length}`);
        if ([...stdin].some((ch) => ch.charCodeAt(0) > 0x7f)) throw new Error(`${id} is not ASCII`);
        drafts.push(draft);
      }
    }
  }
  if (drafts.length !== HOSTS.length * KINDS.length) throw new Error(`expected 39 drafts, got ${drafts.length}`);
  return drafts;
}

function formatCase(obj) {
  return JSON.stringify(obj, null, 2)
    .split("\n")
    .map((line) => `    ${line}`)
    .join("\r\n");
}

function assertPrefix(original, next) {
  if (!original.subarray(original.length - CLOSING.length).equals(CLOSING)) {
    throw new Error("golden file does not end with CRLF cases closer");
  }
  const prefix = original.subarray(0, original.length - CLOSING.length);
  if (!next.subarray(0, prefix.length).equals(prefix)) throw new Error("prefix bytes changed");
  const parsedNext = JSON.parse(next.toString("utf8"));
  const parsedOrig = JSON.parse(original.toString("utf8"));
  if (parsedNext.cases.length !== parsedOrig.cases.length + 39) {
    throw new Error(`case count ${parsedNext.cases.length}`);
  }
  for (let i = 0; i < parsedOrig.cases.length; i += 1) {
    if (JSON.stringify(parsedNext.cases[i]) !== JSON.stringify(parsedOrig.cases[i])) {
      throw new Error(`case ${i} ${parsedOrig.cases[i].id} changed`);
    }
  }
  return createHash("sha256").update(prefix).digest("hex");
}

function expectedMarker(kind, stdout) {
  if (kind === "over-limit") return stdout.includes("payload_too_large");
  return stdout.includes("bad_hook_json") && !stdout.includes("conflicting_aliases") && !stdout.includes("input_truncated");
}

async function main() {
  const goldenPath = fileURLToPath(GOLDEN_URL);
  const original = readFileSync(goldenPath);
  const golden = JSON.parse(original.toString("utf8"));
  const drafts = buildDrafts(golden.cases);
  const ids = drafts.map((item) => item.id);
  if (golden.cases.length === 65 + drafts.length && ids.every((id, index) => golden.cases[65 + index]?.id === id)) {
    const prefix = original.subarray(0, original.length - CLOSING.length);
    console.log(`already appended ${drafts.length} cases`);
    console.log(`prefix sha256 ${createHash("sha256").update(prefix).digest("hex")}`);
    return;
  }
  if (golden.cases.length !== 65) throw new Error(`expected 65 existing cases, got ${golden.cases.length}`);

  const root = await mkdtemp(join(tmpdir(), "nmzp-golden-fail-"));
  try {
    const source = fileURLToPath(new URL("../", import.meta.url));
    await cp(join(source, "core"), join(root, "core"), { recursive: true });
    await mkdir(join(root, "src", "lib"), { recursive: true });
    await cp(join(source, "src", "lib", "monitor"), join(root, "src", "lib", "monitor"), { recursive: true });
    await cp(join(source, "dist"), join(root, "dist"), { recursive: true });
    const packedDir = (await packRelease(root)).dir;
    const entry = join(packedDir, "nmzp.mjs");
    const records = [];
    for (const draft of drafts) {
      const home = await freshHome(root, draft.id);
      const got = await runHook(entry, home, draft.argv, resolveGoldenStdin(draft));
      if (!expectedMarker(draft.kind, got.stdout)) {
        throw new Error(`${draft.id} unexpected stdout ${JSON.stringify(got.stdout)} stderr ${JSON.stringify(got.stderr)} exit ${got.code}`);
      }
      const record = {
        id: draft.id,
        host: draft.host,
        kind: draft.kind,
        argv: draft.argv,
        stdin: draft.stdin,
      };
      if (draft.stdinPadTo !== undefined) {
        record.stdinPadTo = draft.stdinPadTo;
        record.stdinPadChar = draft.stdinPadChar;
      }
      record.stdout = got.stdout;
      record.stderr = got.stderr;
      record.exitCode = got.code;
      records.push(record);
      console.log(`${draft.id} exit=${got.code} stdout=${JSON.stringify(got.stdout)} stderr=${JSON.stringify(got.stderr)}`);
    }
    const body = records.map(formatCase).join(",\r\n");
    const next = Buffer.concat([
      original.subarray(0, original.length - CLOSING.length),
      Buffer.from(",\r\n", "utf8"),
      Buffer.from(body, "utf8"),
      CLOSING,
    ]);
    const prefixSha = assertPrefix(original, next);
    const tmpPath = `${goldenPath}.tmp`;
    writeFileSync(tmpPath, next);
    const reread = readFileSync(tmpPath);
    if (!reread.equals(next)) throw new Error("temp reread mismatch");
    assertPrefix(original, reread);
    copyFileSync(tmpPath, goldenPath);
    unlinkSync(tmpPath);
    console.log(`appended ${records.length} cases; total ${65 + records.length}`);
    console.log(`prefix sha256 ${prefixSha} (bytes before the new cases, unchanged)`);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

await main();
