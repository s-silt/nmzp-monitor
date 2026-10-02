// Policy compatibility guard. Read-only git. Never writes the corpus or the checkout index.
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { expectedDigest, loadRuntime, runCorpus } from "./spec-run.mjs";

export const BOOTSTRAP_COMMIT = "0ea8f6eac4457c5e13b22b7130f64d48e3613927";
export const BOOTSTRAP_EXPECTED_DIGEST =
  "a2588f36346e64f2dc8283f3f549f130dd4b152cd8017b8733adb9bbaa6ce3cd";
export const BOOTSTRAP_ENGINE_REVISION = 2;
export const BOOTSTRAP_CASE_COUNT = 443;
export const BOOTSTRAP_BUNDLE_ANCHOR =
  "b3fb1226310f1bb541b24de9fc1a196584d1be61814173c025e0709eac5af806";
export const BOOTSTRAP_METADATA = Object.freeze({
  "COVERAGE.json": "e8765104059152a1e8e5cf5a5493f8ecc3a8a771678378262b4ec02cb7d2e2a9",
  "PROPOSED_DIGEST.txt": "7d834bb90163666d07abcdafa0eca6c57879283388625701ac6922644644120e",
  "REVIEW_INDEX.md": "7a2d223d9f5f5b826a496819750e4626a690645af399a7192598edf049b63d61",
  "review-index.json": "aac798ef70cd3343ef6fedb2639c4f636baf63b95b6bf3e90792e3b1339411f7",
});
export const PROBE_RULES = Object.freeze([{ id: "synthetic_rule", action: "log" }]);

const CASE_FILES = ["input.json", "policy.json", "context.json", "expected.json"];
const COLLATIONS = ["en", "zh-CN", "zh-TW", "und"];
const WITNESS_BEFORE = "protected/monitor_self_tamper_cmd/disable";
const WITNESS_AFTER = "protected/monitor_self_tamper/disable";
const MAX_CASE_BYTES = 2_000_000;
const ZERO_SHA = "0".repeat(40);

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function scriptRoot() {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
}

// realpathSync.native has already expanded Win32 8.3 names and canonicalized
// case. Fold case on win32 only; do not treat any other path difference as equal.
function sameRoot(left, right) {
  if (process.platform === "win32") return left.toLowerCase() === right.toLowerCase();
  return left === right;
}

export function bundleAnchor(files) {
  const sorted = [...files].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const parts = [];
  for (const file of sorted) {
    if (typeof file.path !== "string" || file.path.includes("\\") || file.path.includes("\0")) {
      throw new Error("bundle path is not a forward-slash relative path");
    }
    parts.push(Buffer.from(file.path, "utf8"), Buffer.from([0]));
    parts.push(Buffer.from(sha256(file.bytes), "utf8"), Buffer.from("\n", "utf8"));
  }
  return sha256(Buffer.concat(parts));
}

export function digestExpected(entries) {
  const ordered = [...entries].sort((a, b) => a.id.localeCompare(b.id, "en"));
  const parts = [];
  for (const entry of ordered) {
    parts.push(Buffer.from(`${entry.id}/expected.json\n`));
    parts.push(entry.bytes);
  }
  return sha256(Buffer.concat(parts));
}

function sameSet(left, right) {
  if (left.length !== right.length) return false;
  const a = [...left].sort();
  const b = [...right].sort();
  return a.every((value, index) => value === b[index]);
}

function gitDetail(result) {
  const stderr = result.stderr ? result.stderr.toString("utf8").trim().split(/\r?\n/)[0] : "";
  if (result.error?.code === "ETIMEDOUT") return "git timed out";
  if (result.error) return result.error.code || result.error.message;
  return stderr || `git exit ${result.status}`;
}

function runGit(repo, args, input) {
  return spawnSync(
    "git",
    ["--no-optional-locks", "-c", "core.quotepath=false", "-C", repo, ...args],
    {
      cwd: repo,
      encoding: "buffer",
      input,
      maxBuffer: 64 * 1024 * 1024,
      timeout: 30_000,
      windowsHide: true,
    },
  );
}

// Last line is the peeled commit. The entire preceding record is the toplevel;
// a middle line stays in that record and is rejected instead of being dropped.
function parseRevParseRootAndCommit(stdout) {
  if (!Buffer.isBuffer(stdout) && typeof stdout !== "string") {
    return { ok: false, detail: "rev-parse format rejected" };
  }
  const text = Buffer.isBuffer(stdout) ? stdout.toString("utf8") : stdout;
  const body = text.replace(/\r?\n$/, "");
  const splitAt = body.lastIndexOf("\n");
  if (splitAt <= 0) return { ok: false, detail: "rev-parse format rejected" };
  let root = body.slice(0, splitAt);
  const sha = body.slice(splitAt + 1);
  if (root.endsWith("\r")) root = root.slice(0, -1);
  if (!/^[0-9a-f]{40}$/.test(sha) || root.length === 0 || /[\0\r\n]/.test(root)) {
    return { ok: false, detail: "rev-parse format rejected" };
  }
  return { ok: true, root, sha };
}

function parseLsTree(buffer) {
  const entries = [];
  let offset = 0;
  while (offset < buffer.length) {
    const nul = buffer.indexOf(0, offset);
    const end = nul < 0 ? buffer.length : nul;
    const line = buffer.toString("utf8", offset, end);
    offset = end + (nul < 0 ? 0 : 1);
    if (!line) continue;
    const tab = line.indexOf("\t");
    if (tab < 0) return null;
    const [mode, type, sha] = line.slice(0, tab).split(" ");
    const filePath = line.slice(tab + 1);
    if (!mode || !type || !/^[0-9a-f]{40}$/.test(sha ?? "") || !filePath) return null;
    entries.push({ mode, type, sha, path: filePath });
  }
  return entries;
}

function readOrderedBatch(repo, requests) {
  if (requests.length === 0) return { ok: false, detail: "git cat-file batch was incomplete" };
  for (const request of requests) {
    if (typeof request !== "string" || request.length === 0 || /[\0\r\n]/.test(request)) {
      return { ok: false, detail: "git cat-file batch was incomplete" };
    }
  }
  const input = Buffer.from(`${requests.join("\n")}\n`, "utf8");
  const result = runGit(repo, ["cat-file", "--batch"], input);
  if (result.error || result.status !== 0) return { ok: false, detail: gitDetail(result) };
  const buffer = result.stdout;
  const blobs = [];
  const missing = [];
  let offset = 0;
  for (let index = 0; index < requests.length; index += 1) {
    const nl = buffer.indexOf(0x0a, offset);
    if (nl < 0) return { ok: false, detail: "git cat-file batch was incomplete" };
    const header = buffer.toString("utf8", offset, nl);
    offset = nl + 1;
    const request = requests[index];
    if (header === `${request} missing`) {
      blobs.push(null);
      missing.push(index);
      continue;
    }
    const match = /^([0-9a-f]{40}) blob (\d+)$/.exec(header);
    if (!match) return { ok: false, detail: "git cat-file batch was incomplete" };
    const size = Number(match[2]);
    if (!Number.isInteger(size) || size < 0 || offset + size > buffer.length) {
      return { ok: false, detail: "git cat-file batch was incomplete" };
    }
    if (!/^[0-9a-f]{40}$/.test(request) || match[1] !== request) {
      return { ok: false, detail: "git cat-file batch was incomplete" };
    }
    blobs.push(Buffer.from(buffer.subarray(offset, offset + size)));
    offset += size;
    if (buffer[offset] !== 0x0a) return { ok: false, detail: "git cat-file batch was incomplete" };
    offset += 1;
  }
  if (offset !== buffer.length) return { ok: false, detail: "git cat-file batch was incomplete" };
  return { ok: true, blobs, missing };
}

function baselineCorpusAndRevision(repo, baseline, grouped, treeEntries) {
  const requests = [];
  const requestIndex = [];
  for (const [id, files] of grouped) {
    for (const name of CASE_FILES) {
      const sha = files.get(name);
      if (!/^[0-9a-f]{40}$/.test(sha ?? "")) {
        return { ok: false, missingRevision: false, detail: "git cat-file batch was incomplete" };
      }
      requests.push(sha);
      requestIndex.push([id, name]);
    }
  }
  const revisionPath = "core/policy/engine-revision.ts";
  const revisionEntry = treeEntries.find((entry) => entry.path === revisionPath);
  if (!revisionEntry && treeEntries.some((entry) => entry.path.startsWith(`${revisionPath}/`))) {
    return {
      ok: false,
      missingRevision: false,
      badRevisionType: true,
      detail: "baseline engine-revision.ts is 040000 tree, not a regular file blob",
    };
  }
  if (
    revisionEntry &&
    (revisionEntry.type !== "blob" ||
      (revisionEntry.mode !== "100644" && revisionEntry.mode !== "100755") ||
      !/^[0-9a-f]{40}$/.test(revisionEntry.sha))
  ) {
    return {
      ok: false,
      missingRevision: false,
      badRevisionType: true,
      detail: `baseline engine-revision.ts is ${revisionEntry.mode} ${revisionEntry.type}, not a regular file blob`,
    };
  }
  const revisionRequest = revisionEntry ? revisionEntry.sha : `${baseline}:core/policy/engine-revision.ts`;
  requests.push(revisionRequest);
  const read = readOrderedBatch(repo, requests);
  if (!read.ok) return { ok: false, missingRevision: false, detail: read.detail };
  const revisionSlot = requestIndex.length;
  if (read.blobs.length !== requests.length) {
    return { ok: false, missingRevision: false, detail: "git cat-file batch was incomplete" };
  }
  if (read.missing.some((index) => index !== revisionSlot)) {
    return { ok: false, missingRevision: false, detail: "git object missing" };
  }
  if (read.missing.length > 0) {
    return { ok: false, missingRevision: true, detail: "git object missing" };
  }
  const before = new Map();
  for (let index = 0; index < requestIndex.length; index += 1) {
    const blob = read.blobs[index];
    if (!Buffer.isBuffer(blob)) {
      return { ok: false, missingRevision: false, detail: "git cat-file batch was incomplete" };
    }
    const [id, name] = requestIndex[index];
    if (!before.has(id)) before.set(id, {});
    before.get(id)[name] = blob;
  }
  const revisionBlob = read.blobs[revisionSlot];
  if (!Buffer.isBuffer(revisionBlob)) {
    return { ok: false, missingRevision: false, detail: "git cat-file batch was incomplete" };
  }
  return { ok: true, before, revisionText: revisionBlob.toString("utf8") };
}

function validCaseId(id) {
  if (!id || id.length > 200 || id.includes("\\")) return false;
  const parts = id.split("/");
  if (parts.length < 2) return false;
  return parts.every((part) => /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(part));
}

function casesFromGit(entries) {
  const grouped = new Map();
  for (const entry of entries) {
    if (entry.path !== "policy-spec" && !entry.path.startsWith("policy-spec/")) continue;
    if (entry.mode === "120000" || entry.mode === "160000" || entry.type !== "blob") {
      return { ok: false, code: "symlink", detail: entry.path };
    }
    if (entry.path === "policy-spec") continue;
    const rel = entry.path.slice("policy-spec/".length);
    const name = path.posix.basename(rel);
    if (!CASE_FILES.includes(name)) continue;
    const id = path.posix.dirname(rel);
    if (!validCaseId(id)) return { ok: false, code: "invalid_case_id", detail: rel };
    if (!grouped.has(id)) grouped.set(id, new Map());
    if (grouped.get(id).has(name)) return { ok: false, code: "duplicate_path", detail: rel };
    grouped.get(id).set(name, entry.sha);
  }
  const ids = [...grouped.keys()];
  for (const id of ids) {
    const shadow = ids.find((other) => other !== id && other.startsWith(`${id}/`));
    if (shadow) return { ok: false, code: "nested_shadow", detail: `${id} hides ${shadow}` };
  }
  for (const [id, files] of grouped) {
    if (files.has("expected.json") && !files.has("input.json")) {
      return { ok: false, code: "orphan_expected", detail: id };
    }
    const missing = CASE_FILES.filter((name) => !files.has(name));
    if (missing.length > 0) return { ok: false, code: "missing_part", detail: `${id} ${missing.join(",")}` };
  }
  return { ok: true, grouped };
}

function findNested(dir, prefix) {
  const dirents = fs.readdirSync(dir, { withFileTypes: true });
  for (const dirent of dirents) {
    if (!dirent.isDirectory()) continue;
    const full = path.join(dir, dirent.name);
    const st = fs.lstatSync(full);
    const rel = `${prefix}/${dirent.name}`;
    if (st.isSymbolicLink()) return { kind: "symlink", path: rel };
    const children = fs.readdirSync(full);
    for (const name of children) {
      const childPath = path.join(full, name);
      const childStat = fs.lstatSync(childPath);
      if (childStat.isSymbolicLink()) return { kind: "symlink", path: `${rel}/${name}` };
      if (CASE_FILES.includes(name) && childStat.isFile()) return { kind: "case", path: rel };
    }
    const nested = findNested(full, rel);
    if (nested) return nested;
  }
  return null;
}

async function enumerateWorktree(root) {
  let rootStat;
  try {
    rootStat = fs.lstatSync(root);
  } catch (error) {
    if (error.code === "ENOENT") return { ok: true, cases: new Map() };
    return { ok: false, code: "enumeration_failed", detail: error.message };
  }
  if (rootStat.isSymbolicLink()) return { ok: false, code: "symlink", detail: "policy-spec" };
  if (!rootStat.isDirectory()) return { ok: false, code: "enumeration_failed", detail: "policy-spec" };
  const cases = new Map();

  function walk(dir, rel) {
    let dirents;
    try {
      dirents = fs.readdirSync(dir, { withFileTypes: true });
    } catch (error) {
      return { ok: false, code: "enumeration_failed", detail: error.message };
    }
    for (const dirent of dirents) {
      const full = path.join(dir, dirent.name);
      const st = fs.lstatSync(full);
      if (st.isSymbolicLink()) {
        return { ok: false, code: "symlink", detail: rel ? `${rel}/${dirent.name}` : dirent.name };
      }
    }
    const names = new Set(dirents.filter((dirent) => !dirent.isDirectory()).map((dirent) => dirent.name));
    const present = CASE_FILES.filter((name) => names.has(name));
    if (present.length > 0) {
      const label = rel || ".";
      if (!rel || !validCaseId(rel)) return { ok: false, code: "invalid_case_id", detail: label };
      if (names.has("expected.json") && !names.has("input.json")) {
        return { ok: false, code: "orphan_expected", detail: label };
      }
      if (present.length !== CASE_FILES.length) {
        const missing = CASE_FILES.filter((name) => !names.has(name));
        return { ok: false, code: "missing_part", detail: `${label} ${missing.join(",")}` };
      }
      const nested = findNested(dir, rel);
      if (nested?.kind === "symlink") return { ok: false, code: "symlink", detail: nested.path };
      if (nested?.kind === "case") return { ok: false, code: "nested_shadow", detail: `${rel} hides ${nested.path}` };
      const files = {};
      for (const name of CASE_FILES) {
        const filePath = path.join(dir, name);
        const st = fs.lstatSync(filePath);
        if (!st.isFile()) return { ok: false, code: "symlink", detail: `${rel}/${name}` };
        if (st.size > MAX_CASE_BYTES) return { ok: false, code: "case_file_too_large", detail: `${rel}/${name}` };
        files[name] = fs.readFileSync(filePath);
      }
      cases.set(rel, files);
      return { ok: true };
    }
    for (const dirent of dirents) {
      if (!dirent.isDirectory()) continue;
      const child = rel ? `${rel}/${dirent.name}` : dirent.name;
      const walked = walk(path.join(dir, dirent.name), child);
      if (!walked.ok) return walked;
    }
    return { ok: true };
  }

  const walked = await walk(root, "");
  if (!walked.ok) return walked;
  return { ok: true, cases };
}

function checkSort(ids, entries, officialDigest) {
  const orders = COLLATIONS.map((locale) => [...ids].sort((a, b) => a.localeCompare(b, locale)));
  for (let index = 1; index < orders.length; index += 1) {
    if (orders[index].some((id, place) => id !== orders[0][place])) {
      return {
        ok: false,
        code: "collation_disagreement",
        detail: `${COLLATIONS[index]} disagrees with en`,
      };
    }
  }
  const manual = digestExpected(entries);
  if (manual !== officialDigest) {
    return {
      ok: false,
      code: "digest_order_drift",
      detail: `en collation ${manual} spec-run ${officialDigest}`,
    };
  }
  if (ids.includes(WITNESS_BEFORE) && ids.includes(WITNESS_AFTER)) {
    const icu = WITNESS_BEFORE.localeCompare(WITNESS_AFTER, "en") < 0;
    const codeUnit = WITNESS_AFTER < WITNESS_BEFORE;
    if (!icu || !codeUnit) {
      return {
        ok: false,
        code: "collation_witness",
        detail: "approved order is ICU en, not code-unit order",
      };
    }
  }
  return { ok: true, collationWitness: ids.includes(WITNESS_BEFORE) && ids.includes(WITNESS_AFTER) };
}

function parseRevisionExport(text) {
  const matches = [...text.matchAll(/^export const ENGINE_REVISION = (\d+);[ \t]*$/gm)];
  if (matches.length !== 1) return null;
  const raw = matches[0][1];
  if (!/^(0|[1-9]\d*)$/.test(raw)) return null;
  const value = Number(raw);
  return Number.isSafeInteger(value) ? value : null;
}

export function parseIntendedChanges(text) {
  const matches = [...text.matchAll(/^```policy-compat-v1\r?\n([\s\S]*?)^```[ \t]*\r?$/gm)];
  if (matches.length !== 1) {
    return {
      ok: false,
      code: matches.length === 0 ? "missing_block" : "duplicate_block",
      detail: `policy-compat-v1 fences ${matches.length}`,
    };
  }
  const lines = matches[0][1].replace(/\r\n/g, "\n").replace(/\n$/, "").split("\n");
  if (lines.length === 1 && lines[0] === "") lines.pop();
  const entries = [];
  let index = 0;
  while (index < lines.length) {
    if (lines[index] === "") {
      index += 1;
      continue;
    }
    if (lines[index] !== "entry") {
      return { ok: false, code: "malformed_entry", detail: lines[index] };
    }
    const body = { cases: [] };
    const required = [
      "oldDigest",
      "newDigest",
      "oldRevision",
      "newRevision",
      "oldBundleAnchor",
      "newBundleAnchor",
      "reason",
    ];
    for (const key of required) {
      index += 1;
      const line = lines[index];
      if (line === undefined || !line.startsWith(`${key}=`)) {
        return { ok: false, code: "malformed_entry", detail: key };
      }
      body[key] = line.slice(key.length + 1);
    }
    if (!/^[0-9a-f]{64}$/.test(body.oldDigest) || !/^[0-9a-f]{64}$/.test(body.newDigest)) {
      return { ok: false, code: "digest_syntax", detail: "digest is not 64 lowercase hex" };
    }
    if (!/^[0-9a-f]{64}$/.test(body.oldBundleAnchor) || !/^[0-9a-f]{64}$/.test(body.newBundleAnchor)) {
      return { ok: false, code: "digest_syntax", detail: "bundle anchor is not 64 lowercase hex" };
    }
    if (!/^(0|[1-9]\d*)$/.test(body.oldRevision) || !/^(0|[1-9]\d*)$/.test(body.newRevision)) {
      return { ok: false, code: "revision_syntax", detail: "revision is not a canonical integer" };
    }
    body.oldRevision = Number(body.oldRevision);
    body.newRevision = Number(body.newRevision);
    if (body.reason.trim() === "" || body.reason.length > 400) {
      return { ok: false, code: "empty_reason", detail: "reason is empty" };
    }
    index += 1;
    const seen = new Set();
    while (index < lines.length && lines[index] !== "" && lines[index] !== "entry") {
      if (!lines[index].startsWith("case=")) {
        return { ok: false, code: "malformed_entry", detail: lines[index] };
      }
      const id = lines[index].slice("case=".length);
      if (!validCaseId(id)) return { ok: false, code: "invalid_case_id", detail: id };
      if (seen.has(id)) return { ok: false, code: "duplicate_case", detail: id };
      seen.add(id);
      body.cases.push(id);
      index += 1;
    }
    entries.push(body);
  }
  const signatures = new Set();
  for (const entry of entries) {
    const signature = `${entry.oldDigest}\0${entry.newDigest}\0${entry.oldRevision}\0${entry.newRevision}\0${entry.oldBundleAnchor}\0${entry.newBundleAnchor}`;
    if (signatures.has(signature)) return { ok: false, code: "duplicate_entry", detail: signature };
    signatures.add(signature);
  }
  return { ok: true, entries };
}

function changedCaseIds(before, after) {
  const ids = new Set([...before.keys(), ...after.keys()]);
  const changed = [];
  for (const id of ids) {
    const left = before.get(id);
    const right = after.get(id);
    if (!left || !right || CASE_FILES.some((name) => !left[name].equals(right[name]))) changed.push(id);
  }
  changed.sort((a, b) => a.localeCompare(b, "en"));
  return changed;
}

function judgeChange(input) {
  const {
    oldRevision,
    newRevision,
    oldDigest,
    newDigest,
    oldBundleAnchor,
    newBundleAnchor,
    changedIds,
    entries,
  } = input;
  if (newRevision < oldRevision) {
    return { ok: false, stage: "revision", code: "revision_decreased", detail: `${oldRevision} -> ${newRevision}` };
  }
  if (oldDigest !== newDigest && newRevision <= oldRevision) {
    return {
      ok: false,
      stage: "revision",
      code: "revision_not_increased",
      detail: "expected digest changed but ENGINE_REVISION did not increase",
    };
  }
  if (oldDigest !== newDigest && changedIds.length === 0) {
    return { ok: false, stage: "digest", code: "digest_without_case", detail: newDigest };
  }
  const exact = entries.filter(
    (entry) =>
      entry.oldDigest === oldDigest &&
      entry.newDigest === newDigest &&
      entry.oldRevision === oldRevision &&
      entry.newRevision === newRevision &&
      entry.oldBundleAnchor === oldBundleAnchor &&
      entry.newBundleAnchor === newBundleAnchor,
  );
  const changed = changedIds.length > 0 || newRevision !== oldRevision;
  if (!changed) {
    if (exact.length > 0) {
      return { ok: false, stage: "intended_changes", code: "spurious_entry", detail: "entry matches an unchanged corpus" };
    }
    return { ok: true };
  }
  if (exact.length > 1) {
    return { ok: false, stage: "intended_changes", code: "duplicate_entry", detail: "more than one matching entry" };
  }
  if (exact.length === 1) {
    if (!sameSet(exact[0].cases, changedIds)) {
      return {
        ok: false,
        stage: "intended_changes",
        code: "case_set_mismatch",
        detail: `entry ${exact[0].cases.join(",")} computed ${changedIds.join(",")}`,
      };
    }
    return { ok: true };
  }
  const sameOld = entries.filter((entry) => entry.oldDigest === oldDigest && entry.oldRevision === oldRevision);
  if (sameOld.length === 1) {
    if (sameOld[0].newDigest !== newDigest) {
      return {
        ok: false,
        stage: "intended_changes",
        code: "digest_mismatch",
        detail: `entry ${sameOld[0].newDigest} computed ${newDigest}`,
      };
    }
    if (sameOld[0].newRevision !== newRevision) {
      return {
        ok: false,
        stage: "intended_changes",
        code: "revision_mismatch",
        detail: `entry ${sameOld[0].newRevision} computed ${newRevision}`,
      };
    }
    if (!sameSet(sameOld[0].cases, changedIds)) {
      return {
        ok: false,
        stage: "intended_changes",
        code: "case_set_mismatch",
        detail: `entry ${sameOld[0].cases.join(",")} computed ${changedIds.join(",")}`,
      };
    }
  }
  return { ok: false, stage: "intended_changes", code: "missing_entry", detail: "no entry matches this transition" };
}

function formulaHash(rules, rewriteRevision, engineRevision) {
  return sha256(
    Buffer.from(JSON.stringify({ rules, rewriteRevision, engineRevision }), "utf8"),
  );
}

function rewriteServiceImports(source, policyDir, revisionFile) {
  let sawRevision = false;
  const rewritten = source.replace(/from\s+["'](\.[^"']+)["']/g, (_full, spec) => {
    const target = spec === "./engine-revision.ts" ? revisionFile : path.resolve(policyDir, spec);
    if (spec === "./engine-revision.ts") sawRevision = true;
    return `from ${JSON.stringify(pathToFileURL(target).href)}`;
  });
  return { rewritten, sawRevision };
}

async function proveRevisionBinding(repoRoot) {
  const policyDir = path.join(repoRoot, "core", "policy");
  const revisionPath = path.join(policyDir, "engine-revision.ts");
  const servicePath = path.join(policyDir, "nmzp-service.ts");
  let revisionNs;
  let serviceNs;
  try {
    revisionNs = await import(pathToFileURL(revisionPath).href);
    serviceNs = await import(pathToFileURL(servicePath).href);
  } catch (error) {
    return { ok: false, code: "import_error", detail: error.message };
  }
  const names = Object.keys(revisionNs).sort();
  if (names.length !== 1 || names[0] !== "ENGINE_REVISION" || !Number.isSafeInteger(revisionNs.ENGINE_REVISION)) {
    return { ok: false, code: "revision_export_mismatch", detail: names.join(",") };
  }
  if (typeof serviceNs.policyRulesHash !== "function") {
    return { ok: false, code: "import_error", detail: "policyRulesHash missing" };
  }
  const liveRevision = revisionNs.ENGINE_REVISION;
  const rules = PROBE_RULES.map((rule) => ({ ...rule }));
  let liveHash;
  try {
    liveHash = serviceNs.policyRulesHash({ RULES: rules });
  } catch (error) {
    return { ok: false, code: "import_error", detail: error.message };
  }
  let revisionText;
  let serviceText;
  try {
    revisionText = await fsp.readFile(revisionPath, "utf8");
    serviceText = await fsp.readFile(servicePath, "utf8");
  } catch (error) {
    return { ok: false, code: "import_error", detail: error.message };
  }
  if (parseRevisionExport(revisionText) !== liveRevision) {
    return { ok: false, code: "revision_export_mismatch", detail: "file export differs from the live value" };
  }
  const bumpedText = revisionText.replace(
    /^export const ENGINE_REVISION = (\d+);/m,
    `export const ENGINE_REVISION = ${liveRevision + 1};`,
  );
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "nmzp-rev-"));
  try {
    const bumpedFile = path.join(dir, "engine-revision.ts");
    const serviceCopy = path.join(dir, "nmzp-service.ts");
    const probeFile = path.join(dir, "probe.mjs");
    await fsp.writeFile(bumpedFile, bumpedText);
    const rewritten = rewriteServiceImports(serviceText, policyDir, bumpedFile);
    await fsp.writeFile(serviceCopy, rewritten.rewritten);
    await fsp.writeFile(
      probeFile,
      [
        'import { pathToFileURL } from "node:url";',
        "const { policyRulesHash } = await import(pathToFileURL(process.argv[2]).href);",
        `const rules = ${JSON.stringify(rules)};`,
        "process.stdout.write(policyRulesHash({ RULES: rules }));",
        "",
      ].join("\n"),
    );
    const child = spawnSync(process.execPath, ["--experimental-strip-types", probeFile, serviceCopy], {
      cwd: dir,
      encoding: "utf8",
      timeout: 20_000,
      windowsHide: true,
    });
    if (child.error?.code === "ETIMEDOUT") return { ok: false, code: "probe_timeout", detail: "revision probe timed out" };
    const bumpedHash = (child.stdout || "").trim();
    if (child.status !== 0 || !/^[0-9a-f]{64}$/.test(bumpedHash)) {
      const line = (child.stderr || child.error?.message || "probe failed").split(/\r?\n/)[0];
      return { ok: false, code: "import_error", detail: line.slice(0, 300) };
    }
    if (!rewritten.sawRevision || bumpedHash === liveHash) {
      return {
        ok: false,
        code: "revision_unbound",
        detail: "policyRulesHash did not change when only ENGINE_REVISION changed",
        liveHash,
        bumpedHash,
        engineRevision: liveRevision,
      };
    }
    const expected = formulaHash(rules, serviceNs.REWRITE_SEMANTICS_REVISION, liveRevision);
    if (liveHash !== expected) {
      return {
        ok: false,
        code: "hash_formula_mismatch",
        detail: "policyRulesHash does not serialize engineRevision after rewriteRevision",
        liveHash,
        engineRevision: liveRevision,
      };
    }
    return {
      ok: true,
      engineRevision: liveRevision,
      rewriteRevision: serviceNs.REWRITE_SEMANTICS_REVISION,
      liveHash,
      bumpedHash,
      bumpedRevision: liveRevision + 1,
    };
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
}

function expectedEntries(cases) {
  return [...cases.entries()].map(([id, files]) => ({ id, bytes: files["expected.json"] }));
}

function anchorFiles(cases) {
  const files = [];
  for (const [id, bundle] of cases) {
    for (const name of CASE_FILES) files.push({ path: `${id}/${name}`, bytes: bundle[name] });
  }
  return files;
}

async function metadataHashes(root) {
  const found = {};
  for (const name of Object.keys(BOOTSTRAP_METADATA)) {
    const full = path.join(root, name);
    const st = fs.lstatSync(full);
    if (st.isSymbolicLink() || !st.isFile()) return { ok: false, detail: name };
    found[name] = sha256(fs.readFileSync(full));
  }
  return { ok: true, found };
}

function parseArgs(argv, ci) {
  let base = null;
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--candidate" || arg === "--corpus" || arg.startsWith("--candidate=") || arg.startsWith("--corpus=")) {
      return { ok: false, stage: "baseline", code: "candidate_override", detail: arg };
    }
    if (arg === "--base") {
      if (ci) return { ok: false, stage: "baseline", code: "baseline_override", detail: "CI accepts only the event baseline" };
      const value = argv[index + 1];
      if (!value || value.startsWith("--")) {
        return { ok: false, stage: "baseline", code: "baseline_required", detail: "missing --base" };
      }
      base = value;
      index += 1;
      continue;
    }
    return { ok: false, stage: "baseline", code: "cli_rejected", detail: arg };
  }
  if (!ci && !base) return { ok: false, stage: "baseline", code: "baseline_required", detail: "pass --base" };
  return { ok: true, base };
}

// A default branch is a single ref name. It is never inferred, and it is never
// passed through a shell.
function validDefaultBranch(branch) {
  if (typeof branch !== "string" || branch.length < 1 || branch.length > 255) return false;
  if (!/^[A-Za-z0-9._/-]+$/.test(branch)) return false;
  if (branch.startsWith("/") || branch.endsWith("/") || branch.startsWith("-") || branch.endsWith(".lock")) return false;
  if (branch.includes("..") || branch.includes("//") || branch.includes("@{")) return false;
  return branch.split("/").every((part) => part.length > 0 && part !== "." && part !== ".." && !part.startsWith("."));
}

function requestMergeBase(event, sourcePrefix) {
  const branch = event.repository?.default_branch;
  if (!validDefaultBranch(branch)) {
    return { ok: false, code: "default_branch_missing", detail: "event.repository.default_branch missing" };
  }
  return { ok: true, mergeBase: true, branch, source: `${sourcePrefix}${branch}` };
}

function resolveMergeBase(repo, branch) {
  const ref = `refs/remotes/origin/${branch}`;
  const verified = runGit(repo, ["rev-parse", "--verify", "--end-of-options", `${ref}^{commit}`]);
  if (verified.error || verified.status !== 0) {
    return { ok: false, code: "merge_base_unavailable", detail: `origin/${branch} is not available` };
  }
  const merged = runGit(repo, ["merge-base", "--end-of-options", "HEAD", ref]);
  if (merged.error || merged.status !== 0) {
    return { ok: false, code: "merge_base_unavailable", detail: `no merge-base for HEAD and origin/${branch}` };
  }
  const sha = merged.stdout.toString("utf8").trim().toLowerCase();
  if (!/^[0-9a-f]{40}$/.test(sha) || sha.includes("\n") || sha === ZERO_SHA) {
    return { ok: false, code: "merge_base_unavailable", detail: `merge-base for origin/${branch} was not one commit` };
  }
  return { ok: true, sha };
}

function revisionExportAt(repo, sha, treeEntries) {
  const revisionPath = "core/policy/engine-revision.ts";
  const entry = treeEntries.find((item) => item.path === revisionPath);
  if (!entry) {
    if (treeEntries.some((item) => item.path.startsWith(`${revisionPath}/`))) {
      return {
        ok: false,
        badType: true,
        detail: "baseline engine-revision.ts is 040000 tree, not a regular file blob",
      };
    }
    // This commit has no engine-revision file. That is a state, not a read failure.
    return { ok: true, present: false, revision: null };
  }
  const loaded = baselineCorpusAndRevision(repo, sha, new Map(), treeEntries);
  if (!loaded.ok) return { ok: false, loaded, badType: Boolean(loaded.badRevisionType), detail: loaded.detail };
  const revision = parseRevisionExport(loaded.revisionText);
  if (revision === null) {
    return { ok: false, missingExport: true, detail: "engine-revision.ts has no single ENGINE_REVISION export" };
  }
  return { ok: true, present: true, revision };
}

function revisionLabel(state) {
  return state.present ? String(state.revision) : "absent";
}

function inspectCommit(repo, sha) {
  const listed = runGit(repo, ["ls-tree", "-r", "-z", sha]);
  if (listed.error || listed.status !== 0) return { ok: false, detail: gitDetail(listed) };
  const treeEntries = parseLsTree(listed.stdout);
  if (!treeEntries) return { ok: false, detail: "ls-tree parse failed" };
  const cases = casesFromGit(treeEntries);
  if (!cases.ok) return { ok: false, detail: `${cases.code}: ${cases.detail}` };
  const revision = revisionExportAt(repo, sha, treeEntries);
  if (!revision.ok) return { ok: false, detail: revision.detail };
  return { ok: true, caseCount: cases.grouped.size, present: revision.present, revision: revision.revision };
}

// CI baseline comes only from the event. The candidate is the checkout worktree:
// pull_request is GitHub's merge commit, push is the pushed commit, and
// workflow_dispatch is the selected ref. A PR can still change this file.
// An all-zero push before and an empty dispatch baseline use merge-base with
// origin/<repository.default_branch>. CLI --base does not.
function eventBaseline(env) {
  if (!env.GITHUB_EVENT_PATH) return { ok: false, code: "event_unreadable", detail: "GITHUB_EVENT_PATH missing" };
  let event;
  try {
    event = JSON.parse(fs.readFileSync(env.GITHUB_EVENT_PATH, "utf8"));
  } catch (error) {
    return { ok: false, code: "event_unreadable", detail: error.message };
  }
  const name = env.GITHUB_EVENT_NAME;
  let raw = "";
  let source = name;
  if (name === "pull_request") {
    raw = event.pull_request?.base?.sha ?? "";
    source = "pull_request.base.sha";
  } else if (name === "push") {
    if (event.deleted === true) {
      return {
        ok: true,
        skip: true,
        code: "push_deleted",
        detail: "deleted branch push skipped",
        source: "push.deleted",
      };
    }
    raw = event.before ?? "";
    source = "push.before";
    if (typeof raw === "string" && raw.trim().toLowerCase() === ZERO_SHA) {
      return requestMergeBase(event, "push.before=zero→merge-base:origin/");
    }
  } else if (name === "workflow_dispatch") {
    source = "workflow_dispatch.inputs.baseline";
    const input = event.inputs?.baseline;
    if (input == null) {
      return requestMergeBase(event, "workflow_dispatch.inputs.baseline=empty→merge-base:origin/");
    }
    if (typeof input !== "string") return { ok: false, code: "baseline_not_sha", detail: source };
    if (input.trim() === "") {
      return requestMergeBase(event, "workflow_dispatch.inputs.baseline=empty→merge-base:origin/");
    }
    raw = input;
  } else {
    return { ok: false, code: "unsupported_event", detail: String(name || "missing") };
  }
  if (typeof raw !== "string" || raw.trim() === "") {
    return { ok: false, code: "baseline_required", detail: source };
  }
  const sha = raw.trim().toLowerCase();
  if (sha === ZERO_SHA) return { ok: false, code: "zero_baseline", detail: "refusing the all-zero before SHA" };
  if (!/^[0-9a-f]{40}$/.test(sha)) return { ok: false, code: "baseline_not_sha", detail: source };
  return { ok: true, sha, source };
}

function finish(partial) {
  return {
    ok: false,
    bootstrap: false,
    bootstrapFrom: null,
    mode: "rejected",
    baseline: null,
    corpusRan: false,
    corpusOk: false,
    changedCases: [],
    ...partial,
  };
}

async function readCandidateRevision(repoRoot) {
  let text;
  try {
    text = await fsp.readFile(path.join(repoRoot, "core", "policy", "engine-revision.ts"), "utf8");
  } catch (error) {
    return { ok: false, stage: "revision", code: "revision_unreadable", detail: error.message };
  }
  const revision = parseRevisionExport(text);
  if (revision === null) {
    return {
      ok: false,
      stage: "revision",
      code: "revision_export_mismatch",
      detail: "current engine-revision.ts has no single canonical ENGINE_REVISION export",
    };
  }
  return { ok: true, revision };
}

async function rejectFixedBootstrap(input) {
  const { repoRoot, corpusRoot, current, official, candidateRevision, sort, baseline, baselineSource, bootstrapFrom, anchor } = input;
  const common = {
    baseline,
    baselineSource,
    bootstrapFrom,
    expectedDigest: official.digest,
    caseCount: current.cases.size,
    sortContract: "icu-en",
    collationWitness: sort.collationWitness,
    bootstrap: true,
    mode: "bootstrap",
    bundleAnchor: anchor,
  };
  if (candidateRevision !== BOOTSTRAP_ENGINE_REVISION) {
    return finish({
      ...common,
      stage: "bootstrap",
      code: "bootstrap_revision_mismatch",
      detail: `candidate ${candidateRevision} approved ${BOOTSTRAP_ENGINE_REVISION}`,
    });
  }
  if (current.cases.size !== BOOTSTRAP_CASE_COUNT) {
    return finish({
      ...common,
      stage: "bootstrap",
      code: "bootstrap_count_mismatch",
      detail: `cases ${current.cases.size}`,
    });
  }
  if (official.digest !== BOOTSTRAP_EXPECTED_DIGEST) {
    return finish({
      ...common,
      stage: "bootstrap",
      code: "bootstrap_digest_mismatch",
      detail: `candidate ${official.digest} approved ${BOOTSTRAP_EXPECTED_DIGEST}`,
    });
  }
  if (anchor !== BOOTSTRAP_BUNDLE_ANCHOR) {
    return finish({
      ...common,
      stage: "bootstrap",
      code: "bootstrap_anchor_mismatch",
      detail: `candidate ${anchor} approved ${BOOTSTRAP_BUNDLE_ANCHOR}`,
    });
  }
  let meta;
  try {
    meta = await metadataHashes(corpusRoot);
  } catch (error) {
    meta = { ok: false, detail: error.message };
  }
  if (!meta.ok) {
    return finish({
      ...common,
      stage: "bootstrap",
      code: "bootstrap_metadata_mismatch",
      detail: meta.detail,
    });
  }
  for (const [name, expected] of Object.entries(BOOTSTRAP_METADATA)) {
    if (meta.found[name] !== expected) {
      return finish({
        ...common,
        stage: "bootstrap",
        code: "bootstrap_metadata_mismatch",
        detail: name,
      });
    }
  }
  let record;
  try {
    record = parseIntendedChanges(await fsp.readFile(path.join(repoRoot, "INTENDED_CHANGES.md"), "utf8"));
  } catch (error) {
    record = { ok: false, code: error.code === "ENOENT" ? "missing_record" : "malformed_entry", detail: error.message };
  }
  if (!record.ok) {
    return finish({
      ...common,
      stage: "intended_changes",
      code: record.code,
      detail: record.detail,
    });
  }
  if (record.entries.length !== 0) {
    return finish({
      ...common,
      stage: "bootstrap",
      code: "bootstrap_spurious_entry",
      detail: "bootstrap exact admission has no intended-change entry",
    });
  }
  return null;
}

async function compareTransition(input) {
  const { repoRoot, baseline, treeEntries, baselineCases, current, official, candidateRevision } = input;
  const loaded = baselineCorpusAndRevision(repoRoot, baseline, baselineCases.grouped, treeEntries);
  if (!loaded.ok) {
    return {
      ok: false,
      failure: finish({
        stage: loaded.missingRevision || loaded.badRevisionType ? "revision" : "baseline",
        code: loaded.badRevisionType
          ? "baseline_revision_type"
          : loaded.missingRevision
            ? "baseline_revision_missing"
            : "git_read_failed",
        detail: loaded.detail,
        baseline,
        mode: "compare",
      }),
    };
  }
  const before = loaded.before;
  const oldEntries = [...before.entries()].map(([id, files]) => ({ id, bytes: files["expected.json"] }));
  const oldDigest = digestExpected(oldEntries);
  const baseSort = checkSort([...before.keys()], oldEntries, oldDigest);
  if (!baseSort.ok) {
    return {
      ok: false,
      failure: finish({ stage: "sort", code: baseSort.code, detail: baseSort.detail, baseline, mode: "compare" }),
    };
  }
  const oldRevision = parseRevisionExport(loaded.revisionText);
  if (oldRevision === null) {
    return {
      ok: false,
      failure: finish({
        stage: "revision",
        code: "baseline_revision_missing",
        detail: "baseline engine-revision.ts has no single ENGINE_REVISION export",
        baseline,
        mode: "compare",
      }),
    };
  }
  const changedIds = changedCaseIds(before, current.cases);
  // Claims in the record are not the transition. Hash baseline blobs and current four-file bytes.
  const oldBundleAnchor = bundleAnchor(anchorFiles(before));
  const newBundleAnchor = bundleAnchor(anchorFiles(current.cases));
  let record;
  try {
    record = parseIntendedChanges(await fsp.readFile(path.join(repoRoot, "INTENDED_CHANGES.md"), "utf8"));
  } catch (error) {
    record = { ok: false, code: error.code === "ENOENT" ? "missing_record" : "malformed_entry", detail: error.message };
  }
  if (!record.ok) {
    return {
      ok: false,
      failure: finish({
        stage: "intended_changes",
        code: record.code,
        detail: record.detail,
        baseline,
        mode: "compare",
        oldDigest,
        newDigest: official.digest,
        oldRevision,
        newRevision: candidateRevision,
        changedCases: changedIds,
      }),
    };
  }
  const judged = judgeChange({
    oldRevision,
    newRevision: candidateRevision,
    oldDigest,
    newDigest: official.digest,
    oldBundleAnchor,
    newBundleAnchor,
    changedIds,
    entries: record.entries,
  });
  if (!judged.ok) {
    return {
      ok: false,
      failure: finish({
        ...judged,
        baseline,
        mode: "compare",
        oldDigest,
        newDigest: official.digest,
        oldRevision,
        newRevision: candidateRevision,
        oldBundleAnchor,
        newBundleAnchor,
        changedCases: changedIds,
        caseCount: current.cases.size,
        expectedDigest: official.digest,
        engineRevision: candidateRevision,
      }),
    };
  }
  return { ok: true, oldDigest, oldRevision, changedIds, oldBundleAnchor, newBundleAnchor };
}

async function runGuardInner(options) {
  const argv = options.argv ?? process.argv.slice(2);
  const env = options.env ?? process.env;
  const cwd = options.cwd ?? process.cwd();
  const ci = env.GITHUB_ACTIONS === "true";
  const parsedArgs = parseArgs(argv, ci);
  if (!parsedArgs.ok) return finish(parsedArgs);

  let requested = parsedArgs.base;
  let baselineSource = "cli --base";
  if (ci) {
    const event = eventBaseline(env);
    if (event.skip) {
      return {
        ok: true,
        stage: "baseline",
        code: event.code,
        detail: event.detail,
        bootstrap: false,
        bootstrapFrom: null,
        mode: "skipped",
        baseline: null,
        baselineSource: event.source,
        corpusRan: false,
        corpusOk: false,
        changedCases: [],
      };
    }
    if (!event.ok) return finish({ stage: "baseline", code: event.code, detail: event.detail });
    if (event.mergeBase) {
      const merged = resolveMergeBase(cwd, event.branch);
      if (!merged.ok) {
        return finish({
          stage: "baseline",
          code: merged.code,
          detail: merged.detail,
          baselineSource: event.source,
        });
      }
      requested = merged.sha;
    } else {
      requested = event.sha;
    }
    baselineSource = event.source;
  }
  if (typeof requested !== "string" || requested.startsWith("-") || /[\0\r\n]/.test(requested)) {
    return finish({ stage: "baseline", code: "baseline_not_sha", detail: baselineSource });
  }

  const resolved = runGit(cwd, [
    "rev-parse",
    "--show-toplevel",
    "--verify",
    "--end-of-options",
    `${requested}^{commit}`,
  ]);
  if (resolved.error || resolved.status !== 0) {
    return finish({
      stage: "baseline",
      code: "git_read_failed",
      detail: `${gitDetail(resolved)}; bootstrap not applied`,
      baseline: null,
    });
  }
  const parsed = parseRevParseRootAndCommit(resolved.stdout);
  if (!parsed.ok) {
    return finish({
      stage: "baseline",
      code: "git_read_failed",
      detail: `${parsed.detail}; bootstrap not applied`,
      baseline: null,
    });
  }
  let repoRoot;
  try {
    repoRoot = fs.realpathSync.native(parsed.root);
  } catch (error) {
    return finish({ stage: "baseline", code: "git_read_failed", detail: error.message, baseline: null });
  }
  let localRoot;
  try {
    localRoot = fs.realpathSync.native(scriptRoot());
  } catch (error) {
    return finish({ stage: "baseline", code: "git_read_failed", detail: error.message, baseline: null });
  }
  if (!sameRoot(repoRoot, localRoot)) {
    return finish({
      stage: "baseline",
      code: "root_mismatch",
      detail: "guard script and git toplevel are different trees",
      baseline: null,
    });
  }
  const baseline = parsed.sha;
  if (ci && baseline !== requested.toLowerCase()) {
    return finish({ stage: "baseline", code: "baseline_mismatch", detail: baselineSource, baseline });
  }
  const ancestor = runGit(repoRoot, ["merge-base", "--is-ancestor", baseline, "HEAD"]);
  if (ancestor.error || (ancestor.status !== 0 && ancestor.status !== 1)) {
    return finish({ stage: "baseline", code: "git_read_failed", detail: gitDetail(ancestor), baseline });
  }
  if (ancestor.status === 1) {
    return finish({
      stage: "baseline",
      code: "not_ancestor",
      detail: "baseline is not an ancestor of HEAD",
      baseline,
    });
  }

  const listed = runGit(repoRoot, ["ls-tree", "-r", "-z", baseline]);
  if (listed.error || listed.status !== 0) {
    return finish({
      stage: "baseline",
      code: "git_read_failed",
      detail: `${gitDetail(listed)}; bootstrap not applied`,
      baseline,
    });
  }
  const treeEntries = parseLsTree(listed.stdout);
  if (!treeEntries) {
    return finish({ stage: "baseline", code: "git_read_failed", detail: "ls-tree parse failed", baseline });
  }
  const baselineCases = casesFromGit(treeEntries);
  if (!baselineCases.ok) {
    return finish({ stage: "baseline", ...baselineCases, baseline, mode: "rejected" });
  }

  const corpusRoot = path.join(repoRoot, "policy-spec");
  const current = await enumerateWorktree(corpusRoot);
  if (!current.ok) return finish({ stage: "enumeration", code: current.code, detail: current.detail, baseline });

  // File parse, digest, bootstrap pins, baseline revision, and the exact transition
  // can reject before the probe. parseRevisionExport does not prove the live export.
  const candidate = await readCandidateRevision(repoRoot);
  if (!candidate.ok) {
    return finish({ stage: candidate.stage, code: candidate.code, detail: candidate.detail, baseline });
  }

  const currentEntries = expectedEntries(current.cases);
  let official;
  try {
    official = fs.existsSync(corpusRoot)
      ? await expectedDigest(corpusRoot)
      : { digest: digestExpected([]), count: 0 };
  } catch (error) {
    return finish({ stage: "digest", code: "digest_failed", detail: error.message, baseline });
  }
  const sort = checkSort([...current.cases.keys()], currentEntries, official.digest);
  if (!sort.ok) return finish({ stage: "sort", code: sort.code, detail: sort.detail, baseline });
  const manual = digestExpected(currentEntries);
  if (manual !== official.digest || official.count !== current.cases.size) {
    return finish({
      stage: "sort",
      code: "digest_order_drift",
      detail: `cases ${current.cases.size} spec-run ${official.count}`,
      baseline,
    });
  }

  const baseIds = [...baselineCases.grouped.keys()];
  // Exact BOOTSTRAP_COMMIT keeps the original admission path: the candidate is
  // pinned to the guard constants, and this branch does not read ENGINE_REVISION
  // from Git. An empty descendant must match that commit's parsed export so a
  // revision change already on the baseline is not skipped.
  let bootstrapFrom = null;
  let bootstrapEligible = false;
  if (baseIds.length === 0 && baseline === BOOTSTRAP_COMMIT) {
    bootstrapEligible = true;
    bootstrapFrom = BOOTSTRAP_COMMIT;
  } else if (baseIds.length === 0) {
    const ancestor = runGit(repoRoot, ["merge-base", "--is-ancestor", BOOTSTRAP_COMMIT, baseline]);
    if (ancestor.error) {
      return finish({ stage: "baseline", code: "git_read_failed", detail: gitDetail(ancestor), baseline, baselineSource });
    }
    if (ancestor.status === 0) {
      const source = inspectCommit(repoRoot, BOOTSTRAP_COMMIT);
      if (!source.ok) {
        return finish({
          stage: "baseline",
          code: "git_read_failed",
          detail: `bootstrap commit: ${source.detail}`,
          baseline,
          baselineSource,
          bootstrapFrom: BOOTSTRAP_COMMIT,
        });
      }
      if (source.caseCount === 0) {
        const baselineRevision = revisionExportAt(repoRoot, baseline, treeEntries);
        if (!baselineRevision.ok) {
          const loaded = baselineRevision.loaded;
          return finish({
            stage: baselineRevision.badType || loaded?.badRevisionType || loaded?.missingRevision || baselineRevision.missingExport ? "revision" : "baseline",
            code: baselineRevision.badType || loaded?.badRevisionType
              ? "baseline_revision_type"
              : loaded?.missingRevision || baselineRevision.missingExport
                ? "baseline_revision_missing"
                : "git_read_failed",
            detail: baselineRevision.detail,
            baseline,
            baselineSource,
            bootstrap: true,
            bootstrapFrom: BOOTSTRAP_COMMIT,
            mode: "bootstrap",
          });
        }
        // Presence and parsed value both count. The pinned commit currently has
        // no engine-revision.ts; an exact match does not read that absence from Git.
        if (baselineRevision.present !== source.present || baselineRevision.revision !== source.revision) {
          return finish({
            stage: "revision",
            code: "bootstrap_baseline_revision_mismatch",
            detail: `baseline ENGINE_REVISION ${revisionLabel(baselineRevision)} differs from ${BOOTSTRAP_COMMIT} ENGINE_REVISION ${revisionLabel(source)}`,
            baseline,
            baselineSource,
            bootstrap: true,
            bootstrapFrom: BOOTSTRAP_COMMIT,
            mode: "bootstrap",
          });
        }
        bootstrapEligible = true;
        bootstrapFrom = BOOTSTRAP_COMMIT;
      }
    }
  }
  if (baseIds.length === 0 && !bootstrapEligible) {
    return finish({
      stage: "baseline",
      code: "baseline_without_corpus",
      detail: "baseline has no corpus and is not an empty-corpus descendant of the pinned bootstrap commit",
      baseline,
      baselineSource,
    });
  }

  const anchor = bootstrapEligible ? bundleAnchor(anchorFiles(current.cases)) : null;
  if (bootstrapEligible) {
    const premature = await rejectFixedBootstrap({
      repoRoot,
      corpusRoot,
      current,
      official,
      candidateRevision: candidate.revision,
      sort,
      baseline,
      baselineSource,
      bootstrapFrom,
      anchor,
    });
    if (premature) return premature;
  }

  let compared = null;
  if (!bootstrapEligible) {
    compared = await compareTransition({
      repoRoot,
      baseline,
      treeEntries,
      baselineCases,
      current,
      official,
      candidateRevision: candidate.revision,
    });
    if (!compared.ok) {
      if (compared.failure.baselineSource == null) compared.failure.baselineSource = baselineSource;
      return compared.failure;
    }
  }

  const binding = await proveRevisionBinding(repoRoot);
  if (!binding.ok) {
    return finish({
      stage: "hash_binding",
      code: binding.code,
      detail: binding.detail,
      baseline,
      baselineSource,
      bootstrapFrom,
      ...(bootstrapEligible ? { bootstrap: true, mode: "bootstrap" } : {}),
    });
  }
  if (binding.engineRevision !== candidate.revision) {
    return finish({
      stage: "hash_binding",
      code: "revision_export_mismatch",
      detail: `live ENGINE_REVISION ${binding.engineRevision} differs from candidate ${candidate.revision}`,
      baseline,
      baselineSource,
      bootstrapFrom,
      ...(bootstrapEligible ? { bootstrap: true, mode: "bootstrap" } : {}),
    });
  }

  const shared = {
    baseline,
    baselineSource,
    bootstrapFrom,
    engineRevision: binding.engineRevision,
    expectedDigest: official.digest,
    caseCount: current.cases.size,
    sortContract: "icu-en",
    collationWitness: sort.collationWitness,
    hashBinding: {
      changed: true,
      liveHash: binding.liveHash,
      bumpedHash: binding.bumpedHash,
      bumpedRevision: binding.bumpedRevision,
    },
  };

  if (bootstrapEligible) {
    const corpus = await runCurrentCorpus(repoRoot, corpusRoot);
    if (!corpus.ok) {
      return finish({ ...shared, ...corpus, bootstrap: true, mode: "bootstrap", bundleAnchor: anchor, changedCases: [] });
    }
    return {
      ok: true,
      stage: "ok",
      code: "ok",
      ...shared,
      bootstrap: true,
      mode: "bootstrap",
      bundleAnchor: anchor,
      changedCases: [],
      corpusRan: true,
      corpusOk: true,
      detail: "",
    };
  }

  const corpus = await runCurrentCorpus(repoRoot, corpusRoot);
  if (!corpus.ok) {
    return finish({
      ...shared,
      ...corpus,
      mode: "compare",
      oldDigest: compared.oldDigest,
      newDigest: official.digest,
      oldRevision: compared.oldRevision,
      newRevision: binding.engineRevision,
      oldBundleAnchor: compared.oldBundleAnchor,
      newBundleAnchor: compared.newBundleAnchor,
      changedCases: compared.changedIds,
    });
  }
  return {
    ok: true,
    stage: "ok",
    code: "ok",
    detail: "",
    ...shared,
    bootstrap: false,
    mode: "compare",
    oldDigest: compared.oldDigest,
    newDigest: official.digest,
    oldRevision: compared.oldRevision,
    newRevision: binding.engineRevision,
    oldBundleAnchor: compared.oldBundleAnchor,
    newBundleAnchor: compared.newBundleAnchor,
    changedCases: compared.changedIds,
    corpusRan: true,
    corpusOk: true,
  };
}

async function runCurrentCorpus(repoRoot, corpusRoot) {
  try {
    const api = await loadRuntime(repoRoot);
    const result = await runCorpus(corpusRoot, api);
    if (result.ok) return { ok: true };
    const first = result.failures[0];
    return {
      ok: false,
      stage: "corpus",
      code: first?.code || "corpus_failed",
      detail: `${first?.id || ""} ${first?.detail || ""}`.trim().slice(0, 500),
      corpusRan: true,
      corpusOk: false,
    };
  } catch (error) {
    return { ok: false, stage: "corpus", code: "import_error", detail: error.message, corpusRan: true, corpusOk: false };
  }
}

export async function runGuard(options = {}) {
  const started = Date.now();
  try {
    const result = await runGuardInner(options);
    result.elapsedMs = Date.now() - started;
    return result;
  } catch (error) {
    return finish({
      stage: "guard",
      code: "unexpected",
      detail: error instanceof Error ? error.message : String(error),
      elapsedMs: Date.now() - started,
    });
  }
}

function invokedDirectly() {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return sameRoot(fs.realpathSync.native(fileURLToPath(import.meta.url)), fs.realpathSync.native(entry));
  } catch {
    return false;
  }
}

if (invokedDirectly()) {
  runGuard()
    .then((result) => {
      process.stdout.write(`${JSON.stringify(result)}\n`);
      process.exitCode = result.ok ? 0 : 1;
    })
    .catch((error) => {
      process.stdout.write(
        `${JSON.stringify({
          ok: false,
          stage: "guard",
          code: "unexpected",
          detail: error instanceof Error ? error.message : String(error),
          bootstrap: false,
          bootstrapFrom: null,
          corpusRan: false,
        })}\n`,
      );
      process.exitCode = 1;
    });
}
