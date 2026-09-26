import assert from "node:assert/strict";
import { it } from "node:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { DatabaseSync } from "node:sqlite";
import { writeAuditExport } from "./export-stream.ts";
import { AuditStore } from "./store.ts";

const MARKER = "m14-only-corrupt-body-9f3c2a";

function event(id) {
  return {
    id, ts: 100, machineId: "m", agent: "grok", sessionId: "s", layer: "app_pre", tool: "Read",
    nativeTool: "Read", input: "synthetic", risk: "info", decision: "log", category: "other",
    workdirScope: "project", redacted: "synthetic", policyVersion: 1, evaluation: "log",
    enforcement: "pending_verify",
  };
}

async function seeded(t, ids, corruptId) {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-audit-corrupt-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, "nmzp.db");
  const store = AuditStore.create(path, { maxAgeMs: 0, minFreeBytes: 0 });
  for (const id of ids) await store.append(event(id));
  let seq = null;
  const corruptIds = Array.isArray(corruptId) ? corruptId : corruptId ? [corruptId] : [];
  if (corruptIds.length > 0) {
    const db = new DatabaseSync(path);
    try {
      const select = db.prepare("SELECT seq FROM audit_events WHERE id=?");
      const update = db.prepare("UPDATE audit_events SET body=? WHERE id=?");
      const marker = Buffer.from(MARKER);
      for (const id of corruptIds) {
        const row = select.get(id);
        if (corruptIds.length === 1) seq = row.seq;
        update.run(marker, id);
      }
    } finally {
      db.close();
    }
  }
  return { store, seq };
}

function captureResponse() {
  const chunks = [];
  const response = new Writable({
    write(chunk, _encoding, callback) {
      chunks.push(Buffer.from(chunk));
      callback();
    },
  });
  response.writeHead = () => response;
  return { response, text: () => Buffer.concat(chunks).toString("utf8") };
}

async function exportText(store, format) {
  const captured = captureResponse();
  await writeAuditExport({
    response: captured.response,
    store: {
      auditDeletionHighWatermark: () => store.deletionHighWatermark(),
      queryAudit: (query) => store.query(query),
      auditDeletionsAfter: (deletionId, highWatermark) => store.deletionCountAfter(deletionId, highWatermark),
    },
    format,
    gzip: false,
    filter: {},
    project: (row) => row,
  });
  return captured.text();
}

it("query skips a corrupt row, reports it and keeps the good rows", async (t) => {
  const { store, seq } = await seeded(t, ["good-a", "bad", "good-b"], "bad");
  let page;
  await assert.doesNotReject(async () => {
    page = await store.query({ limit: 25 });
  }, "query must not reject when a row is corrupt");
  assert.deepEqual(page.events.map((row) => row.id), ["good-b", "good-a"]);
  assert.deepEqual(page.corrupt, [{ seq, machineId: "m", id: "bad" }]);
  assert.equal(JSON.stringify(page).includes(MARKER), false);
  assert.equal((await store.get("m", "good-a")).id, "good-a");
  assert.equal((await store.get("m", "good-b")).id, "good-b");
  await assert.rejects(store.get("m", "bad"), /audit_corrupt/);
});

it("pagination advances past a page made only of corrupt rows", async (t) => {
  const { store } = await seeded(t, ["good-a", "bad", "good-b"], "bad");
  const ids = [];
  const corrupt = [];
  let terminated = false;
  await assert.doesNotReject(async () => {
    let page = await store.query({ limit: 1 });
    const highWatermark = page.highWatermark;
    for (let guard = 0; guard < 8; guard++) {
      ids.push(...page.events.map((row) => row.id));
      corrupt.push(...page.corrupt);
      if (page.nextBeforeSeq === null) {
        terminated = true;
        break;
      }
      page = await store.query({ limit: 1, highWatermark, beforeSeq: page.nextBeforeSeq });
    }
  }, "pagination must not reject when a page is corrupt");
  assert.deepEqual(ids, ["good-b", "good-a"], "pagination must include every good row past corrupt pages");
  assert.equal(corrupt.length, 1);
  assert.equal(corrupt[0].id, "bad");
  assert.equal(terminated, true);
});

it("export trailer marks corruption as incomplete", async (t) => {
  const { store, seq } = await seeded(t, ["good-a", "bad", "good-b"], "bad");
  let jsonText = "";
  let jsonlText = "";
  await assert.doesNotReject(async () => {
    jsonText = await exportText(store, "json");
    jsonlText = await exportText(store, "jsonl");
  }, "export must not reject when a row is corrupt");
  const body = JSON.parse(jsonText);
  assert.equal(body.exportedCount, 2);
  assert.equal(body.deletionsDuringExport, 0);
  assert.equal(body.corruptCount, 1);
  assert.deepEqual(body.corrupt[0], { seq, machineId: "m", id: "bad" });
  assert.equal(body.complete, false, "complete must be false when corruptCount is 1");
  assert.equal(jsonText.includes(MARKER), false);
  assert.equal(body.events.map((row) => row.id).includes("bad"), false);
  const jsonlLines = jsonlText.trimEnd().split("\n").map((line) => JSON.parse(line));
  const summary = jsonlLines.at(-1);
  assert.equal(summary.kind, "summary");
  assert.equal(summary.exportedCount, 2);
  assert.equal(summary.deletionsDuringExport, 0);
  assert.equal(summary.corruptCount, 1);
  assert.equal(summary.corrupt, undefined);
  assert.deepEqual(
    jsonlLines.filter((line) => line.kind === "corrupt"),
    [{ kind: "corrupt", seq, machineId: "m", id: "bad" }],
  );
  assert.equal(summary.complete, false, "complete must be false when corruptCount is 1");
  assert.equal(jsonlText.includes(MARKER), false);
  const exportedIds = jsonlLines.filter((line) => line.kind === undefined).map((line) => line.id);
  assert.deepEqual(exportedIds, ["good-b", "good-a"]);
});

it("recent skips corrupt rows and says so", async (t) => {
  const { store } = await seeded(t, ["good-a", "bad", "good-b"], "bad");
  const chunks = [];
  const original = process.stderr.write;
  process.stderr.write = function spy(chunk, encoding, callback) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk));
    return original.call(process.stderr, chunk, encoding, callback);
  };
  let recent;
  try {
    await assert.doesNotReject(async () => {
      recent = await store.recent(10);
    }, "recent must not reject when a row is corrupt");
  } finally {
    process.stderr.write = original;
  }
  assert.deepEqual(recent.map((row) => row.id), ["good-a", "good-b"]);
  assert.deepEqual(
    chunks.filter((line) => line.includes("audit_recent")),
    ["audit_recent_corrupt_rows_skipped count=1\n"],
  );
  assert.equal(chunks.some((line) => line.includes(MARKER) || line.includes("bad")), false);
});

it("clean export keeps the existing trailer contract", async (t) => {
  const { store } = await seeded(t, ["clean"]);
  const jsonText = await exportText(store, "json");
  const jsonlText = await exportText(store, "jsonl");
  const body = JSON.parse(jsonText);
  assert.equal(body.metadata.kind, "metadata");
  assert.equal(body.metadata.formatVersion, 1);
  assert.equal(body.metadata.historyCompleteness, "unknown");
  assert.deepEqual(body.metadata.filters, {});
  assert.equal(typeof body.metadata.highWatermark, "number");
  assert.equal(typeof body.metadata.startedAt, "number");
  assert.deepEqual(Object.keys(body.metadata), [
    "kind", "formatVersion", "highWatermark", "filters", "historyCompleteness", "startedAt",
  ]);
  assert.deepEqual(body.events.map((row) => row.id), ["clean"]);
  assert.equal(body.exportedCount, 1);
  assert.equal(body.complete, true);
  assert.equal(body.deletionsDuringExport, 0);
  assert.equal(body.corruptCount, 0, "clean export corruptCount must be 0");
  assert.deepEqual(body.corrupt, []);
  assert.match(
    jsonText,
    /\],"corrupt":\[\],"exportedCount":1,"complete":true,"deletionsDuringExport":0,"corruptCount":0\}\n$/,
  );
  const lines = jsonlText.trimEnd().split("\n").map((line) => JSON.parse(line));
  assert.equal(lines[0].kind, "metadata");
  assert.equal(lines[0].formatVersion, 1);
  assert.equal(lines[0].historyCompleteness, "unknown");
  assert.equal(lines[1].id, "clean");
  assert.deepEqual(Object.keys(lines[2]), [
    "kind", "exportedCount", "complete", "deletionsDuringExport", "corruptCount",
  ]);
  assert.equal(lines[2].kind, "summary");
  assert.equal(lines[2].exportedCount, 1);
  assert.equal(lines[2].complete, true);
  assert.equal(lines[2].deletionsDuringExport, 0);
  assert.equal(lines[2].corruptCount, 0, "clean export corruptCount must be 0");
  assert.equal(lines.filter((line) => line.kind === "corrupt").length, 0);
});

it("jsonl export keeps the summary line small when many rows are corrupt", async (t) => {
  const ids = Array.from({ length: 101 }, (_, index) => `row-${String(index).padStart(3, "0")}-${"x".repeat(100)}`);
  assert.ok(ids.length >= 101);
  assert.ok(ids.every((id) => id.length >= 100));
  const { store } = await seeded(t, ids, ids);
  const jsonlText = await exportText(store, "jsonl");
  const lines = jsonlText.trimEnd().split("\n").filter((line) => line.length > 0);
  const summaryLine = lines.at(-1);
  const parsed = lines.map((line) => JSON.parse(line));
  const summary = parsed.at(-1);
  assert.equal(summary.kind, "summary");
  assert.equal(summary.corruptCount, ids.length);
  assert.ok(summaryLine.length < 1024, "jsonl summary line must be shorter than 1024 characters");
  const corruptLines = parsed.filter((line) => line.kind === "corrupt");
  assert.equal(corruptLines.length, 100);
  assert.deepEqual(parsed.slice(-101, -1), corruptLines);
  assert.equal(summary.complete, false);
});
