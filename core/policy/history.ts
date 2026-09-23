import { closeSync, lstatSync, openSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { isAbsolute } from "node:path";
import { createPolicySnapshot, type PolicyRevision, type PolicySnapshot } from "./snapshot.ts";

export interface HistoricalPolicy<T extends PolicyRevision> extends PolicySnapshot<T> {
  readonly formatVersion: 1;
  readonly publishedAt: number;
  readonly rulesHash: string;
  readonly engineVersion: string;
}

export interface PolicyHistoryRow {
  version: number;
  hash: string;
  publishedAt: number;
  rulesHash: string;
  engineVersion: string;
}

const MAX_REVISIONS=10_000;

/** SQLite owns current+history in one transaction. Connections are short lived. */
export class PolicyHistory<T extends PolicyRevision> {
  readonly #path: string;
  readonly #readOnly: boolean;
  #closed = false;

  private constructor(path: string, readOnly = false) { this.#path = path; this.#readOnly = readOnly; }

  static create<T extends PolicyRevision>(path: string, initial: PolicySnapshot<T>, rulesHash: string, engineVersion: string): PolicyHistory<T> {
    if (!isAbsolute(path)) throw new Error("policy_history_path_required");
    const fd = openSync(path, "wx", 0o600);
    closeSync(fd);
    const history = new PolicyHistory<T>(path);
    try {
      history.#withDb(true, (db) => {
        db.exec("CREATE TABLE policy_revisions(version INTEGER PRIMARY KEY, format_version INTEGER NOT NULL, policy_json TEXT NOT NULL, hash TEXT NOT NULL, published_at INTEGER NOT NULL, rules_hash TEXT NOT NULL, engine_version TEXT NOT NULL); CREATE TABLE policy_current(singleton INTEGER PRIMARY KEY CHECK(singleton=1), version INTEGER NOT NULL REFERENCES policy_revisions(version))");
        const checked = createPolicySnapshot(initial.policy as T);
        if (checked.hash !== initial.hash) throw new Error("policy_history_invalid");
        db.exec("BEGIN IMMEDIATE");
        try {
          history.#insert(db, initial, rulesHash, engineVersion);
          db.prepare("INSERT INTO policy_current(singleton,version) VALUES(1,?)").run(initial.policy.version);
          db.exec("COMMIT");
        } catch (error) { db.exec("ROLLBACK"); throw error; }
      });
      return history;
    } catch (error) { history.close(); throw error; }
  }

  static open<T extends PolicyRevision>(path: string, readOnly = false): PolicyHistory<T> {
    if (!isAbsolute(path)) throw new Error("policy_history_path_required");
    const entry = lstatSync(path);
    if (!entry.isFile() || entry.isSymbolicLink()) throw new Error("policy_history_not_regular");
    const history = new PolicyHistory<T>(path, readOnly);
    history.current();
    return history;
  }

  #withDb<R>(write: boolean, fn: (db: DatabaseSync) => R): R {
    if (this.#closed) throw new Error("policy_history_closed");
    if (write && this.#readOnly) throw new Error("policy_history_read_only");
    const db = new DatabaseSync(this.#path, {readOnly: !write});
    try {
      if (write) db.exec("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=1000");
      return fn(db);
    } finally { db.close(); }
  }

  #insert(db: DatabaseSync, snapshot: PolicySnapshot<T>, rulesHash: string, engineVersion: string): void {
    if (!/^[a-f0-9]{64}$/.test(snapshot.hash) || !rulesHash || rulesHash.length > 128 || !engineVersion || engineVersion.length > 128) {
      throw new Error("policy_history_invalid");
    }
    db.prepare("INSERT INTO policy_revisions(version,format_version,policy_json,hash,published_at,rules_hash,engine_version) VALUES(?,1,?,?,?,?,?)")
      .run(snapshot.policy.version, JSON.stringify(snapshot.policy), snapshot.hash, Date.now(), rulesHash, engineVersion);
  }

  #decode(row: Record<string, unknown> | undefined): HistoricalPolicy<T> | undefined {
    if (!row) return undefined;
    if (row.format_version !== 1 || typeof row.policy_json !== "string" || typeof row.hash !== "string"
      || !Number.isSafeInteger(row.published_at) || typeof row.rules_hash !== "string" || typeof row.engine_version !== "string") {
      throw new Error("policy_history_corrupt");
    }
    let parsed: T;
    try { parsed = JSON.parse(row.policy_json) as T; }
    catch { throw new Error("policy_history_corrupt"); }
    const snapshot = createPolicySnapshot(parsed);
    if (snapshot.hash !== row.hash || snapshot.policy.version !== row.version) throw new Error("policy_history_corrupt");
    return Object.freeze({ ...snapshot, formatVersion: 1 as const, publishedAt: row.published_at as number,
      rulesHash: row.rules_hash, engineVersion: row.engine_version });
  }

  #current(db: DatabaseSync): HistoricalPolicy<T> {
    const row = db.prepare("SELECT r.* FROM policy_current c JOIN policy_revisions r ON r.version=c.version WHERE c.singleton=1").get();
    const policy = this.#decode(row);
    if (!policy) throw new Error("policy_history_corrupt");
    return policy;
  }

  current(): HistoricalPolicy<T> { return this.#withDb(false, (db) => this.#current(db)); }

  get(version: number): HistoricalPolicy<T> | undefined {
    if (!Number.isSafeInteger(version) || version < 1) throw new Error("policy_history_version_invalid");
    return this.#withDb(false, (db) => this.#decode(db.prepare("SELECT * FROM policy_revisions WHERE version=?").get(version)));
  }

  list(beforeVersion = Number.MAX_SAFE_INTEGER, limit = 100): PolicyHistoryRow[] {
    if (!Number.isSafeInteger(beforeVersion) || beforeVersion < 1 || !Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
      throw new Error("policy_history_query_invalid");
    }
    return this.#withDb(false, (db) => db.prepare("SELECT version,hash,published_at,rules_hash,engine_version FROM policy_revisions WHERE version<? ORDER BY version DESC LIMIT ?")
      .all(beforeVersion, limit).map((r) => ({version:r.version as number,hash:r.hash as string,publishedAt:r.published_at as number,
        rulesHash:r.rules_hash as string,engineVersion:r.engine_version as string})));
  }

  commit(next: PolicySnapshot<T>, previous: PolicySnapshot<T>, rulesHash: string, engineVersion: string): "committed" | "conflict" | "capacity" {
    const checked = createPolicySnapshot(next.policy as T);
    if (checked.hash !== next.hash || next.policy.version !== previous.policy.version + 1 || next.policy.updatedAt < previous.policy.updatedAt) {
      throw new Error("policy_history_transition");
    }
    return this.#withDb(true, (db) => {
      db.exec("BEGIN IMMEDIATE");
      try {
        const active = this.#current(db);
        if (active.hash !== previous.hash || active.policy.version !== previous.policy.version) {
          db.exec("ROLLBACK");
          return "conflict";
        }
        const count=Number(db.prepare("SELECT count(*) AS n FROM policy_revisions").get()!.n);
        if(count>=MAX_REVISIONS){
          const hasAudit=db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_events'").get();
          const refs=hasAudit ? "AND NOT EXISTS (SELECT 1 FROM audit_events e WHERE e.policy_version=policy_revisions.version)" : "";
          const deleted=db.prepare(`DELETE FROM policy_revisions WHERE version IN (SELECT version FROM policy_revisions WHERE version<>? ${refs} ORDER BY version LIMIT ?)`)
            .run(active.policy.version,count-MAX_REVISIONS+1);
          if(Number(deleted.changes)<count-MAX_REVISIONS+1){db.exec("ROLLBACK");return "capacity";}
        }
        this.#insert(db, next, rulesHash, engineVersion);
        db.prepare("UPDATE policy_current SET version=? WHERE singleton=1").run(next.policy.version);
        db.exec("COMMIT");
        return "committed";
      } catch (error) { try { db.exec("ROLLBACK"); } catch { /* outcome unknown */ } throw error; }
    });
  }

  close(): void { this.#closed = true; }
}
