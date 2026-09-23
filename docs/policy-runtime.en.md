# Core policy, audit, and optional SQLite storage

[English home](../README.en.md) · [中文](policy-runtime.md) · [Policy patches](policy-customization.en.md)

## Choose a storage mode

| Mode | Retention and interfaces | Prerequisite |
| --- | --- | --- |
| `window` (default) | `events.jsonl` and at most 2,000 recent events; existing `/api/v1/state` and `/api/v1/export` contracts; no complete policy history | No SQLite required; proposal validation and publication still work |
| `sqlite` (optional) | Same recent window, plus persistent audit queries, retention, compressed export, policy history and restore | Explicit CT setting `NMZP_STORAGE_MODE=sqlite`; migrate existing data first, or initialize an empty directory |

SQLite uses Node 24's built-in module. Neither CT nor device needs a separate database server. **Do not switch an existing data directory by changing only an environment variable: preflight and migration are required.** In window mode, audit history/storage/history-export and policy history/restore return `404 storage_not_enabled`. This means disabled, not zero historical records. Legacy export and proposal routes remain available.

## Policy publication and recovery

HTTP, offline CLI, and pause/resume use `NmzpStore → NmzpPolicyService → PolicyPublisher`. A writable core exclusively acquires `.policy-writer.lock` before initialization. An existing older service pointer also prevents a new writer. Do not remove a lock based on age or PID alone. Stop any old program that does not honor this lock protocol before upgrading; it must not write alongside the new core.

In SQLite mode, `policy_revisions` and `policy_current` share one database transaction. That commit is the sole policy commit point; `policy.json` is a compatibility projection. Its temporary file is written and synced before database commit, then installed afterward. A projection failure after commit blocks reads and writes; an ordinary restart does not pick a temporary file as the current version. With all other writers excluded, offline `nmzp storage recover-policy --data-dir <absolute-path>` backs up the projection and restores it from the committed database state.

Revisions store policy content, increasing policy version, format version, publication time, content SHA-256, trusted catalog SHA-256, and engine version. Rows are immutable. Restoring old content revalidates against today's trusted catalog and publishes a new version using CAS. Rewrite retries require the original request digest, policy hash, catalog, and engine history. Missing evidence causes explicit refusal; no real tool is replayed and new rules cannot fabricate an old decision.

At most 10,000 policy revisions are retained. At the limit, only non-current revisions unreferenced by retained audit events can be removed; if none qualify, new publication fails without committing. Tombstones mark expired old calls. Versions already missing before migration remain unknown. Database pages, indexes, and DELETE journals must not be described as physically erased data.

`core/audit/events.ts` manages the recent projection; `NmzpStore` coordinates permissions, devices, and write ordering. Runtime audit work goes through the single worker in `core/audit/runtime.ts`, with at most 32 outstanding calls. Timeouts or worker exit produce errors rather than fallback success. Shutdown drains accepted calls before ending the worker. Offline migration uses `AuditStore` directly. The audit worker does not publish policies. New HTTP routes live in `core/audit/http.ts` and `core/policy/http-history.ts`; legacy routes remain in `serve.ts`.

## Migrate existing data

1. On an isolated copy, run `nmzp storage preflight --data-dir <absolute-path>`. This is read-only and reports original-byte digests, formats, damaged rows/tails, duplicate or conflicting IDs, missing history, and estimated space. Invalid legacy policy receives a blocking reason; startup does not silently normalize it.
2. Review the report. During an authorized maintenance window, exclude all writers and run `nmzp storage migrate --data-dir <absolute-path>`. It first preserves original-byte backups and a manifest, then creates/imports the database. Interruptions leave recognizable progress; repeating migration does not duplicate imports. Source data is not deleted before success.
3. Verify `nmzp.db`, the migration manifest, policy version, event count, and original-byte backup digests. Only then separately set the CT storage mode to `sqlite` and start the core. Fresh empty directories do not need a legacy import.
4. To roll back, stop the new writer, preserve its database, queues, and manifest, then restore the original data and runtime configuration from backup. New audit events and policy publications after switching are not automatically converted back into the old format.

The CLI requires an explicit data directory and never migrates on ordinary startup. These instructions do not themselves authorize production downtime or migration. For program upgrades, record the core and `nmzp-viewer` service states and back up runtime and data first. Stopping the core also stops its dependent viewer; restore both services if they were running and verify core and page access separately. Existing devices retain their identities and pinned certificate; a core upgrade alone is not a reason to re-register them or rewrite host hooks.

## Audit, compression, and backfill

`/api/v1/state` still returns at most 2,000 recent events. SQLite history has its own queries. Bodies use gzip only when it saves space, and reads return the original logical event JSON. Corruption raises an error rather than an empty event. Time, device, agent, risk, decision, rule, and policy version have separately indexed fields; receipt updates do not rewrite all bodies.

| CT setting | Default |
| --- | --- |
| `NMZP_AUDIT_MAX_RECORDS` | 100,000 records |
| `NMZP_AUDIT_MAX_DAYS` | 30 days, measured from local ingestion time |
| `NMZP_AUDIT_MAX_MB` | 1,024 MiB (1 GiB) |
| `NMZP_AUDIT_MIN_FREE_MB` | 256 MiB minimum free space |
| `NMZP_AUDIT_TOMBSTONE_DAYS` | 90 days |

Whichever limit is reached first takes effect; 30 days is not a guaranteed minimum. Failed capacity checks reject new evaluations with `503 audit_storage_unavailable`; they do not claim a saved event. Cleanup records reasons and counts. Storage status `reusableBytes` means reusable database pages, not a smaller file or secure erasure. `deleted` is a cumulative cleanup count. Cleanup after startup processes at most 100 events per batch; `retentionPending` reports outstanding work, not completed retention enforcement.

Updated devices have a persistent queue bounded to 256 items, 256 KiB, seven days, and eight backoff attempts. It stores minimal event metadata and receipts, not tool bodies or credentials. After official hook stdout is acknowledged, a receipt is queued; online hooks attempt delivery within the remaining budget. After a successful heartbeat, a probe sends at most two queued items. A paused probe polls without sending queued events. SQLite acknowledges after persistence; the device removes an item after acknowledgment. IDs and content are checked for duplicates and conflicts. Identity changes, expiry, and drops are counted locally. This is bounded at-least-once delivery with idempotent receipt, not exactly-once transport or proof that the host honored a deny. Device queue telemetry is not collected by the core; do not invent fleet queue counts.

## History interfaces and permissions

These routes require both administrator access and SQLite. A viewer cannot access them.

| Query | Default page size | Maximum | Cursor |
| --- | --- | --- | --- |
| `GET /api/v1/policy/history` | 50 | 100 | Exclusive `beforeVersion` |
| `GET /api/v1/audit/events` | 20 | 25 | Fixed `highWatermark` and `beforeSeq` |

For policies, start with `GET /api/v1/policy/history?limit=50`. The response is `{revisions,nextBeforeVersion}`; pass the returned cursor as `beforeVersion` until it is null. `GET /api/v1/policy/history/:version` returns the revision including its policy; missing history is `404 policy_history_missing`. Restore with `POST /api/v1/policy/restore` and `{ "expectedVersion": 3, "sourceVersion": 1 }`. Success is `{ok,version,mode,stopped}`. On `409 cas_conflict`, reload and compare before confirming again. The version counter never rolls back.

For audit, start with `GET /api/v1/audit/events?limit=20`. The response contains `events`, `highWatermark`, `nextBeforeSeq`, and `historyCompleteness:"unknown"`. Keep the same filters and high watermark for later pages; use `nextBeforeSeq` as `beforeSeq`, stopping when null. Filters are `machineId`, `agent`, `decision`, `risk`, `ruleId`, `fromTs`, and `toTs`. Invalid queries return `400 audit_query_invalid`; a page exceeding 4 MiB returns `413 audit_page_too_large`. New events do not enter the fixed high watermark, but concurrent cleanup can leave gaps. Recent-window counts are not total history counts.

`GET /api/v1/audit/storage` reports capacity and cleanup. `GET /api/v1/audit/export?format=json&gzip=0` defaults to plain JSON; `format=jsonl` and `gzip=1` are optional, with the same filters. Export streams pages under a fixed high watermark, enforcing permissions and sensitive-field handling on the server. The trailer's `complete` and `deletionsDuringExport` describe concurrent cleanup; `historyCompleteness:unknown` means completeness cannot be established. Cancellation releases resources. Existing `/api/v1/export` behavior is unchanged.

The history page keeps only the current page and cancels stale requests when filters change. It does not retry empty/error responses forever. Browsers with a file-save picker stream directly to disk; gzip downloads remain actual gzip files. Other browsers use a bounded 16 MiB download buffer and explicitly fail above it; use a streaming-capable browser or an administrator CLI/HTTP client for larger exports. `nmzp board` also streams and verifies the pinned certificate, limits parallel exports to two per session service, and uses a 300-second deadline. Canceling closes the upstream connection. Restore confirmation binds the policy version captured when opened.

Devices can use `POST /api/v1/audit/backfill` with strictly limited `kind:event|receipt` metadata. Event backfill is rejected while paused. Unauthenticated users and viewers cannot use administrator routes. Unknown agent names preserve their raw value rather than impersonating a supported agent.

## Extension examples and limits

[examples/custom-rule.json](../examples/custom-rule.json) blocks a synthetic URL marker. Publish through the existing `PUT /api/v1/policy` with `customRules` and `expectedVersion`, still subject to trusted catalog constraints. [examples/local-adapter.mjs](../examples/local-adapter.mjs) converts a synthetic `WebFetch` input to `/api/v1/evaluate`; it neither executes a tool nor installs a hook or relabels an unknown agent. `node --experimental-strip-types --test tests/compat/customization.test.mjs` checks publication, decisions, and the legacy state parser against a random local HTTPS server.

Windows file `sync` is used, but hardware power-loss durability is not established. Directory sync, process crashes, and power loss require separate evidence. Synchronous audit work runs in a worker and HTTP gzip streams, but 100,000-event export timing still needs CT measurement. SQLite's per-record persistence adds write cost and is not promised to outperform window mode. Measure actual disk latency and log volume. Core upgrades do not update installed device probes or prove real host enforcement.
