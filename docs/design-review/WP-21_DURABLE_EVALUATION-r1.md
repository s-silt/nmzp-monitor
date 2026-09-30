# WP-21 durable evaluation application, candidate r1

Base: `3e40ee268d79a4796f294081361d4231aa7d6aae`. Coordinator accepted rendered evidence after root static/build/443 guard and 1998 tests (1987 pass, 11 skip, 0 fail). This package is atomic SQLite record storage plus the shared prepared evaluation application. `/api/v2/evaluate` remains unregistered. ICs remain NOT_SWITCHED; G8 remains OPEN.

## Authority and scope

The user approved SQLite-required V2 evaluation and minimum private stopped/out-of-scope decisions. Existing V1 storage modes remain supported. Events use their original protocol; cross-protocol retries are incompatible. Transient layout and source-coordinate rewrite evidence were approved previously. No source layout, arbitrary keys, replacements, full observation trace, or raw request is saved for replay. Public V2 audit events retain the existing sanitized public projection, separately from immutable private metadata.

## Storage and visibility

`EvaluationRecord` is a closed metadata codec. Reasons/threats/decisions/statuses are fixed enums; rule, exemption and secret-kind references are numeric indices into the policy/catalog-bound server catalog. The engine's synthetic `privacy:<kind>` rules are reconstructed from that bound catalog, not stored as arbitrary private strings. Binding/witness values require lowercase SHA-256 shape. Identity values are nonempty bounded protocol identifiers; they deliberately do not enable IC-10's new event-id grammar/128-unit rejection. Identifier syntax cannot attest that a client did not choose meaningful text as an identifier.

A visible record owns one sanitized `publicEvent`; an internal record forbids it. Public get, recent/recovery, query/export cursors, corrupt-row diagnostics, counts, receipt lookup and cache publication filter internal rows at SQL row level. Hidden inserts do not displace visible cache/history rows. Receipts update only SQL enforcement; the encoded outcome and replay witness remain immutable. Hidden receipts return the same fixed not-found result as absent rows. Backfill event collisions with any V2 identity return the fixed protocol-incompatible error; neither alias upgrades an existing event. Metadata-only backfill remains its own source semantics and is not interpreted as a V2 evaluation merely because its HTTP alias is V2.

Each visibility lane has the configured `maxRecords` cap and max age. `retained_count` continues to mean public rows; `internal_count` is separate private accounting. Steady-state maximum physical event rows can therefore reach twice `maxRecords`, plus any bounded maintenance backlog. Both lanes share the existing physical database/free-space ceiling. Maintenance processes both lanes. A private boolean requests the existing 50ms follow-up after either lane fills the 100-row batch; public removed/count APIs stay public-only. Hidden deletions do not increment public deletion counts. Admin clear intentionally removes both lanes and copies full origin/hash/visibility into tombstones, while its public count excludes hidden rows. Tombstone expiry bounds identity; it is not an eternal cross-protocol lock.

Migration first classifies the complete signature: both event/tombstone tables lack all four new columns and meta lacks the counter (pristine legacy), or all nine additions exist (modern). Partial signatures are corruption and are never repaired. Only pristine legacy receives origin/hash/visibility/counter additions in one SQLite transaction and missing-origin V1 provenance. Modern NULL origin, invalid metadata or a private counter inconsistent with hidden rows is corruption. Writable open migrates. Read-only old databases use connection-local TEMP read projections over `main` tables, with V1/default metadata; database bytes and schema remain unchanged. Partial modern column sets or malformed modern identity metadata are rejected. Codec identity/hash/policy/visibility/projection columns are crosschecked on decoding. Cache keys use collision-free JSON tuples.

## Shared application and failure boundary

`applyEvaluate` now resolves once and calls `applyPreparedEvaluation`; the same business path handles genuine prepared input/source views. No engine rule or policy rule was changed. The durable service is server-internal: package 2 must validate and prepare canonical requests and supply a closed wire projection; passing a `PreparedEvaluation` is not hostile-input reattestation.

The service requires the trusted policy snapshot captured after authentication and before awaiting request-body bytes; it owns a copy of that snapshot and the prepared input before waiting on the mutex. Fresh recovery/revocation fences do not substitute a newer policy snapshot. The service holds the store mutex for identity lookup, post-await policy/device/worker fences, historical resolution, evaluation, budget, session publication and append. V2 requires SQLite. The hash domain is `canonical_event_v1_without_upload_size`; only `context.uploadSize` is omitted. Duplicate decisions and egress observations come from the first committed record, not current time/policy/upload observations.

Session evaluation uses a disposable copy. Record codec/size validation and the complete serialized response ceiling (262144 UTF-8 bytes, matching `https-client`'s default BODY_LIMIT) precede session publication and any append attempt. SQLite inserts the complete immutable metadata/public projection and retention effects transactionally. In-memory session publication and SQLite are **not one atomic transaction**. Publication occurs just before append; a failed or uncertain append can retain that session effect, like the existing V1 failure boundary. Once append is attempted, storage/fence failure is `audit_storage_unavailable` with unknown disposition, never `not_committed`. Lost acknowledgment is resolved by durable identity lookup on retry. Duplicate replay oversize is replay-unavailable, not a claim that the prior decision was uncommitted.

V1 ordinary fingerprint material, response shape and engine/rewrite behavior remain unchanged. One intentional migration exception precedes stopped V1 ALLOW: a mutex-protected protocol lookup refuses an already V2 identity. This adds possible storage-unavailable/recovery/revocation results during that prefilter. Active V1 uses the same lookup instead of an additional public get; malformed modern storage is not silently treated as absence. No V2 record is exposed through V1 response spreading.

## Historical replay binding

Binding includes normalized policy content hash, catalog/rules hash and a hashed explicit implementation vector: package version, engine revision, adapter/layout, rewrite semantics, observation/rendering, structural projection, private codec and response-template revision. This is version-contract enforcement, not an automatic source-byte/prototype proof: maintainers must increment the corresponding entry when semantics change. Historical executable implementations are not retained; any mismatch is replay-unavailable.

The application obtains the historical policy from the store and checks the historical engine/catalog plus the recorded binding. Only then does it invoke rewrite-only regeneration with server-owned privacy functions and compare the full metadata witness. It never calls evaluate/session correlation or current egress logic during replay. The accepted rendered-evidence tests separately prove source/ownership/prototype behavior; a hash does not prove prototype equality.

## Errors and next usable package

Three closed, fixed-message/no-data codes: `event_protocol_incompatible` (409, rejected), `evaluation_replay_unavailable` (409, rejected), `evaluation_result_too_large` (413, not_committed only before effects). Runtime contract imports and generic dynamic v2 error construction remain forbidden.

Package 2 is required immediately after review: actual authenticated V2 route, separate compatibility/strict ingress schemas without implicit IC-10 activation, full envelope alias-conflict handling, genuine PROBE source preparation, complete compact wire projection explicitly distinguishing omitted trace from complete observations, real HTTP/AJV/differential coverage and p95 <=105% evidence. The trusted projection callback in this package does not establish that wire contract. No usable V2 route or completed performance gate is claimed here.

## Focused evidence

- Initial 70 tests: 67 pass, 3 fail. Two new tests incorrectly passed SQLite Uint8Array to the Buffer-only codec; one implementation comparison retained undefined egress properties while the public projection omitted them. Corrected without changing first-observation values.
- New application/store/HTTPS correction: 16/16 pass. Added rollback/read-only/mutation coverage is recorded separately.
- First visibility mutation survived because its query high-watermark itself excluded the hidden row; strengthened explicit high-watermark coverage detects the row-filter regression. No mutation was accepted as implementation.
- Four negative controls cover SQL visibility, SQL/body hash binding, closed private fields and pre-effect response budget. Original failure logs are retained. Full aggregate remains the coordinator's gate.
- Final changed-boundary batch: 18/18 pass, including all four mutation controls. Final codec/SQL metadata hardening: 9/9 pass. Typecheck, scoped zero-warning ESLint, generated/error-code synchronization and layers (225 files, 0 violations, 0 stale, 83 existing suppressions) passed. The layer map classifies the pure codec as domain; no rule or allowlist was relaxed.
- No candidate full-suite, build, Windows, CI or p95 claim. Baseline protection covers 23 unchanged files (policy package, constants, guard, original hook golden).


## Independent review corrections

- Device binding mismatch now returns unauthorized before lookup/effects, separately from origin/source incompatibility; targeted 1/1 passed. The first attempted targeted run lacked the deliberately removed local dependency symlink; restored the temporary link and retained that infrastructure log.
- Reviewer demonstrated partial-modern migration resetting `internal_count` and defeating the private retention cap. Complete schema classification now precedes any migration/create repair; partial modern, modern NULL origin and inconsistent private counter reject with unchanged database bytes on read-only and writable paths. No historical metadata is reconstructed.
- Reviewer identified missing ingress snapshot ownership. The application now requires the trusted pre-body capture and owns snapshot/prepared copies; stop/resume across the body/queue wait preserves that original decision policy, with current fences retained.
- Hidden-only full maintenance batches now trigger the same private fast follow-up as public batches without exposing hidden counts. Targeted corrected application/storage/HTTPS: 20/20; the device/snapshot/schema/scheduler boundary batch: 4/4. Final correction checks are in the candidate evidence manifest.
