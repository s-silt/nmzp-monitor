# 当前候选协调者检查点（补充历史设计库，不替换旧记录）

## 2026-09-30 Item9 exact contents leaves

基线 bda7afcd2135c8ee82daedcc1555fe0cc79074f3；独立工作树 exact-leaves。技术修订见 WP-21_CONTENT_LEAVES-r1.md；同步 DECISIONS_REQUIRED、闭合 schema、OpenAPI/generated 类型、活动 JavaScript 候选验证器及测试。

### 已实施

- 精确有序 leaves 唯一结构；共享枚举真值，桥接才 trim/空值丢弃/去重/拼接；edits 排除边界、ingest 元数据边界及 v1 行为保持。
- 原始 RFC6901 指针逐叶保留、mapped/extras 计账；Antigravity 仅首级自有属性映射。独立复核发现 constructor/toString/__proto__ 继承属性误映射，已修复，并加入全部 root/nested 原型同名键及恢复漏洞的真实失败变异。
- 候选验证器对 null contents 安全返回 false，补反例夹具；每次变异恢复后除了 exit0，还断言完整17项通过。
- D5 多叶定位、updatedFields、哈希/patch 实现仍缺；当前占位不可作为证据。scalar 空白保存另列残余。候选 wire 结构/序列化边界变化有明确记录；没有声称旧候选 wire兼容或生产 v2 路由已存在。

### 本候选实际验证（Linux / Node v24.19.0）

- 直接本地 node 工具：typecheck、eslint、layers、lint:contract（含生成类型一致性）、build 全部 exit0；layers 217 files / 0 violations / 0 stale / 83 suppressed。构建保留 >500kB chunk 提示。
- 相关聚合：260 tests / 260 pass / 0 fail / 0 skip，含全部 contract、packed 104 golden、别名共享、hook-protocol、Antigravity、spec-run 和错误码检查。
- 精确叶专测：17行为项，含真实13宿主输出比较、Unicode字节指针界、raw bytes/hash/重复成员开关、300 mapped叶与257真实extras区别。
- 15个隔离源变异逐个使目标真实断言失败，恢复SHA-256后每次17/17 green；外层行为+变异18/18。
- 一次完整 scripts/run-tests.mjs：1936 tests / 1925 pass / 0 fail / 0 cancelled / 11 skip，222272ms。跳过项为平台/环境专项，不算Windows证据；未靠重复全量重跑变绿。
- guard 基线 c811cda05403322df848670b068d9b896c4c295a：ok、443 cases、changedCases=[]，digest a2588f36346e64f2dc8283f3f549f130dd4b152cd8017b8733adb9bbaa6ce3cd。
- core/policy/**、core/constants.ts、guard与原golden等23个受保护文件逐字等于基线。git diff --check通过。

### 证据与残余

证据由父协调者保存在 nmzp-validation/exact-leaves-final：static.log、targeted.log、content-mutants.log、guard.log、aggregate.log、protected-hashes.json、manifest.json。manifest固定全部候选文件、patch及证据哈希；日志路径是交接证据位置，不是运行时代码依赖。

独立复核已执行有价值的定向检查和随机差分；正式 hash-pinned 接受结论由复核者另行给出。此检查点不冒充独立冻结，也不记录尚未发生的提交/推送/CI。

G8 OPEN，IC-01/02/10/11/12 NOT_SWITCHED。审计持久化路由接线、D5实现、真实Windows专项、后续集成全门/远端CI与冻结审查仍按原计划处理。无部署、主机配置、Git提交或推送。当前临时只读依赖链接在打包前移除；隔离变异临时副本已清理。


## 2026-09-30 Real v1 oracle integration

- Replaced test-owned v1 input reconstruction with the real offline hook and eval-bridge path; packed entrypoints cover bootstrap and raw-byte limits. Production source and golden seeds unchanged.
- Independent reviewer approved patch 5541a86795abce59888e81c07d9fd52e5eca192fbfe9def4674ca2eb07707101. The combined equivalence test retains the separately accepted exact-leaf assertion.
- Combined focused verification: 42 tests passed, zero failures/skips/cancellations, including the four actual failure-family mutation suites and restored-positive checks. Child positive runs require 41 passes and zero failures/skips/cancellations.
- Direct typecheck, zero-warning lint, layers, generated types, contract validation, build and pinned-base 443-case guard passed; changedCases is empty and digest unchanged.
- Final combined full-suite validation is pending this integration; Windows and remote CI for new commits remain pending. D5 is not implemented; G8 stays OPEN; all ICs remain NOT_SWITCHED.


## 2026-09-30 Windows A2 negative-control repair and combined Linux gate

- Windows Node 24.15.0 libuv attaches non-detached descendants to a kill-on-job-close Job Object. The parent-only-kill mutant therefore survived even though the original 30 positive repetitions passed. Those negative results are retained, not counted as acceptance.
- Test-only repair: detach the fixture grandchild on Windows only; preserve Unix process-group behavior and every process-tree/marker assertion. No production guard behavior changed.
- Independent Windows evidence verified: normal /T case passed; the parent-only mutant failed the intended marker-growth assertion (130 to 133), with cooperative stop acknowledgment. Export encoding/diagnostic-line differences were normalized for source comparison; fresh exact UTF-8/LF fixture SHA 0d25eeb746e5b9dcf8cffbea087229739235fad3a1eb1fa616ff86d503dc60c0 Windows30 remains in progress.
- Combined Linux run on these exact source bytes: 1,942 tests, 1,931 passed, zero failed/cancelled, 11 explicit platform/environment skips; 240.6 seconds. Direct static checks, generated types, build and guard passed. Guard: 443 cases, changedCases=[], digest a2588f36346e64f2dc8283f3f549f130dd4b152cd8017b8733adb9bbaa6ce3cd.
- Earlier Windows snapshot 8a75292: A1 30/30 plus four negative controls passed. Loopback runner pass-count metadata corrected from 16 to 12; actual full file 12/12 and 30 targeted runs passed, with zero failures/skips/cancellations. This does not claim final-new-commit Windows aggregate or CI.
- New commits are local only. Final Windows source validation, exact commit dual-platform CI, phase-2 prerequisite and G8 remain open; no merge/deployment or IC switch.

### Windows fixed-fixture follow-up

The Windows executor completed 30/30 consecutive A2 runs against exact UTF-8/LF source SHA 0d25eeb746e5b9dcf8cffbea087229739235fad3a1eb1fa616ff86d503dc60c0, checked before each run; each recorded tests=1/pass=1/fail=0/cancelled=0/skipped=0, without retry-to-green. Evidence: a2-fixed-test-hash-30.zip, SHA256 2bb57d1f0e1e8790fdbb99627a1066e01fa44cbe57bf32007dca44ee05865cf6. This is fixed-test-source evidence, not final combined commit Windows aggregate or CI. Read-only process-identity evidence also records historical PID reuse by a later pwsh process; no termination signal was sent to the reused PID.


## 2026-09-30 Windows PowerShell module-path casing fix

- Final 0dac Windows aggregate was retained as failed: 1947 tests, 1903 passed, one verify-package failure, 43 skips, zero cancellations. Get-FileHash was missing before package-integrity assertions executed. No push occurred.
- Read-only Python→Node→PowerShell A/B/C diagnostic confirmed uppercase PSMODULEPATH survives the old mixed-case delete. Original and old-delete cases failed; case-insensitive removal succeeded with built-in Utility and a real SHA256. No system, profile, security or global environment changes.
- Test-only launcher now removes every case-insensitive key from a copied child environment. Regression covers mixed/upper/lower/multiple/absent keys and preserves unrelated keys and frozen caller input. Hash/signature checks and PowerShell arguments remain unchanged.
- Full integration caught one obsolete source-contract assertion expecting the old deletion syntax. It was updated to require the new copy/loop/regression, while retaining all script, failure, timeout and forbidden-action gates; parent-environment mutation exclusion was strengthened. Original failed Linux log remains retained.
- Independent review approved both changes. Old-behavior mutation failed the uppercase regression. Combined focused: 18 passed, zero failed, two platform skips. Final Linux aggregate: 1943 tests, 1932 passed, zero failures/cancellations, 11 explicit skips, 243.5 seconds; static gates/build/guard443 passed.
- Windows original test under a controlled cleaned child environment passed all 8 existing tests and executed the real verification script. This is not acceptance of the new 9-test source or final aggregate. Updated fixed candidate still needs native Windows validation, push and exact-SHA dual-platform CI before phase2; G8 OPEN, no IC switch/merge/deployment.


## 2026-09-30 Windows CI checkout-EOL mutation harness repair

- Exact pushed 93a9541 Quality run 36707797392 attempt1: Ubuntu success, Windows Test failure. Windows job109862102754 failed only the content-leaf mutation unique-anchor check for forget mapped leaves (1 versus2), after ten successful mutants. No rerun was requested.
- Deterministic actual-source reproduction: old LF anchor finds exactly once in LF copy, zero times in CRLF copy. Match now accepts exactly one LF or CRLF spelling without normalizing checkout files, and restores original raw Buffers with byte/hash checks. Missing or duplicate anchors still fail.
- Isolated regression exercises the real forget-mapped mutant with both EOLs; both fail the intended assertion and restore all17 positive tests. All other14 mutants remain required. Parent independent focused run:2/2 passed,16 intended negative runs plus restored positives.
- Final combined Linux:1944 tests,1933 passed,zero failed/cancelled,11 platform/environment skips,244.9seconds. Typecheck,zero-warning lint,layers,contract/generated types,build andguard443 passed; digest and decisions unchanged.
- Only a test harness and this evidence record changed. No production code, policy, golden seeds, global Git EOL settings or permissions changed. Prior full native Windows93a evidence is retained; next native run targets this updated harness and its LF/CRLF controls, then exact-new-SHA full dual-platform CI remains mandatory before phase2. G8OPEN and ICs NOT_SWITCHED.

## 2026-09-30 Stage2 request/auth contract candidate (not runtime completion)

- Isolated candidate from 173ecd3. Coordinator technical choices are recorded in WP-21_REQUEST_AUTH-r1.md; no freeze authority is claimed.
- Added legacy-shaped receipt/heartbeat and metadata-only backfill request schemas, candidate bearer declaration, forbidden/not_found enum closure, optional normalized permissionMode/uploadSize, and unconnected identity/context helpers. Only v1 production change extracts its existing receipt checks without changing malformed/null/truthy/immutable outcomes. No v2 route was added.
- Linux Node v24.19.0: focused 39/39 tests, zero failure/skip/cancellation; existing real HTTPS v1 receipt ownership/immutable regression 1/1. Typecheck and zero-warning scoped lint pass. Layers:219 files,0 violations,0 stale,83 suppressed; ErrorCode and generated-type checks pass.
- Three isolated real receipt-source mutants (unknown enforcement accepted, null no longer throws, immutable evaluation ignored) each failed a differential assertion; untouched-positive and restored source each passed2/2. Temporary mutation directories were removed. Initial development checks exposed expected census drift, lint regex spacing and a prohibited dynamic v2Error code; those were corrected in source, not by weakening the checkers.
- Pinned-base guard:c811cda,443 cases,changedCases=[],digest a2588f36346e64f2dc8283f3f549f130dd4b152cd8017b8733adb9bbaa6ce3cd. No core/policy,constants,guard or original golden change.
- Evidence: nmzp-validation/p2-request-contract in the coordinator workspace. No new full-suite/build/Windows/remote CI evidence is claimed for this narrow package; independent review remains pending.
- D5 and cross-version idempotency remain actual blockers for the shared application-layer evaluate package. No dummy rewrite HTTP output, re-evaluation of backfill metadata, new fingerprint field, IC switch, deployment or push. G8 OPEN.

## 2026-09-30 Stage2 four device routes candidate

- Based on accepted e52f5e2 (first-package19 reviewed hashes preserved). Parent first-package static/build/guard passed; full1953 tests/1942 passed/11 explicit skips/0 failures. Those results apply to e52, not this new candidate.
- Added policy/receipts/backfill/heartbeat v2 aliases through the same v1 business branches; common token/revocation checks precede body reads and v2 errors use fixed privacy-safe messages. policy adds same-source rulesHash and exact strong ETag/empty304. No evaluate route, raw-payload persistence, retries, policy-rule changes or new proof version.
- Coordinator accepted original heartbeat proof preimage as a compatibility alias: NMZP-PROBE-1 continues to sign the v1 path and original body text; device binding and one-use nonce remain. Corrected error inventory with the actual backfill final-enforcement409 conflict, distinct from event_conflict; v1 unchanged.
- Linux Node v24.19.0: combined focused49/49 passed,0 failed/skipped/cancelled. After lint-only source cleanup, final actual HTTPS+mutation10/10 and existing v1 receipt/backfill regressions2/2 passed. Typecheck, scoped zero-warning lint, generated-type/ErrorCode checks and layers220 files/0 violations/0 stale/83 suppressed passed. Guard443 unchanged, digest a2588f36346e64f2dc8283f3f549f130dd4b152cd8017b8733adb9bbaa6ce3cd, changedCases=[].
- HTTPS tests AJV-check actual responses; cover auth before incomplete body/admin/wrong/revoked tokens, ETag200/304, receipt immutable/ownership/audit, metadata-only backfill+real tombstone+both conflicts/stopped, heartbeat proof/raw serialization/device/nonce/pollOnly/stopAck, revocation during waits and unknown-write faults without retry/secret echo.
- Four isolated real-source mutants (auth bypass, ETag trim, proof body normalization, immutable bypass) failed intended assertions; each exact-byte restoration passed target1/1 with0skip. The initial mutation runner inherited NODE_TEST_CONTEXT and Node skipped its nested suite; this was retained as a development failure, fixed by clearing only that copied child-environment key. Initial lint expression/unused-variable issues were corrected; no checks weakened.
- Evidence: nmzp-validation/p2-device-routes; frozen candidate manifest/patch provided separately. No full aggregate/build/Windows/CI for this package claimed; parent and independent review own those gates.23 protected files remain byte-identical to e52. G8 OPEN and all ICs remain NOT_SWITCHED. Evaluate/hash/history/realD5 remain separate unfinished work.

## 2026-09-30 Stage2 optional rewrite-layout helper candidate

- Base166a3bd accepted four-route package: parent static/build/443guard and full1963 tests/1952passed/11explicit skips/0failures. These are predecessor results, not a full test claim for this helper candidate.
- Added optional closed rewriteLayout and opt-in build/materialize helpers. Chosen original parameter-bag structure reuses existing exact fragments; genuine remap/resolve/rewriteSource computes the view. Explicit sourcePresent preserves undefined; mapping uses actual parser format, with restricted envelopeCwd references. No client trim, literal string payloads, raw stdin union, HTTP/hook activation, migration storage or D5.
- Nonwinning scalar aliases and skipped blank cwd candidates now remain in existing extras rather than being falsely marked mapped. Exact winner, engine/contents projection and v1 behavior remain unchanged. Serialized candidate size/strict extra counts change; IC-10 remains off.
- Linux Nodev24.19.0: combined focused84/84 passed,0fail/skip/cancel; final helper+four actual-code mutants13/13 passed after adding the explicit residual regression. Includes 13-host real offline output comparison, genuine privacy rule/nonstring residue difference, prototype data, ordering, special numbers, source presence, graph/ref injection and expanded byte budget. Initial census expectation and prototype-reference test comparison were corrected without changing production rewrite semantics or weakening assertions.
- Typecheck, scoped zero-warning lint, generated/ErrorCode checks passed; layers221 files/0violations/0stale/83suppressed. Pinned443-case guard unchanged: changedCases=[],digest a2588f36346e64f2dc8283f3f549f130dd4b152cd8017b8733adb9bbaa6ce3cd.23 protected files remain identical to166a.
- Four isolated source mutants (lost boolean residue, unbound source, lost nonwinner alias, ignored sourcePresent) fail real assertions, each restored target1/1 with exact original bytes. Mutation anchors accept uniquely matching LF/CRLF form; no source normalization or parent-env changes.
- New verified residual: Antigravity args={} with cwd=/generic and workspacePaths=[/actual] yields legacy/actual versus canonical/generic; generic hook with only workspacePaths yields legacyundefined versus canonical/ignored. The helper returns typed projection failure, not a guessed view. Fix deferred to a separate actual-parser-parity package before evaluate activation. Exact fixtures are in rewrite-layout.test.mjs and WP-21_REWRITE_LAYOUT-r1.md.
- Top-level envelope aliasConflict HTTP binding, real D5/encoded edits/safe patch persistence/replay and evaluate/p95 remain open. Evidence under nmzp-validation/p2-rewrite-layout. No new fullsuite/build/Windows/CI/deployment claim; G8 OPEN, ICs unchanged. Candidate awaits independent review.

## 2026-09-30 Stage2 parser-format cwd parity candidate

- Based on23e35f5 (accepted optional layout). Its parent static/build/guard passed; the first aggregate ended on environment network policy during npm notifier access, with no complete summary. An unchanged-source offline aggregate then passed1976total/1965pass/11explicit skip/0fail. The interruption remains documented and is not a code retry-to-green.
- Shared selectHookEnvelopeCwd preserves exact old parser values and format rules, including blank/untrimmed Antigravity workspacePaths elements and array-vs-object checks. Canonical fallback now uses the real selection; tool-input cwd still wins. No v1 decision change or IC switch.
- Layout builder selects from real raw/parser; materializer bounds declared refs and checks canonical projection rather than guessing external array shape from extras. No claim of original-input re-attestation. Future local transport denial/request boundary is documented only; no HTTP/hook activation, D5, replay or persistence.
- Linux Nodev24.19.0: combined focused99/99 passed,0fail/skip/cancel. Includes540 independent-literal legacy cwd comparisons, two corrected examples across13 real offline host outputs each,3 new actual-code mutants with restored1/1 positives, and the prior layout mutation regressions. Typecheck, zero-warning scoped lint, generated/ErrorCode checks, layers221/0violations/0stale/83suppressed passed. Guard443 unchanged, changedCases=[],digest a2588f36346e64f2dc8283f3f549f130dd4b152cd8017b8733adb9bbaa6ce3cd.
-23 protected files remain byte-identical; request-contracts.test.mjs is untouched so the independent Windows newline-only repair can compose. Evidence:nmzp-validation/p2-cwd-parity. No package fullsuite/build/Windows/CI claim; awaiting independent review and parent aggregate. G8 OPEN, all ICs NOT_SWITCHED.

## 2026-09-30 Stage2 actual rendered-composite evidence candidate

- Based ond120149 accepted cwd package (parent static/build/guard and1984total/1973pass/11explicit skip/0fail). New candidate does not inherit that full-suite result.
- Added actual structuredRewrite observation, distinct version1 rendered-composite evidence schema/generator, bound apply helper and metadata-only rewrite replay witness. Edits address exact effective-view UTF-16 leaves before transformation, with separate original fragment and derived-copy binding; empty replacement is explicit. Detector merges remain in the original algorithm.
- Observer records actual calls/order/short-circuit and explicit URL/decoded/persona spaces. URL text fallback is not reported as URL validation success; shell checks are not a full parser. Throwing/mutating observer tests preserve v1 output and scan order. Default v1 route/rules are not changed.
- Full-string replacements/updated values/keys/layout are transient only. Witness contains fixed versions, hashes and counts; malformed non-hash plaintext is rejected. Rewrite-only reproduction matches historical-rule witness without engine/session re-evaluation. Real historical policy/catalog/engine availability, atomic storage and immutable decision replay remain future integration obligations.
- Linux Nodev24.19.0: combined focused78/78 passed; subsequent scoped rewrite/evidence31/31 and final evidence+mutations14/14 passed after witness hardening. All0fail/skip/cancel. Actual artifacts pass AJV; tests cover production persona, URL encoding/query/fallback, shell refusal, overlap/touching/secret priority, nonstring residue, derived copies, shared/repeated leaves, empty deletion fixture, Unicode, observer failures, tampering, source-free metadata and separate prototype/ownership parity.
- Three isolated real-code mutants (remove result hash, ignore derivation, remove residue refusal) fail real assertions and restore1/1 targeted positives with exact bytes. Typecheck, scoped zero-warning lint, generated/ErrorCode checks and layers223/0violations/0stale/83suppressed passed. Guard443 unchanged: changedCases=[],digest a2588f36346e64f2dc8283f3f549f130dd4b152cd8017b8733adb9bbaa6ce3cd.23 protected files unchanged.
- No evaluate/HTTP/hook activation, persisted source or replacement, new retry policy, fullsuite/build/Windows/CI claim or freeze. Legacy CanonicalRewrite/compatibility dummy converter was not silently reinterpreted; future wire integration must explicitly choose the real versioned artifact. Observation size/HTTP budget and evaluate p95 remain unverified. Evidence:nmzp-validation/p2-rendered-evidence. G8 OPEN, ICs unchanged; independent review pending.

## 2026-09-30 durable evaluation application candidate (base 3e40ee2)

- Root accepted base: 1998 total, 1987 pass, 11 skip, 0 fail; static/build/443 compatibility guard passed.
- User-authorized SQLite-only V2 + private stopped/out-of-scope rows implemented behind a server-internal application boundary. V2 evaluate HTTP remains unregistered; package 2 must deliver real route/compact schema/PROBE/performance proof.
- See `WP-21_DURABLE_EVALUATION-r1.md` for row-level privacy, explicit two-lane retention cost, read-only legacy projections, transactional identity metadata, historical rewrite-only replay and non-atomic session/SQLite failure semantics.
- Targeted evidence includes ordinary V1 business projection, real HTTPS protocol precheck/stopped bytes/receipt-backfill isolation, restart replay, upload-observation immutability, response-size-before-effects, lost-write acknowledgment and SQL rollback. Initial failures and mutation-coverage correction are retained, not erased.
- Candidate final changed-boundary 18/18 and final codec 9/9 pass; initial batch's remaining 54 preexisting tests passed. Four isolated mutation controls detected real assertion failures. Typecheck/scoped lint/contract generation/layers pass (225 files, 0 violations, 0 stale, 83 unchanged suppressions). No candidate aggregate/Windows/p95 claim; 23 protected files unchanged.

- Independent-review fixes: trusted pre-body snapshot and prepared ownership; complete legacy-vs-modern signature (including private counter), modern NULL-origin/counter corruption rejection with unchanged bytes; device mismatch 401; hidden-only batch fast scheduling through a private boolean. Corrected storage/application/HTTPS batch 20/20 and focused four boundary checks 4/4 passed. Revised artifact hashes supersede the first frozen candidate.

## 2026-09-30 actual V2 evaluate HTTP candidate (base 364811b)

- Registered authenticated SQLite-required V2 evaluate, actual closed compatibility ingress and complete compact rendered response, plus opt-in producer/consumer helpers. Current hook/probe network clients remain V1; no client migration, deployment or IC switch. G8 OPEN.
- Genuine PROBE source/metadata mapping, local full-envelope alias denial and independent generated strict candidate preserve approved boundaries. Historical application bindings increment; exact event/request hashes and source/result-bound edits are checked before local application. Omitted full trace is explicit, not fabricated complete findings.
- Final scoped Linux Node v24.19.0 batch:83 tests/83 pass/0 fail/0 skip/0 cancelled. Includes8 real HTTPS tests and4 isolated source mutants with exact restoration; all13 actual offline host outputs match. Typecheck, scoped zero-warning ESLint, error/generated-contract checks, exact self-contained validator regeneration and layers228/0 violations/0 stale/83 existing suppressions passed. No new full-suite/Windows/CI claim.
- Real paired performance:100 alternating HTTPS/SQLite pairs per scenario after20 warmups. Initial p95 V2/V1 ratios allow1.068/rewrite1.328/PROBE0.959. After avoiding an extra response parse/stringify, one retained separate run measured allow1.146/rewrite1.145/PROBE1.196. The <=1.05 criterion remains unmet. No unchanged-source rerun or weaker validation/persistence was used to claim success.
- A300-sample isolated phase microprofile measured p50/p95 ms:canonical ingress0.040/0.110; plain legacy rewrite0.014/0.050; actual rendered evidence including rewrite/bindings/observations/hashing/self-check0.129/0.391. This identifies incremental pure-work cost, not full route/SQLite attribution.
- Isolated worktree recovery preserved19 WIP source files with stable SHA256 verification after an interrupted writer continued updating the prior directory. Both original evidence and development failures are retained. New candidate evidence:nmzp-validation/p2-evaluate-route; recovery manifest:p2-evaluate-recovery. Final review/freeze and aggregate belong to coordinator; no push/merge/deployment.

### Integrated full-gate corrections for the evaluate HTTP candidate

The coordinator's initial full run retained2040 tests/2026 passes/3 failures/11 skips. One doctor-pack failure was a missing completed dist build prerequisite; the build was subsequently completed and no doctor source/assertion was changed. Two actual integration defects were corrected: the PROBE producer now reuses EVAL_BRIDGE_FILE_PATH_KEYS instead of duplicating its literal array, and the existing cwd negative control now targets the renamed resolveLayoutRef symbol in both original and mutated source. Its exact-one LF/CRLF anchor, intended assertion failure and byte restoration remain required. The corrected boundary batch passed51/51 with0 failure/skip/cancellation; revised full aggregate remains the coordinator's responsibility. Revision1 manifest/logs are preserved.

### Coordinator acceptance of evaluate HTTP revision 2

- Independent functional review approved exact 28-file candidate manifest SHA256 5ab4aef7ed2a6f28761d3f35b802cec0e3708ce5d3e91a6576c91306c4311cf0. Independent HTTP/schema19, related35, alias27 and2850-case PROBE differential passed; real negative controls and byte restoration verified.
- Initial aggregate retained three failures: missing prebuilt dist (coordinator prerequisite sequencing), duplicated alias constants, stale cwd mutation symbol. The latter two were narrowly corrected and independently reviewed; no doctor assertion changed.
- Revised exact-source Linux aggregate:2040 total,2029 passed,11 explicit skips,0 failures/cancellations,290.5seconds. Typecheck, zero-warning lint, layers, generated validators/OpenAPI, build and pinned443-case compatibility guard passed; no policy decision changes.
- The 28 reviewed source files were hash-verified before and after transfer to the main development tree. Evidence remains in nmzp-validation/p2-evaluate-route/root and p2-evaluate-independent.
- Performance gate remains OPEN: existing controlled wall p95 comparisons exceed the1.05 ratio. Separate scheduling optimization is not included in this functional acceptance. Windows/new exact-SHA CI not yet run; no hook IC activation, merge, deployment or G8 freeze.

## 2026-09-30 immutable built-in rule snapshot candidate (base 0980d5a)

- Deep-frozen process/module-lifetime built-in catalog and ID map; frozen readonly monitor façade. Engine, overrides and exemption-scope retain the same immutable objects. Full runtime replacement/restart is the supported built-in update boundary; no partial hot-swap API. Existing custom-rule policy snapshots remain unchanged.
- Policy-service loading initializes the exact original catalog/engine/rewrite fingerprint once. Reuse is limited to recursively verified immutable plain data; mutable, shallow-frozen, accessor and proxy-injected sources keep per-call hashing. Independent review found the proxy admission gap; node:util proxy detection and root/nested regressions close it.
- Fresh V2 now refuses a captured historical policy/catalog/engine mismatch before session or append effects. Explicit policy publish/restore creates the next matching revision; old rows and identities are never rewritten. Existing typed fixed HTTP409 error reused. V1 behavior preserved and upgrade compatibility/preflight documented in both runtime guides.
- Focused Linux Node24.19.0:201 tests/201 pass/0 fail/skip/cancel, including real13-host parity and existing actual-code negative controls; final new snapshot suite5/5 and zero-warning lint pass after LF/CRLF-safe anchor cleanup. Three isolated new real-source mutants fail intended assertions; each exact-byte restoration passes its targeted positive. Initial restore-method test typo and reviewer correction retained in evidence.
- Typecheck, whole-repository zero-warning lint, layers228 files/0 violations/0 stale/83 unchanged suppressions, error/OpenAPI/generated validator checks and build pass. Build retains the >500kB chunk warning. Pinned c811cda guard passes443 cases with changedCases=[] and unchanged digest a2588f36346e64f2dc8283f3f549f130dd4b152cd8017b8733adb9bbaa6ce3cd. Built-in JSON content/order and exact fingerprint remain equal to0980d5a.
- Evidence:nmzp-validation/p2-immutable-rule-snapshots. Final hash-pinned independent approval, root full aggregate and controlled performance are separate pending gates. No rejected gzip scheduling change, push, deployment, IC switch or G8 freeze. Windows/new exact-SHA CI remain unclaimed.

### Immutable snapshot aggregate fixture correction

- Initial root aggregate retained2045 total/2033 pass/1 fail/11 skips: the owned-rule negative control appended RULES.splice after module publication, so immutable rules correctly caused import_error before the intended corpus comparison.
- Test-only correction removes the target rule from the owned source immediately before immutable publication, using an exact-one EOL-independent anchor. The catalog remains frozen. Every original expected result_mismatch, changed-case, rule-ID and digest assertion remains; exact source restoration and a fresh positive corpus run are additionally required. No production changes.
- Corrected target1/1 and scoped zero-warning lint pass; full guard-meta/regression, revised independent hash-pin and root aggregate are tracked separately. Failed root log remains evidence; no performance run has occurred.

### Coordinator acceptance of immutable catalog snapshot

- Accepted exact15-file manifest f896f347252482939f15622984a68a06f1d6ee1047137638708f2cdd3540e914 after independent final review. Only the guard mutation fixture/checkpoint changed after initial14-file review: mutation now happens before immutable publication, preserving actual result-mismatch assertions and exact restoration.
- Final root aggregate:2045 tests,2034 passed,11 explicit skips,0 failed/cancelled,283.8seconds. Prior interrupted aggregate is retained and is not claimed as a pass. Source hashes verified during transfer to main; existing full static/build/guard evidence is preserved.
- One predeclared controlled500-pair/scenario/arm performance run completed successfully as a measurement, but FAILED the1.05 performance gate: optimized allow1.12719,rewrite1.18052,PROBE1.17405. All6240 requests were retained and succeeded. The immutable catalog design is functionally accepted; it does not establish performance acceptance.
- No mixed-result gzip optimization was integrated. Stage2performance/G8 remain OPEN, new Windows/CI pending; no IC switch, merge or deployment.
