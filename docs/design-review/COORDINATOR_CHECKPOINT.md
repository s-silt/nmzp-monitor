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
