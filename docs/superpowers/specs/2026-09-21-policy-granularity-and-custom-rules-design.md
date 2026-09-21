# 策略粒度（规则 / 威胁族 / 全局三层覆盖）+ 自定义策略优化 — 设计与验收

状态：验收测试已写好（红灯），等待实现。实现者按本文件逐条实现，直到「验收」一节全部通过。

硬约束（违反即作废）：
- 不修改任何已存在的 `*.test.ts`（含本轮新增的四个）。可以新增测试。
- 不 `git`、不 `npm run pack`、不部署、不联网、不改 `~/.nmzp`、`~/.claude`、`~/.codex`、`~/.grok`、`~/.zcode`、`~/.gemini` 下任何真实文件。
- 不采集 transcript，不读 `.env*`，不打印 token，不写真实密钥；心跳 `agentProcs` 永远 `[]`；不改 `core/agent-discovery-scan.ts`。
- LAN viewer 永远只读：新字段只投影、只打码，`PUT` 仍 405。
- 新策略字段必须向后兼容：旧探针收到不认识的字段不能崩、不能 fail-open；新探针收到旧 CT 的策略（无新字段）行为与今天完全一致。
- 不做需要管理员权限才能跑的东西。
- 「看起来能拦其实拦不住」的功能宁可不做（见 §8）。

分工一句话：**`core/**` 与 `src/lib/monitor/**`（引擎、schema、纯函数、i18n 键）由 Grok CLI 实现；`src/routes/**`、`src/components/**`、`src/lib/monitor/store.ts`、`src/lib/monitor/api.ts` 的看板改动由 Antigravity 按 §7 实现；两者都不许动 `*.test.ts`。**

---

## 0. 已核实的现状（不用再查）

- `PolicyState`（core/schema.ts:185）：`version / mode / customRules / stopped / previousMode? / updatedAt / githubUpload? / archiveUpload?`。`DEFAULT_POLICY` 在 core/persist.ts:75。
- 决策：`src/lib/monitor/engine.ts:173 applyIntervention(action, intervention, family, risk)`。`off→allow`，`permissive→log`，`enforcing`：`rewrite→rewrite`；CUT 族（exfil/tamper/isolate/poison）→block；`secret && action==="block"`→block；`risk==="high"`→block；其余 log。**guard.test.ts 断言 `applyIntervention("block","enforcing",undefined,"medium")==="log"`，所以该函数签名与语义不能动。**
- 内置规则 75 条（33 block / 41 log / 1 rewrite）。`family` 只出现在 exfil(15)/secret(2)/isolate(4)/poison(2)/tamper(3)/recon(2)。`ThreatKind` 里有 `destructive` 但没有任何规则用它。
- `CustomPrivacyRule {id, enabled, mode:"block"|"replace", match, kind, replaceWith}`，`MAX_CUSTOM_RULES=24`，`scanCustom` 每次调用都 `new RegExp`，`compileMatch` 没有 ReDoS 防护。
- 服务端 `PUT /api/v1/policy` **不校验 `customRules`**（core/persist.ts:407 原样存）。
- hook 硬预算 `HOOK_BUDGET_MS=6500`，CT 调用 `HOOK_CT_MS=1500`，离线路径在 `windows.transact(..., lockMs≤400)` 里跑 `applyEvaluate`。
- 压缩包 `archiveUpload.action="block"` 被 `core/egress-consent.test.ts` L61/L63/L97-114 钉死为观察模式。**本轮不放开（用户已拍板）。**
- LAN viewer 投影用白名单：`projectCustomRule` 对未知嵌套键返回 null → 整个 state `ok:false`。新字段不投影就会把 viewer 打挂。
- `src/lib/monitor/egress-evidence.ts` 通过 `../../../core/egress-schema.ts` 复用 core 解析器，`core/pack.ts:125` 有一份需要改路径的文件名单。

---

## 1. 粒度模型（设计题 1）

### 1.1 三层 + 全局闸门

```
内置默认 rule.action  ←  威胁族覆盖 overrides.families[family]  ←  单条覆盖 overrides.rules[ruleId]
                                        ↑ 以上仅在 mode === "enforcing" 生效
全局 mode：off → 一律 allow；permissive → 一律 log（覆盖也失效，是全局急停）；enforcing → 按合成结果
```

- `rules[ruleId] ∈ "block" | "log" | "off"`。`off` = 该规则不参与匹配（`firstMatch` 跳过，动态查找 `telemetry_drop`/`persona_cloak` 前先查）。
- `families[family] ∈ "block" | "log"`。族级**没有 `off`**（一键开大洞的风险不值得）。
- 单条 > 族 > 默认。`source` 只在**有效动作和基础动作不同**时才记录（`dangerous_delete` 本来就是 block，族级再 block 不算覆盖）。

### 1.2 不可降级（guarded）

`PROTECTED_FAMILIES = {exfil, tamper, isolate, poison, secret}`。
**guarded ⇔ 当前 `action === "block"` 且当前 `family ∈ PROTECTED_FAMILIES`**（用评估过程中的 `action/family`，不是只看 `rule` 的静态字段——`curl_pipe_shell` 被降级但命令里带 Bearer token 出网时，secretLeak 把 family 升成 secret，仍必须 block）。

- guarded 时：覆盖、豁免一律忽略（`block` 覆盖是空操作，允许存在）。
- CT `PUT /policy` 对 guarded 规则的 `log/off` 覆盖、对 PROTECTED 族的 `log` 覆盖返回 400 并列出 id；引擎侧再防一次（缓存被篡改也不放行）。
- 静态判定 `isProtectedRule(rule) = rule.family ∈ PROTECTED_FAMILIES && rule.action === "block"`，目前命中 26 条（15 exfil + 2 secret + 4 isolate + 2 poison + 3 tamper）。
- 理由：这五族是产品承诺（静默切断外传 / 自毁 / 投毒 / 密钥），所有动态升级（session correlate、secretLeak、self-protection、snapshot、relay poison）都落在这五族；逐条放开等于给 prompt-injection 留后门，且 permissive 已经是合法的全局急停。

### 1.3 补 `destructive` 族

以下 6 条规则加 `family: "destructive"`（其余字段不动）：`dangerous_delete`、`disk_overwrite`、`fork_bomb`、`db_destructive_command`、`git_force_push`、`chmod_world_writable_recursive`。默认行为不变（destructive 不在 CUT，`applyIntervention` 走 risk 分支），只是事件多一个 `threat: "destructive"`。`i18n.ts` 新增键 `destructive: { zh: "破坏性", en: "Destructive" }`，`threatMsg("destructive")` 返回 `"destructive"`。

### 1.4 决策合成真值表（enforcing）

| 基础 action | family | rules[id] | families[f] | 有效 action | source | decision |
|---|---|---|---|---|---|---|
| log | — | — | — | log | — | `applyIntervention`（今天的行为） |
| log | — | block | — | block | rule | **block**（不再被 risk 启发式压回 log） |
| log | destructive | — | block | block | family | block |
| log | destructive | log | block | log | rule | log |
| block(非族) | — | log | — | log | rule | log |
| block(非族) | — | off | — | 规则不匹配 | — | 由下一条规则决定 |
| rewrite | recon | — | log | log | family | log，不 cloak，`rewritten=false` |
| rewrite | recon | — | block | block | family | block |
| block | exfil/…/secret | log/off | log | **block** | — | block（guarded） |
| 任意 | 任意 | 任意 | 任意 | — | — | permissive→log，off→allow |
| 任意（有豁免命中，非 guarded） | | | | log | exemption | log |

`applyPolicyDecision(action, intervention, family, risk, overridden)`：`off→allow`；`permissive→log`；`overridden===true` 时 `block→block / rewrite→rewrite / 其它→log`；否则回落到 `applyIntervention`。

### 1.5 三档去留

保留 `enforcing / permissive / off`（stop/resume 依赖 `mode="off"+previousMode`）。文案改成：`enforcing` = 「按规则表执行（含你的覆盖）」，`permissive` = 「全部只记，覆盖与豁免均不生效」，`off` 不变。看板必须在覆盖编辑区顶部常驻一行：「覆盖只在『静默』模式下生效；当前：{mode}」。

### 1.6 本机 vs 全局

边界不动：能改本机文件系统 / ACL / hook 文件 / 网络所有权的操作只能在被监护机执行（`nmzp snapshot-guard apply`、`nmzp discover paths`、`nmzp network-owner approve`、join 写 hook）。补只读可见：

- `DeviceRecord` 公开投影新增 `networkOwnerCount: number`（`activeOwnerGrants(d.networkOwners).length`，只有数量，不带 id/路径/哈希），出现在 `/api/v1/state`、LAN viewer state（`DEVICE_KEYS` 加 `networkOwnerCount: "num"`）。
- 已有的 `snapshotGuard`、`discovery`、`probeProtection`、`capabilities.hook_*` 不变，看板收成一张「本机控制项（只读）」卡（§7.4）。

### 1.7 看板如何不让人误以为「设了就一定拦」

每条覆盖/豁免/自定义规则行显示三段状态 chip：
1. `策略 v{version} 已保存`（PUT 成功即亮）
2. `已同步 {n}/{m} 台`（`devices.filter(d => d.lastPolicyVersion >= version && status==="online")`）
3. `Hook 有回执`（该 agent 的 `capabilities.hook_<agent>.active`）

审计页与总览的「已拦截」只信 `enforcement === "blocked"`；`decision==="block" && enforcement!=="blocked"` 显示为「已返回拒绝/待验证」（沿用现有文案）。事件行新增小标签：`overrideSource==="rule"` →「因规则覆盖」、`"family"` →「因族覆盖」、`exemptionId` →「已豁免 {id}」、`dryRunKinds` →「试运行命中 {kinds}」。

---

## 2. 自定义策略（设计题 2）

### 2.1 上限与预算

- `MAX_CUSTOM_RULES: 24 → 64`。`MAX_EXEMPTIONS = 32`。`MAX_RULE_OVERRIDES = 128`。`MATCH_MAX` 仍 80。
- `compileMatch` 结果缓存：模块级 `Map<string, RegExp | null>`，上限 256 条，满了清空重来（不做 LRU）。**每次使用前 `lastIndex = 0`**。
- ReDoS 启发式（`compileMatch` 返回 `null`）：
  - 反向引用 `\1`–`\9` → 拒绝。
  - 「被量词修饰的分组，其分组体内含未转义量词」→ 拒绝。量词 = `+`、`*`、`{`，以及不紧跟 `(` 且不紧跟另一量词的 `?`。字符类 `[...]` 内部整体跳过，`\x` 转义跳过。示例：`(a+)+$`、`(\w+\s?)*x`、`([a-z]+\.)+example` 拒绝；`(RSA |OPENSSH |EC )?PRIVATE`、`(postgres|mysql)://[^\s]+`、`(?:foo|bar)+` 接受。`SUGGESTED_PRIVACY` 九条必须全部仍能编译。
  - 无法识别的正则（`new RegExp` 抛错）沿用现有回退：按字面量转义。
- 预算验收：64 条规则 × 256 KiB 命令体，`evaluate` 单次 < 1000 ms（测试跑两次都要过）。

### 2.2 `CustomPrivacyRule` 扩展（core/schema.ts 与 src/lib/monitor/types.ts 同步）

```ts
export interface CustomRuleScope { tools?: string[]; fields?: Array<"command"|"file_path"|"url"|"contents"> }
export interface CustomPrivacyRule {
  id: string; enabled: boolean; mode: "block" | "replace"; match: string; kind: string; replaceWith: string;
  /** 缺省 = 所有工具、所有字段（今天的行为）。tools 取 CanonicalTool 名。 */
  scope?: CustomRuleScope;
  /** true ⇒ 命中只记录、只在审计视图打码，不改决策、不改 tool_input。规范化时强制 enabled=false（旧探针直接跳过，不会误拦）。 */
  dryRun?: boolean;
}
```

- 状态函数 `customRuleState(rule)`：`dryRun===true → "dry_run"`；否则 `enabled===false → "off"`；否则 `"on"`。
- `sanitizeCustomRules`：接受 `scope`（经 `parseCustomRuleScope`，去重、非法整行丢弃）、`dryRun`（true 时 `enabled=false`）；`replaceWith` 规则不变；上限 64。
- 字段作用域实现建议：`inspect = joinFields(command, filePath, url, dest, contents, nativeTool)`，记录每段在 `inspect` 中的 `[start,end)`（`dest` 并入 `url` 段，`nativeTool` 段任何 scope 都不覆盖）；规则带 `scope.fields` 时只接受**完全落在允许段内**的命中；带 `scope.tools` 时 `tool ∉ tools` 直接跳过。超出作用域的命中既不影响决策也**不打码**。
- 试运行：`dryHits` 单独扫描（只取 `dry_run` 规则，同样受 scope 与豁免约束），并入 `redacted` 打码，`EvalResult.dryRunKinds = uniqueKinds(dryHits)`（无命中则不设该字段）；不进 `secretKinds`，不影响 `customBlock/customReplace`。core 侧 `structuredRewrite / extractDeclaredEndpoints / sanitize*` 继续用 `scanCustom`，它跳过 `enabled=false` 的规则，因此试运行规则天然不会改写 tool_input。

### 2.3 草稿语法（`compilePrivacyDraft`，SSH `nmzp rules add` 共用）

现有：`<pattern>`（默认出网拦截）、`<pattern> => <kind>`（替换）、`<pattern> | block|replace [| kind]`。
新增**前缀作用域**：`<tok>[,<tok>...]: <其余同上>`，`tok ∈ CanonicalTool 名 ∪ {command,file_path,url,contents}`。工具名进 `scope.tools`，字段名进 `scope.fields`。任一 tok 不认识 → 整行丢弃。不认识的前缀（如 `http:`）不当作作用域，整行仍是 pattern。示例：

```
Bash,url: db.prod.internal | block | internal_host   → scope {tools:["Bash"], fields:["url"]}
url: api\.corp\.example => corp_api                  → scope {fields:["url"]}, replace
http://plain.example | block                         → 无 scope，match "http://plain.example"
```

不在语法里表达 dry-run / 到期（看板与 `nmzp rules` 子命令负责；本轮 CLI 不加子命令）。

### 2.4 豁免（exemptions）

```ts
export interface PolicyExemption {
  id: string;            // /^x_[a-z0-9]{1,24}$/
  ruleId: string;        // /^[a-z][a-z0-9_]{0,63}$/：内置规则 id 或自定义规则 id（p_…）。没有 ":"，所以合成的 privacy:* 不能被指向
  match: string;         // 4..80 字符，无控制字符，走 compileMatch
  tools?: string[];      // CanonicalTool 名，非空、去重
  note?: string;         // ≤120
  createdAt: number;     // 安全整数 ≥ 0
  expiresAt?: number;    // > createdAt 且 ≤ createdAt + 365d
  sourceEventId?: string;// ≤64
}
```

引擎语义（`activeExemption(ruleId, inspect, tool, exemptions, now)`）：`ex.ruleId === 命中规则 id`、`compileMatch(ex.match).test(inspect)`、`tools` 缺省或包含当前 tool、`expiresAt` 缺省或 `> now` → 生效。

- 内置规则命中且非 guarded：`action="log"`，`rewritten=false`，`EvalResult.exemptionId = ex.id`，decision 走 `applyPolicyDecision(..., overridden=true)`。
- 自定义规则（live 与 dry-run）命中：该规则的命中从 `customHits/dryHits` 中移除（不再触发 customBlock/customReplace），**但仍在 `redacted` 里打码**，并设 `exemptionId`。
- guarded 规则、`scanSecrets` 凭据命中：永不豁免。
- CT `PUT` 对指向 guarded 规则的豁免返回 400 `protected_rule_exemption`；`match` 不能编译（含 ReDoS 拒绝）返回 400 `invalid_policy_exemptions`。
- 看板「这条是误报」按钮（§7.3）预填 `{ ruleId: event.ruleId, match: escapeRegExp(event.redacted 首行.slice(0,80)), tools: [event.tool], sourceEventId: event.id }`，管理员必须改成稳定字面量并确认后才 PUT；默认 `expiresAt = now + 30d`。

### 2.5 AI 闭环：导出 → 建议 → 预览回放 → 确认

**导出**（审计页现有「导出 JSON」，Antigravity 实现）：在现有 `evidenceExport` 之外附 `policyContext = buildPolicyContext(...)`：

```ts
{
  schema: "nmzp-policy-context/1", proposalSchema: "nmzp-policy-proposal/1",
  policyVersion, mode, overrides, exemptions, customRules,          // viewer 角色：exemptions[].match 与 customRules[].match/replaceWith 用 ADMIN_HIDDEN 打码
  catalog: RULES.map(r => ({ id, family, action, risk, tools, field, pattern, title, titleEn })),
  protectedRuleIds: string[],
  limits: { maxCustomRules: 64, maxExemptions: 32, maxRuleOverrides: 128, matchMax: 80 },
}
```

**建议格式**（AI 产出，看板导入）：

```json
{
  "schema": "nmzp-policy-proposal/1",
  "basePolicyVersion": 12,
  "overrides": { "rules": { "sudo_usage": "block" }, "families": { "destructive": "block" } },
  "customRules": [ { "match": "内部代号", "mode": "block", "kind": "codename", "scope": { "fields": ["command"] }, "dryRun": true } ],
  "exemptions": [ { "ruleId": "download_operation", "match": "registry\\.npmjs\\.org", "tools": ["Bash"], "note": "npm registry", "expiresAt": 1790000000000 } ],
  "remove": { "customRuleIds": ["p_old"], "exemptionIds": ["x_1"], "overrideRuleIds": ["git_operation"], "overrideFamilies": ["recon"] },
  "rationale": "≤2000 字自由文本"
}
```

`parsePolicyProposal(raw, { rules })` 返回 `{ok:true, proposal}` 或 `{ok:false, errors: string[]}`，错误码：`bad_schema`、`forbidden_field:<key>`（任何未列出的顶层键，特别是 `mode/stopped/githubUpload/archiveUpload`）、`invalid_overrides`、`unknown_rule:<id>`、`protected_rule_override:<id>`、`protected_family_override:<family>`、`invalid_custom_rule:<index>`、`invalid_exemption:<index>`、`protected_rule_exemption:<id>`、`too_many_custom_rules`、`too_many_exemptions`、`rationale_too_long`、`invalid_remove:<key>`（`remove` 下任一键不是字符串数组）。解析期 `customRules[].dryRun` 缺省为 `true`。

`mergeProposal(current, proposal, { now, forceDryRun })`：
- `overrides`：键级合并（proposal 覆盖同键），再减去 `remove.overrideRuleIds/overrideFamilies`。
- `customRules`：先减 `remove.customRuleIds`；proposal 里 `match.toLowerCase()` 已存在的跳过（保留原 id/状态）；新规则 `id = draftRuleId(match)`（与 `compilePrivacyDraft` 同一哈希，`privacy.ts` 导出）、`replaceWith = REDACT_TAG`、`kind` 缺省走 `slugKind`、`dryRun = forceDryRun || proposal.dryRun !== false`、`enabled = !dryRun`。超 64 → `too_many_custom_rules`。
- `exemptions`：先减 `remove.exemptionIds`；新豁免 `id = exemptionId(ruleId, match)`（`x_` + 哈希 base36）、`createdAt = now`、`expiresAt = 提案值 ?? now + 30d`；按 `(ruleId, match.toLowerCase())` 去重。超 32 → `too_many_exemptions`。
- 提案永远不会被自动应用；看板把 `next` 作为普通 `PUT /policy`（带 `expectedVersion`）提交，服务端校验是最后一道。`basePolicyVersion` 与当前不一致只提示不阻断。

**命中回放** `replayPolicy(events, next, current, rules, now)`：历史事件只有 `redacted`（已打码、≤240 字）没有原文，所以：
- 覆盖部分**精确**（只依赖 `ruleId/threat/decision`）：`base = { ruleId, family: e.threat ?? rule.family, action: rule.action }`；`e.decision==="block" && e.threat ∈ PROTECTED` → guarded，不列。否则 `composeAction(base, next.overrides)` → `applyPolicyDecision(..., next.mode, overridden = 有 source)`；`off` 视为 `log` 且 `approximate=true`。
- 豁免部分：`next.exemptions` 里 `ruleId === e.ruleId` 且 `compileMatch(match).test(e.redacted)` 且 tools 匹配 → `after="log"`，`source="exemption"`，`approximate=true`。
- 新自定义规则（在 `next` 不在 `current`，按 match 小写比）：`compileMatch(match).test(e.redacted)` → `source="custom"`，`after = mode==="block" ? "block" : "rewrite"`，`approximate=true`。
- 只列 `after !== e.decision` 的行。`summary = { block, log, exempt, customHits, approximate, unchanged }`（`unchanged = events.length - rows.length`）。UI 必须标「估算」。

### 2.6 规则状态

自定义规则三态：`on / dry_run / off`（§2.2）。内置规则：默认 / block / log / off（§1.1）。豁免：有效 / 已过期（引擎按 `expiresAt` 判断；存储不主动清理，看板显示并可一键删除过期项）。

---

## 3. 数据结构与接口（测试引用，必须一致）

### 3.1 `core/policy-schema.ts`（新）

```ts
export const THREAT_KINDS = ["exfil","secret","tamper","destructive","recon","isolate","poison"] as const;
export const CANONICAL_TOOL_NAMES = ["Bash","Read","Write","Edit","MultiEdit","Glob","Grep","WebFetch","WebSearch","Task","Skill","MCP"] as const;
export const CUSTOM_RULE_FIELDS = ["command","file_path","url","contents"] as const;
export const RULE_ID_RE = /^[a-z][a-z0-9_]{0,63}$/;
export const MAX_RULE_OVERRIDES = 128;
export const MAX_EXEMPTIONS = 32;
export const EXEMPTION_MAX_TTL_MS = 365 * 24 * 60 * 60 * 1000;
export const EXEMPTION_ID_RE = /^x_[a-z0-9]{1,24}$/;
export type RuleOverride = "block" | "log" | "off";
export type FamilyOverride = "block" | "log";
export interface PolicyOverrides { rules: Record<string, RuleOverride>; families: Partial<Record<(typeof THREAT_KINDS)[number], FamilyOverride>> }
export interface PolicyExemption { …见 §2.4 }
export interface CustomRuleScope { tools?: string[]; fields?: string[] }

/** 严格：非普通对象 / 未知顶层键 / rules 非对象 / 键不合 RULE_ID_RE / 值不合法 / 超 MAX / families 键不在 THREAT_KINDS / 值不合法 → undefined。缺省子对象 = {}。返回深拷贝。 */
export function parsePolicyOverrides(raw: unknown): PolicyOverrides | undefined;
export function policyOverrides(raw: unknown): PolicyOverrides;            // parse ?? { rules: {}, families: {} }
/** 严格：非数组 / 超 MAX / 任一行非法（字段规则见 §2.4，未知键也非法）/ id 重复 → undefined。不按时间过滤。返回深拷贝。 */
export function parsePolicyExemptions(raw: unknown): PolicyExemption[] | undefined;
export function policyExemptions(raw: unknown): PolicyExemption[];         // parse ?? []
/** undefined → {ok:true}；{} → {ok:true}；tools/fields 各为非空字符串数组且全部合法（去重）→ {ok:true, scope}；其它 → {ok:false} */
export function parseCustomRuleScope(raw: unknown): { ok: true; scope?: CustomRuleScope } | { ok: false };
export function customRuleState(rule: { enabled?: unknown; dryRun?: unknown }): "on" | "dry_run" | "off";
```

`src/lib/monitor/policy-schema.ts`（新）只做 re-export（同 `egress-evidence.ts` 的写法），`core/pack.ts:125` 的名单加 `"policy-schema"`。

### 3.2 `core/schema.ts`

```ts
export interface PolicyState { …现有字段; overrides?: PolicyOverrides; exemptions?: PolicyExemption[] }
export interface CustomPrivacyRule { …现有字段; scope?: CustomRuleScope; dryRun?: boolean }
export interface StoredEvent { …现有字段; overrideSource?: "rule" | "family"; exemptionId?: string; dryRunKinds?: string[] }
```

### 3.3 `core/persist.ts`

- `load()`：`overrides !== undefined && !parsePolicyOverrides(...)` → `throw Error("corrupt_json:policy.overrides")`；`exemptions` 同理 → `corrupt_json:policy.exemptions`。
- `getPolicy()`：返回 `overrides: policyOverrides(this.policy.overrides)`、`exemptions: policyExemptions(this.policy.exemptions)`（**始终存在**，深拷贝）。
- `casPolicy(expectedVersion, patch)`：`patch` 增加 `overrides?`、`exemptions?`；用解析器校验，非法 `throw Error("invalid_policy_overrides")` / `"invalid_policy_exemptions"`。
- `customRules` 仍不在 persist 里做行级校验（服务端做）。
- **默认覆盖种子**（与 `defaultRules` 同一机制，只在 policy.json ENOENT 时写入）：`load(opts?: { defaultRules?; defaultOverrides?: PolicyOverrides })`。`DEFAULT_POLICY` 本身不带 overrides（无 opts 的 `load()` 仍得到空覆盖）。`core/serve.ts` 与 `core/cli.ts` 在 `store.load` 时传 `defaultOverrides: monitor.SUGGESTED_OVERRIDES`（经 `loadMonitor` 暴露）。
- `src/lib/monitor/overrides.ts` 导出 `SUGGESTED_OVERRIDES: PolicyOverrides = { rules: { ssh_authorized_keys_bash_write, disable_security_controls, user_account_management, c2_framework_execution, browser_credential_read, fork_bomb, chmod_world_writable_recursive, setuid_setgid_bit 全为 "block" }, families: {} }`。理由：这 8 条是「Agent 静默做了就该停」的持久化 / 提权 / 凭据窃取动作，日常开发几乎不会合法触发；sudo / pip / npm -g / docker / force push / DROP 仍默认记账。已部署的 CT 不受影响（policy.json 已存在），需要管理员在规则页手动应用。

### 3.4 `core/policy-cache.ts`

`readPolicyCache`：`overrides !== undefined && !parsePolicyOverrides` → null；`exemptions` 同理。字段缺席（旧 CT）正常返回，保持 `undefined`。

### 3.5 `core/hook.ts`

- 「缓存停机 → GET /policy 恢复」分支重建 cache 时带 `overrides: policyOverrides(pol.overrides)`、`exemptions: policyExemptions(pol.exemptions)`。
- 「在线判定返回 stopped → 写停机缓存」分支带 `overrides: cache?.overrides`、`exemptions: cache?.exemptions`。
- 离线路径不变（`applyEvaluate` 吃 `cache`）。

### 3.6 `core/eval-bridge.ts`

- `applyEvaluate`：`monitor.evaluate(input, policy.mode, policy.customRules, { overrides: policyOverrides(policy.overrides), exemptions: policyExemptions(policy.exemptions) })`。
- `EvalResponse` 与 `StoredEvent` 透传 `overrideSource / exemptionId / dryRunKinds`（`sanitizeStoredEvent` 不得丢弃它们；`reason` 不变仍是 `rule.id`）。
- 传给 `structuredRewrite / extractDeclaredEndpoints / sanitize*` 的 `customRules` 不变（它们靠 `enabled=false` 跳过 dry-run 规则）。

### 3.7 `core/serve.ts`

- `PUT /api/v1/policy` 新增 body 键 `overrides?`、`exemptions?`。校验顺序与错误：
  1. `overrides` 形状 → 400 `{error:"invalid_policy_overrides"}`
  2. `unknownRuleIds(overrides, monitor.RULES)` 非空 → 400 `{error:"unknown_rule_override", ruleIds}`
  3. `protectedDowngrades(overrides, monitor.RULES)` 非空 → 400 `{error:"protected_rule_override", ruleIds}`（族用 `"family:<f>"`）
  4. `exemptions` 形状 → 400 `{error:"invalid_policy_exemptions"}`；任一 `match` 经 `monitor.privacy.compileMatch` 为 null → 同上
  5. 任一豁免 `ruleId` 指向 `isProtectedRule` 的内置规则 → 400 `{error:"protected_rule_exemption", ruleIds}`
  6. `customRules !== undefined`：`monitor.privacy.sanitizeCustomRules(customRules)` 为 undefined、或长度与输入不等、或 > `MAX_CUSTOM_RULES` → 400 `{error:"invalid_custom_rules"}`；通过则存**规范化后的**数组
  7. 其余同现状；成功响应增加 `overrides`、`exemptions`（规范化后）。
- `GET /api/v1/policy`、`GET /api/v1/state`：增加 `overrides`、`exemptions`。`state.devices[]` 增加 `networkOwnerCount`。
- `/api/v1/evaluate` 响应透传 `overrideSource / exemptionId`。
- `paths.ts loadMonitor` 增加 `RULES`、`RULE_BY_ID`（`rules.ts`）和 `overrides` 模块导出（`isProtectedRule / protectedDowngrades / unknownRuleIds / protectedRuleIds`）；`privacy` 已整模块暴露。

### 3.8 `core/lan-viewer.ts`

- `projectCustomRule`：允许键增加 `scope`、`dryRun`；`scope` 经 `parseCustomRuleScope` 不合法 → null；`dryRun` 非布尔 → null；输出保留 `scope`、`dryRun`，`match/replaceWith` 仍打码。
- `projectViewerState`：`overrides` 经 `parsePolicyOverrides`（缺省 `{rules:{},families:{}}`，非法 → `{ok:false}`）原样投影；`exemptions` 经 `parsePolicyExemptions`（非法 → `{ok:false}`），投影为 `{ id, ruleId, tools?, createdAt, expiresAt?, sourceEventId?, match: VIEWER_HIDDEN_RULE }`，**`note` 不投影**。
- `EVENT_KEYS/EVENT_TYPES` 增加 `overrideSource:"str"`、`exemptionId:"str"`、`dryRunKinds:"str[]"`；`DEVICE_KEYS/DEVICE_TYPES` 增加 `networkOwnerCount:"num"`。
- `projectViewerExport`：接受顶层 `policy`（`{version, mode, overrides, exemptions}`），豁免同样打码去 note。

### 3.9 `core/export.ts`

bundle 增加 `policy: { version, mode, overrides, exemptions }`；`categories` 增加 `"policy_overrides"`。

### 3.10 `src/lib/monitor/overrides.ts`（新）

```ts
export const PROTECTED_FAMILIES: ReadonlySet<ThreatKind>;   // exfil, tamper, isolate, poison, secret
export function isGuarded(action: Action, family: ThreatKind | undefined): boolean;
export function isProtectedRule(rule: Pick<RuleDef, "action" | "family">): boolean;
export function protectedRuleIds(rules: RuleDef[]): string[];
export function composeAction(base: { ruleId?: string; family?: ThreatKind; action: Action }, overrides: PolicyOverrides): { action: Action | "off"; source?: "rule" | "family" };
export function applyPolicyDecision(action: Action, intervention: Intervention, family: ThreatKind | undefined, risk: Risk, overridden: boolean): Decision;
export function ruleDisabled(ruleId: string, overrides: PolicyOverrides, rules: Record<string, RuleDef>): boolean; // rules[ruleId]==="off" && 规则存在 && !isProtectedRule
export function protectedDowngrades(overrides: PolicyOverrides, rules: RuleDef[]): string[];   // 升序；族为 "family:<f>"
export function unknownRuleIds(overrides: PolicyOverrides, rules: RuleDef[]): string[];        // 升序
export function activeExemption(ruleId: string | undefined, inspect: string, tool: CanonicalTool, exemptions: PolicyExemption[], now: number): PolicyExemption | undefined;
```

### 3.11 `src/lib/monitor/engine.ts`

```ts
export interface EnginePolicy { overrides?: PolicyOverrides; exemptions?: PolicyExemption[]; now?: number }
export function evaluate(input: EvalInput, intervention: Intervention, customRules: CustomPrivacyRule[] = [], policy: EnginePolicy = {}): EvalResult;
export interface EvalResult { …现有; overrideSource?: "rule" | "family"; exemptionId?: string; dryRunKinds?: string[] }
```

插入点（保持其余流程不变）：
1. `firstMatch` 跳过 `ruleDisabled` 的规则；`telemetry_drop`、`persona_cloak` 的动态命中前先查 `ruleDisabled` 与 `composeAction`（`log/off` 则不改写、不 cloak）。
2. 自定义命中改为带 scope/豁免/三态的扫描（§2.2、§2.4）；`redacted = redactAll(inspect, hits, [...customHits, ...suppressedCustomHits, ...dryHits])`。
3. 所有升级逻辑跑完、`applyIntervention` 之前：

```ts
const guarded = isGuarded(action, family);
let overridden = false;
if (rule && !guarded) {
  const ex = activeExemption(rule.id, inspect, tool, exemptions, now);
  if (ex) { exemptionId = ex.id; action = "log"; rewritten = false; overridden = true; }
  else {
    const c = composeAction({ ruleId: rule.id, family, action }, overrides);
    if (c.action === "off") { rule = undefined; action = "log"; risk = "info"; family = undefined; }
    else if (c.source) { action = c.action; overrideSource = c.source; overridden = true; if (action !== "rewrite") rewritten = false; }
  }
}
const decided = overridden ? applyPolicyDecision(action, intervention, family, risk, true) : applyIntervention(action, intervention, family, risk);
```

`risk` 不因覆盖而改变。`SessionWindows.apply` 不动（correlate 升级落在 guarded 族）。

### 3.12 `src/lib/monitor/privacy.ts`

`MAX_CUSTOM_RULES = 64`；`compileMatch` 缓存 + ReDoS 启发式；`sanitizeCustomRules` 支持 `scope/dryRun`；`compilePrivacyDraft` 支持前缀作用域；导出 `draftRuleId(match)`、`exemptionId(ruleId, match)`、`liveCustomRules(rules)`（`state==="on"`）、`dryRunCustomRules(rules)`；`scanCustom` 语义不变（跳过 `enabled=false`）。

### 3.13 `src/lib/monitor/policy-proposal.ts`、`policy-replay.ts`（新）

签名见 §2.5：`PROPOSAL_SCHEMA`、`CONTEXT_SCHEMA`、`parsePolicyProposal`、`mergeProposal`、`buildPolicyContext`、`replayPolicy`。类型 `PolicyProposal`、`PolicyView = { mode, overrides, customRules, exemptions }`、`ReplayRow`、`ReplayResult`。

### 3.14 `src/lib/monitor/types.ts`、`map-event.ts`、`rules.ts`、`i18n.ts`

- `types.ts`：`CustomPrivacyRule` 加 `scope?/dryRun?`；`AuditEvent` 加 `overrideSource?/exemptionId?/dryRunKinds?`；re-export `PolicyOverrides/PolicyExemption/CustomRuleScope`（来自 policy-schema）。
- `map-event.ts`：`mapEvent` 读取三个新字段（类型不对就忽略）；`parseViewerCustomRules` 保留 `scope/dryRun`。
- `rules.ts`：§1.3 六条加族。
- `i18n.ts`：新增键见 §7.6（Grok CLI 只需加 `destructive`；其余由 Antigravity 加，但不得删改已有键）。

---

## 4. 兼容矩阵

| 组合 | 行为 |
|---|---|
| 旧探针 + 新 CT | `overrides/exemptions` 被忽略 → 今天的行为；`dryRun` 规则 `enabled=false` → 跳过；`scope` 被忽略 → 规则在所有字段生效（更严，不是放行） |
| 新探针 + 旧 CT | 字段缺席 → `policyOverrides(undefined)` 空、`policyExemptions(undefined)` 空 → 今天的行为 |
| 新探针 + 缓存被改成非法形状 | `readPolicyCache` 返回 null → NEED_CHECK 工具 `no_policy_cache` 拒绝（fail-closed，同 archiveUpload 现状） |
| 新探针 + 缓存里有 guarded 降级 | 形状合法 → 引擎 guarded 忽略 → 仍 block |
| 旧看板 + 新 CT | `parseApiState` 忽略多余键 |
| LAN viewer | 新字段投影、打码，`PUT` 405 |

---

## 5. 验收（全部必须通过）

```
node --experimental-strip-types --test --test-timeout=60000 core/*.test.ts
node --experimental-strip-types --test --test-timeout=60000 src/lib/monitor/*.test.ts
npx tsc --noEmit
npm run build
```

- 本轮新增（现在全红，实现后必须全绿，不得修改）：
  - `core/policy-schema.test.ts` — 解析器形状、默认值、上限、非法输入
  - `core/policy-flow.test.ts` — persist/CAS/重载、policy-cache、离线 hook、CT PUT/GET/state/evaluate/export、LAN viewer 投影与打码
  - `src/lib/monitor/policy-overrides.test.ts` — 引擎三层优先级、guarded、off、destructive 族、豁免、试运行、作用域、ReDoS、草稿前缀、64 条 × 256 KiB 预算
  - `src/lib/monitor/policy-proposal.test.ts` — `overrides.ts` 真值表、提案解析/合并/上下文、命中回放
- 已知：`core/snapshot-guard.test.ts` 的 14 条真实 NTFS ACL 测试在本机 ZCode 进程运行时会因 `zcode_running` 失败，忽略。
- 手工：`grep -rn "24 条\|MAX_CUSTOM_RULES = 24" src core README.md` 不再出现。

---

## 6. 本次不做（明确）

1. **压缩包 `archiveUpload.action="block"` 不放开**：三处既有断言钉死为观察；且大小观察只覆盖命令里显式写出的单个压缩包（变量、管道、多文件看不见），放开就是「看起来能拦其实拦不住」。下一轮先撤断言再议。
2. 不改 `applyIntervention` 的签名与语义；不加新 `ThreatKind`（持久化/提权类规则只能逐条覆盖）。
3. 不做按 agent 的作用域（hook 自报身份，不可信）。
4. 不做服务端直接吃 proposal；不做提案自动应用；不做 `mode/stopped/github/archive` 的导入。
5. 不改 GitHub `unlimited` 对 `large_archive` 的豁免逻辑。
6. 不给 `nmzp rules` 加 `dry/on/off/exempt` 子命令（看板承担）。
7. 不做过期豁免的自动清理（只显示、可手删）。
8. 不改本机/全局边界；本机项只补只读可见性（`networkOwnerCount`）。
9. 不做真正的原文回放（原文不存，回放按 `redacted` 估算并标注）。

---

## 7. 看板（Antigravity 实现；测试不覆盖 UI，但字段与语义必须与 §1–§3 一致）

### 7.1 store / api
- `MonitorState` 增加 `overrides: PolicyOverrides`、`exemptions: PolicyExemption[]`，`syncFromServer` 从 `state.overrides/exemptions` 取（viewer 角色：exemptions 已被 viewer 打码，直接用）。
- `putPolicy` body 增加 `overrides?`、`exemptions?`；返回值增加两者。
- 新动作：`setRuleOverride(ruleId, value | null)`、`setFamilyOverride(family, value | null)`、`setCustomRuleState(id, "on"|"dry_run"|"off")`、`setCustomRuleScope(id, scope | undefined)`、`addExemption(ex)`、`removeExemption(id)`、`applyProposal(next)`；全部走 `gate()`，CAS 冲突时 `syncFromServer()` 并 toast。
- `ApiState.devices[].networkOwnerCount?: number`。

### 7.2 规则页 `/rules`
- 顶部常驻：`覆盖只在「静默」模式生效 · 当前 {mode} · 策略 v{version} · 已同步 {n}/{m} 台`。
- 内置规则列表：每行右侧四段控件 `默认 / 拦截 / 记录 / 停用`；`isProtectedRule` 的行显示锁图标 + 「不可降级」，只保留 `默认/拦截`。族分组标题行带 `默认 / 拦截 / 记录` 三段控件；PROTECTED 族只显示「强制拦截」。行内显示「当前有效动作」徽章（`composeAction` 的结果）与 `source`。
- 自定义规则区：三态开关（开 / 试运行 / 关）、作用域编辑（工具多选 + 字段多选）、试运行行显示「近 {N} 条命中」（从 `events[].dryRunKinds` 数）；草稿输入框 placeholder 增加一行 `Bash,url: db.prod.internal | block`；计数改为 `{n}/64`。
- 豁免区：列表（ruleId、打码/明文 match、tools、note、到期、来源事件链接）、删除、过期项灰显。
- viewer 角色：全部只读，match 显示 `ADMIN_HIDDEN`。

### 7.3 审计页 `/audit`
- 事件行新标签：`因规则覆盖 / 因族覆盖 / 已豁免 {id} / 试运行命中 {kinds}`。
- 每行「这条是误报」按钮（仅 admin，且 `event.ruleId` 存在且非 protected）：弹层预填 §2.4 的豁免草案，管理员编辑 match 后保存 → `addExemption`。
- 「导出 JSON」附 `policyContext`（§2.5）；新增「复制 AI 提示词」按钮，文本固定为：「以下是 NMZP 审计导出与策略上下文。请只输出一个 `nmzp-policy-proposal/1` JSON，不要修改受保护规则，不要包含 mode 字段，所有新自定义规则默认 dryRun。」
- 「导入建议」按钮：文件选择 → `parsePolicyProposal` → 错误列表 / 成功后 `mergeProposal` + `replayPolicy` 预览（表格：事件、规则、之前、之后、来源、估算标记；顶部 summary）→ 勾选「全部先试运行」（默认勾）→ 确认 → `applyProposal`。`basePolicyVersion` 不一致时黄条提示。

### 7.4 总览 `/`
- 机器卡片新增「本机控制项（只读）」折叠区：快照绊索（现有 snapshotGuard）、发现路径（现有 discovery）、探针绑定（现有 probeProtection）、网络所有权授权 `{networkOwnerCount} 项`，每项末尾固定一句「需在该机执行 nmzp …」。
- 顶部 hint 文案按 §1.5 更新。

### 7.5 设置区
- 压缩包设置里 `block` 选项仍 disabled，文案改为「拦截（本轮仍为观察，见规则页覆盖）」。

### 7.6 i18n 新键（zh/en 成对；不得删改已有键）
`destructive`、`overrideOnlyEnforcing`、`overrideDefault`、`overrideBlock`、`overrideLog`、`overrideOff`、`overrideLocked`、`overrideSourceRule`、`overrideSourceFamily`、`exempted`、`dryRunHit`、`ruleStateOn`、`ruleStateDry`、`ruleStateOff`、`scopeTools`、`scopeFields`、`exemptions`、`exemptionAdd`、`exemptionExpired`、`markFalsePositive`、`proposalImport`、`proposalPreview`、`proposalApply`、`proposalForceDry`、`proposalEstimated`、`copyAiPrompt`、`localControls`、`networkOwnerCount`、`syncedHosts`。

---

## 8. 风险与不确定项

- ReDoS 启发式会误拒 `([a-z]+\.)+example` 这类合法写法；看板报错时给出改写提示（`[a-z.]+example`）。
- `off` 覆盖让下一条规则接管，历史回放对此只能估算。
- 覆盖促成的 block 沿用规则原 `risk`（例如 sudo 仍是 medium），总览「高危」计数不会因此上升——这是有意的。
- LAN viewer 投影是白名单，漏加任何新键都会让 viewer 整页 `ok:false`；测试已覆盖 `scope/dryRun/overrides/exemptions/overrideSource`。
