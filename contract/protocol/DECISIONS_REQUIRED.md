# WP-21 候选未决项

状态：OPEN。本文只记录候选与依据。协议没有冻结，Claude 没有批准，G8 / P2 没有通过。

D2、D3、D4、D8 以及 r3 的 D1、D5、D6、D7、D9、D10、D11、D12、D13 已按协调者技术选择写进本候选。D8 迁移、D9、D14 的合同部分已按 r1 裁决落地，裁决文档是 `nmzp-1.0-design/design-review/WP-21_D8_D9_D14_DECISIONS-r1.md`。这仍不是协议冻结，G8 / P2 没有通过。D12、D13 只记录运行时义务，验证器保持 PENDING，不记成通过。IC-01、IC-02 保持 NOT_SWITCHED。PROTOCOL §8 三项证明保持未完成。本包不实现 `/api/v2` 路由。

## 已按本次任务约束落地、仍不是冻结条文

1. **BODY_LIMIT。** 原始 host stdin 与序列化后的 canonical 请求各自独立使用 262144 个 UTF-8 字节，`len(bytes) > 262144` 拒绝，等于 262144 允许。数字与 `core/constants.ts` 的 `BODY_LIMIT` 以及 `core/http-util.ts` `readLimited` 的 `n > limit` 相同。Schema 不用 `maxLength` 或 `maximum` 表示这个数。没有单独的单值或累计解码上限，见 D1。两条上限的分工见 D3。
2. **超限与歧义失败关闭。** 超限、截断标志或无法确定的解析不生成缩短后的成功事件，也不从保留前缀制造 `rawPayloadHash`。别名冲突不合并成一个字段。当前 `parseHookEvent` 在 `toolInputTruncated` / `tool_input_truncated` 为真时返回 null（`core/hook-protocol.ts`）。本候选把这两种标志拒成 adapter parse failure，不收成 CanonicalToolEvent。`errorCode` 见 D9 映射。
3. **raw 不上送。** CanonicalToolEvent 只有 `rawPayloadHash`。13 个宿主 fixture 保存 UTF-8 哈希和来源路径，不保存 raw 字符串。
4. **IC-01 不切换。** `kind: UNKNOWN` 只是 schema 枚举里的一个值。未知工具仍按当前策略，不在本候选改写。

## OPEN 项

### D1. extraFields 限额与路径语法

**已按 r3 落地（候选，不冻结）。** 容器嵌套深度 ≤ 64，含顶层容器。`extraFields` ≤ 256 条，schema 用 `maxItems`。每条 JSON Pointer ≤ 1024 个 UTF-8 字节。没有单独的单值或累计解码上限；D3 的 262144 字节 canonical 上限同时封住这两项。超出任一限额是 adapter parse failure，不裁剪。`hook.ts` 在字节上限之后用 UTF-16 的 `stdin.length` 再查一次；v2 只按字节。验证器不用 `uniqueItems` 冒充“只按 path 唯一”。

路径拼写已由协调者裁决，见 `WP-21_PATH_DECISION-r1.md`（2026-09-27）。本候选的 `provenance` 与 `extraFields.path` 使用 RFC6901 JSON Pointer 的字符串形式，不接受 URI fragment（`#` 开头）。这只决定本候选的路径身份，不冻结协议，也不关闭 G8。

- 成员名按原文比较。键名不做 trim、大小写折叠或 Unicode 归一化。`~` 编成 `~0`，`/` 编成 `~1`。解码先处理 `~1`，再处理 `~0`。`~` 后面不是 `0` 或 `1` 则拒绝，因此 `~~1` 不是另一种合法拼写。
- 当前容器是数组时，token 必须是规范的非负十进制下标（除 `0` 外不许前导零）。`-`、越界、以及不存在的成员都不是字符串叶。对象里的键 `"01"` 或 `"-"` 仍是普通成员名。
- 空字符串指针不是 object 或 array 宿主载荷里的字段叶。空成员名写成 `/`。
- 验证器拒绝：extra path 与任一 `fields.*.provenance` 的指针字符串完全相同，或两条 extra path 完全相同。比较不做解码后再归一。`/a~1b` 与 `/a/b` 不是同一条路径。
- v2 CanonicalToolEvent 保存宿主精确字符串，键名和值都不 trim。1.0 的别名冲突判定按 v1 `str()`（trim，空白视为缺失），因此 `echo a` 与 `  echo a  ` 不冲突。按精确字符串比较更严格，会改变决策，登记为 **IC-02 NOT_SWITCHED**。见 D8 与 `WP-21_D8_D9_D14_DECISIONS-r1.md`。本候选不改 v1。值的比较不是指针规范化。
- 重复的 JSON raw member 由 D3 的严格 v2 字节解析拒绝。`json.loads` 会留下最后一次出现，不能代替那条路径。JSON Pointer 也不解决重复成员。这不是 v1 等价声明。
- 只列出 unmapped 不算映射完整。13 个宿主投影仍是 `PARTIAL_PROPOSED`，`privacyScanComplete=false`，直到每个字符串叶被映射、进入 extras，或由明确的 host-metadata 规则排除。

### D2. 成功事件不携带 `truncated`

协调者已选择：成功的 CanonicalToolEvent 在其声明的映射范围内是完整的。不增加带 `truncated=true` 的成功事件。体积超限、输入截断或无法确定的解析，返回有类型的 adapter parse failure，本地按 deny 处理。它不产生缩短事件，也不表示评估或回执已经成功。PROTOCOL 示例与“超限时输出 `truncated: true`”那句冲突；本候选取失败关闭，不取带标志的成功事件。

- Schema 拒绝 CanonicalToolEvent 上的 `truncated`，包括顶层和字段内。成功事件必填 `truncated` 的那一支不采用。
- 已识别的 incoming 标志是 `toolInputTruncated` 与 `tool_input_truncated`。值为 `true` 或 `"true"` 时，严格 v2 解析返回 parse failure。标志缺失，或值为 false，都不能证明载荷完整。
- `errorCode` 按 D9 映射填写，不再是 JSON null。`failureClass` 仍是验证器分类；schema 用 if/then 把它映到 ErrorCode。
- 不得把保留前缀的 SHA-256 写成 `rawPayloadHash`。失败对象没有该属性。
- Schema 不能证明发送方没有隐瞒截断。验证器仍用“超限正文 + 一份 schema 合法的短事件”必须拒绝来覆盖这一点。

### D3. 传输字节与解码

协调者已选择。这是新的 v2 边界，不是当前 `Buffer.toString("utf8")` / `JSON.parse` 的行为声明，也不关闭 v1 入口等价。

- 原始 host stdin 与序列化后的 canonical 请求各自独立以 262144 字节为含上限。一边在限额内，另一边超限，仍然失败关闭。不删 extras，也不改成缩短后的成功事件。
- 没有单独的单值或累计解码上限。D1 的深度、extras 和指针限额另行检查，不从 JavaScript `string.length` 推断。
- 非法 UTF-8 拒绝，不替换解码，不做 Unicode 归一化。JSON 解码之后，任意深度的孤立高代理或孤立低代理都拒绝，成员名也包括在内。成对的补充平面代理不是孤立代理。
- 任意深度的重复成员，在 JSON 转义解码之后、普通对象物化之前拒绝。值相同也拒绝。转义与字面解码成同一个键，算重复。只差空白、大小写或 Unicode 归一化的键仍是不同键。
- 上述边界用原始字节样例检查。只校验已经物化的对象不能证明这些情况。`json.loads` 留下最后一次出现，不能代替这条路径。
- JSON 转义的字节算进报文大小，不算进解码后的 span。

### D4. span 使用 UTF-16 码元

协调者已选择。单位与当前 JavaScript 匹配器一致：`src/lib/monitor/privacy.ts` `scanCustom` 使用 `RegExpExecArray.index` 与 `match.length`；`core/rewrite.ts` `applySpans` 使用 `String.slice`。审查里的 UTF-8 字节偏移不作为 span 单位。协议本身仍未冻结。

- 对解码后的 `fields[field].value`，零基、左闭右开，单位是 UTF-16 码元。start 与 end 是整数，且 `0<=start<end<=length`。两端不许切开代理对。
- 不按 UTF-8 字节计，也不按 JSON 源码里的转义字节计。匹配、哈希、切片之前不 trim，不做 Unicode 归一化。组合字符仍是独立码点。字素簇边界不检查，因此拆开基字与组合记号在这一项里允许。
- `originalHash` 是 `sha256:` 加上所选子串 UTF-8 字节的小写十六进制。子串必须是合式 Unicode。
- `rawPayloadHash` 覆盖 BOM 与空白处理之前的完整原始字节，不是重新拼出来的 JSON。`baseInputHash` / `resultInputHash` 与 patch 重叠见 D5。
- 零宽 span 与 `start<end` 冲突，所以 `rewrite-zero-width-span.json` 改为 invalid。原因见 `WP-21_D2348_EVIDENCE.md`。emoji 占 2 个码元。

### D5. 哈希序列化

**已按 r3 落地（候选，不冻结）。** `rawPayloadHash` 的候选预映像是宿主 raw 字符串的 UTF-8 字节。patch `originalHash` 的候选预映像见 D4，并且是合并后的并集子串。

`baseInputHash` / `resultInputHash` 是 `sha256:` 加上 RFC8785 JCS，对象只含解码后的 `fields` 值 `{fieldName: value}`。不含 provenance、extras 或宿主元数据。未改写字段包含在内。`resultInputHash` 是 patch 之后的同一对象。字符串 map 上，JCS 与 v1 `stableJson` 一致：按 UTF-16 码元排序键，非 ASCII 不转义。这与 `json.dumps(sort_keys=True)` 的码点排序和默认 `\u` 转义不同。Schema 仍只检查 `sha256:` 外形。外形通过不等于每一份 schema fixture 都核对了预映像。

重叠或相接的 span 按 v1 `resolveSpans` 合并为并集。secrets 优先级 2 高于 custom 的 1。同优先级且替换不同时，替换变成 kind tag `<标签>`。合并发生在哈希之前。验证器把重叠输入当成合并后有效，不把重叠当 PENDING，也不直接拒绝。优先级在合并时不提升，与 v1 源码一致。

### D6. eventId 形式

**已按 r3 落地（候选，不冻结）。** 非空字符串，1..128 个 UTF-16 码元，拒绝 C0/C1 控制字符，不强制 UUID。超长是 parse failure `event_id_invalid`，不截断。现有 `evt-<host>` 仍有效。claude 与 grok 样例没有 id，沿用生成的 32 位小写十六进制占位；本候选不实现生成器。宿主 id 的优先顺序与 v1 `hook-protocol.ts` 相同。antigravity 仍是 `conversationId + ":" + stepIdx`。

- **PROPOSED-UUID-V7：** 强制版本 7。会拒绝现有样例 id。未采用。

### D7. 工具 kind 与 v1 `compare.tool`

**已按 r3 落地（候选，不冻结）。** `native-kind-map.json` 逐项抄 `src/lib/monitor/agents.ts` 的 `NATIVE_TOOL_MAP`，不增不漏。canonical 名再映射：Bash→SHELL；Read、Glob、Grep→FILE_READ；Write→FILE_WRITE；Edit、MultiEdit→FILE_EDIT；WebFetch→WEB_FETCH；WebSearch→WEB_SEARCH；`mcp__*`→MCP；Task、Skill 以及表外名字→UNKNOWN。`nativeName` 保留宿主拼写。查找先转小写。

13 个宿主投影的 kind 按这张表填写。当前这 13 个 nativeName 都落到 SHELL。v1 `compare.tool` 仍是 `Bash`，不写进 kind。IC-01 **NOT_SWITCHED**：UNKNOWN 的策略评估在 IC-01 处置前保持 v1 的 Bash 待遇。cursor `Delete` 按 v1 到 Bash 再到 SHELL，留给等价 golden，不改分类。

- 旧的「解析出 command 就填 SHELL」不再作为 kind 规则。IC-01 不因此启用。

### D8. 封闭对象与精确字符串

**已按 r1 裁决落地（候选，不冻结）。** 裁决：`WP-21_D8_D9_D14_DECISIONS-r1.md`。

- v2 CanonicalToolEvent 保存宿主精确字符串（不 trim）。桥接到引擎按 v1 `str()`：trim，空白视为缺失。
- 别名冲突判定在 1.0 按 v1 `str()` 语义（`echo a` 与 `  echo a  ` 不冲突）。候选原文「按精确字符串比较」更严格，会改变决策，登记为 **IC-02 NOT_SWITCHED**，与 IC-01 同样需 Gate A 后单独开关。
- 别名组（1.0 完整清单，v1/v2 共用 `core/hook-protocol.ts` 一份实现）：command ⇔ cmd；file_path ⇔ filePath ⇔ path ⇔ target_file；dest ⇔ host ⇔ hostname；cwd ⇔ working_directory ⇔ workingDirectory；contents ⇔ content（取值不同 → conflicting_aliases，不再拼接）；Antigravity TargetFile ⇔ AbsolutePath → file_path（取值不同 → conflicting_aliases）。
- 精确字符串与 trim 结果不同的输入只作审计观察（`d8TrimObservations`），不改决策。
- canonical 对象按各自 schema 闭合，包括嵌套对象。多余属性拒绝，不剥离。`error.data` 的闭合见 D9，不再使用 D9_OPEN_NOT_A_MAP。
- 空字符串和纯空白字符串是合法的精确字段值。键出现且值为 `""` 或空白，与键缺失不是同一状态。`userMessage` 的非空要求没有改，D13 仍 PENDING。

### D9. 错误码枚举

**已按 r1 裁决落地（候选，不冻结）。** 裁决：`WP-21_D8_D9_D14_DECISIONS-r1.md`。枚举成员仍是 r3 的两组，每个成员有 description 和 `x-remediation`。第一组是 v1 实际发出的 code：`payload_too_large`、`bad_json`、`bad_schema`、`unauthorized`、`event_conflict`、`event_expired`、`evaluation_immutable`、`bad_receipt`、`bad_backfill`、`bad_heartbeat`、`storage_not_enabled`、`processing_stopped`、`policy_conflict`、`cas_conflict`、`policy_recovery_required`、`policy_not_committed`、`policy_queue_full`、`audit_storage_unavailable`、`probe_proof_required`、`internal_error`。第二组是 v2 parse-failure code：`input_truncated`、`invalid_utf8`、`lone_surrogate`、`duplicate_member`、`depth_exceeded`、`extras_exceeded`、`pointer_too_long`、`event_id_invalid`。

PROTOCOL 示例里的单词 `conflict` 不是单独成员。v1 发出的是 `event_conflict` 与 `cas_conflict`。

Adapter parse failure 的 `errorCode` 从 JSON null 改为映射：`over_limit` 与 `canonical_over_limit` → `payload_too_large`；`json_syntax` → `bad_json`；`invalid_utf8` → `invalid_utf8`；`unpaired_surrogate` → `lone_surrogate`；`duplicate_member` → `duplicate_member`；`incoming_truncation` → `input_truncated`；`depth_exceeded` → `depth_exceeded`；`extras_exceeded` → `extras_exceeded`；`pointer_too_long` → `pointer_too_long`；`event_id_invalid` → `event_id_invalid`。`failureClass` 本身不是 ErrorCode。

`error.data` 按 code 闭合，不再是 D9_OPEN_NOT_A_MAP。有 data 的 code 只有两个：`policy_conflict` 为 `{ currentVersion: integer≥0, currentRulesHash: sha256: }`；`cas_conflict` 为 `{ currentVersion: integer≥0 }`（v1 在正文顶层返回 `version`）。其它所有 code 禁止 `data`。CI 检查已接入 `npm run lint:contract`（quality workflow，在 lint:layers 之后）：v2 错误信封只能经 `v2Error` 产生，code 类型来自 openapi ErrorCode 生成的联合类型；脚本检查字面量 code、每个成员的 description 与 x-remediation、error-envelope 的 code 枚举与 ErrorCode 成员及顺序一致，并跑 `contract:types:check`。v1 `{ok:false,error}` 字符串不在本检查范围。

### D10. reasonCode、risk、ASK

**已按 r3 落地（候选，不冻结）。** reasonCode 仍是开放集合，pattern 为 `^[a-z][a-z0-9_:]{0,127}$`。已出现的例子写在 decision schema 的 description，不是枚举。

v2 `risk` 保持 `none|low|medium|high|critical`。schema 仍拒绝 `info`。投影里 v1 `info` 映射为 `none`。`budget_low_risk` / `no_cache_low_risk` 路径要由等价 golden 确认，该项 **NOT_RUN**。

v1 `confirm` 在 `core/hook.ts` 被送到 deny 分支。v2 ASK 保留，在全部 13 个宿主上按该宿主的 deny 形式渲染，与 v1 confirm 相同。antigravity / cursor 的 `ask` 形状仍只是 rewrite 载体，不是 ASK。ASK 的 RenderDecision 字节 **NOT_RUN**。

矩阵（2026-09-28 协调者澄清 r3 歧义）：APPLIED⇔REWRITE；NOOP_NO_SPAN⇒LOG；REFUSED⇒BLOCK；LOG 取 NONE 或 NOOP_NO_SPAN；BLOCK 取 NONE（普通策略阻断、别名冲突）或 REFUSED（改写失败）；ALLOW、ASK 只取 NONE。ASK+REFUSED 与 ALLOW+REFUSED 无效。`NOOP_NO_SPAN` 时 action 为 `LOG` 这条原约束保留。

### D11. 证据 UNKNOWN、VERIFIED 与回执绑定

**已按 r3 落地（候选，不冻结）。** EVIDENCE_MODEL §2 已给出多数 state/source/trust 行。本候选用 if/then 编码这些行。

- UNKNOWN 只允许显式 JSON null：source、trust、selfReported、hostRealVerified、ref 都必须出现且为 null。缺省这些键的分支已删除。
- VERIFIED 保留精确的 `hostVersion` 字符串，加上 `adapterRevision`。版本范围与 action **PENDING**，留给 Evidence 实现工作包，本候选不声称已覆盖。
- 回执必须绑定 token 上的设备、eventId 和决策摘要。Schema 不能证明。**PENDING**（运行时）。
- 工具 UNKNOWN 与证据 state UNKNOWN 不是同一件事。本候选不把前者写成后者。

### D12. 设备 token 与正文身份

**已按 r3 落地（候选，不冻结）。** 设备身份只来自 bearer token。v1 在设备路由上不读正文里的设备 id。v2：正文 `device.id` 如果出现，必须等于 token 的设备 id，否则 401 `unauthorized`，不另设错误码。Schema 接受 `device.id` 不能证明 token、主体或正文未被替换。验证器把这项标 **PENDING**，`runtimeObligation`，不记成通过。

旁证，不在本候选实现：`persist.ts` 用 `===` 比较 token 的 SHA256 hex，而不是 `safeEqualHex`。这是单独的加固任务。

### D13. userMessage 不回显秘密

**已按 r3 落地（候选，不冻结）。** `userMessage` 由每个 reasonCode 的固定模板渲染，不插入字段值、span 或路径。测试义务：每份 rewrite / privacy fixture 的渲染输出字节都不得包含 fixture 里的秘密子串。Schema 只能要求非空字符串。验证器把这项标 **PENDING**，`runtimeObligation`，不记成通过。

### D14. 其它未写正文的路由

**已按 r1 裁决落地（合同部分，候选，不冻结）。** 裁决：`WP-21_D8_D9_D14_DECISIONS-r1.md`。本包不实现 `/api/v2` 路由。

- **ETag**：强 ETag，字节格式 `"p<policyVersion>.<rulesHashHex>.e<engineRevision>"`（含两侧双引号）。rulesHashHex 为 64 位小写十六进制，不含 `sha256:`。`If-None-Match` 与当前 ETag 逐字节相等，或逗号列表中任一段逐字节相等（不修剪空白）→ 304，无正文，带 ETag。`W/` 弱标签与 `*` 不命中 → 200。
- **GET /api/v2/policy 正文**：闭合对象。成员与 v1 `GET /api/v1/policy` 逐字段相同，另加 `rulesHash`（`sha256:`，与策略历史同一 `policyRulesHash` 计算）。子对象沿用 v1 形状，本包不重新建模。
- **receipts / backfill / heartbeat 的 v2 成功正文**：与 v1 成功正文逐字段相同。失败统一用 v2 错误信封。这三条路由的请求正文仍 PENDING。
- **hookBlind**：`origin=HOOK` 恒为 false；`origin=PROBE|BACKFILL` 取上报方给出的布尔。不从字段缺失推断。

`adapterRevision`、`occurredAt`、`device.id` 在现有 raw 里没有。投影中的 `0`、`1970-01-01T00:00:00Z`、`UNOBSERVED_DEVICE` 是占位，不是观测值。运行时 `/api/v2/evaluate` 的 `device.id` 按 D12 由 token 决定，验证器仍 PENDING。

`host.id` 不做成 13 值封闭枚举。13 是当前 `HOOK_AGENTS`，不是 PROTOCOL 里的永久枚举。

完整决策轨迹（`nmzp explain`）没有单独 schema。PROTOCOL 说它没有网络端点。短 `explain` 禁止 span。

## 明确没有当成通过的门禁

PROTOCOL §8 其余三项保持未完成：13 宿主 v1→v2 决策等价（IC-01 例外）、13 宿主 RenderDecision 字节 golden、Kiro-Q2。候选映射的 schema 自测不是这些证明。

IC-01、**IC-02 NOT_SWITCHED**。IC-02 是「别名冲突改为按宿主精确字符串比较」。1.0 仍按 v1 `str()`。与 IC-01 一样，需 Gate A 后单独开关。裁决见 `WP-21_D8_D9_D14_DECISIONS-r1.md`。
