# WP-21 候选未决项

状态：OPEN。本文只记录候选与依据。协议没有冻结，Claude 没有批准，G8 / P2 没有通过。

D2、D3、D4、D8 以及 r3 的 D1、D5、D6、D7、D9、D10、D11、D12、D13 已按协调者技术选择写进本候选。D8 迁移、D9、D14 的合同部分已按 r1 裁决落地，裁决文档是 `nmzp-1.0-design/design-review/WP-21_D8_D9_D14_DECISIONS-r1.md`。这仍不是协议冻结，G8 / P2 没有通过。D12、D13 只记录运行时义务，验证器保持 PENDING，不记成通过。IC-01、IC-02、IC-10 保持 NOT_SWITCHED。PROTOCOL §8 三项证明保持未完成。本包不实现 `/api/v2` 路由。

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
- 本节以及 D1、D6 的严格失败类都在 **IC-10 NOT_SWITCHED** 开关之后，默认关闭。见文末 IC-10。

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

**候选，不冻结。** scalar 字段沿用 `WP-21_D8_D9_D14_DECISIONS-r1.md`；contents 以当前代码候选 `docs/design-review/WP-21_CONTENT_LEAVES-r1.md` 的协调者修订为准。

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
- **receipts / backfill / heartbeat 的 v2 成功正文**：与 v1 成功正文逐字段相同。失败统一用 v2 错误信封。这三条路由的请求正文已按 docs/design-review/WP-21_REQUEST_AUTH-r1.md 的协调者候选写入，运行时接线仍待完成。
- **hookBlind**（按 r2 修订，见 `WP-21_D8_D9_D14_DECISIONS-r2.md`）：`origin=HOOK` 恒为 false；`origin=PROBE` 取 v1 evaluate 正文 `body.hookBlind === true`（仅 JSON true 为 true，`core/serve.ts:224`、`engine.ts:710`）；`origin=BACKFILL` 恒为 true（v1 `core/serve.ts:1101`）。r1 所称「ingest.ts 语义」不是运行时来源（`parseHookPayload` 无运行时调用方）。不从字段缺失推断。

`adapterRevision`、`occurredAt`、`device.id` 在现有 raw 里没有。投影中的 `0`、`1970-01-01T00:00:00Z`、`UNOBSERVED_DEVICE` 是占位，不是观测值。运行时 `/api/v2/evaluate` 的 `device.id` 按 D12 由 token 决定，验证器仍 PENDING。

`host.id` 不做成 13 值封闭枚举。13 是当前 `HOOK_AGENTS`，不是 PROTOCOL 里的永久枚举。

完整决策轨迹（`nmzp explain`）没有单独 schema。PROTOCOL 说它没有网络端点。短 `explain` 禁止 span。

## 明确没有当成通过的门禁

PROTOCOL §8 其余三项保持未完成：13 宿主 v1→v2 决策等价（IC-01 例外）、13 宿主 RenderDecision 字节 golden、Kiro-Q2。候选映射的 schema 自测不是这些证明。

IC-01、**IC-02 NOT_SWITCHED**。IC-02 是「别名冲突改为按宿主精确字符串比较」。1.0 仍按 v1 `str()`。与 IC-01 一样，需 Gate A 后单独开关。裁决见 `WP-21_D8_D9_D14_DECISIONS-r1.md`。

### IC-10 NOT_SWITCHED：v2 严格入口

编号说明：IC-03…IC-09 已由 `NMZP_1_0_PRIVACY_REWRITE.md` §10 定义（policy-spec 也引用 KNOWN_IC-03/05），本项用 IC-10，不复用 IC-03。

D1、D3、D6 的严格边界与原始字节失败类统一放在一个开关后：`core/protocol/v2-adapter.ts` 的 `V2_STRICT_INGRESS_DEFAULT = false`，调用级参数 `AdapterOptions.strictIngress`。开关关闭时这些失败类不产生，v2 决策与 v1 一致，由 `tests/contract/v1-v2-equivalence.test.mjs` 断言。开关打开时，下表输入 v1 照常评估、v2 失败关闭（DENY），是已知差异，同一测试逐类断言。

| 失败类 | 触发 | v1 当前行为 |
|---|---|---|
| `invalid_utf8` | 原始字节不是合法 UTF-8 | `Buffer.toString("utf8")` 替换成 U+FFFD 后评估 |
| `duplicate_member` | 任意深度、转义解码后的重复成员 | `JSON.parse` 取最后一次出现 |
| `unpaired_surrogate` | 值或成员名中的孤立代理 | 照常评估 |
| `depth_exceeded` | 容器深度 > 64 | 照常评估 |
| `extras_exceeded` | extraFields > 256 | 无此概念 |
| `pointer_too_long` | 指针 > 1024 UTF-8 字节 | 无此概念 |
| `event_id_invalid` | eventId 空、> 128 UTF-16 码元或含 C0/C1 | 照常评估；只有审计 outbox 拒收 > 128 |
| `canonical_over_limit` | 原始正文 ≤ 262144 字节，序列化 canonical 请求 > 262144 字节 | 无此概念 |

- 严格扫描器 `strictJsonScan` 在 `JSON.parse` 之前做词法级解码，按文档顺序报告第一个失败。只校验物化后的对象看不到重复成员。
- `invalid_utf8` 只能从原始字节判断，入口是 `toCanonicalToolEventFromBytes`。字符串入口拿到的已是解码后的文本。
- **启用是路由层义务。** 本包不实现 `/api/v2`。将来的 `/api/v2` 路由须把原始正文字节交给 `toCanonicalToolEventFromBytes(bytes, ctx, { strictIngress: true })`，并在 Gate A 后单独处置本 IC。不得把 v1 入口切成严格模式，也不得把开关关闭时的等价说成严格边界已生效。
- **审查前提更正。** 审查说 v1 按 UTF-16 码元计 BODY_LIMIT，这不成立。生产入口都按原始 UTF-8 字节计：hook `hookMain` → `readStdin`（`core/hook.ts:76`），serve `readLimited`（`core/http-util.ts:24`）。只有进程内直接调用 `runToolHook` 时多一道 `opts.stdin.length > BODY_LIMIT`（`core/hook.ts:420`，UTF-16 码元），`runHook` 的 zcode 分支同理。经 `hookMain` 进入时 UTF-16 码元数 ≤ 原始字节数（含替换字符），这道检查不会先触发。所以 262144/262145 原始字节上限不属于本 IC 的差异，v2 字节入口与 v1 一致。
- 字符串入口按解码后文本的 UTF-8 字节计上限，合法 UTF-8 时等于原始字节数。接近上限的非法 UTF-8 每个坏字节解码成 3 字节 U+FFFD，字符串入口会比 v1 多拒，所以有原始字节时一律走字节入口。测试有此断言。
- 开关关闭时不限深度，与 v1 一致。遍历改为迭代实现，10 万层嵌套不栈溢出，测试有此断言。


### IC-11 NOT_SWITCHED：嵌套内容别名（B3）

协调者技术记录（2026-09-30），不是冻结批准。当前 v1/v2 仅对 toolInput 顶层和 edits[] 行的 contents/content 做别名冲突检测。内嵌 input:{contents,content}、数组 patch 等其它嵌套对象继续扫描所有字符串叶子，trim、去重并以换行拼接；两份不同内容不会被当作冲突，也不丢弃任意一份。若改成任意深度别名冲突即拒绝，会改变 v1 决策，登记 **IC-11 NOT_SWITCHED**，本项不实现或启用拒绝开关。旧来源中的 IC-04 编号不适用。

- N2：workdir 不在 CWD_KEYS，也不是顶层操作字段；它仍作为内容叶子进入 contents，不作为 cwd。未来扩展必须单独处理兼容性，本项不扩展集合。
- B6：command/cmd 等别名按 trim 后值比较；echo a 与前后空白包围的同值不冲突。精确字符串冲突比较仍属于 **IC-02 NOT_SWITCHED**。
- 验证：tests/contract/alias-compatibility.test.mjs；包含实际 hook.ts 离线执行与 v2 渲染字节比较，tests/contract/alias-compatibility-mutations.test.mjs 在隔离副本运行同一测试并验证变异失败、恢复哈希及恢复后通过。

### IC-12 NOT_SWITCHED：路径精确值与 trim 的差异（B7）

filePath/cwd 前后空白会被 v1 桥接 trim；精确路径与 trim 路径可能指向不同目标。示例：cwd=/home/u/.ssh 且 file_path=" /tmp/a"，POSIX 精确相对路径落在 /home/u/.ssh/ /tmp/a，策略接收 /tmp/a。现有 v1 决策为 log，宿主放行；v2 保持同一决策和输出字节。这是词法风险演示，不是已实测宿主漏洞，也不证明 /tmp 豁免配置。

- 拒绝此类输入会改变决策，登记 **IC-12 NOT_SWITCHED**；未来 Gate A 后另行批准开关，本项不增加拒绝路径。旧来源中的 IC-05 编号不适用。
- d8TrimObservations 对 filePath/cwd 的精确值不同于 v1 trim 结果时生成 warning（固定 code=path_whitespace_difference）。普通 command 等差异仅保留观察。
- d8TrimAuditWarnings 返回仅含 code/severity/field/compatibility/status 的安全投影。exact/trimmed 是敏感的内存诊断值，不得直接序列化进审计、日志或 hook 输出；不记录原值、哈希、长度、任意成员名或 provenance。
- 本 helper 无 I/O，不写 stdout/stderr。当前没有 v2 路由运行时调用方，持久化审计告警接线明确留给阶段2，不得把当前实现记为审计已落盘。
- 覆盖 ASCII 空格、TAB、NBSP、U+2028、工具 cwd、信封 cwd、无差异负例及规范事件中空白串变成缺失的边界；13 宿主按真实 v1 hook 输出验证该风险示例字节等价。
- IC-01/02/10 同样不切换；G8 继续 OPEN，无独立冻结结论。


### Item9：精确 contents 多叶候选修订（冻结前 wire change）

- 唯一闭合结构为 `fields.contents:{leaves:[{value,provenance}]}`；无旧结构 union 或聚合第二真值。空白及重复值按来源精确保存；无叶才省略字段。其余 scalar 空白保存问题留作独立残余。
- 共用 core/hook-alias-keys.ts 精确叶枚举，顺序为顶层 CONTENT_KEYS、edits 行 CONTENT_KEYS、其它非操作根成员的递归叶。edits 未知键及对象型内容不扩大扫描，ingest 信封过滤不移入 canonical bag。
- trim/空值丢弃/去重/换行拼接仅发生在评价桥接；目标是 v1 决策和13宿主字节不变。所有 provenance 对应原始宿主字符串；Antigravity 首级 remap 必须取自有属性，原型同名键不受禁用。
- 此项明确改变未冻结 canonical wire shape、序列化大小及 extras 计账。IC-10 严格限制仍默认关闭；IC-01/02/11/12 同样不切换。没有已部署 v2 兼容或冻结声明。
- D5 的 patch 叶定位、逐叶 updatedFields、contents 数组值哈希预像均未实现；当前 scalar rewrite schema 不能证明这些能力。D8 审计安全投影不泄漏叶值或指针，运行时持久化接线仍待阶段2。
- 完整裁决与证据：docs/design-review/WP-21_CONTENT_LEAVES-r1.md 及同目录 COORDINATOR_CHECKPOINT.md。G8 OPEN。


### 阶段2首包：请求、鉴权与上下文（候选，不冻结）

详见 docs/design-review/WP-21_REQUEST_AUTH-r1.md。receipts/backfill/heartbeat 请求结构按现有 parser 闭合；receipt/heartbeat 的 unknown-key ignore 是明确的 legacy V1_SHAPE 例外。UTF-16/cross-field/时间等义务仍由 parser 完成，schema 单独不是完整接受判定。

五条路由声明设备 bearer；token/device.id 绑定为运行时义务。forbidden/not_found 纳入 ErrorCode，保留403/404、rejected、非retryable、无data。canonical context 可选 permissionMode/uploadSize 仅延续现有解析器及指纹语义。服务端新建context禁止占位；客户端原有epoch/adapterRevision=0不被新增拒绝。D5、跨版本幂等与真实HTTP路由仍阻塞，G8 OPEN，无IC切换。


### 阶段2四条设备路由（未冻结）

policy/receipts/backfill/heartbeat 已共享 v1 业务分支接线，详见 docs/design-review/WP-21_DEVICE_ROUTES-r1.md。evaluate 仍未实现；前述“本包不实现路由”为历史合同包状态，不代表这四条现状。原始 bytes proof 保持 NMZP-PROBE-1/v1-heartbeat-path；v2 是同一逻辑资源的兼容别名，不引入新签名版本。

确认原错误盘点漏项：core/audit/store.ts confirmBackfillReceipt 对已经确定的最终 enforcement 返回409 conflict；现纳入枚举，rejected/非retryable/无data，与事件内容 event_conflict 不合并。v1返回不变。D5、evaluate共享应用层及其跨版本/历史规则继续阻塞；不由本包裁决。G8 OPEN，IC均不切换。
