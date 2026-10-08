# WP-21 候选未决项

状态：G8 r1 = NOT_FREEZE（2026-10-02，`docs/design-review/G8_FREEZE-r1.md`）；G8 r2 用户已签（2026-10-02，"按你建议来"：不否决，IC-13 保留，IC-14 选项二，IC-15 选项二、上限 64），两项新代码已在 worktree 实现，待独立 r8 复核，见 `docs/design-review/G8_FREEZE-r3.md` 与文末「G8 r2 修订」。D1–D14 都已选定方案，没有待选项；未实现或未证明的部分在各节标为 PENDING / NOT_RUN。本文是候选登记，不是冻结条文。

D2、D3、D4、D8 以及 r3 的 D1、D5、D6、D7、D9、D10、D11、D12、D13 已按协调者技术选择写进本候选。D8 迁移、D9、D14 的合同部分已按 r1 裁决落地，裁决文档是 `nmzp-1.0-design/design-review/WP-21_D8_D9_D14_DECISIONS-r1.md`。这仍不是协议冻结，G8 / P2 没有通过。D12、D13 只记录运行时义务，验证器保持 PENDING，不记成通过。IC-01、IC-02 保持 NOT_SWITCHED。IC-10 已于 2026-10-08 在路由层与客户端 transport 切换，adapter 默认仍为 false。PROTOCOL §8 三项证明保持未完成。合同包阶段不实现 `/api/v2` 路由；P2 的路由接线现状见「阶段2四条设备路由」「阶段2 evaluate 实际 wire」。

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
- 本节以及 D1、D6 的严格失败类在 IC-10 切换后于 v2 路由与客户端 transport 生效；adapter 默认仍关闭。见文末 IC-10。

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
- 空字符串和纯空白字符串是合法的精确字段值。键出现且值为 `""` 或空白，与键缺失不是同一状态。`userMessage` 的非空要求没有改。D13 已由 `docs/design-review/WP-21_D11_D14_DECISIONS-r1.md` 关闭：固定模板。客户端校验入口 `applyCanonicalEvaluateResponse`（`core/protocol/evaluate-response.ts:49`，内部调用 `validateEvaluateResponse`，失败关闭）已实现，但目前没有生产调用方，客户端失败关闭仍是 PENDING 的接线义务。

### D9. 错误码枚举

**已按 r1 裁决落地（候选，不冻结）。** 裁决：`WP-21_D8_D9_D14_DECISIONS-r1.md`。枚举成员仍是 r3 的两组，每个成员有 description 和 `x-remediation`。第一组是 v1 实际发出的 code：`payload_too_large`、`bad_json`、`bad_schema`、`unauthorized`、`event_conflict`、`event_expired`、`evaluation_immutable`、`bad_receipt`、`bad_backfill`、`bad_heartbeat`、`storage_not_enabled`、`processing_stopped`、`policy_conflict`、`cas_conflict`、`policy_recovery_required`、`policy_not_committed`、`policy_queue_full`、`audit_storage_unavailable`、`probe_proof_required`、`internal_error`。第二组是 v2 parse-failure code：`input_truncated`、`invalid_utf8`、`lone_surrogate`、`duplicate_member`、`depth_exceeded`、`extras_exceeded`、`pointer_too_long`、`event_id_invalid`。

PROTOCOL 示例里的单词 `conflict` 不是单独成员。v1 发出的是 `event_conflict` 与 `cas_conflict`。

Adapter parse failure 的 `errorCode` 从 JSON null 改为映射：`over_limit` 与 `canonical_over_limit` → `payload_too_large`；`json_syntax` → `bad_json`；`invalid_utf8` → `invalid_utf8`；`unpaired_surrogate` → `lone_surrogate`；`duplicate_member` → `duplicate_member`；`incoming_truncation` → `input_truncated`；`depth_exceeded` → `depth_exceeded`；`extras_exceeded` → `extras_exceeded`；`pointer_too_long` → `pointer_too_long`；`event_id_invalid` → `event_id_invalid`。`failureClass` 本身不是 ErrorCode。

`error.data` 按 code 闭合，不再是 D9_OPEN_NOT_A_MAP。有 data 的 code 只有两个：`policy_conflict` 为 `{ currentVersion: integer≥0, currentRulesHash: sha256: }`；`cas_conflict` 为 `{ currentVersion: integer≥0 }`（v1 在正文顶层返回 `version`）。其它所有 code 禁止 `data`。CI 检查已接入 `npm run lint:contract`（quality workflow，在 lint:layers 之后）：v2 错误信封只能经 `v2Error` 产生，code 类型来自 openapi ErrorCode 生成的联合类型；脚本检查字面量 code、每个成员的 description 与 x-remediation、error-envelope 的 code 枚举与 ErrorCode 成员及顺序一致，并跑 `contract:types:check`。v1 `{ok:false,error}` 字符串不在本检查范围。

### D10. reasonCode、risk、ASK

**已按 r3 落地（候选，不冻结）。** reasonCode 仍是开放集合，pattern 为 `^[a-z][a-z0-9_:]{0,127}$`。已出现的例子写在 decision schema 的 description，不是枚举。

v2 `risk` 在 canonical-decision 保持 `none|low|medium|high|critical`；实际 wire `canonical-evaluate-response-v2` 的枚举不含 `critical`（G8 r1 N3，待统一或写明有意收窄）。schema 仍拒绝 `info`。投影里 v1 `info` 映射为 `none`。`budget_low_risk` / `no_cache_low_risk` 路径要由等价 golden 确认，该项 **NOT_RUN**。

v1 `confirm` 在 `core/hook.ts` 被送到 deny 分支。v2 ASK 保留，在全部 13 个宿主上按该宿主的 deny 形式渲染，与 v1 confirm 相同。antigravity / cursor 的 `ask` 形状仍只是 rewrite 载体，不是 ASK。ASK 的 RenderDecision 字节 **NOT_RUN**。

矩阵（2026-09-28 协调者澄清 r3 歧义）：APPLIED⇔REWRITE；NOOP_NO_SPAN⇒LOG；REFUSED⇒BLOCK；LOG 取 NONE 或 NOOP_NO_SPAN；BLOCK 取 NONE（普通策略阻断、别名冲突）或 REFUSED（改写失败）；ALLOW、ASK 只取 NONE。ASK+REFUSED 与 ALLOW+REFUSED 无效。`NOOP_NO_SPAN` 时 action 为 `LOG` 这条原约束保留。

### D11. 证据 UNKNOWN、VERIFIED 与回执绑定

**已按 r3 落地（候选，不冻结）。** EVIDENCE_MODEL §2 已给出多数 state/source/trust 行。本候选用 if/then 编码这些行。

- UNKNOWN 只允许显式 JSON null：source、trust、selfReported、hostRealVerified、ref 都必须出现且为 null。缺省这些键的分支已删除。
- VERIFIED 保留精确的 `hostVersion` 字符串，加上 `adapterRevision`。版本范围与 action 粒度的规则已由 D11_D14 r1 选定（同 major.minor 且 patch 不低于实测值；逐 action）。运行时证明 **PENDING**，等 HOST_REAL 产物。
- 回执必须绑定 token 上的设备、eventId 和决策摘要。Schema 不能证明。运行时 **PASS**：`tests/contract/device-routes.test.mjs` 回执差分的两条负例（决策被改写 → 409 `evaluation_immutable`；跨设备 eventId → 404），见 D11_D14 r1。
- 工具 UNKNOWN 与证据 state UNKNOWN 不是同一件事。本候选不把前者写成后者。

### D12. 设备 token 与正文身份

**已按 r3 落地（候选，不冻结）。** 设备身份只来自 bearer token。v1 在设备路由上不读正文里的设备 id。v2：正文 `device.id` 如果出现，必须等于 token 的设备 id，否则 401 `unauthorized`，不另设错误码。Schema 接受 `device.id` 不能证明 token、主体或正文未被替换。验证器把这项标 **PENDING**，`runtimeObligation`，不记成通过。

旁证，不在本候选实现：`persist.ts` 用 `===` 比较 token 的 SHA256 hex，而不是 `safeEqualHex`。这是单独的加固任务。

### D13. userMessage 不回显秘密

**已按 r3 落地（候选，不冻结）。** `userMessage` 由每个 action 的固定模板渲染（`core/protocol/evaluate-response.ts` 的 `messages`，ALLOW/LOG/ASK/BLOCK/REWRITE 各一句），不按 reasonCode 区分，不插入字段值、span 或路径。本条只覆盖实际 wire；已排除在冻结外的旧候选 `v2-adapter.ts` 的 `userMessageFor` 会把 reasonCode 插进文案，不适用本条。测试义务：每份 rewrite / privacy fixture 的渲染输出字节都不得包含 fixture 里的秘密子串。Schema 只能要求非空字符串。验证器把这项标 **PENDING**，`runtimeObligation`，不记成通过。

### D14. 其它未写正文的路由

**已按 r1 裁决落地（合同部分，候选，不冻结）。** 裁决：`WP-21_D8_D9_D14_DECISIONS-r1.md`。（历史：合同包阶段不实现 `/api/v2` 路由；P2 已在 `core/serve.ts` 接线 policy/receipts/backfill/heartbeat/evaluate，见「阶段2四条设备路由」「阶段2 evaluate 实际 wire」。）

- **ETag**：强 ETag，字节格式 `"p<policyVersion>.<rulesHashHex>.e<engineRevision>"`（含两侧双引号）。rulesHashHex 为 64 位小写十六进制，不含 `sha256:`。`If-None-Match` 与当前 ETag 逐字节相等，或逗号列表中任一段逐字节相等（不修剪空白）→ 304，无正文，带 ETag。`W/` 弱标签与 `*` 不命中 → 200。
- **GET /api/v2/policy 正文**：闭合对象。成员与 v1 `GET /api/v1/policy` 逐字段相同，另加 `rulesHash`（`sha256:`，与策略历史同一 `policyRulesHash` 计算）。子对象沿用 v1 形状，本包不重新建模。
- **receipts / backfill / heartbeat 的 v2 成功正文**：与 v1 成功正文逐字段相同。失败统一用 v2 错误信封。这三条路由的请求正文已按 docs/design-review/WP-21_REQUEST_AUTH-r1.md 的协调者候选写入，运行时接线仍待完成。
- **hookBlind**（按 r2 修订，见 `WP-21_D8_D9_D14_DECISIONS-r2.md`）：`origin=HOOK` 恒为 false；`origin=PROBE` 取 v1 evaluate 正文 `body.hookBlind === true`（仅 JSON true 为 true，`core/serve.ts:225`、`engine.ts:710`）；`origin=BACKFILL` 恒为 true（v1 `core/serve.ts:1194`）。r1 所称「ingest.ts 语义」不是运行时来源（`parseHookPayload` 无运行时调用方）。不从字段缺失推断。

`adapterRevision`、`occurredAt`、`device.id` 在现有 raw 里没有。投影中的 `0`、`1970-01-01T00:00:00Z`、`UNOBSERVED_DEVICE` 是占位，不是观测值。运行时 `/api/v2/evaluate` 的 `device.id` 按 D12 由 token 决定，验证器仍 PENDING。

`host.id` 不做成 13 值封闭枚举。13 是当前 `HOOK_AGENTS`，不是 PROTOCOL 里的永久枚举。

完整决策轨迹（`nmzp explain`）没有单独 schema。PROTOCOL 说它没有网络端点。短 `explain` 禁止 span。

## 明确没有当成通过的门禁

PROTOCOL §8 其余三项保持未完成：13 宿主 v1→v2 决策等价（IC-01 例外）、13 宿主 RenderDecision 字节 golden、Kiro-Q2。候选映射的 schema 自测不是这些证明。

IC-01、**IC-02 NOT_SWITCHED**。IC-02 是「别名冲突改为按宿主精确字符串比较」。1.0 仍按 v1 `str()`。与 IC-01 一样，需 Gate A 后单独开关。裁决见 `WP-21_D8_D9_D14_DECISIONS-r1.md`。

### IC-10 SWITCHED（2026-10-08）：v2 严格入口

编号说明：IC-03…IC-09 已由 `NMZP_1_0_PRIVACY_REWRITE.md` §10 定义（policy-spec 也引用 KNOWN_IC-03/05），本项用 IC-10，不复用 IC-03。

D1、D3、D6 的严格边界与原始字节失败类：`core/protocol/v2-adapter.ts` 的 `V2_STRICT_INGRESS_DEFAULT` 仍为 `false`，调用级参数 `AdapterOptions.strictIngress`。adapter 默认关闭时这些失败类不产生，与 v1 等价，由 `tests/contract/v1-v2-equivalence.test.mjs` 断言。显式 `strictIngress: true` 时，下表输入 v1 照常评估、v2 失败关闭（DENY），是已知差异，同一测试逐类断言。IC-10 已于 2026-10-08 在路由层与客户端 transport 显式打开，默认值不再代表开关状态。

| 失败类 | 触发 | v1 当前行为 |
|---|---|---|
| `invalid_utf8` | 原始字节不是合法 UTF-8 | `Buffer.toString("utf8")` 替换成 U+FFFD 后评估 |
| `duplicate_member` | 任意深度、转义解码后的重复成员 | `JSON.parse` 取最后一次出现 |
| `unpaired_surrogate` | 值或成员名中的孤立代理 | 照常评估 |
| `depth_exceeded` | 容器深度 > 64 | IC-15 后 v1 也拒绝（hook `bad_hook_json`，v1 evaluate 400 `bad_schema`）。IC-10 后 `/api/v2/evaluate` 在解析前返回 400 `depth_exceeded`。adapter 默认关闭时 v2 记为 `json_syntax`，见 IC-15 |
| `extras_exceeded` | extraFields > 256 | 无此概念 |
| `pointer_too_long` | 指针 > 1024 UTF-8 字节 | 无此概念 |
| `event_id_invalid` | eventId 空、> 128 UTF-16 码元或含 C0/C1 | 照常评估；只有审计 outbox 拒收 > 128 |
| `canonical_over_limit` | 原始正文 ≤ 262144 字节，序列化 canonical 请求 > 262144 字节 | 无此概念 |

- 严格扫描器 `strictJsonScan` 在 `JSON.parse` 之前做词法级解码，按文档顺序报告第一个失败。只校验物化后的对象看不到重复成员。
- `invalid_utf8` 只能从原始字节判断，入口是 `toCanonicalToolEventFromBytes`。字符串入口拿到的已是解码后的文本。
- **路由形态（2026-10-08 协调者裁决，已生效）。** `/api/v2/evaluate` 收到的已经是 CanonicalToolEvent，不是宿主 stdin，服务端不调 `toCanonicalToolEventFromBytes`。服务端严格入口 = 原始字节严格解码 + 词法扫描 + 兼容 schema + 严格限额 + 严格 schema。宿主 stdin 的严格入口在客户端 adapter（`prepareHookTransport` 传 `{ strictIngress: true }`）。v1 入口永不严格。不得把 adapter 默认关闭时的等价说成严格边界未在路由生效。
- **设备路由（2026-10-08）。** `/api/v2/heartbeat`、`/api/v2/receipts`、`/api/v2/backfill` 在 v2 请求上用 `parseStrictV2Json` 代替 `JSON.parse`。空正文仍用 `"{}"` 兜底。JSON 语法错误保持各路由原错误码（heartbeat/receipts 为 `bad_json`，backfill 为 `bad_backfill`）；`invalid_utf8`、`lone_surrogate`、`duplicate_member`、`depth_exceeded` 返回各自的码，400。heartbeat 的 probe 证明仍在解析之前、仍用 `body.text`。闭合成员只在 v2、在 `bindBodyDevice` 删掉 `device` 之后检查：receipts 只允许 `eventId`、`evaluation`、`enforcement`，否则 `bad_receipt`；heartbeat 只允许该路由实际读取的成员，外加 `probeTick` 必发且路由不读的 `os`，否则 `bad_heartbeat`；backfill 的 `parseBackfill` 已闭合，不改。v1 四条路由不严格。
- **审查前提更正。** 审查说 v1 按 UTF-16 码元计 BODY_LIMIT，这不成立。生产入口都按原始 UTF-8 字节计：hook `hookMain` → `readStdin`（`core/hook.ts:77`），serve `readLimited`（`core/http-util.ts:24`）。只有进程内直接调用 `runToolHook` 时多一道 `opts.stdin.length > BODY_LIMIT`（`core/hook.ts:391`，UTF-16 码元），`runHook` 的 zcode 分支同理。经 `hookMain` 进入时 UTF-16 码元数 ≤ 原始字节数（含替换字符），这道检查不会先触发。所以 262144/262145 原始字节上限不属于本 IC 的差异，v2 字节入口与 v1 一致。
- 字符串入口按解码后文本的 UTF-8 字节计上限，合法 UTF-8 时等于原始字节数。接近上限的非法 UTF-8 每个坏字节解码成 3 字节 U+FFFD，字符串入口会比 v1 多拒，所以有原始字节时一律走字节入口。测试有此断言。
- IC-15 后 adapter 默认关闭时 v2 也限深度 64（路由层已打开，见上）：`parseCanonical` 在 JSON.parse 之后、任何遍历之前以 `json_syntax` 失败关闭，渲染字节与 v1 `bad_hook_json` 相同；开关打开时仍报 `depth_exceeded`。原「container depth 65」已知差异随之删除。遍历仍是迭代实现；`tests/contract/v1-v2-equivalence.test.mjs` 断言 65 层与 10 万层两种开关都失败关闭、不栈溢出。


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
- IC-01/02 同样不切换；IC-10 已在路由层与客户端 transport 切换（见该节）。G8 继续 OPEN，无独立冻结结论。


### Item9：精确 contents 多叶候选修订（冻结前 wire change）

- 唯一闭合结构为 `fields.contents:{leaves:[{value,provenance}]}`；无旧结构 union 或聚合第二真值。空白及重复值按来源精确保存；无叶才省略字段。其余 scalar 空白保存问题留作独立残余。
- 共用 core/hook-alias-keys.ts 精确叶枚举，顺序为顶层 CONTENT_KEYS、edits 行 CONTENT_KEYS、其它非操作根成员的递归叶。edits 未知键及对象型内容不扩大扫描，ingest 信封过滤不移入 canonical bag。
- trim/空值丢弃/去重/换行拼接仅发生在评价桥接；目标是 v1 决策和13宿主字节不变。所有 provenance 对应原始宿主字符串；Antigravity 首级 remap 必须取自有属性，原型同名键不受禁用。
- 此项明确改变未冻结 canonical wire shape、序列化大小及 extras 计账。IC-10 已在 v2 路由与客户端 transport 生效，adapter 默认仍为 false；IC-01/02/11/12 不切换。没有已部署 v2 兼容或冻结声明。
- D5 的 patch 叶定位、逐叶 updatedFields、contents 数组值哈希预像均未实现；当前 scalar rewrite schema 不能证明这些能力。D8 审计安全投影不泄漏叶值或指针，运行时持久化接线仍待阶段2。
- 完整裁决与证据：docs/design-review/WP-21_CONTENT_LEAVES-r1.md 及同目录 COORDINATOR_CHECKPOINT.md。G8 OPEN。


### 阶段2首包：请求、鉴权与上下文（候选，不冻结）

详见 docs/design-review/WP-21_REQUEST_AUTH-r1.md。receipts/backfill/heartbeat 请求结构按现有 parser 闭合；receipt/heartbeat 的 unknown-key ignore 是明确的 legacy V1_SHAPE 例外。UTF-16/cross-field/时间等义务仍由 parser 完成，schema 单独不是完整接受判定。

五条路由声明设备 bearer；token/device.id 绑定为运行时义务。forbidden/not_found 纳入 ErrorCode，保留403/404、rejected、非retryable、无data。canonical context 可选 permissionMode/uploadSize 仅延续现有解析器及指纹语义。服务端新建context禁止占位；客户端原有epoch/adapterRevision=0不被新增拒绝。D5、跨版本幂等与真实HTTP路由仍阻塞，G8 OPEN。IC-01/02/11/12 不切换；IC-10 已另节切换。


### 阶段2四条设备路由（未冻结）

policy/receipts/backfill/heartbeat 已共享 v1 业务分支接线，详见 docs/design-review/WP-21_DEVICE_ROUTES-r1.md。（当时 evaluate 尚未实现；现已实现，见「阶段2 evaluate 实际 wire」。）前述“本包不实现路由”为历史合同包状态，不代表现状。原始 bytes proof 保持 NMZP-PROBE-1/v1-heartbeat-path；v2 是同一逻辑资源的兼容别名，不引入新签名版本。

确认原错误盘点漏项：core/audit/store.ts confirmBackfillReceipt 对已经确定的最终 enforcement 返回409 conflict；现纳入枚举，rejected/非retryable/无data，与事件内容 event_conflict 不合并。v1返回不变。（当时 D5、evaluate 共享应用层及其跨版本/历史规则阻塞；现 `core/evaluation-application.ts` 已实现并由 `/api/v2/evaluate` 调用，见「阶段2 evaluate 实际 wire」。跨版本/历史规则的证明仍未完成。）G8 OPEN。IC-01/02/11/12 不切换；IC-10 已在路由层切换，见该节。


### 可选瞬态rewriteLayout与alias计账（候选）

见 docs/design-review/WP-21_REWRITE_LAYOUT-r1.md。可选layout只描述选中的原始tool参数bag结构，string只引用已有fields/leaves/extras；安全复原后调用真正remap/resolve/rewriteSource，无客户端v1_trim、raw stdin或持久化。显式sourcePresent保持undefined边界，mapping按实际parser格式而非host.id。默认adapter、runHook和HTTP均不主动启用。

未保存的scalar alias及信封cwd空白不再虚标mapped，回到既有extras计账；engine fields/contents/v1决策和宿主字节不变。候选wire体积与strict extras计数改变。IC-10 已在路由层与客户端 transport 显式打开，adapter 默认仍为 false。原stdin完整性、顶层信封aliasConflict的canonical HTTP绑定、真实D5及replay是明确剩余门，G8 OPEN。

### cwd parser格式一致性修正（候选）

详见docs/design-review/WP-21_CWD_PARITY-r1.md。实际parser与canonical fallback共用选择器，保留Generic与toolCall不同优先序及Antigravity空白数组项的旧返回。layout builder由raw选择有界envelopeCwd引用；materializer仅核对声明ref/投影，不从extras猜外部容器shape。旧v1不变；先前已记录的两项cwd projection失败被修正。完整信封aliasConflict传输边界仍是未实施设计，不代表evaluate/D5或原stdin证明已完成。

### 真实RenderedRewriteEvidence/version1候选（不同于旧D5 detector-union类型）

见docs/design-review/WP-21_RENDERED_EVIDENCE-r1.md。新rendered-composite edit使用变换前effective view叶UTF-16整段坐标、完整叶hash、原fragment独立绑定及viewLeafIndex/derivation；允许空replacement。真实observer记录实际scan/URL/shell/persona/short-circuit，保留旧v1结果。固定legacy结构投影与真实serialized hash共同验证；prototype/ownership另测，不由hash冒充。

该artifact有独立闭合schema及apply/rewrite-only witness helper；不静默替换旧CanonicalRewrite、不激活evaluate。只含metadata的witness不保存source/replacement/keys；真正历史policy/engine绑定、原子存储、immutable decision重放和HTTP/p95仍待证明。G8 OPEN，无IC切换。

### 阶段2 evaluate 实际 wire（候选，G8 OPEN）

OpenAPI 的 `/api/v2/evaluate` 现在选择 `CanonicalEvaluateRequestV2` 与 `CanonicalEvaluateResponseV2`。旧 `CanonicalToolEvent`、`CanonicalDecision`、`CanonicalRewrite` 的候选定义及既有 fixture 继续独立验证；它们不再被当作此路由的实际成功合同。此项不切换任何 IC，不代表协议冻结、性能门通过或部署。

- 兼容 ingress 为闭合 HOOK/PROBE 结构，要求 transient `rewriteLayout`；PROBE 使用 `probe-eval-v1`、真实直接 evaluate aliases、固定 top-level fallback refs 和可选 `context.agentPresent` 声明。声明 layout 自洽不证明未传输的原 stdin。device 绑定、alias/source 投影一致性及字节上限仍是运行时义务
- `CanonicalEvaluateRequestV2Strict` 现为 `/api/v2/evaluate` 的 requestBody。live ingress 在兼容 schema 与 device 绑定之后检查 eventId、extraFields 与指针限额，再调用该严格 schema。pointer UTF-8 字节与原始字节词法扫描仍是运行时检查，不是 JSON Schema 单独能够证明的边界。IC-10 已于 2026-10-08 SWITCHED
- 实际响应固定 `v:2`、`kind:canonical_evaluate_response`、`origin:SERVER`，并携带 `requestHash`、immutable enforcement/duplicate 与原 egress 观察。`requestHash` 使用 `canonical_event_v1_without_upload_size`，消费端须对保留请求核对
- REWRITE 使用独立 `rendered_composite_payload`，完整传输真实 composite edits、source/result binding 和 completion；省略 detector `observations`/`findings`，用 `trace.availability:omitted` 及真实 hash/count 表示。`privacy.engineSummary.coverage:unique_kinds_only` 不是完整 findings；`privacy.renderedSummary.availability:full_trace_omitted` 明示省略，非 rewrite 为 `not_retained`。重复 hash/count 一致性须由运行时核对，schema 不证明被省略的扫描实际执行过
- `scripts/generate-evaluate-validator.mjs` 在构建时生成 self-contained validator；生产模块不导入 AJV 或合同文件。`--check` 校验精确生成一致性；OpenAPI types 沿用既有 `contract:types` / `contract:types:check`。新 schema tests 同时运行 AJV 和生成验证器，保留旧 candidate fixtures、闭合对象 census 与未知字段拒绝检查


## G8 r2 修订（2026-10-02，候选，不冻结）

G8 r1 B1 指出 `hook-bytes-golden.json` 不全是 v0.2.6 字节。协调者用 v0.2.6 源码树（tag v0.2.6，e9ac5a3）对全部 104 条 golden stdin 和 179 条别名探针重新采集，结果固定在 `tests/compat/fixtures/hook-bytes-v026.json`，生成器 `scripts/gen-golden-v026.mjs --base <v0.2.6 树> [--check]`，测试 `tests/compat/hook-bytes-v026.test.mjs`。探针 = 每个宿主 allow stdin 注入一对别名或一组键：r1 的 74 条成对冲突，加 r2–r6 复核后补的 105 条（空/空白/null/非字符串宿主键占位、`edits[]` 行内 content/contents、Antigravity 内容别名、把 Antigravity 调用整体换成 `write_to_file` 或 `read_url_content` 的探针、AbsolutePath 承载各类规则串或与字面 path/target_file/filePath 并存的探针，以及 claude 的 2 条深层嵌套探针）。差异按 HEAD 字节分类：深层嵌套探针进 `ic15`；Antigravity TargetFile 无效的探针（857f3eb）无论 HEAD 字节如何都进 `ic14`；其余 HEAD 为 `bad_hook_json` 拒绝的进 `ic13`，剩下的进 `ic14`。fixture 只能证明所列探针的字节，不能证明某类差异不存在。`--check` 与测试均通过（2026-10-02，win32-arm64，Node 见 fixture `capturedFrom`）。

- r3 更新（IC-14/15 选项二实现后重采）：别名探针 181 条（claude 深层嵌套探针改为 deep 62/63/4000/6000 四条）；差异 `ic13` 55、`ic14` 9、`ic15` 3。`--check` 与目标测试通过。

- 出处更正：`hook-bytes-golden.json` 头部 `capturedFrom` 说全部取自"CJS bundle 前的 baseline-pack"，对 cd57459 后加入的 39 条不准确。不改写 golden 本身；v0.2.6 真实字节以本 fixture 为准。
- 范围说明：本 fixture 只覆盖 hook 决策字节。c663cb6 改了 `core/model-response-risk.ts` 的 `suspected_instruction_hijack` 启发式，属于模型网关响应观察（`core/model-gateway.ts:133`："not automatic blocking"），不改变任何放行/拒绝决策，不登记 IC；已随提示注入检测在 6e0c1b5 定稿。

### IC-13 已在 P2 生效的失败关闭收紧：别名冲突改判 bad_hook_json（B1）

- 104 条 golden 中只有 `antigravity-alias-conflict` 与 v0.2.6 不同：v0.2.6 为 `deny`/`env_piped_outbound`，HEAD 为 `deny`/`bad_hook_json`。两边都拒绝。
- 别名探针中，以下组合 v0.2.6 放行（exit 0、无输出），HEAD 以 `bad_hook_json` 拒绝：12 个非 Antigravity 宿主的顶层 content+contents 不同值（两种变体）、`edits[]` 行内 content+contents 不同值（两种变体，由 `toolInputHasAliasConflict` 的 edits 行检查引入）；Antigravity TargetFile≠AbsolutePath（两种变体），CodeContent≠content（run_command 与 write_to_file 各一条），字面 contents≠content，args 内 `edits[]` 行 content≠contents。file_path/path、file_path/target_file、filePath/file_path、cwd/working_directory 的直接冲突两边已一致拒绝；经 857f3eb 改映射后才出现的 file_path 冲突见 IC-14 收紧类三。
- 对照：单独在 Write content 中放秘密值、单独用 Antigravity view_file 读 id_rsa，两边都放行。因此 v0.2.6 的放行不是已证实的绕过，"secret" 变体名只表示注入值，不表示被漏检。IC-13 本身只把放行改成拒绝；HEAD 相对 v0.2.6 的放宽另登记为 IC-14、IC-15，不在本项内。
- 受影响的 55 个 id 在 fixture `ic13` 字段与测试中逐字固定：`antigravity-alias-conflict`；12 个宿主（grok、claude、codex、zcode、kimi、trae、qwen、qoder、lingma、codebuddy、gemini、cursor）各自的 `<host>-alias-content-contents-secret`、`<host>-alias-contents-content`、`<host>-alias-edits-content-contents`、`<host>-alias-edits-content-contents-secret`；`antigravity-alias-targetfile-absolutepath`、`antigravity-alias-targetfile-absolutepath-env`、`antigravity-alias-codecontent-content`、`antigravity-alias-contents-content`、`antigravity-alias-edits-content-contents`、`antigravity-alias-write-codecontent-content`。
- 处置：保留收紧，登记为已生效（不同于 IC-11/12 的 NOT_SWITCHED；IC-10 已另节切换）。用户已在 G8 r2 签署"保留"（2026-10-02）。
- 混合版本：同一别名冲突判定经 `core/eval-bridge.ts` 的 `resolveEvalBody` 也作用于服务端 `/api/v1/evaluate`。v0.2.6 hook 连 HEAD 服务端时，这类请求同样被拒。否决本项需同时恢复服务端判定。

### IC-14 选项二已实现（待 r8 复核）：Antigravity 空宿主键不再占住 file_path（857f3eb）

本节「机制」到「两边字节相同的对照」描述的是选项二实现前的 HEAD（8e6df90），保留作记录；现行行为见本节末「选项二实现」。

857f3eb（"Antigravity 空值或非字符串别名不再占住 file_path（P1-1）"）按安全修复提交，未登记 IC。`remapAntigravityArgs`（`core/hook-protocol.ts:107-134`）现在跳过 `str()` 不通过的宿主键（空串、纯空白、null 以及任何非字符串值），同组下一个通过的宿主键（如 `AbsolutePath`）补上该槽位。没抢到槽位的宿主键不删除，留在 args 里；它不是 OP 键，会被当作内容叶扫描。fixture 共有 33 条 Antigravity 探针，其中约 27 条直接针对无效或空宿主键，多数由 r2–r6 补入。

- 机制：TargetFile 不通过 `str()`（空/空白/null/非字符串）时，v0.2.6 让它占住 file_path，`AbsolutePath` 留在 args 里当内容叶，进入引擎的 `commandish`/`contents`（`src/lib/monitor/engine.ts:438` `joinFields(command, contents)`）。8e6df90 让 `AbsolutePath` 补上 file_path，不再作为内容扫描（选项二已改为两者兼有）。所以差异按类出现，fixture 里的探针只是例子：
  - 放宽类：v0.2.6 在 AbsolutePath 作为内容时命中的任何规则，在 TargetFile 无效时都不再命中。fixture 里 9 条，拒绝 → 放行：`antigravity-alias-targetfile-empty-absolutepath-pipe`（`env_piped_outbound`）、`-curl-sh`（`curl_pipe_shell`）、`antigravity-alias-targetfile-null-absolutepath-rm-rf`（`dangerous_delete`）、`antigravity-alias-targetfile-empty-absolutepath-drop-host` 与 `antigravity-alias-read-url-targetfile-empty-absolutepath-drop-host`（`anonymous_drop_host`）、`antigravity-alias-write-targetfile-empty-absolutepath-poison`（`poison_instruction_file`），以及 TargetFile 为 123/false/[] 的 `antigravity-alias-targetfile-{number,false,empty-array}-absolutepath-pipe`（`env_piped_outbound`）。`AbsolutePath` 本身不会被执行，这些拒绝多数是把路径串当命令的误报，但字节上是放宽，不由协调者代签。
  - 收紧类一：受保护路径不再被无效 TargetFile 遮住。fixture 里 4 条，放行 → 拒绝：`antigravity-alias-write-targetfile-{empty,null,number}-absolutepath-nmzp`（`monitor_self_tamper`）、`antigravity-alias-write-targetfile-empty-absolutepath-zcode-trust`（`zcode_trust_store_tamper`）。对照 `antigravity-alias-write-targetfile-nmzp`（直接写 .nmzp）两边都拒绝。这是 857f3eb 的本意。
  - 收紧类二：非字符串 TargetFile 被当内容扫描。fixture 里 2 条，放行 → `env_piped_outbound` 拒绝：`antigravity-alias-targetfile-{array,object}-pipe-absolutepath`。
  - 收紧类三：补上 file_path 的 `AbsolutePath` 与字面 `path`/`target_file`/`filePath` 比较，值不同即别名冲突（`core/hook-alias-keys.ts:17` `FILE_PATH_KEYS`、`:130`）。v0.2.6 由空 TargetFile 占槽，`str()` 后为缺失，不冲突。fixture 里 3 条，放行 → `bad_hook_json`：`antigravity-alias-targetfile-empty-absolutepath-path`、`antigravity-alias-targetfile-empty-absolutepath-target-file`（run_command）、`antigravity-alias-view-file-targetfile-empty-absolutepath-filepath-ssh`（view_file，`filePath` 指向 `.ssh/id_rsa`）。字节形状与 IC-13 相同，但起因是 857f3eb，所以登记在本项，不在 IC-13 的 55 个 id 内；用户否决 IC-13 不影响这一类，它随本项的选项走。对照：字面键换成 `file_path` 时两边字节相同（`antigravity-alias-targetfile-empty-absolutepath-file-path`）。
  - 选项二实现前 18 条在 fixture `ic14`；实现后见下方「选项二实现」。
- 两边字节相同的对照：TargetFile 空/空白/null + AbsolutePath 指向 `.ssh`（run_command，命中的是 log 规则）、TargetFile 空 + `.env`，CommandLine/Url/CodeContent 空 + 对应字面键。
- 处置：用户在 G8 r2 选选项二（2026-10-02）。原三个选项留作记录：
  - 选项一：整体保留 HEAD，登记为已生效。接受整个放宽类，保留三类收紧。
  - 选项二（协调者倾向，按"最大防护、对用户最便利"）：TargetFile 无效、`AbsolutePath` 补上 file_path 时，同时把该 `AbsolutePath` 当内容扫描。预期是 v0.2.6 与 HEAD 的并集：放宽类恢复为拒绝，三类收紧保留。若某条规则以 file_path 缺失为条件，并集不严格成立，需新探针逐条证明。需新代码、新探针和再复核；本选项改的是共享实现 `core/hook-protocol.ts` 的 `remapAntigravityArgs`，v2 adapter（`core/protocol/v2-adapter.ts:370`、`:714`）随之改变；v2 没有 v0.2.6 对应物，需另行补 v2 探针。代价是放宽类里那些把路径当命令的误报也一并恢复。
  - 选项三：整体回退 857f3eb，恢复 v0.2.6 字节，登记 NOT_SWITCHED。会同时撤销三类收紧（含 `.nmzp` 自保护），不推荐。本选项改的是共享实现 `core/hook-protocol.ts` 的 `remapAntigravityArgs`，v2 adapter（`core/protocol/v2-adapter.ts:370`、`:714`）随之改变；v2 没有 v0.2.6 对应物，需另行补 v2 探针。
- 选项二实现（2026-10-02，协调者直接实现，未经 grok）：`remapAntigravityArgs`（`core/hook-protocol.ts:107-134`）用 `firstPresent` 记下每组第一个出现的宿主键，只有它在补位后被删除；补位的非首个宿主键（如 TargetFile 无效时的 `AbsolutePath`）既写入 file_path，也留在 args 里作内容叶。v1 hook 与 v2 adapter 共用这一实现，v2 的 `fields.contents` 随之包含 `/toolCall/args/AbsolutePath` 叶（`tests/contract/content-leaves.test.mjs` 两条 Antigravity 测试已更新）。
  - fixture 重采后 `ic14` 只剩三类收紧共 9 条（收紧类一 4、类二 2、类三 3），全部保留。
  - 原放宽类 9 条在测试 `IC14_RESTORED` 中逐条断言 HEAD 字节与 v0.2.6 相同，即恢复为拒绝。
  - 并集只由这些探针证明；"以 file_path 缺失为条件的规则"未逐条枚举，没有发现反例，也不能据此断言不存在。
  - 代价：放宽类里把路径当命令的误报也一并恢复，与 v0.2.6 相同。

### IC-15 选项二已实现（待 r8 复核）：容器深度 > 64 失败关闭

下面「机制」到「服务端」各条描述的是选项二实现前的 HEAD（深层嵌套放行、遍历 O(深度²)），保留作记录；实现见本节末「选项二实现」。

- 机制：v0.2.6 的叶子遍历是递归（`core/hook-protocol.ts:140`，v0.2.6 树），深层嵌套栈溢出后走 bootstrap 失败路径，exit 2 拒绝（`nmzp_hook_bootstrap_failed`，stderr 同名）。HEAD 的 `walkScanLeaves` 改为迭代 DFS（现 `core/hook-alias-keys.ts:182`，未设默认深度上限），单个工具输入包时所有叶子照常扫描后放行。同时带 `tool_input` 与 `toolInput` 两个包时，`objectsConflict` 调用的 `stableJson`（`core/hook-alias-keys.ts:75-80`）仍是递归，深层嵌套两棵树都 bootstrap 拒绝，字节相同，不是差异。
- 探针：claude Bash `command:"git status"`，额外键下嵌套无害空数组。`claude-alias-deep-4000` 两边都放行（对照）；`claude-alias-deep-6000` v0.2.6 拒绝 → HEAD 放行，固定在 fixture `ic15` 与测试 `IC15_EXPECTED`。v0.2.6 的溢出阈值随栈大小和平台变化，fixture 只证明本机（win32-arm64）这两点。
- 影响：HEAD 仍扫描深层叶子，深处藏的秘密或命令串照样命中规则；放宽的是"深层嵌套本身即拒绝"。v0.2.6 的拒绝是崩溃的副作用，不是设计。
- 耗时与宿主超时（r5 复核发现）：HEAD 迭代遍历每压一层复制一次 token 路径（`core/hook-alias-keys.ts:177`、`:182`），耗时约 O(深度²)；每个请求遍历多次（`core/hook.ts:392` parseHookEvent、`:405` toolInputToEvalFields 在 `:589` 预算检查之前，评估阶段还有一次）。本机实测 claude Bash：1 万层 0.42 s、2 万层 4.3 s、3 万层（60116 字节）9.4 s，都放行；复核者另测 4 万层以上走 `core/hook.ts:589-592` 的 `budget` 拒绝，grok、antigravity 3 万层约 9 s 放行。grok、codex、antigravity 的宿主超时是 8 s（`core/install.ts:222`、`core/codex-hooks.ts:19`、`core/antigravity-hooks.ts:44`），claude 用宿主默认值。所以远低于 262144 字节正文上限的负载就能让 NMZP 在宿主超时之后才出结论，结果由宿主超时语义决定，`budget` 拒绝管不到。宿主超时后放行还是拒绝，HOST_REAL 未验证。数字随机器速度变化，不进 fixture。
- 上述 hook 计时都走未配对路径（无 serve）。配对路径下 `core/hook.ts:525` `ctMs = Math.min(HOOK_CT_MS, remaining())` 把服务端调用限在约 1.5 s 内，失败后回退本地评估，预算余量更少，`budget` 拒绝的深度阈值会更低，3 万层可能已走 `budget` 拒绝。这是读码推断（r7），未实测。
- IC-10 节「10 万层嵌套不栈溢出，测试有此断言」只覆盖 v2 adapter（`tests/contract/v1-v2-equivalence.test.mjs`），不覆盖 hook 路径耗时。
- 服务端（r6 复核发现）：同一遍历也在服务端执行。`POST /api/v1/evaluate`（`core/serve.ts:969`）在 `:1019` 调 `evaluateRequestHash`（`:214-215`）→ `core/eval-bridge.ts:181` `requestFingerprint` → `resolveEvalBody` → `toolInputToEvalFields` → `walkScanLeaves`，之后递归 `stableJson` 抛 RangeError。整段在 `store.withMutex`（`:1020`）之前同步执行，占住整个事件循环。本机进程内计时 `requestFingerprint`：5000 层 0.02 s、3 万层 4.7 s，均以 RangeError 结束；复核者另测 6 万层 16.8 s、12 万层（240 KB，低于 262144 上限）66.6 s；v0.2.6 同样输入立即 RangeError。持有任一设备 bearer 的客户端（含 v0.2.6 hook）即可让服务端停摆一分钟以上。RangeError 之后外层 catch（`:1222`）的 HTTP 响应未实测。`POST /api/v2/evaluate` 的 `prepareCanonicalEvaluation` 也调用 `collectContentLeaves`/`toolInputToEvalFields`（`core/protocol/evaluate-ingress.ts:65-66`），耗时未单独计时。
- 处置：用户在 G8 r2 选选项二、上限 64（2026-10-02）。原两个选项留作记录：
  - 选项一：保留 HEAD，登记为已生效，接受上述宿主超时暴露与服务端事件循环阻塞。
  - 选项二（协调者倾向，按"最大防护、对用户最便利"）：v1 hook 加确定的深度上限，超过即失败关闭拒绝。检查须在第一次遍历之前做：hook 在 parse 阶段，服务端在 `/api/v1/evaluate` 与 `/api/v2/evaluate` 的 JSON.parse 之后、指纹与 prepare 之前（返回 400 `bad_schema` 或等价失败关闭），这样同时消除宿主超时暴露与服务端阻塞。上限建议与 IC-10 的 64 对齐；真实宿主 tool_input 远低于此。也可取更宽的值（如 1024），只要低于 v0.2.6 的溢出阈值。需新代码、新探针和再复核。
- 选项二实现（2026-10-02，协调者直接实现，未经 grok）：`MAX_JSON_CONTAINER_DEPTH = 64` 与迭代检查 `jsonDepthExceeds`（`core/hook-alias-keys.ts:60-63`），计法同 IC-10 严格扫描器（根容器为第 1 层）。检查点四处，都在 JSON.parse 之后、第一次叶子遍历之前：
  - hook：`parseHookEvent`（`core/hook-protocol.ts:185`）返回 null，即 `bad_hook_json` 拒绝。
  - v2 adapter 开关关闭：`parseCanonical`（`core/protocol/v2-adapter.ts:682`）报 `json_syntax`，渲染字节同 v1；开关打开仍是 `depth_exceeded`。
  - 服务端：`/api/v2/evaluate`（`core/serve.ts:952`，在 `prepareCanonicalEvaluation` 之前）与 `/api/v1/evaluate`（`:992`，在 `:1023` `evaluateRequestHash` 之前）都返回 400 `bad_schema`。IC-10 后（2026-10-08）`/api/v2/evaluate` 超深在 JSON.parse 之前由严格扫描返回 400 `depth_exceeded`；`/api/v1/evaluate` 仍是 400 `bad_schema`。`jsonDepthExceeds` 仍留在 v2 解析成功之后。
  - v2 rewriteLayout 物化（`core/protocol/rewrite-layout.ts:162`，实现时新发现的缺口）：v2 wire 本身只有约 6 层，深度编码在 layout 的 nodes/指针里，路由层的原始 JSON 深度检查看不到。物化时按「信封根 + sourceRoot 段数 + 节点路径长度」计深度，超过 64 即 `invalid_rewrite_layout`，路由返回 400 `bad_schema`。修复前探针：声明 3000 层的 layout 被接受并物化出 3000 层视图，2 万层 3.2 s 后才拒绝；修复后 63 层即拒绝，2 万层 96 ms 拒绝（`nmzp-wp21b-evidence/g8/v2-layout-depth-probe.mjs`，本机）。测试见 `tests/contract/rewrite-layout.test.mjs` 末条。
  - fixture：claude 深层探针 deep(62) 两边都放行（对照）；deep(63)、deep(4000) 放行 → `bad_hook_json`，deep(6000) bootstrap 拒绝 → `bad_hook_json`。`tests/contract/evaluate-routes.test.mjs` 断言两条路由 65 层与 6001 层返回 400、v1 64 层返回 200。
  - 因上限远低于 O(深度²) 生效的规模，上面记录的宿主超时暴露与服务端事件循环阻塞不再可达；实现后没有重新计时 hook 路径。
  - 不覆盖：`ingestObservation`（`src/lib/monitor/trust.ts:47`）没有加检查。它不做决策，当前没有运行时调用方（只在 `core/paths.ts:109` 导出、测试调用）；接入运行时前须补同一检查。
  - 已随 IC-10 关闭（r8 发现的缺口，2026-10-08）：`prepareHookTransport` 现调用 `toCanonicalToolEventFromBytes(..., { strictIngress: true })`，超深在首次遍历前以 `depth_exceeded` 拒绝；`prepareProbeTransport` 用 `parseStrictV2Json` 代替 `JSON.parse`，超深同样在首次遍历前以 `depth_exceeded` 拒绝。
  - 错误码次序（r8 发现）：`/api/v2/evaluate` 的 bearer 认证 `requireDevice` 仍在最前；正文 deviceId 与 token 不符时，超深正文现返回 400 `bad_schema` 而非 401。两者都失败关闭，不放宽判定。
  - 测试期望随之更新：`v1-v2-equivalence` 删除 depth 65 已知差异、`protocol-failure-mutations` 选中测试数 41 → 40；`single-projection-mutations` 删除「reintroduce clone depth ceiling」变异体（64 层远低于 structuredClone 的上限，该变异体已等价）；`single-projection`、`rewrite-layout` 的深层用例收到 62 层并补 63 层拒绝断言。

### 候选（未实现）：Antigravity 空宿主键压过字面键

两棵树一致的残余：Antigravity `CommandLine:""` + 字面 `command` 为管道外传串、`Url:""` + `url`、`CodeContent:""` + `contents` 含秘密值，v0.2.6 与 HEAD 都放行（探针 `antigravity-alias-commandline-empty-command-pipe` 等）。对照非 Antigravity 宿主 `command:""` + `cmd` 管道串，两边都按 `env_piped_outbound` 拒绝。真实 Antigravity 是否会发出空 `CommandLine` 同时带字面 `command`，HOST_REAL 未验证。不是回归，不登记 IC；列为 1.0 后候选收紧，未经决定不实现。

### B2 冻结范围：旧 CanonicalDecision / CanonicalRewrite 不在 wire 上

- `core/protocol/v2-adapter.ts` 的 `toCanonicalDecision`、`renderCanonicalDecision` 只有测试调用方，REWRITE 字段是 D5 占位。它们与 `canonical-decision.schema.json`、`canonical-rewrite.schema.json` 排除在冻结范围之外，不作为任何路由的响应合同。
- 实际 wire 为 `CanonicalEvaluateResponseV2` + `CompactRenderedRewrite`（见「阶段2 evaluate 实际 wire」）。
- 守护测试 `tests/contract/legacy-canonical-decision-scope.test.mjs`：非测试模块不得引用上述函数和 schema；OpenAPI `/api/v2/evaluate` 200 引用 `CanonicalEvaluateResponseV2`，任何 path operation 经 `$ref` 都到不了 `CanonicalDecision`/`CanonicalRewrite`。
- OpenAPI `components.schemas.CanonicalDecision`、`CanonicalRewrite`（`openapi.yaml:254-255`、`:262-263`）只为旧候选 fixture 的独立校验保留，同样排除在冻结范围之外。冻结时只冻结 path operation 可达的 schema。
- 旧候选里的 `validation.residueScan:"PASS"`（`canonical-rewrite.schema.json:22`；`v2-adapter.ts:1003`、`:1025` 写入）是占位常量，不是扫描证据，不得引用为"残留扫描已通过"。值本身未改，因为旧候选已排除在冻结范围外。
- 守护测试的已知缺口（不阻塞）：整个 `v2-adapter.ts` 豁免；只做字符串匹配，动态 import 或重导出可绕过。
