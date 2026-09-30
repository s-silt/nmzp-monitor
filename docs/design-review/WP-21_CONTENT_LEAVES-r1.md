# WP-21 exact contents leaves：协调者技术裁决 r1

2026-09-30；实施基线 bda7afcd2135c8ee82daedcc1555fe0cc79074f3。
状态：未冻结候选的协调者技术选择，不是 Claude 冻结批准。G8 OPEN；IC-01/02/10/11/12 均不切换。本文是当前代码候选的修订真值，补充历史设计库中的 D8，不改写历史原件。

## 1. 唯一闭合结构及 wire 影响

CanonicalToolEvent.fields.contents 改为：

```ts
{ leaves: Array<{ value: string; provenance: string }> }
```

contents 可省略；存在时 leaves 至少一项。没有字符串叶时省略；有空字符串、纯空白字符串、精确重复或 trim 后相等的值，都按独立来源原样保留。对象闭合，没有聚合 value/provenance，也没有旧/新结构 union。其余六个 scalar 字段形状不变，scalar 空白值是否保存是独立残余，本项不扩张。

这是冻结前 wire shape 修订，不是上一版候选的 wire-compatible 扩展；不得描述为已部署 v2 消费者兼容。当前未实现生产 /api/v2 路由。既有 v1 政策输入、决策与宿主输出字节必须不变。

## 2. 枚举真值与桥接

core/hook-alias-keys.ts 提供无 I/O 的精确叶枚举，共用 CONTENT_KEYS 与既有操作字段集合。严格顺序：
1. 顶层 CONTENT_KEYS 顺序，只收字符串。
2. edits 数组行顺序，每行 CONTENT_KEYS 顺序，只收字符串。
3. 其余顶层非操作字段按 Object.entries 顺序，嵌套对象深度优先、数组索引升序。

顶层 edits 不再进入第3步；其行内未知键、对象型内容值和非对象行仍排除，不能借迁移扩大扫描。顶层 CONTENT_KEYS 的对象/数组值进入第3步。仅根级操作字段排除，嵌套同名字段继续扫描。canonical tool bag 的 session_id/eventId/hookBlind/workdir 等字符串仍是内容叶，ingest 对信封和额外 bag 的元数据过滤不移入这里。枚举使用迭代 DFS，保留既有循环/共享对象保护，不新增默认深度限制。

只有评价桥接 contentLeavesToV1 执行 trim、空值丢弃、按 trim 后值去重及换行连接；v1 toolInputToEvalFields 与 v2 canonicalToEvalInput 共用这一投影。不得在存储精确叶时提前做这些处理。

## 3. 来源、映射与边界

- provenance 是原始解析宿主对象上的 RFC6901 字符串，按原始 token 编码一次。空键、Unicode、~、/ 和规范数组索引都必须可解析到与 value 严格相等的字符串。
- bag 前缀支持 /tool_input、/toolInput、/input 和 Antigravity /toolCall/args。
- Antigravity 只对首级 canonical 参数键按 hostArgMap 的**自有属性**还原。constructor、toString、__proto__ 是合法普通原始键，不能读取 Object.prototype，也不能禁止它们。嵌套同名键不 remap。
- 被 remap 遮住的原始 canonical 键仍由 extras 计账；未认领的 host 键仍按原行为扫描。每个内容叶的原始指针加入 mapped，extraFields 不重复列出它，包括空白或重复值的独立叶。
- contents 内不得重复同一来源指针；但 scalar query 与某个内容叶可以合法共享指针。schema 只能校验形状；源值解析、指针唯一和 extras 不重叠是路由运行时义务。本包的候选交叉验证器和适配器测试证明示例，不冒充生产路由已接线。
- 所有内容叶指针参与 strict 1024 UTF-8 字节上限；只对真正 extraFields 计256项，不把内容叶数误当 extras 数。raw BODY_LIMIT 与既有常量不改。
- 精确叶使 canonical 序列化大小、mapped/extras 数量不同于旧候选。IC-10 canonical 大小/extra/pointer 严格限制继续默认关闭；打开后的边界结果属于该未切换入口的候选修订，不剪枝、不新加默认失败条件。

## 4. D8 审计隐私

d8TrimObservations 对 contents 逐叶产生内存诊断，可含 leafIndex、exact、trimmed。d8TrimAuditWarnings 的持久化安全投影仍只含固定的路径警告元数据；内容值、任意路径/键名、leafIndex、哈希和长度都不进入它。无 stdout/stderr 或审计落盘 I/O；阶段2路由接线仍待实现。

## 5. D5 明确未实现

精确叶结构只解决真实来源，不能证明多叶 rewrite 已实现：
- patch.field=contents 加 span 不能选择哪一叶。
- updatedFields.contents:string 仍是既有占位合同，不能表达多个叶更新。
- trim、去重及添加换行后的聚合文本偏移，不能直接应用于精确原叶；重复内容可能对应多个宿主位置。
- 后续需独立裁决叶定位（例如索引及其来源绑定）、各叶 UTF-16 span、逐叶 updatedFields，以及原来的 string-valued JCS 预像如何编码有序叶值数组。

当前未实现这些定位/哈希/patch 改写；不修改 structuredRewrite 或 v1 updatedInput。现有 patches:[]、dummyHash、rendererRevision:0、privacy.findings:[] 不构成 D5 证据。canonical-rewrite.schema.json 的说明同步明确该缺口，不因候选 schema 可通过就宣称冻结。

## 6. 验证与独立复核

活动候选验证器是 tests/contract/protocol-checks.mjs（JavaScript，配合 Ajv）。交接包中归档的 Python validator 未迁移本修订的 leaves/content_leaf_account，不可作为本修订验证证据；本项不修改历史归档。

见同目录 COORDINATOR_CHECKPOINT.md 的实际证据状态。核心测试为 content-leaves.test.mjs、content-leaves-mutations.test.mjs；覆盖顺序/精确值、原始来源、Antigravity 普通及原型同名键、Unicode 字节边界、真实13宿主输出以及真正导致断言失败的隔离变异。候选接受须另有独立复核，本文不代替它。
