# WP-21 请求与鉴权候选：协调者技术裁决 r1

2026-09-30；基线 173ecd3ae1e39a062aa0a57968bdb81f55684d9b。
本项为协调者批准的窄范围技术选择，不是协议冻结。G8 OPEN；IC-01/02/10/11/12 NOT_SWITCHED。

## 范围与真实完成状态

本包闭合原 PENDING 的三个请求结构、五路由的 bearer 声明、已有 403/404 的错误枚举，并提供共享 receipt 解析与未接线的上下文辅助函数。唯一生产路径变化是 v1 receipt 把原判定提取为共享函数；不新增 v2 HTTP 路由。policy/ETag 沿用现有候选合同与纯函数，本包未接线。

不能把 request schema、辅助函数或纯函数 AJV 检查当作真实 v2 HTTP 输出验证。完整 evaluate 路由、实际设备认证接线、跨版本幂等、审计安全投影接线、AJV HTTP、p95≤105%、D5 与 G8 均未完成。

## 请求边界

- evaluate 唯一输入仍是 CanonicalToolEvent，不接受 v1 raw-body union。
- receipts：eventId 为非空 string，不增添长度上限或决策摘要。enforcement 为现有8值。evaluation 保留任意 JSON 值的旧 truthy/strict-equality 行为，不发明枚举；falsy 不触发不可变错误。unknown keys 忽略，不持久化。
- v1 receipt 的非对象、truthy 非字符串 eventId 与 null 异常行为原样保留；v2 候选 parser 对非对象/非字符串 eventId 返回 bad_receipt。该不同明确属于新请求结构，不偷偷修 v1。parseLegacyReceiptBody 的类型 cast 仅延续原 handler 的历史运行时行为，不能被看作实际输入已获 string 证明。
- backfill：直接复用 parseBackfill 的 event/receipt 两个 metadata-only 分支。外层/内层 eventId 必须相同，relatedEventId 不能是自身，未知字段拒绝。ts=0 仍允许；policyVersion≥1。禁止新增 input、command、URL 或原文；不得把 metadata-only 回填包装成重新评价。
- heartbeat：parseHeartbeatBody 及后续 evidence parsers 不变。unknown 顶层/capability 属性忽略，不持久化；只白名单字段进入后续处理。policyVersion 接受有限 number（包括负数、小数），写入阶段才判断 safe integer 及版本范围。discovery/network/snapshotGuard/agentProcs 不在此包重塑；调用现有 parser/merge，不能原样持久化。
- heartbeat/backfill 的 JS UTF-16 长度、安全整数、cross-field 与时间窗口义务保持由现有 parser 执行。JSON Schema 结构校验不是全部接受判定；未用 code-point maxLength 冒充 UTF-16。测试明确覆盖 schema通过、parser拒绝的边界，不把这种结果记为完整合同验证。
- legacy request 的开放对象是明确记录的 D8 例外（V1_SHAPE），canonical 对象仍闭合。所有 HTTP BODY_LIMIT 保持262144 UTF-8字节；IC-10不因此启用。

## 鉴权、错误与上下文

所有五条候选路由使用设备 bearer token（不是 JWT、admin cookie 或新 credential）。实际接线必须沿用 findDeviceByToken 的 revoked 排除，认证先于正文/业务，evaluate 的正文 device.id 不等于 token 设备则401 unauthorized。已绑定 probe 的 heartbeat 继续先对原始正文校验现有 proof；不得重序列化后验签。

增加 forbidden/not_found 为现有语义闭合：403/404，retryable=false、outcome=rejected、禁止data。v2AccessError 使用固定消息，不能拼入设备、eventId、原文或异常文本。其他错误仍使用 v2Error；外层错误接线仍待后续工作。

| 路径/错误 | 保持的状态 |
| --- | --- |
| 所有路由 unauthorized；heartbeat probe_proof_required | 401 |
| receipts/backfill receipt forbidden / not_found | 403 / 404 |
| receipts evaluation_immutable；backfill conflict/expired/immutable | 409 |
| backfill storage_not_enabled / processing_stopped | 404 / 503 |
| oversize / malformed JSON | 413 / 400 |
| backfill malformed JSON | 400 bad_backfill（保留该路由合并解析行为） |

serverAdapterContext 仅接受认证结果的设备号；服务端新建 context 使用真实时钟、非零 SERVER_ADAPTER_REVISION=1，禁止 UNOBSERVED_DEVICE/1970 默认值。该 helper 不代表已认证 HTTP。CanonicalToolEvent 的 occurredAt/host.adapterRevision 是设备声明，已有 schema 允许 epoch/0，不能一概拒绝；不能覆盖后再声称是已观测事实。服务端接收时刻应另记 receivedAt；原 backfill ts 不改。

origin 由调用路径确定：HOOK false；PROBE 仅旧 body.hookBlind===true；BACKFILL true。snapshot 的 actor 特例仍在原引擎，不混入 hookBlind。proc/parentProc 按旧 str() 投影；canonical leaf/provenance 不由该函数重新规范化。

canonical context 新增可选 permissionMode 与 uploadSize；仅传递现有 permissionMode/parseUploadSize 的规范输出，无效旧值省略。checkedAt>now+30000 拒绝、实际评价时的<30000年龄判断不改。上传证据不进入旧 requestFingerprint，permissionMode 仍按其原语义计入。不得将观察性 egress 信息变成新的授权/策略判定。

## 下一包的实际阻塞

- D5：现有 toCanonicalDecision 的 patches:[]、空hash、rendererRevision:0、privacy.findings:[] 不能作为真实证明，禁止暴露为 v2 HTTP rewrite 成功。必须先明确多叶定位、逐叶更新、真实hash/patch与扫描证据。
- 跨版本幂等：旧指纹包括 tool_input 的非字符串结构与部分原信封字段，canonical leaves 不能无损还原。不能从 leaves 虚构原 v1 body，也不能为幂等保存敏感原文。新旧表示之间的可靠身份/指纹关联需后续独立裁决。
- 共享应用层需在不改规则的前提下保留 capturePolicy、恢复 fence、锁内撤销检查、历史rewrite回放/tombstone，以及现有审计脱敏。不得另写一个只调用 engine 的 v2 路由，不能通过500或强制BLOCK伪装REWRITE等价。

后续才执行真实 HTTP AJV、v1/v2 decision/actor/idempotency/audit差分和配对p95证据；本包不承诺已达到这些门禁。
