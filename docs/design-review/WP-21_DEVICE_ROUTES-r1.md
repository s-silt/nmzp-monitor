# WP-21 四条设备路由：协调者技术裁决 r1

2026-09-30；基线 e52f5e2c451c53cbafe8883625d475ab5337ad90。
首包19文件已独立接受；父协调者静态/build/guard通过，完整门1953项、1942通过、11明确skip、0失败。本包另为窄范围候选，不是冻结。G8 OPEN，IC-01/02/10/11/12 NOT_SWITCHED。

## 实施边界

新增 GET /api/v2/policy 与 POST /api/v2/receipts、backfill、heartbeat；每条都进入对应 v1 同一业务分支，不复制handler，不自调用HTTP。只有入口pathname、已裁决receipt输入边界、v2响应编码及policy ETag不同。旧v1成功/错误正文、判定顺序、锁/恢复与存储调用保留。

- 五路由契约不等于五路由实现：evaluate仍404，未实现任何canonical评价或dummy rewrite。
- deviceReply只投影错误传输；requireDevice仍使用现有bearer解析/findDeviceByToken/revoked判断，v2认证在读正文前完成。成功路径不借此修改数据。
- 所有v2错误经固定消息/字面量v2Error编码，requestId服务端新建；异常字符串仅用于既有分类，不回显。未知写结果保持unknown，无自动重放。
- policy使用同一次getPolicy所得正文，加policyRulesHash同源hash；强ETag命中304且无正文。逗号段不trim，weak/*不匹配；v1不新增ETag或304。
- receipts共享getEvent、truthy immutable判定、updateReceipt和成功投影。v1 null仍500；v2已接受结构下null为400。不新增digest或证据可信度。
- backfill共享原sqlite门、parseBackfill、两分支、duplicate/conflict/tombstone、停止/吊销与锁。仍是metadata-only，ts=0允许、hookBlind恒true，未重新评价。
- heartbeat保留raw proof→JSON/parser→version/pollOnly→touchDevice(expectedProbeKey)→撤销检查→network→再次撤销检查顺序；未知字段不持久化，辅助证据继续旧parser。

## 心跳证明兼容别名

core/probe-auth.ts 的 NMZP-PROBE-1 proofMessage 将 POST /api/v1/heartbeat 固定写入签名前像。本包明确让/api/v2/heartbeat成为同一逻辑资源的兼容别名，继续验证旧前像，保持原始正文bytes、device、key、单次nonce与失效语义。未修改probe-auth.ts、未发新凭据/签名版本，现有挑战仍由v1 challenge路径取得。

这里的原文沿用v1 readLimited→body.text→proofMessage的UTF-8文本口径；没有引入IC-10非法UTF-8严格解析，也不声称新增了编码证明。不能为v2请求改签名前像path，也不能先JSON规范化再验证。若将来需要按新URL签名，必须另行设计版本与迁移，不把本包伪装成新证明协议。

## 已授权的错误盘点补正

原枚举漏掉core/audit/store.ts confirmBackfillReceipt已经返回的409 conflict：最终enforcement已确定时，改成另一种最终值会拒绝。新增该候选枚举、schema、generated type、构造器映射，固定消息，retryable=false/outcome=rejected/无data。v1仍返回原字符串，不泛化成catch-all conflict，也不混作event_conflict（事件请求内容不一致）。

## 不在本包裁决/实施

- evaluate共享应用层、旧指纹不可逆信息缺口、跨版本重试、历史回放迁移及真实D5。
- 不新增原文存储、客户端legacyHash信任、规则、重试、保留策略、凭据或主机设置。
- 不使用BLOCK/500/dummy REWRITE冒充v1等价；未声称evaluate p95已验证。
- HTTP证据仅覆盖四路由；不是冻结、全WP-21完成、真实宿主执行或部署证明。

## 验证范围

tests/contract/device-routes.test.mjs 使用隔离临时数据、CA/pin校验的真实loopback HTTPS。所有v2实际响应过AJV；断言v1/v2业务和审计投影一致、认证先于不完整body、已吊销与等待期间吊销、policy 200/304、receipt隔离/immutable、backfill两种conflict/metadata/tombstone/停止、heartbeat原bytes/device/nonce与pollOnly/stopAck、外层unknown故障无重放和隐私回显。

tests/contract/device-routes-mutations.test.mjs 在私有隔离副本修改真实源码：认证绕过、ETag trim、proof正文规范化、跳过immutable。每项要求目标断言失败、恢复原始bytes/hash后目标1/1通过；不以测试拥有的伪输出代替真正路径。子进程仅移除继承的NODE_TEST_CONTEXT，避免Node跳过递归测试；父环境不动，临时副本清理。

最终实际计数与证据见同目录COORDINATOR_CHECKPOINT；独立复核及父协调者后续聚合门另行记录。
