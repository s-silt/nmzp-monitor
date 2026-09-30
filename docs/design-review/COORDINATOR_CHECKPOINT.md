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
