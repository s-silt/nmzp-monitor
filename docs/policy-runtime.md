# 核心策略、审计和可选 SQLite 存储

[中文首页](../README.md) · [English](policy-runtime.en.md) · [策略补丁](policy-customization.md)

## 选择存储模式

| 模式 | 保留与可用接口 | 启用前提 |
| --- | --- | --- |
| `window`（默认） | `events.jsonl` 与最多 2,000 条近期窗口；保留旧 `/api/v1/state`、`/api/v1/export` 契约；无完整策略历史 | 不需要 SQLite；策略提案校验与发布仍可用 |
| `sqlite`（可选） | 近期窗口不变；增加持久审计查询、保留清理、压缩导出、策略历史与恢复 | CT 管理员显式设置 `NMZP_STORAGE_MODE=sqlite`；现有数据先迁移，全新空目录可初始化 |

SQLite 使用 Node 24 内置模块，设备端和 CT 均无需另装数据库服务。**已有数据目录不能只改环境变量直接切换存储模式，必须先预检与迁移。** window 模式访问审计历史/存储/历史导出及策略历史/恢复接口时返回 `404 storage_not_enabled`，表示未启用，不是历史有 0 条。旧近期导出和提案接口不受此限制。

## 策略写入和恢复

HTTP、离线 CLI、停止/恢复都经 `NmzpStore → NmzpPolicyService → PolicyPublisher`。可写核心在初始化前独占取得 `.policy-writer.lock`，已有旧服务指针也阻止新写入者；锁不能按年龄或 PID 自动删除。旧程序若不遵守锁协议，必须在升级前退出，不能与新核心并行写入。

SQLite 模式把 `policy_revisions` 和 `policy_current` 放在同一数据库事务中，事务提交是唯一的策略提交点；`policy.json` 是兼容投影。投影先写临时文件并同步，数据库提交后替换正式文件。数据库提交后投影失败会阻断读写，普通重启不会从临时文件猜测版本。离线 `nmzp storage recover-policy --data-dir <绝对路径>` 在排除其他写入者后备份原投影，再按已提交的数据库当前版本恢复。

`core/audit/events.ts` 独立管理旧窗口或 SQLite 的近期投影，`NmzpStore` 只协调权限、设备和写入顺序。运行中的审计读写经 `core/audit/runtime.ts` 的单工作线程执行，最多接受 32 个待完成调用；单调用超时或工作线程退出会显式报错，不会回退为假成功。关闭核心时先等待已接收的调用，再终止工作线程。离线迁移仍直接调用 `AuditStore`，不启动 HTTP 或后台线程。策略提交仍由独占写入者管理；审计工作线程不发布策略版本。新增审计查询与策略历史 HTTP 路由分别在 `core/audit/http.ts`、`core/policy/http-history.ts`；旧接口仍在 `serve.ts`。

历史行保存策略内容、递增策略版本、格式版本、发布时间、内容 SHA-256、可信规则目录 SHA-256 和引擎版本。历史行不可原地更新；恢复旧内容会按当前可信规则重新校验并发布新版本。策略发布与相同版本竞争仍使用 CAS。改写重试要求原事件的请求摘要、策略哈希、规则目录和引擎版本都有可用的历史依据；缺失时明确拒绝，不调用实际工具，不用新规则伪造旧决定。

最多保存 10,000 个策略修订。达到上限时，只能删除没有被保留审计事件引用、也不是当前版本的旧行；若没有可删除行，新发布会返回未提交错误。已清理事件的旧调用通过墓碑标记过期，迁移前缺失的版本保持未知，绝不补造。SQLite 文件、索引和 DELETE 日志的空间不能当作已物理擦除。

## 旧数据迁移

先在隔离副本执行 `nmzp storage preflight --data-dir <绝对路径>`；它只读，报告原始字节摘要、旧格式、损坏行与尾部、重复或冲突标识、缺失历史和空间估计。不规范策略会给出阻塞原因，不在启动时静默改写。

经人工核对后，仅在维护窗口、排除运行中的写入者时执行 `nmzp storage migrate --data-dir <绝对路径>`。工具先保留原始字节备份和清单，再建立数据库并导入；中断后可识别进度，再次执行不重复导入。成功前不删除旧数据。验证 `nmzp.db`、迁移清单、策略版本、事件数量与原字节备份摘要后，才单独把 CT 配置切到 `sqlite`。回退须停止新核心，保存新数据库、队列和清单，再按备份恢复原数据及旧运行配置；切换后的新审计或策略发布不会自动倒灌进旧格式。

不在普通启动时自动迁移，不默认读取用户目录。本说明没有授权执行生产迁移或停机。程序升级与策略数据补丁也不同：升级前记录核心和 `nmzp-viewer` 的运行状态，备份原程序及数据，核对策略兼容性；停止核心会联动停止依赖它的只读服务，切换后应恢复原先运行的两项服务，并分别验证核心和网页。已加入的设备可沿用原身份与证书，不应为了验收重复注册或重写宿主 Hook 配置。

## 审计范围、压缩和补传

`/api/v1/state` 仍只返回最多 2,000 个近期事件；SQLite 历史由独立接口分页查询。审计正文只有压缩后确有收益才用 gzip 保存，读取后仍输出原来的逻辑事件 JSON。损坏正文抛错，不伪装成空事件。时间、设备、Agent、风险、决定、规则和策略版本是独立可索引字段；回执更新不重写全部正文。

SQLite 默认限制 100,000 条、按本地入库时间计算的 30 天、数据库 1 GiB、最低剩余空间 256 MiB、墓碑 90 天，先碰到哪项就按哪项处理。对应 CT 配置如下；30 天是时间上限，不是保留至少 30 天的承诺。

| 配置 | 默认值 |
| --- | --- |
| `NMZP_AUDIT_MAX_RECORDS` | 100,000 条 |
| `NMZP_AUDIT_MAX_DAYS` | 30 天，按本地入库时间 |
| `NMZP_AUDIT_MAX_MB` | 1,024 MiB（1 GiB） |
| `NMZP_AUDIT_MIN_FREE_MB` | 最低剩余 256 MiB |
| `NMZP_AUDIT_TOMBSTONE_DAYS` | 90 天 |

容量检查失败会拒绝新评估并返回 `503 audit_storage_unavailable`，不会声称事件已保存。清理留原因和计数；`/api/v1/audit/storage` 的 `reusableBytes` 是数据库可复用页，不是文件实际缩小，也不是安全擦除；`deleted` 是累计清理计数。

设备本地有有界待传队列（256 项、256 KiB、7 天、8 次退避重试），只放事件元数据和回执，不放工具正文或凭证。Hook 官方 stdout 确认后排队，在线 Hook 在剩余预算内尝试回执；探针成功心跳后每次最多补传两项。暂停时探针只做轮询，不发送待传事件。核心在 SQLite 持久化成功后确认；设备收到确认才移除，重复按事件标识和内容核对，冲突、身份变更、过期和丢弃在本地队列状态中计数。核心尚未采集设备补传队列状态，界面不能据此虚构队列数量。语义是有界至少一次发送加核心幂等接收，不是网络恰好一次，也不代表宿主真正执行了 Hook 输出的 deny。

核心启动后以每批最多 100 条清理过期或超额事件；尚待清理数量由 `retentionPending` 报告，清理过程中不能把尚未完成的保留承诺当作已经兑现。

## 新接口与权限

以下接口仅限管理员，且需要 SQLite；普通 viewer 不可访问。两类分页上限不同：

| 查询接口 | 默认条数 | 最大条数 | 游标 |
| --- | --- | --- | --- |
| `GET /api/v1/policy/history` | 50 | 100 | `beforeVersion`（不含该版本） |
| `GET /api/v1/audit/events` | 20 | 25 | 固定 `highWatermark` 与 `beforeSeq` |

策略列表例：`GET /api/v1/policy/history?limit=50`，响应 `{revisions,nextBeforeVersion}`；下页携带返回的 `nextBeforeVersion`，为 `null` 时结束。`GET /api/v1/policy/history/:version` 读取详情，缺失为 `404 policy_history_missing`。恢复用 `POST /api/v1/policy/restore`，请求 `{ "expectedVersion": 3, "sourceVersion": 1 }`，成功返回 `{ok,version,mode,stopped}`；`409 cas_conflict` 时重新加载并核对，不回退版本号。

审计列表例：`GET /api/v1/audit/events?limit=20`。响应包含 `events`、`highWatermark`、`nextBeforeSeq` 和 `historyCompleteness: "unknown"`；下页保留同一筛选和高水位，以 `nextBeforeSeq` 作为 `beforeSeq`，为 `null` 时结束。可筛选 `machineId`、`agent`、`decision`、`risk`、`ruleId`、`fromTs`、`toTs`。无效查询返回 `400 audit_query_invalid`，一页超过 4 MiB 返回 `413 audit_page_too_large`。新事件不会插入固定高水位内，清理并发仍可能形成缺口；窗口计数不等于全部历史。

`GET /api/v1/audit/storage` 查询容量与清理状态。`GET /api/v1/audit/export?format=json&gzip=0` 默认普通 JSON；可选 `format=jsonl` 与 `gzip=1`，筛选同审计查询。导出按固定高水位逐页写出，服务端链路执行权限检查与敏感字段处理；尾部的 `complete` 和 `deletionsDuringExport` 说明期间是否发生清理，`historyCompleteness: unknown` 表示不能证明历史完整。支持取消；旧 `/api/v1/export` 默认行为不变。

历史页每次只保留当前页，筛选变化会取消旧请求；空结果和失败不会自动无限重试。支持文件保存选择器的浏览器直接流式写文件，压缩下载保存为实际 gzip；无此能力时仅允许 16 MiB 有界缓冲下载，超限明确报错，使用支持流式保存的浏览器或管理员 CLI/HTTP 通道。`nmzp board` 代理同样流式转发并校验证书指纹，每会话服务最多两个并行导出，300 秒截止；取消会释放上游连接。恢复确认绑定打开确认时的策略版本，冲突须重新加载并核对。

设备仅可用 `POST /api/v1/audit/backfill`，请求严格限制为 `kind: event|receipt` 和相应元数据。事件暂停时拒绝，普通只读或未认证请求不能访问管理员接口。未知 Agent 名称保留原值；新接口不伪造旧前端未支持的 Agent 类型。

## 自定义示例

`examples/custom-rule.json` 是一个作用于 URL 字段的合成标记阻断规则；通过原有 `PUT /api/v1/policy` 的 `customRules` 数组和 `expectedVersion` 发布，仍受当前可信规则目录与受保护规则限制。`examples/local-adapter.mjs` 把一个合成 `WebFetch` 宿主事件转换为现有 `/api/v1/evaluate` 协议，不执行实际工具、不安装 Hook，也不把未知 Agent 冒充已知 Agent。运行 `node --experimental-strip-types --test tests/compat/customization.test.mjs` 可在随机本地 HTTPS 服务上核对规则发布、决定和旧状态解析。

## 明确限制

Windows 文件 `sync` 已用于写入，但没有硬件断电保证；目录项同步、进程崩溃和断电需要分别验证。SQLite 同步操作在专用工作线程，HTTP gzip 使用流式管道；十万条级别的总导出耗时仍需在 CT 上测量。已安装设备探针、旧二进制和宿主对 deny 的实际执行不因核心升级自动改变。SQLite 的逐条持久确认增加写入成本，不承诺比默认窗口更快；是否启用应结合 CT 实际磁盘延迟和日志量测量。
