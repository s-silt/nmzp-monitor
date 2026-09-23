# 审计稳定性测试

[English](testing-stability.en.md) · [贡献指南](../CONTRIBUTING.md) · [运行与存储说明](policy-runtime.md)

这是一条明确选择文件的审计稳定性验证路径，不是全项目验收，也不证明宿主已执行 Hook 的拒绝结果。适合先验证审计工作线程、缓存与编解码，再按修改范围补充服务端、策略和前端契约测试。

## 在开发机运行

需要 Node.js 24 或更新。这个小型测试集只使用 Node 内置模块和项目本地模块，不要求先安装前端依赖。

```bash
node --version
node scripts/run-stability-tests.mjs --list
node scripts/run-stability-tests.mjs
```

`--list` 仅检查并列出文件，不执行测试。正常执行固定使用文件级并发 2 和每文件 60 秒截止；失败保留非零退出码。脚本拒绝额外参数，不递归发现其他测试，不自动扩大范围，也不接受测试目录外的符号链接。

| 文件 | 实际验证范围 |
| --- | --- |
| `core/audit/worker-channel.test.mjs` | 合成传输事件与模拟时间；另有真实 Node Worker 的正常排空、退出和异常场景。不是 SQLite 测试 |
| `core/audit/runtime-drain.test.mjs` | 真实 AuditRuntime、生产 worker、临时 SQLite 文件；关闭时的写入排空、失败传播、回执保存及重新打开 |
| `core/audit/runtime.test.mjs` | 原有真实 worker 的顺序、队列上限、损坏行与启动失败测试 |
| `core/audit/json-codec.test.ts` | JSON/gzip 的往返和输入边界 |
| `core/audit/recent-events.test.ts` | 有界近期事件索引 |

新增文件只有经过导入链及副作用审查后才能加入此清单。不要用一次通过的总数替代测试范围说明。

## 不触碰工作中的宿主

这些测试只使用合成事件、OS 临时目录和测试自己创建的 Node 工作线程。不安装或卸载 Hook，不读取真实凭据，不运行用户命令，不扫描/结束 ZCode，不操作真实 `.zcode`、`.codex`、`.nmzp` 或 NTFS ACL。无需为这条测试路径关闭正在使用的 Agent。

它们不创建 HTTP 监听。将来加入服务端测试时，要单独审查其临时目录、回环端口、证书与清理方式，不能把“代码 worktree 独立”当成操作系统隔离。

## 关闭语义

`AuditRuntime` 保持存储方法与返回数据不变；内部 `AuditWorkerChannel` 只负责工作线程通信生命周期，不决定策略、不实现另一套数据库。

- 关闭立即停止接收新请求，但已接收请求仍会正常成功或失败。
- 关闭期间出现 worker 错误、退出或原请求截止时，待处理请求仍必须结束，不能因为已进入关闭状态就忽略错误。
- 并发调用 `close()` 共享同一份关闭结果；后来的调用者不能提前返回。
- 单条存储错误（例如损坏记录）不自动禁用整个 worker；通信/协议失败才终止通道。
- 通道失败不会自动重新执行写入。收到异常不证明磁盘未提交；恢复仍由原有存储/策略机制决定。

`close()` 完成表示相关资源已经释放，不表示所有写入都成功；调用者必须处理每个请求自己的结果。原有 32 个待完成调用上限与 30 秒请求截止保持不变。请求截止限制等待结果的时间，但 Node 的 `Worker.terminate()` 仍要等待线程退出，不能据此承诺硬件或原生 I/O 卡死时的绝对退出时限。

## 公开 CI

`.github/workflows/core-stability.yml` 在 GitHub 托管的 Linux/Windows runner 上运行同一份清单，使用 Node 24。只读仓库权限，checkout 不保留凭据；不使用自托管 runner、生产密钥、`pull_request_target`、npm 生命周期脚本或 ACL 测试。

这是限定范围的 CI，首次实际运行前不能称为已经通过。它不替代全项目类型检查、lint、构建、打包、HTTP 权限测试或真实 Agent 验证。CI 使用 Node 24 当前补丁版本，日志应记录实际版本；本地复核结果要另外注明操作系统与 Node 版本。

## 复核要求

存储数据结构、HTTP 路由或策略没有因为这次生命周期修复改变。正式发布前仍须在完整仓库验证前后端契约、类型与构建，并确认打包后的 `audit/` 包含 `worker-channel.ts` 而不包含测试。

需要排查故障时，保留第一次失败的输出和运行条件。不要无限重跑到绿灯，不要将跳过、超时或导入错误记为通过，也不要将进程正常重开等同于断电恢复验证。
