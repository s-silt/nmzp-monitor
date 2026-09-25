# 审计稳定性测试

[English](testing-stability.en.md) · [贡献指南](../CONTRIBUTING.md) · [运行与存储说明](policy-runtime.md)

这是一条明确选择文件的审计稳定性验证路径，不是全项目验收，也不证明宿主已执行 Hook 的拒绝结果。适合先验证审计工作线程、缓存与编解码，再按修改范围补充服务端、策略和前端契约测试。

下文「全量质量门禁」是另一条没有路径过滤的检查。它和这条五文件路径都只覆盖各自写明的命令。

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

`.github/workflows/core-stability.yml` 在 GitHub 托管的 Linux/Windows runner 上运行上面表格里的五份文件，使用 Node 24。只读仓库权限，checkout 不保留凭据；不使用自托管 runner、生产密钥、`pull_request_target`、npm 生命周期脚本或 ACL 测试。`pull_request` 和发往 `main` 的 `push` 都带路径过滤：`core/audit/**`、`core/schema.ts`、稳定性脚本和 workflow 自身。只改 `core/hook.ts` 这类清单外文件不会触发这条窄工作流。

这是限定范围的 CI。首次实际运行前不能称为已经通过。CI 选择 Node 24 的当前补丁，日志应记录实际版本；本地结果要另外注明操作系统与 Node 版本。

## 全量质量门禁

`.github/workflows/quality.yml` 另外定义 `pull_request`、`push` 和 `workflow_dispatch`，三处都没有 `paths`、`branches` 或 `tags` 过滤。矩阵是 GitHub 托管的 `ubuntu-latest` 与 `windows-latest`，`node-version` 为 `'24'`。这个主版本不是某一个补丁的 pin，当次日志里的版本才是那次运行的版本。权限只有 `contents: read`。checkout 使用 `persist-credentials: false`。action pin 与窄工作流相同：

- `actions/checkout@11d5960a326750d5838078e36cf38b85af677262`
- `actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020`

托管步骤依次是 `npm ci --ignore-scripts`、`npm run typecheck`、`npm run lint`、`npm test`、`npm run build`。`--ignore-scripts` 不运行依赖的生命周期脚本。`strategy.fail-fast` 为 false，一个系统失败不会取消另一个系统的作业。作业时限 30 分钟，超时是失败，不是跳过，也不是通过。

作业名称展开后是 `Quality / ubuntu-latest / Node 24` 和 `Quality / windows-latest / Node 24`。这两个名字要等 workflow 进入默认分支并至少运行过，才会出现在检查列表里。维护者需要在仓库设置中把两个检查都设为必需状态检查。只把 workflow 文件合并进去，不会打开分支保护或规则集，也没有可以引用的成功运行。

workflow 不设置 `NMZP_TEST_REAL_ACL`，不安装或卸载宿主，不读取生产凭据，不使用 `pull_request_target` 或自托管 runner。fork 上的 pull request 也只有这份只读权限。`push` 没有路径过滤，所以 tag 推送也会触发这条只读工作流。它没有写权限，不能创建、移动或删除 tag，也不能把已经推上去的 tag 撤回。workflow 文件和本地脚本不能代替仓库规则。

发布前核对目标 commit，并核对上面两个 action SHA 仍是审查过的 pin。有管理权限或被允许绕过规则的帐户仍可以在没有这些检查的情况下推送。要限制这种绕过，以及要限制 tag，都只能改仓库的分支保护、规则集和 tag 规则。

## 显式跳过

`npm test` 退出码 0 只表示已执行的用例没有失败。跳过的用例没有运行，不能记成通过。质量工作流和本地 preflight 都不设置 `NMZP_TEST_REAL_ACL`、`NMZP_LIVE_NETWORK_PROOF` 或 `NMZP_LIVE_PROOF_DIR`。

| 用例 | Linux 作业 | Windows 作业 |
| --- | --- | --- |
| `core/snapshot-guard.test.ts` 的 `snapshot-guard real NTFS ACL` | 跳过，原因是需要 Windows | 跳过，除非 `NMZP_TEST_REAL_ACL=1` |
| `core/install.test.ts`、`core/host-files-carry.test.ts`、`core/codex-hooks.test.ts`、`core/antigravity-hooks.test.ts`、`core/host-adapters.test.ts`、`core/zcode-hooks.test.ts` 里使用同一 opt-in 的用例 | 会执行。skip 为 false，结果不是 Windows ACL | 跳过，除非 `NMZP_TEST_REAL_ACL=1` |
| `core/install-hooks.test.ts` 的真实 PowerShell hook 命令 | 跳过 | 执行 |
| `core/network-collect.test.ts` 的真实回环 TCP 观测 | 跳过 | 执行 |
| `core/native-probe-service/verify-package.test.mjs` | 跳过 | 执行 |
| `core/snapshot-guard.test.ts` 的 Windows 目标缺失状态 | 跳过 | 执行 |
| `core/snapshot-guard.test.ts` 的 unsupported-platform 状态 | 执行 | 跳过 |
| `core/storage-firewall.test.ts` 的 Windows 观测 | 跳过 | 执行。这不是上面的真实 NTFS opt-in |
| `core/agent-discovery-registry.test.ts` 的 Windows 注册表源解析 | 跳过 | 执行 |
| `scripts/test-gates.test.mjs` 的 Windows TAP skip 检查 | 跳过 | 执行 |

`core/network-live-proof.test.ts` 默认跳过，除非同时设置 `NMZP_LIVE_NETWORK_PROOF=1` 和 `NMZP_LIVE_PROOF_DIR`。即使设置了，非 Windows、缺少独立二进制哈希或正向对照不可用时，用例内部仍会跳过并记下 `not_verified`。质量门禁不设置这些变量。

因此 Linux 绿灯不包含 Windows 才执行的那些行，Windows 绿灯也不包含只在非 Windows 上执行的 unsupported-platform 状态。两边都不执行真实 NTFS ACL。本机通过不是托管 Linux 作业的证据，也不是宿主认证。宿主安装、卸载和 ZCode 操作都不在这条门禁里。

## 本地发布前检查

当前工作副本已经装好依赖时，在仓库根目录运行：

```bash
node scripts/release-preflight.mjs
```

脚本按顺序运行 `npm run typecheck`、`npm run lint`、`npm test`、`npm run build`。它不执行 `npm ci`，不创建、移动或删除 tag，也不发布。某一步退出非零时，脚本立刻以该状态结束，后面的步骤不运行。在 `node:test` 进程里直接启动会被拒绝并退出 1，避免 `npm test` 再跑一遍全量 preflight。

在 Windows 上，脚本不直接启动 `npm.cmd`。Node 对 `shell: false` 的 `.cmd` 会返回 `EINVAL`。它改为用当前 Node 执行 PATH 里那份 npm 会选定的 `npm-cli.js`；如果 PATH 上有真正的 `npm.exe`，则直接执行那个文件。参数只允许上述四条检查和 `npm --version`。Linux 和 macOS 仍直接执行 `npm`。

preflight 进程收到 `SIGINT` 或 `SIGTERM` 时，只结束自己启动的检查，在有限时间内等待它们退出，然后以非零状态结束。超时或失败的检查也不是成功。父进程的 `exit` 事件不能代替这个处理：默认的 POSIX `SIGTERM` 不会发出 `exit`。

Linux 和 macOS 上，被启动的检查会成为新进程组的组长，信号发给该组的负 pid。它再启动的子进程只要留在组里也会收到信号。若期限内没有退出，才对同一组发送 `SIGKILL`。这次修改没有在 Linux 上实际跑过这条路径。

Windows 没有 POSIX 进程组。脚本对已启动的 pid 执行 `taskkill /PID <pid> /T /F`，只结束这棵进程树，不按进程名搜索，也不结束其他进程。不能把这种 Windows 行为当成 Linux 信号已经验证。

如果操作系统硬终止 preflight 自身，处理函数不会运行。这里不声称那种情况下的子进程已经被清理。在 Windows 上，另一次本地检查里，别的进程对一个装了处理函数的 Node 进程发送 `SIGTERM` 时，处理函数没有运行，进程直接以退出码 1 结束。那次检查不是 Linux 证据，也没有测量控制台 Ctrl+C。

`scripts/quality-gates.test.mjs` 用注入的子进程替身检查命令顺序和失败后是否停止。它被 `npm test` 收集，不会再跑一遍 typecheck、lint、完整测试和 build。同一文件会真实执行一次 `npm --version`，只打印版本，不安装、不构建。取消路径用的是会自行到期的临时子进程，不是那四条检查。

这条命令会真正执行 `npm test`，包括临时目录和回环契约测试。它不会因此去安装宿主或打开真实 ACL opt-in。本机通过只说明当前操作系统和当前 Node 上的结果。

## 复核要求

存储数据结构、HTTP 路由或策略没有因为这次生命周期修复改变。正式发布前要看两个托管作业对目标 commit 的结果，并确认打包后的 `audit/` 包含 `worker-channel.ts` 而不包含测试。`npm run pack` 不在质量工作流里，需要单独运行。`npm test` 会发现 `tests/compat/` 里的契约测试；上面表格里跳过的平台和 ACL 用例除外。

需要排查故障时，保留第一次失败的输出和运行条件。不要无限重跑到绿灯，不要将跳过、超时或导入错误记为通过，也不要将进程正常重开等同于断电恢复验证。
