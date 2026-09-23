# 现在别指望的事

[中文首页](../README.md) · [English](limits.en.md) · [安全模型](../SECURITY.md)

当前版本 0.2.4。原生沙箱和 protected-session 把 `productionReady` 设为 false。那不是这条 hook 的能力声明，hook 本身也不是沙箱。

| 没做的 | 为什么 |
| --- | --- |
| 屏幕捕获提醒 | 做过又拆了。监听 `Windows.Graphics.Capture` 要管理员，普通用户下耗 CPU，还会把你自己的截图算进去 |
| 压缩包超阈值拦截 | 看板上的「拦截」是禁用的，只有提醒。大小只在命令里写明了单个压缩包时才看得见 |
| 按 Agent 限定规则 | hook 里的 agent 身份是自报的。作用域是工具和字段 |
| 阻断 GitHub / OSS / COS 上传 | 只观察。断网是防火墙的事 |
| 通用上传阻断 | 同上 |
| 剪贴板或截屏隔离 | 容易绕开，也妨碍正常工作 |
| 把 WFP 内核过滤打进普通包 | 实验模块，不在 `npm run pack` 里 |
| 采集完整聊天 | 刻意不做。不读 `grok.db`、Claude projects、Codex sessions |
| 内存打包、换目录、管道、自定义域名 | ZCode 目录绊索覆盖不到 |
| 拦住本机管理员 | 管理员、SYSTEM 或属主可以解开 ACL |
| 审计不可篡改、无损完整历史 | 不承诺。新版设备有有界持久补传，但队列满、过期或故障仍会缺失；默认仅保留近期 2000 条，管理员可显式启用受保留上限约束的 SQLite 历史。`historyCompleteness` 仍为 `unknown` |
| 定时导出、自动调用模型、每日报告 | 没做。审计分析是人导出之后交给外部 AI |
| 本地语义检查 | 规划。见 [local-semantic-review.md](plans/local-semantic-review.md)。模型层尚未接入 |

发现到安装或进程，只说明发现到了。看板上的「已回执」来自新鲜的 `hook-status.json`。适配器被调用，也不等于宿主执行了 deny。
