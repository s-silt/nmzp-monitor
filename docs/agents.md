# 宿主适配器

[中文首页](../README.md) · [English](agents.en.md)

13 个适配器由本仓库维护，对接各宿主公开的 hook 接口。它们不是厂商认证，也不是厂商代为安装的组件。`join` 只给本机已经存在的目录写配置。

配置写上，不等于每次操作都受保护。要同时满足：宿主会加载这类 hook，信任或重启已经做完，这次调用进了 NMZP，策略处于执行档，并且宿主执行了拒绝或改写。

本机卸载不等于在核心上吊销设备凭据。`uninstall` 只清这台电脑上的 hook 和探针。凭据要管理员在核心上吊销。吊销会拒绝这台设备之后的请求，但已经离线、拿着缓存策略在跑的 hook 不会被远程停掉。

Copilot、Windsurf、Aider、Cline 只出现在发现目录里，没有 PreToolUse 适配器。

| Agent | join 写入 | 拦截 | 改写 | 记账 | 额外条件 |
| --- | --- | :---: | :---: | :---: | --- |
| Grok | `~/.grok/hooks/nmzp.json` | 能 | 能 | 能 | 超时或崩溃时宿主可能放行。`GROK_HOOK_EVENT` 与 `GROK_SESSION_ID` 同时存在时，Claude 形态的那一份空返回 |
| Claude Code | `~/.claude/settings.json` | 能 | 能 | 能 | 超时或崩溃时宿主可能放行 |
| Codex | `~/.codex/hooks.json` | 能 | 能 | 能 | 须在宿主里信任。NMZP 不写信任表。见下文 |
| ZCode | `~/.zcode/cli/config.json` | 能 | 能 | 能 | 打开 `hooks.enabled`。新会话才生效 |
| Antigravity | `~/.gemini/config/hooks.json` | 能 | 变成询问 | 能 | 须重启 IDE。Windows 有不触发的公开报告 |
| Gemini CLI | `~/.gemini/settings.json` | 能 | 能 | 能 | 事件名 `BeforeTool`。`settings.json` 已经存在才写 |
| Cursor | `~/.cursor/hooks.json` | 能 | 变成询问 | 能 | 无判定时输出空，由宿主决定。2.1.x 起有不触发的公开报告。以 Claude 身份加载且载荷带 `cursor_version` 时，那一份空返回 |
| Kimi Code | `~/.kimi-code/config.toml` | 能 | 改写即拒绝 | 能 | TOML 按块切，不是完整解析器。设计笔记里宿主超时按 fail-open 记录，本仓库没有重测 Kimi 二进制 |
| Trae | `~/.trae/hooks.json`、`~/.trae-cn/` | 能 | 能 | 能 | 以 Claude 身份加载且载荷带 `llm_tool_name` 时，那一份空返回 |
| Qwen Code | `~/.qwen/settings.json` | 能 | 能 | 能 | — |
| Qoder | `~/.qoder/settings.json` | 能 | 能 | 能 | — |
| Lingma | `~/.lingma/`、`~/.qoder-cn/` | 能 | 能 | 能 | — |
| CodeBuddy | `~/.codebuddy/settings.json` | 能 | 能 | 能 | 改写键是 `modifiedInput` |

“能改写”指协议映射存在并有契约测试；各宿主是否真正采纳改写没有真实宿主验证（HOST_REAL），面板只显示“改写指令已下发”。

NMZP 把自己的 hook 工作压在 6.5 秒预算里（`HOOK_BUDGET_MS`），因为按宿主超时可能放行来设计。本仓库不带那些宿主自己的 runner。`hook` 在导入安装器、服务和其他子命令模块之前进入 hook 处理。没有在杀毒软件环境下测过冷启动，合成计时不能当成生产预算。`HOOK_BUDGET_MS` 仍是 6500。`core/cli.ts` 的帮助按 `HOOK_AGENTS` 列出协议 id。列在帮助里只说明实现接受这个 id，不是该宿主已经执行拒绝或改写，也不是 HOST_REAL。

两次 `join` 用 `.nmzp/install.lock` 串行。这把锁只管 NMZP 自己的加入和离开，不管宿主或其他程序同时改同一份配置。写入前会再核对快照的字节、哈希和路径身份；对不上就留下对方的内容并报 `host_config_conflict`。核对和写入之间仍有一小段窗口。

改写改的是即将执行的参数。`PostToolUse` / `AfterTool` 直接空返回，不评估工具结果。

<a id="codex"></a>

## Codex

适配器由本仓库维护，使用 Codex 公开的 PreToolUse 文件。不是 OpenAI 的产品、合作或认证。没有「所有版本兼容」的记录。

### 源码已实现

`join` 写入 `~/.codex/hooks.json`，标记 `NMZP PreToolUse v1`，timeout 为 8 秒。Windows 上是指向本机 runtime 的 PowerShell 编码命令。NMZP 不写 `~/.codex/config.toml` 的 `[hooks.state]`。`core/codex-hooks.ts` 只读该文件，区分未配置、未信任、已修改、已禁用、功能关闭和已信任。读失败是 unknown，不是已信任。Codex 目录不存在时不提示缺信任。配置写过且状态不是已信任时，成功加入会提示在 Codex 里执行 `/hooks` 手动确认 `NMZP PreToolUse v1`；已修改或 unknown 会单独写明。没有这份状态的旧调用仍印 `codex=/hooks approve NMZP PreToolUse v1`。

拒绝是 `permissionDecision: deny`，退出码 0。改写是 `permissionDecision: allow` 加上 `updatedInput`。没有 `updatedInput` 的改写变成拒绝（`rewrite_missing_updated_input`）。stdout 确认后写 `~/.nmzp/hook-status.json`。已加入的设备再把评估报到核心。`stopped` 时放行，并且不再上传工具正文。不是 `PreToolUse` 的事件不评估。`Bash` 或 `apply_patch` 没有字符串 `command` 时拒绝，原因 `missing_tool_command`。

### 自动化测试

`core/codex-hooks.test.ts` 使用合成 stdin 和隔离的假 HOME，覆盖合并、安装与卸载、普通命令、危险命令、损坏输入、超长输入、信任哈希，以及「只有 hooks.json 还不等于已信任」。这些测试不启动 Codex 客户端。NMZP 打出 deny，不能当成 Codex 已经拒绝执行。

### 真实客户端

未验证。本仓库没有一份记录同时写明 Codex 版本、操作系统、信任步骤、场景、预期、实际结果和日期。

## ZCode

两条独立机制，不要混在一起。

1. Hook。`join` 写了 `~/.zcode/cli/config.json` 之后，新开会话才跑 `nmzp hook --agent zcode`。`ZCode.exe` 在跑而没有新会话，就没有回执。
2. NTFS 绊索。针对旧版把 `~/.zcode/v2/checkpoints` 打包再外传的路径。不依赖 hook。默认关，要 `nmzp snapshot apply`。ZCode 在跑时拒绝 apply 和 restore。

绊索只认这一个目录。管理员、SYSTEM 或属主可以解开 ACL。它拦不住内存打包、换目录、管道或自定义域名。ZCode 3.14.0 已去掉那条上传管线。这是给残留的 3.12.3 风格客户端的绊索，不是「每个版本都还在外传」。`/api/v1/snapshot/upload-credential` 和 `/v2/oss-credentials` 与产品域名不是一回事。连上产品域名或对象存储，本身不是整库外传的证据。`rights stop` 不解这项 ACL，要 `nmzp snapshot restore`。

`join` 还会装上 PermissionRequest、SessionStart、UserPromptSubmit 和 Stop。PermissionRequest 不代替宿主审批。这一阶段如果还要改参数，拒绝原因是 `rewrite_requires_pretooluse`。生命周期事件只在 `hook-status.json` 的 `events.zcode` 里留一条没有正文的回执。`hooks.zcode` 仍然表示 PreToolUse 回执。

插件不因名称、作者、`official` 字段或官方域名而豁免。检查看得见的 hook 和 MCP 声明。不递归解析外部脚本、压缩包或已安装插件的代码。远程 MCP 内部和宿主 TLS 不因此变成已防护。
