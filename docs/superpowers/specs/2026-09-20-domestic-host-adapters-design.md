# 批次二：Kimi / Trae / Qwen Code / Qoder / 灵码(Qoder CN) / CodeBuddy / Gemini CLI / Cursor 适配器 — 设计与验收

状态：验收测试已写好（`core/host-adapters.test.ts`，红灯；`core/antigravity-hooks.test.ts` 的 join 门槛用例已更新）。
实现者按本文件逐条实现，直到「验收」一节全部通过。禁止修改任何已存在的 `*.test.ts`（可新增）。
禁止：git、npm run pack、部署、联网、读写 `~/.kimi-code ~/.trae* ~/.qwen ~/.qoder* ~/.lingma ~/.codebuddy ~/.gemini ~/.cursor ~/.nmzp ~/.claude ~/.codex ~/.grok ~/.zcode` 真实文件。
协议事实均已核实（官方文档 / 官方仓库，2026-09-20），不需要再查。

## 1. 宿主协议事实

| 宿主 id | 配置文件（用户级） | 事件键 | 条目形状 | stdin 特有字段 | 拒绝 | 改写 | 超时 |
|---|---|---|---|---|---|---|---|
| `kimi` | `~/.kimi-code/config.toml`，TOML `[[hooks]]`，**只允许 event/matcher/command/timeout 四个键**，多一个键整个配置失败 | `event = "PreToolUse"` | `[[hooks]]\nevent = "PreToolUse"\ncommand = <toml string>\ntimeout = 8\n` | snake_case；`tool_call_id`（不是 tool_use_id） | exit 2 + stderr；stdout `{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason"}}` | 不支持 → deny `rewrite_unsupported_host` | 秒，默认 30，fail-open |
| `trae` | `~/.trae/hooks.json` 与 `~/.trae-cn/hooks.json`（各自目录存在才写） | `hooks.PreToolUse` | 顶层 `version: 1`；`{ matcher: "", hooks: [ { type: "command", command, timeout: 8 } ] }` | `workspace_roots, agent_id, agent_type, model, llm_tool_name`；工具名 `RunCommand/Read/Write/Edit/...`，`tool_input.command` | exit 2 + stdout `hookSpecificOutput.permissionDecision=deny` | `hookSpecificOutput.updatedInput` | 秒 |
| `qwen` | `~/.qwen/settings.json` | `hooks.PreToolUse` | `{ matcher: "*", hooks: [ { type: "command", command, timeout: 8 } ] }` | `timestamp, permission_mode, tool_use_id`；工具名 `run_shell_command/read_file/write_file/edit` | 同 Claude | `updatedInput` | 秒（≥1000 视为毫秒） |
| `qoder` | `~/.qoder/settings.json` | 同上 | 同上 | `agent_id, agent_type, tool_use_id`；工具名 Claude 兼容 | 同 Claude | `updatedInput` | 秒 |
| `lingma` | `~/.lingma/settings.json`（IDE）与 `~/.qoder-cn/settings.json`（CLI），各自目录存在才写 | 同上 | 同上 | 工具名 IDE 原生 `run_in_terminal/read_file/create_file/search_replace` | 同 Claude | `updatedInput` | 秒 |
| `codebuddy` | `~/.codebuddy/settings.json` | 同上 | 同上 | 可能没有 tool_use_id | 同 Claude | **`modifiedInput`**（不是 updatedInput） | 秒 |
| `gemini` | `~/.gemini/settings.json`（**文件已存在才写**，Gemini CLI 首次运行会创建；`~/.gemini` 目录本身不算） | `hooks.BeforeTool` | `{ matcher: "", hooks: [ { name: "nmzp", type: "command", command, timeout: 8000 } ] }` | `hook_event_name: "BeforeTool"`，`timestamp, mcp_context`；工具名 `run_shell_command/read_file/write_file/replace` | exit 2 + stderr；stdout `{"decision":"deny","reason"}` | `{"hookSpecificOutput":{"tool_input": {...}}}` | **毫秒** |
| `cursor` | `~/.cursor/hooks.json` | `hooks.preToolUse` | 顶层 `version: 1`；条目是**扁平对象** `{ command, timeout: 8, matcher: ".*" }`（没有内层 hooks 数组） | `conversation_id, generation_id, cursor_version, workspace_roots, tool_use_id`；工具名 `Shell/Read/Write/Grep/Delete/Task`；**Windows stdin 带 UTF-8 BOM** | exit 2 + stdout `{"permission":"deny","user_message","agent_message"}` | `{"permission":"ask","user_message":"NMZP rewrote parameters","updated_input":{...}}` | 秒 |

Cursor 与 Trae 会（可选）导入 `~/.claude/settings.json`，因此 NMZP 的 Claude 副本会在这两个宿主下被调用：识别到宿主特征就空转，不写回执（同 Grok 兼容逻辑）。

## 2. 新文件与签名（测试已引用）

### `core/host-adapters.ts`
```ts
export const EXTRA_HOOK_AGENTS = ["kimi", "trae", "qwen", "qoder", "lingma", "codebuddy", "gemini", "cursor"] as const;
export type ExtraHookAgent = (typeof EXTRA_HOOK_AGENTS)[number];
/** 只返回门槛存在的目标文件绝对路径（顺序固定如下）。 */
export function hostHookTargets(agent: ExtraHookAgent, home: string): string[];
//   kimi     → [~/.kimi-code/config.toml]           门槛：目录 ~/.kimi-code
//   trae     → [~/.trae/hooks.json, ~/.trae-cn/hooks.json]  门槛：各自目录
//   qwen     → [~/.qwen/settings.json]              门槛：目录 ~/.qwen
//   qoder    → [~/.qoder/settings.json]             门槛：目录 ~/.qoder
//   lingma   → [~/.lingma/settings.json, ~/.qoder-cn/settings.json]  门槛：各自目录
//   codebuddy→ [~/.codebuddy/settings.json]         门槛：目录 ~/.codebuddy
//   gemini   → [~/.gemini/settings.json]            门槛：该文件已存在
//   cursor   → [~/.cursor/hooks.json]               门槛：目录 ~/.cursor
export function hostHookWrite(agent: ExtraHookAgent, raw: string | null, nodePath: string, entry: string, os?: string): string;
export function hostHookStrip(agent: ExtraHookAgent, raw: string): string;
export function hostHookConfiguredRaw(agent: ExtraHookAgent, raw: string): boolean;   // 坏内容 → false
export function hostHookState(agent: ExtraHookAgent, home: string): { present: boolean; configured: boolean };
//   present = 任一目标文件存在；configured = 任一目标文件含自有条目。
```
- 命令统一用 `hookCommand(nodePath, entry, agent, os)`（Windows 为 PowerShell EncodedCommand，cmd.exe / Git Bash / PowerShell 下都能直接执行）。
- 自有条目判定统一用 `isNmzpOwnedHook`（对 command 解码后匹配 `nmzp` + `hook --agent`）；写入前先剔除所有自有条目再追加，保证幂等。
- JSON 家族（trae/qwen/qoder/lingma/codebuddy/gemini/cursor）：`raw === null` → `{}`；解析失败 / 顶层非对象 / `hooks` 非对象 → `throw Error("<agent>_hooks_corrupt")`；其它顶层键与其它事件原样保留；返回 `JSON.stringify(doc, null, 2) + "\n"`。trae/cursor 缺 `version` 时补 `version: 1`。
- `kimi` TOML：逐行处理。`[[hooks]]` 块 = 从该行起到下一个以 `[` 开头的表头行之前。剔除 command 值（解码 EncodedCommand 后）匹配 `/hook --agent kimi(?:;|\s|$)/` 的块，其它内容逐字节保留；追加块前保证前面有一个空行；块格式严格为
  ```
  [[hooks]]
  event = "PreToolUse"
  command = '<command>'
  timeout = 8
  ```
  command 无 `'` 时用 TOML 字面量字符串 `'...'`；含 `'` 时用基本字符串并转义 `\` 与 `"`。**不得出现 matcher/statusMessage/args 键。** `raw === null` → 只有该块。

### `core/hook-protocol.ts`
- `export const HOOK_AGENTS = ["grok","claude","codex","zcode","antigravity","kimi","trae","qwen","qoder","lingma","codebuddy","gemini","cursor"] as const; export type HookAgent = (typeof HOOK_AGENTS)[number];`
- `parseHookEvent`：开头剥离 UTF-8 BOM（`﻿`）；eventId 别名增加 `tool_call_id`；sessionId 别名增加 `conversation_id`；cwd 回退 `workspace_roots[0]`（字符串数组）。冲突规则沿用 `pickDefinedSame`。
- `detectHookAgent`：flag 为 13 个之一直接返回；无 flag 时新增启发：`RunCommand` → trae，`Shell|Delete` → cursor（其余保持）。
- `formatHookResponse` 返回类型增加可选 `stderr?: string`。规则（`reason` 指 `d.reason`）：
  - `qwen/qoder/lingma/trae`：deny → `{ stdout: JSON.stringify({hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:reason}})+"\n", exitCode: 2, stderr: reason+"\n" }`；updatedInput → `{ stdout: JSON.stringify({hookSpecificOutput:{hookEventName:"PreToolUse",updatedInput}})+"\n", exitCode: 0 }`；否则 `{ stdout:"", exitCode:0 }`。
  - `codebuddy`：同上，但改写键为 `modifiedInput`。
  - `kimi`：deny → `{ stdout: JSON.stringify({hookSpecificOutput:{permissionDecision:"deny",permissionDecisionReason:reason}})+"\n", exitCode: 2, stderr: reason+"\n" }`（**无 hookEventName**）；updatedInput → 按 deny 处理，reason 固定 `rewrite_unsupported_host`；否则空 exit 0。
  - `gemini`：deny → `{ stdout: JSON.stringify({decision:"deny",reason})+"\n", exitCode: 2, stderr: reason+"\n" }`；updatedInput → `{ stdout: JSON.stringify({hookSpecificOutput:{tool_input: updatedInput}})+"\n", exitCode: 0 }`；否则空 exit 0。
  - `cursor`：deny → `{ stdout: JSON.stringify({permission:"deny",user_message:reason,agent_message:reason})+"\n", exitCode: 2, stderr: reason+"\n" }`；updatedInput → `{ stdout: JSON.stringify({permission:"ask",user_message:"NMZP rewrote parameters",updated_input: updatedInput})+"\n", exitCode: 0 }`；pass → `{ stdout: JSON.stringify({permission:"allow"})+"\n", exitCode: 0 }`。
  - `claude`、`grok`：stdout/exitCode 不变，deny 时**增加** `stderr: reason+"\n"`。`codex`、`zcode`、`antigravity` 完全不变（不带 stderr 键）。
  - 键顺序必须与上面一致（测试做字符串比对）。

### `core/hook.ts`
- `HookResult` 增加 `stderr?: string`；`runHook` 把 `formatHookResponse` 的 stderr 原样带出；`hookMain` 在 stdout 确认写入之后、settle 之前用 `process.stderr.write(stderr)` 写出（失败忽略）。
- 新增 `export function isForeignHostPayload(flag: string | undefined, parsed: ParsedHook): "cursor" | "trae" | undefined`：仅当 `flag === "claude"`：`rawKeys` 含 `cursor_version` → `"cursor"`；含 `llm_tool_name` → `"trae"`；否则 undefined。`runHook` 在解析成功后若返回非 undefined，直接 `{ stdout: "", exitCode: 0, startedAt }`（不写回执）；`hookMain` 同样处理。
- 事件过滤：原来只跳过包含 `post` 的事件名，改为 `/^(post|after)/i.test(eventName) || eventName.toLowerCase().includes("post")` 也跳过（Gemini 的 `AfterTool`）。
- `isHookAgent` 改为基于 `HOOK_AGENTS`。

### `core/constants.ts`
- `NEED_CHECK_TOOLS` 增加：`RunCommand`、`run_shell_command`、`run_in_terminal`、`create_file`、`replace`、`Shell`、`Delete`、`FetchURL`、`web_fetch`、`read_url_content`（已有）。

### `core/install.ts`
- `InstallManifest` 增加 `hostFiles?: Array<{ agent: string; path: string; created: boolean; writtenSha256: string }>`。
- join：对每个 `EXTRA_HOOK_AGENTS`，`for (const path of hostHookTargets(agent, home))`：读 prev → `hostHookWrite(agent, prev, nodePath, entry, os)` 校验（在任何写入之前对全部目标先跑一遍，失败即抛）→ 备份/noteCreated → `mkdirSync(dirname)` → `atomicWriteFile(path, next, 0o600)` → 记入 `hostFiles`（`created = prev === null || 上一份 manifest 里同路径 created === true`）与 `files`。
- Antigravity 门槛改为目录 `~/.gemini/antigravity` 存在（原来是 `~/.gemini`）。
- leave：遍历 `manifest.hostFiles`：文件存在且 `created && sha256(当前) === writtenSha256` → `rmSync`；否则 `atomicWriteFile(path, hostHookStrip(agent, raw))`。旧 manifest 无该字段时跳过。

### `core/probe.ts` / `core/probe-status.ts`
- `HOOK_STATUS_CONTRACT.agents` = 全部 13 个。
- `assembleProbeReport` 对每个 `EXTRA_HOOK_AGENTS` 追加 `hookCapability("hook_<agent>", hostHookState(agent, home).configured, agent, status, now)`（无 gateError）。

### 前端
- `src/lib/monitor/types.ts` `AgentId` 增加 `"kimi" | "qoder" | "lingma" | "codebuddy"`。
- `src/lib/monitor/agents.ts`：新增四个 `AgentDef`：
  - kimi：`name "Kimi Code", vendor "Moonshot AI", process "kimi", hookPath "~/.kimi-code/config.toml", projectHookPath "(none)", models ["kimi-k2"], transcriptHint "~/.kimi-code/", letter "K"`
  - qoder：`name "Qoder", vendor "Alibaba", process "qoder", hookPath "~/.qoder/settings.json", projectHookPath ".qoder/settings.json", models ["qwen3-coder"], transcriptHint "~/.qoder/", letter "Q"`
  - lingma：`name "通义灵码 / Qoder CN", vendor "Alibaba", process "lingma", hookPath "~/.lingma/settings.json", projectHookPath ".lingma/settings.json", models ["qwen3-coder"], transcriptHint "~/.lingma/", letter "L"`
  - codebuddy：`name "CodeBuddy", vendor "Tencent", process "codebuddy", hookPath "~/.codebuddy/settings.json", projectHookPath ".codebuddy/settings.json", models ["hunyuan"], transcriptHint "~/.codebuddy/", letter "B"`
  - 修正已有：`gemini.hookPath = "~/.gemini/settings.json"`，`trae.hookPath = "~/.trae/hooks.json"`，`cursor.hookPath = "~/.cursor/hooks.json"`，`qwen.hookPath = "~/.qwen/settings.json"`。
  - `AGENT_ORDER` 在 `"antigravity"` 之后依次加入 `"kimi","qoder","lingma","codebuddy"`。
  - `NATIVE_TOOL_MAP` 增加：`runcommand→Bash, run_shell_command→Bash, run_in_terminal→Bash, create_file→Write, replace→Edit, delete→Bash, fetchurl→WebFetch, web_fetch→WebFetch, google_web_search→WebSearch, list_directory→Glob, read_many_files→Read, invoke_agent→Task`（键全小写，与 `normalizeTool` 的 `toLowerCase` 一致）。
- `core/egress-schema.ts` `GITHUB_AGENT_IDS` 增加 `'kimi','qoder','lingma','codebuddy'`。
- `src/lib/monitor/store.ts` `agentCardDisplay` 的能力查找改为通用：`lookupCap(capabilities, \`hook_${agent}\`)`（保留旧 camelCase 备用键）。
- `src/routes/index.tsx` `HOOK_ADAPTERS` 覆盖全部 13 个（类型用 `HookAgent`/AgentId 兼容写法）。
- `src/routes/install.tsx` `SUPPORTED` 覆盖 13 个；`SNIPPETS` 为每个新宿主给出配置文件路径与 `hooks-config.ts` 中的示例常量：`KIMI_HOOK`（TOML）、`TRAE_HOOK`、`QWEN_HOOK`、`QODER_HOOK`、`LINGMA_HOOK`、`CODEBUDDY_HOOK`、`GEMINI_HOOK`、`CURSOR_HOOK`；每个宿主的 hint 追加对应 i18n 键 `<agent>MustEnable`。
- `src/lib/monitor/hooks-config.ts`：新增上述 8 个常量（形状与 join 实际写入一致，命令用 `node ~/.nmzp/runtime/0.1.0/nmzp.mjs hook --agent <agent>` 示意）；`ATTACH_HINT_ZH` 改为「13 个适配器」并保留 Codex/ZCode/Antigravity 的注意事项；`PROBE_CONFIG.processes` 覆盖 13 个。
- `src/lib/monitor/i18n.ts` 新增 zh/en 键：`kimiMustEnable`（TOML 只认四个键；新会话生效；Windows 用 cmd.exe 启动；改写不支持，命中改写即拒绝）、`traeMustEnable`（`~/.trae` 与 `~/.trae-cn` 各写一份；需重启 IDE；Windows 用 PowerShell；开启「Import Hook configuration in CLAUDE」时 Claude 副本自动空转）、`qwenMustEnable`（Windows 走 cmd.exe，路径含空格的引号 bug 尚未修复，NMZP 命令无引号不受影响）、`qoderMustEnable`（CLI 经 Git Bash 执行；IDE 无热加载需重启）、`lingmaMustEnable`（IDE 与 Qoder CN CLI 各写一份；需重启）、`codebuddyMustEnable`（Hooks 为 Beta；文档要求 Git Bash；改写键为 modifiedInput）、`geminiMustEnable`（事件名 BeforeTool；timeout 毫秒；项目级 hook 指纹变更需重新信任，用户级不需要）、`cursorMustEnable`（Windows stdin 带 BOM 已处理；2.1.x 起有 hook 不触发的公开报告；Cursor 会导入 ~/.claude/settings.json，Claude 副本自动空转）；`attachNote`、`hookLayerBody` 改为「13 个适配器，Grok/Claude/Codex/ZCode/Antigravity/Kimi/Trae/Qwen Code/Qoder/灵码/CodeBuddy/Gemini CLI/Cursor」表述。保留所有既有键与 `not implemented` 字样。

## 3. 验收（全部必须通过）
```
node --experimental-strip-types --test --test-timeout=60000 core/host-adapters.test.ts core/zcode-hooks.test.ts core/antigravity-hooks.test.ts core/install-hooks.test.ts core/codex-hooks.test.ts core/hook-process.test.ts core/hook-protocol.test.ts core/probe.test.ts core/hook.test.ts core/install.test.ts core/hook-protocol-grok-shape.test.ts
node --experimental-strip-types --test --test-timeout=60000 src/lib/monitor/*.test.ts
npx tsc --noEmit
npx eslint core src      # 本任务新增/改动文件 0 error；既有 19 条 error 不要求清扫
```
- `core/host-adapters.test.ts` 与更新后的 `core/antigravity-hooks.test.ts` 是验收标准，不得改动。
- 手工检查：`grep -rn "hook --agent" src/lib/monitor/hooks-config.ts` 应覆盖 13 个 agent。
