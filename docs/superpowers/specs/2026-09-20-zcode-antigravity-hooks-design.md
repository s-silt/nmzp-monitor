# ZCode / Antigravity PreToolUse 适配器 + 两处规则误判修复 — 设计与验收

状态：验收测试已写好（红灯），等待实现。实现者按本文件逐条实现，直到「验收」一节全部通过。
不要修改任何已存在的 `*.test.ts`（可以新增测试）。不要 `git`、不要 `npm run pack`、不要部署、不要改动
`~/.zcode`、`~/.gemini`、`~/.nmzp`、`~/.claude`、`~/.codex`、`~/.grok` 下的任何真实文件。不要联网（NMZP hook 会拦截下载）。
所有协议事实已在下文给出，不需要再查文档。

## 1. 已核实的宿主协议（本机实测，2026-09-20）

### ZCode 3.14.0（桌面版，运行时 `C:\Program Files (x86)\ZCode\resources\glm\zcode.cjs`）
- 用户级配置 `~/.zcode/cli/config.json`（顶层键 `plugins` / `hooks` / `mcp`）。项目级 hooks 被忽略。
- `hooks` 结构：`{ enabled?: boolean, timeoutMs?: number, maxOutputBytes?: number, events: { PreToolUse: [ { matcher?: string, hooks: [entry] } ] } }`。
  **`hooks.enabled` 默认 false，必须为 true 才会运行配置文件 hook。**
- entry（zod 严格 schema）：
  - `{ type: "process", command: string, args?: string[], enabled?: boolean, timeoutMs?: number, statusMessage?: string }` — argv 直接 spawn，不经 shell（Windows 首选）。
  - `{ type: "command", command, enabled?, async?, shell?, timeout?(秒), timeoutMs?, statusMessage? }`。
- stdin：Claude 兼容 snake_case：`hook_event_name`、`session_id`、`cwd`、`tool_name`（Bash/Read/Write/Edit/Agent…）、`tool_input`、`tool_use_id`。`parseHookEvent` 现有逻辑已能解析。
- stdout：严格 JSON（多余键即失败）。PreToolUse 允许：
  `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"|"ask"|"deny","permissionDecisionReason"?:string,"updatedInput"?:unknown,"additionalContext"?:string}}`
  以及顶层 `decision:"approve"|"block"`、`reason`、`continue`、`stopReason`、`suppressOutput`、`systemMessage`。
- 退出码：0 → 解析 stdout（空 stdout 合法）；2 → deny，reason 取 stderr（否则 stdout 原文）；其它非零 → 工具执行失败。
- 结论：**deny 用 exit 0 + JSON**（reason 干净），pass 用空 stdout + exit 0，rewrite 用 `hookSpecificOutput.updatedInput`。
- 会话启动时快照配置：改完配置需新会话。日志 `~/.zcode/cli/log/zcode-<date>.jsonl`（事件 `hook.run.failed` 等）。

### Antigravity 2.15.0（IDE，`language_server.exe` 内嵌契约）
- 全局配置 `~/.gemini/config/hooks.json`；工作区 `.agents/hooks.json`。结构：顶层键是 hook 名，
  `{ "<name>": { "enabled"?: boolean, "PreToolUse": [ { "matcher": "*", "hooks": [ { "type": "command", "command": string, "timeout": 秒 } ] } ] } }`。默认 timeout 30s。
- stdin（camelCase）：`{ "toolCall": { "name": "run_command", "args": { "CommandLine": "npm test", "Cwd": "..." } }, "stepIdx": 19, "conversationId", "workspacePaths": [..], "transcriptPath", "artifactDirectoryPath", "modelName" }`。
  工具名：`run_command`、`write_to_file`(`TargetFile`,`CodeContent`)、`replace_file_content`(`TargetFile`,`ReplacementContent`)、`multi_replace_file_content`(`ReplacementChunks`)、`view_file`(`AbsolutePath`)、`list_dir`、`find_by_name`、`grep_search`、`search_web`(`Query`)、`read_url_content`(`Url`)、`invoke_subagent` 等。
- stdout：`{ "decision": "allow"|"deny"|"ask"|"force_ask", "reason"?: string, "permissionOverrides"?: string[], "overwrite"?: { <argKey>: value } }`。`overwrite` 是对工具参数的顶层浅合并（改写）。
- 无 `hookEventName` 字段；只注册 PreToolUse，缺省即 PreToolUse。
- 结论：deny → `{"decision":"deny","reason"}`；pass → `{}`（不下 allow，避免绕过宿主自身审批）；rewrite → `{"decision":"ask","reason":"nmzp_rewrite","overwrite":{...}}`。
- 公开 bug：Windows IDE 有 hook 不触发的报告，须以回执为准。

## 2. 新文件与签名（测试已引用，必须一致）

### `core/zcode-hooks.ts`
```ts
export function zcodeConfigPath(home: string): string;            // join(home, ".zcode", "cli", "config.json")
export function zcodeHookGroup(nodePath: string, entry: string): Record<string, unknown>;
// => { hooks: [ { type: "process", command: nodePath,
//      args: ["--experimental-strip-types", entry, "hook", "--agent", "zcode"], timeoutMs: 8000, statusMessage: "NMZP PreToolUse v1" } ] }
// 不带 matcher 键（省略 = 匹配全部工具）。
export function mergeZcodeConfig(raw: string | null, group?: Record<string, unknown>): string;
// 解析失败 / 顶层非对象 / hooks 非对象 / events 非对象 / PreToolUse 非数组 → throw Error("zcode_config_corrupt")。
// 有 group：hooks.enabled = true；保留 hooks.timeoutMs/maxOutputBytes 与其它事件；PreToolUse 先剔除所有自有条目再 push group；幂等。
// 无 group：只剔除自有条目，不改 enabled；PreToolUse 保持为数组（可为空 []）。
// 顶层其它键（plugins/mcp…）原样保留。返回 JSON.stringify(doc, null, 2) + "\n"。
export function zcodeHookConfiguredRaw(raw: string): { configured: boolean; enabled: boolean }; // 坏 JSON → {false,false}
export function zcodeHookState(home: string): { present: boolean; configured: boolean; enabled: boolean };
export function zcodeHookGateError(state: { configured: boolean; enabled: boolean }): string | undefined; // configured && !enabled → "hooks_disabled"
```
自有条目判定：`statusMessage === "NMZP PreToolUse v1"` 且（`type==="process"` 且 args 含连续 `"hook","--agent","zcode"`）
或（`type==="command"` 且 `decodeWindowsEncodedCommand(command) ?? command` 匹配 `/hook --agent zcode(?:;|\s|$)/`）。

### `core/antigravity-hooks.ts`
```ts
export const ANTIGRAVITY_HOOK_NAME = "nmzp";
export function antigravityHooksPath(home: string): string;        // join(home, ".gemini", "config", "hooks.json")
export function antigravityHookDoc(nodePath: string, entry: string, os?: string): Record<string, unknown>;
// => { enabled: true, PreToolUse: [ { matcher: "*", hooks: [ { type: "command", command: hookCommand(nodePath, entry, "antigravity", os), timeout: 8 } ] } ] }
export function mergeAntigravityHooks(raw: string | null, doc?: Record<string, unknown>): string;
// 坏 JSON / 顶层非对象 / 已存在的 "nmzp" 键不是对象 → throw Error("antigravity_hooks_corrupt")。
// 先删除所有「任一事件数组里含 NMZP 自有 command（isNmzpOwnedHook）」的命名 hook；有 doc 则 doc["nmzp"] = doc。幂等。返回 pretty JSON + "\n"。
export function antigravityHookConfiguredRaw(raw: string): { configured: boolean; enabled: boolean };
// configured = 某个命名 hook 的 PreToolUse 含自有 command；enabled = 该 hook 的 enabled !== false。
export function antigravityHookState(home: string): { present: boolean; configured: boolean; enabled: boolean };
export function antigravityHookGateError(state: { configured: boolean; enabled: boolean }): string | undefined; // configured && !enabled → "hook_disabled"
```

## 3. 现有文件改动

### `core/hook-protocol.ts`
- `HookAgent = "grok" | "claude" | "codex" | "zcode" | "antigravity"`。
- `ParsedHook` 增加 `hostArgMap?: Record<string, string>`（规范键 → 宿主参数键）。
- `parseHookEvent`：当 `parsed.toolCall` 是普通对象时走 Antigravity 分支：
  - `toolCall.name` 非空字符串，否则返回 null；`args` 非对象视为 `{}`。
  - 规范化映射（只映射存在的键，其余 args 原样并入 toolInput）：`CommandLine→command`、`Cwd→cwd`、`TargetFile→file_path`、`AbsolutePath→file_path`（TargetFile 优先）、`Url→url`、`CodeContent→contents`、`ReplacementContent→new_string`。`hostArgMap` 只记录被映射的键，如 `{ file_path: "TargetFile", contents: "CodeContent" }`、`{ command: "CommandLine", cwd: "Cwd" }`。
  - `sessionId = conversationId`；`cwd = args.Cwd ?? workspacePaths[0]`；`eventId = "<conversationId>:<stepIdx>"`（两者都有且 stepIdx 为数字），否则 `newEventId()`；`eventName = hookEventName ?? "PreToolUse"`；`agentHint = "antigravity"`。
- `detectHookAgent`：flag 接受 `zcode`/`antigravity`；`agentHint === "antigravity"` 返回 antigravity；无 flag 且工具名匹配
  `/^(run_command|write_to_file|replace_file_content|multi_replace_file_content|view_file|list_dir|find_by_name|grep_search|read_url_content)$/` → "antigravity"。
- `formatHookResponse(agent, d, host?: { argMap?: Record<string, string> })`：
  - zcode：deny → `JSON.stringify({hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:d.reason}})+"\n"`，**exitCode 0**；updatedInput → `{hookSpecificOutput:{hookEventName,updatedInput}}` exit 0；否则 `{stdout:"",exitCode:0}`。
  - antigravity：deny → `JSON.stringify({decision:"deny",reason:d.reason})+"\n"` exit 0（键顺序 decision, reason）；updatedInput → 每个键经 argMap 映射为 overwrite，任一键无映射则 deny `rewrite_unsupported_host`；否则 `JSON.stringify({decision:"ask",reason:"nmzp_rewrite",overwrite})+"\n"`；pass → `"{}\n"` exit 0。
  - grok/claude/codex 行为不变。

### `core/hook.ts`
- 所有 `"grok" | "claude" | "codex"` 联合改为 `HookAgent`；`flaggedAgent` 接受 zcode/antigravity；`statusFor` 接受五个 agent。
- `pass()`/`deny()` 增加可选 `argMap` 并在 `runHook` 内传入 `parsed.hostArgMap`。`isGrokHostedClaudeCompat` 不变。

### `core/constants.ts`
- `NEED_CHECK_TOOLS` 增加 `run_command`、`write_to_file`、`replace_file_content`、`multi_replace_file_content`、`read_url_content`。

### `core/install-hooks.ts`
- `windowsHookInnerScript` / `encodeWindowsHookCommand` / `hookCommand` 的 agent 参数类型改为 `HookAgent`（`import type` 自 hook-protocol）。

### `core/install.ts`（joinDevice / leaveDevice / InstallManifest）
- join：`zcodePath = zcodeConfigPath(home)`，仅当目录 `join(home,".zcode","cli")` 存在才写（读 prev → 先 `mergeZcodeConfig(prev)` 校验 → 备份/noteCreated → `mergeZcodeConfig(prev, zcodeHookGroup(opts.nodePath, entry))` → `atomicWriteFile(..., 0o600)`）。
- join：`antigravityPath = antigravityHooksPath(home)`，仅当 `join(home,".gemini")` 存在才写（`mkdirSync(dirname)`；同样先校验、备份、合并 `antigravityHookDoc(opts.nodePath, entry, os)`）。
- manifest 新增 `zcodePath?: string; antigravityPath?: string; antigravity?: { created: boolean; writtenSha256: string }`；`files` 追加写入的路径。任何失败走现有 `rb.rollback()`。
- leave：zcode 存在则 `mergeZcodeConfig(raw)` 剔除自有条目（不改 enabled）；antigravity 存在则：若 `manifest.antigravity.created` 且当前 sha256 等于 writtenSha256 → `rmSync`，否则写 `mergeAntigravityHooks(raw)`。
- 旧 manifest 没有这些字段时必须兼容（可选字段）。

### `core/probe.ts` / `core/probe-status.ts`
- `assembleProbeReport` 新增能力 `hook_zcode`、`hook_antigravity`：`configured` 取 `zcodeHookState/antigravityHookState(...).configured`，`gateError` 取对应 GateError；receipt/TTL 逻辑复用 `hookCapability`。
- `HOOK_STATUS_CONTRACT.agents` 增加 `"zcode"`、`"antigravity"`；`recordHookOutcome` 无需改。

### 规则误判修复
- `src/lib/monitor/rules.ts` `zcode_snapshot_host.pattern` 改为 `zcode\\.z\\.ai(?!(?::\\d+)?/(?:[a-z]{2}/)?docs(?:[/?#]|$))`（排除 `/docs`、`/en/docs`、`/cn/docs`），`/v2/oss-credentials` 仍命中。
- `src/lib/monitor/snapshot.ts` `classifySnapshot`：当 `blob` 中所有 `zcode.z.ai` 引用都是文档路径（同上正则含义）时，不返回 `SNAPSHOT_RULE.host`；其余逻辑不变。

### UI / 前端
- `src/lib/monitor/types.ts` `AgentId` 增加 `"antigravity"`；`src/lib/monitor/agents.ts` 增加
  `antigravity: { id, name: "Antigravity", vendor: "Google", process: "antigravity", hookPath: "~/.gemini/config/hooks.json", projectHookPath: ".agents/hooks.json", models: ["gemini-3-pro", "gemini-3-flash"], transcriptHint: "~/.gemini/antigravity/brain/", letter: "A" }`，
  `AGENT_ORDER` 在 `"claude"` 之后加入 `"antigravity"`；`NATIVE_TOOL_MAP` 增加 `run_command→Bash`、`write_to_file→Write`、`replace_file_content→Edit`、`multi_replace_file_content→MultiEdit`、`view_file→Read`、`list_dir→Glob`、`find_by_name→Glob`、`grep_search→Grep`、`read_url_content→WebFetch`、`invoke_subagent→Task`。
- `src/lib/monitor/fingerprint.ts` `TOOL_AGENT` 增加 Antigravity 工具名 → `"antigravity"`。
- `core/egress-schema.ts` `GITHUB_AGENT_IDS` 增加 `'antigravity'`。
- `src/lib/monitor/store.ts` `agentCardDisplay` 的 lookupCap 增加 `zcode → hook_zcode/hookZcode`、`antigravity → hook_antigravity/hookAntigravity`。
- `src/routes/index.tsx` `HOOK_ADAPTERS` 增加 `["zcode","hook_zcode"]`、`["antigravity","hook_antigravity"]`（类型联合同步扩展）。
- `src/routes/install.tsx` `SUPPORTED` 增加 `zcode`、`antigravity`；`SNIPPETS` 增加 `zcode: ~/.zcode/cli/config.json → ZCODE_HOOK`、`antigravity: ~/.gemini/config/hooks.json → ANTIGRAVITY_HOOK`；hint：zcode 追加 `tx("zcodeMustEnable")`，antigravity 追加 `tx("antigravityMustEnable")`。
- `src/lib/monitor/hooks-config.ts`：`ZCODE_HOOK` 改为 join 实际写入的形状（hooks.enabled=true + process 条目）；新增 `ANTIGRAVITY_HOOK`（命名 hook `nmzp`）；`ATTACH_HINT_ZH` 改为「Grok / Claude / Codex / ZCode / Antigravity 五个适配器；Codex 需宿主内信任；ZCode 需 hooks.enabled=true 且新会话生效；Antigravity 需重启 IDE，Windows 有不触发的公开报告；回执只证明适配器被调用」；`PROBE_CONFIG.processes` 加 `zcode`、`antigravity`。
- `src/lib/monitor/i18n.ts`：`attachNote`、`hookLayerBody` 改为五个适配器的表述；`zcodeMustEnable` 改为「join 会把 ~/.zcode/cli/config.json 的 hooks.enabled 设为 true 并写入 process 型 PreToolUse；ZCode 在会话启动时快照配置，需开新会话；看板以回执为准」；新增 `antigravityMustEnable`（zh/en）：「join 写 ~/.gemini/config/hooks.json 的命名 hook nmzp；需完全退出并重启 Antigravity；Windows IDE 有 hook 不触发的公开报告，未收到回执前显示『配置存在，宿主未回执』」。
- 保留所有现有 i18n 键与 `not implemented` 字样（有测试断言）。

## 4. 验收（全部必须通过）
```
node --experimental-strip-types --test --test-timeout=60000 core/zcode-hooks.test.ts core/antigravity-hooks.test.ts core/install-hooks.test.ts core/codex-hooks.test.ts core/hook-process.test.ts core/hook-protocol.test.ts core/probe.test.ts core/hook.test.ts core/install.test.ts core/hook-protocol-grok-shape.test.ts
node --experimental-strip-types --test --test-timeout=60000 src/lib/monitor/*.test.ts
npx tsc --noEmit
npx eslint core src
```
- 新增测试文件 `core/zcode-hooks.test.ts`、`core/antigravity-hooks.test.ts` 与 `core/probe.test.ts`、`src/lib/monitor/guard.test.ts` 中的新用例是验收标准，不得改动。
- 手工检查：`grep -rn "ZCode adapter is not implemented\|Codex adapter is not implemented\|无适配器" src core` 不再出现指向 zcode/antigravity 的过时文案。
