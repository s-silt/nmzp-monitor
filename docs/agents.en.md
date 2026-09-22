# Host adapters

[English home](../README.en.md) · [中文](agents.md)

Thirteen adapters are maintained in this repository. They call hook interfaces the hosts publish. They are not a vendor certification, and the vendors do not install them for you. `join` writes a config only where that host's directory already exists.

A written file is not protection of every later action. The host must load the hook, trust or restart must already be done, this call must enter NMZP, the policy mode must be enforcing, and the host must apply the deny or rewrite.

Copilot, Windsurf, Aider, and Cline are catalog names only. They have no PreToolUse adapter.

| Agent | Written on join | Block | Rewrite | Audit | Extra |
| --- | --- | :---: | :---: | :---: | --- |
| Grok | `~/.grok/hooks/nmzp.json` | yes | yes | yes | The host may fail open on timeout or crash. A Claude-shaped copy no-ops when `GROK_HOOK_EVENT` and `GROK_SESSION_ID` are both set |
| Claude Code | `~/.claude/settings.json` | yes | yes | yes | The host may fail open on timeout or crash |
| Codex | `~/.codex/hooks.json` | yes | yes | yes | Runs only after in-host trust. NMZP does not write the trust table. See below |
| ZCode | `~/.zcode/cli/config.json` | yes | yes | yes | Turns on `hooks.enabled`. A new session is required |
| Antigravity | `~/.gemini/config/hooks.json` | yes | becomes ask | yes | Restart the IDE. Public reports of hooks not firing on Windows |
| Gemini CLI | `~/.gemini/settings.json` | yes | yes | yes | Event name `BeforeTool`. Written only when `settings.json` already exists |
| Cursor | `~/.cursor/hooks.json` | yes | becomes ask | yes | An allow is explicit `permission: allow`. Public reports of hooks not firing since 2.1.x. A Claude-flagged copy that sees `cursor_version` returns empty |
| Kimi Code | `~/.kimi-code/config.toml` | yes | deny instead | yes | TOML is split on hook blocks. A design note records that host as fail-open on timeout. This repository has not retested the Kimi binary |
| Trae | `~/.trae/hooks.json`, `~/.trae-cn/` | yes | yes | yes | A Claude-flagged copy that sees `llm_tool_name` returns empty |
| Qwen Code | `~/.qwen/settings.json` | yes | yes | yes | — |
| Qoder | `~/.qoder/settings.json` | yes | yes | yes | — |
| Lingma | `~/.lingma/`, `~/.qoder-cn/` | yes | yes | yes | — |
| CodeBuddy | `~/.codebuddy/settings.json` | yes | yes | yes | Rewrite key is `modifiedInput` |

NMZP keeps its own hook work inside a 6.5 second budget (`HOOK_BUDGET_MS`) because host timeouts are treated as fail-open. This repository does not ship those host runners. `core/cli.ts` help text still lists `grok|claude|codex` only. The implementation accepts every id in `HOOK_AGENTS`.

Rewrite changes arguments before the tool runs. `PostToolUse` and `AfterTool` return empty stdout and are not evaluated.

<a id="codex"></a>

## Codex

The adapter is maintained here and uses the PreToolUse file Codex exposes. It is not an OpenAI product, partnership, or certification. There is no record that every Codex version is compatible.

### Implemented in source

`join` writes `~/.codex/hooks.json` with the marker `NMZP PreToolUse v1` and a timeout of 8 seconds. On Windows the command is a PowerShell encoded command for the local runtime. NMZP does not write `[hooks.state]` in `~/.codex/config.toml`. `core/codex-hooks.ts` only reads that file and classifies not configured, untrusted, modified, disabled, feature off, and trusted. A successful join prints `codex=/hooks approve NMZP PreToolUse v1`.

A deny is `permissionDecision: deny`, exit code 0. A rewrite is `permissionDecision: allow` plus `updatedInput`. A rewrite without `updatedInput` becomes a deny (`rewrite_missing_updated_input`). After stdout is confirmed, NMZP writes `~/.nmzp/hook-status.json`. A joined device also reports the evaluation. While stopped, the hook allows the call and does not upload the tool body. Events other than `PreToolUse` are not evaluated. `Bash` or `apply_patch` without a string `command` is denied as `missing_tool_command`.

### Automated tests

`core/codex-hooks.test.ts` uses synthetic stdin and an isolated fake HOME. It covers merge, install and leave, an ordinary command, a dangerous command, malformed input, oversized input, the trust hash, and the case where `hooks.json` exists but is not trusted. Those tests do not start a Codex client. A deny from NMZP is not evidence that Codex refused to run the tool.

### Real client

Not verified. This repository has no record that names a Codex version, an operating system, the trust step, the scenario, the expected result, the observed result, and the date.

## ZCode

Two separate mechanisms.

1. The hook. After join writes `~/.zcode/cli/config.json`, a new session runs `nmzp hook --agent zcode`. A running `ZCode.exe` without that new session has no receipt.
2. An NTFS tripwire for an older pattern that packed `~/.zcode/v2/checkpoints`. It does not depend on the hook. It stays off until `nmzp snapshot apply`. Apply and restore refuse while ZCode is running.

The tripwire is that one directory. An administrator, SYSTEM, or the owner can undo the ACL. It does not stop an in-memory pack, another directory, a pipe, or a custom domain. ZCode 3.14.0 removed that upload pipeline. The tripwire is for leftover 3.12.3-style clients. It is not a claim that every version is still uploading. `/api/v1/snapshot/upload-credential` and `/v2/oss-credentials` are not the same thing as a connection to the product domain. `rights stop` does not remove the ACL. `nmzp snapshot restore` does.

Join also installs PermissionRequest, SessionStart, UserPromptSubmit, and Stop. PermissionRequest does not grant host consent. If that stage still needs an argument rewrite, the reason is `rewrite_requires_pretooluse`. Lifecycle events store a receipt without the prompt body under `events.zcode`. `hooks.zcode` stays the PreToolUse receipt.

A plugin is not exempt because of its name, author, `official` field, or an official domain. NMZP inspects hook and MCP declarations it can see. It does not recursively parse external scripts, archives, or installed plugin code. Remote MCP internals and host TLS are outside this check.
