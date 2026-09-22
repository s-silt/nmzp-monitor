# Security Policy

NMZP Monitor is an open-source security guardrail for AI coding agents. This document describes the boundary this repository implements. It is not a certification and it is not an audit report.

Current release: **0.2.3**. License: [MIT](LICENSE).

## Security Model

NMZP sits on the tool-execution boundary.

```text
Coding agent
      │
      ▼
 Tool call
      │
      ▼
 Host hook (only if the host invokes NMZP)
      │
      ▼
 Security policy
      │
      ├── block   → host is asked to deny the tool
      ├── rewrite → host is asked to run updated arguments
      └── detect  → tool is allowed and a security event is recorded
      │
      ▼
 Tool execution
```

The hook process is `nmzp hook`. `join` installs that command into each supported coding agent's own hook config. The policy engine is the rule list in `src/lib/monitor/rules.ts`, plus operator overrides, exemptions, and privacy rules. A joined machine prefers the core's `/api/v1/evaluate` result and falls back to a local policy cache.

A second, narrower control exists for one directory: an optional NTFS ACL on `~/.zcode/v2/checkpoints`, applied only by `nmzp snapshot apply`. It is not part of the tool-call hook.

A probe can also observe TCP peer metadata and some upload warnings. Observation does not block the tool call.

NMZP is vendor-neutral. The Codex adapter is one host adapter. Nothing in this repository is an OpenAI product, partnership, or certification.

## Trust Boundaries

| Boundary | What NMZP trusts | What it does not trust |
| --- | --- | --- |
| Host hook runner | The host's decision to start `nmzp hook` and to honor stdout | That every tool call will be submitted. A missing, untrusted, crashed, or timed-out hook is outside NMZP |
| Tool-call payload | The JSON the host passes on stdin, parsed by `core/hook-protocol.ts` | The agent id inside that JSON. It is self-reported. Rule scope is tool and field, not agent identity |
| Operator policy | A policy document the core has validated | A proposal that tries to downgrade a protected rule, exempt one, or smuggle mode and upload settings |
| Local administrator | Nothing. The operator is inside the trust boundary | Hooks, config files, the probe, and discretionary ACLs. An administrator can remove them |
| Compromised host | Nothing | A host that already controls the agent, the hook binary, or the policy cache can bypass or impersonate NMZP |
| Network path to the core | The pinned certificate on the device | A network filter as a product feature. OSS and COS warnings are observation |

Discovery of an install or a process is not a trust decision. `hook-status.json` is a receipt that the hook ran. A config file on disk is not a receipt.

## Protected Actions

When the hook runs and the policy mode is `enforcing`, NMZP can:

- **Block** a tool call by returning the host's deny shape. Whether the tool stays unexecuted depends on the host honoring that response.
- **Rewrite** outbound tool arguments before execution, for privacy hits that are not credential-shaped, for custom replace rules, and for the built-in `persona_cloak` timezone and locale tags. Codex, Grok, Claude Code, ZCode, Qwen Code, Qoder, Lingma, Trae, Gemini CLI, and CodeBuddy have a rewrite response. Kimi Code turns a rewrite into a deny. Antigravity and Cursor turn a rewrite into an ask.
- **Detect and audit** by allowing the call and storing a security event, up to 2000 events on the core, plus a local hook receipt.
- **Refuse to relax** 29 built-in block rules whose family is `exfil`, `tamper`, `isolate`, `poison`, or `secret`. The core returns `protected_rule_override` or `protected_rule_exemption` instead of saving that change.

The built-in set in this tree is 81 rules: 37 block, 43 log, 1 rewrite. Eight block rules are outside the non-downgradable set: `telemetry_drop`, `zcode_feedback_upload`, `dangerous_delete`, `disk_overwrite`, `curl_pipe_shell`, `reverse_shell_pattern`, `encoded_payload_exec`, `webshell_pattern_in_write`.

Credential-shaped secrets on an outbound tool call are blocked. A single read of a `.env`-like path (`env_file_read`) is log, not block. Reading a session transcript is not a default block.

`permissive` logs instead of blocking. `off` allows. A stopped policy allows the call and does not upload the tool body.

## Security Invariants

These are properties the current code is written to keep. They are not a formal proof.

- A hook body over `BODY_LIMIT` (262144 bytes) is denied as `payload_too_large`. It is not truncated and then allowed.
- A rewrite decision without `updatedInput` is denied as `rewrite_missing_updated_input`.
- With no policy cache, tool names in `NEED_CHECK_TOOLS`, and names matching `command|write|edit|patch|fetch|bash|shell`, are denied as `no_policy_cache`. Other tool names are allowed as `no_cache_low_risk`. `Read` is not in `NEED_CHECK_TOOLS`.
- If local evaluation throws, the hook denies (`offline_eval_failed` or `lock_timeout`). This is the hook process failing closed. It does not help when the host never starts the process.
- The hook budget is 6500 ms (`HOOK_BUDGET_MS`). Codex and most other written hook entries use timeout 8. Gemini CLI's entry uses 8000, which that host treats as milliseconds. The budget exists because host runners are treated as fail-open on timeout. ZCode's hook entry does not set its own timeout field.
- NMZP does not write Codex `[hooks.state]` trust. An untrusted Codex hook is not run by Codex.
- Join writes a host adapter only when that host's directory or settings file is already present. It does not invent a product install.
- The LAN viewer rejects mutating methods and admin routes even when an admin token is presented.
- Native sandbox and protected-session code set `productionReady` to false. They are not the shipping enforcement path.

## Known Limitations

- **The hook can fail open at the host.** If the coding agent does not invoke NMZP, the tool runs without this policy. The hook budget exists because host runners are treated as fail-open on timeout or crash. Codex skips an untrusted hook. The design note `docs/superpowers/specs/2026-09-20-domestic-host-adapters-design.md` records Kimi's hook timeout as seconds, default 30, fail-open. That note is not a fresh test of the Kimi binary. Cursor and Antigravity have public reports of hooks not firing. NMZP cannot close that gap from inside a hook that was not called.
- **A local administrator can bypass it.** Removing the hook file, disabling the host's hook feature, or restoring an ACL is enough. The ZCode directory tripwire is a discretionary ACL, not a cage.
- **A fully controlled host is out of scope.** An attacker who can change the hook command, the runtime under `~/.nmzp/runtime`, or the policy cache is not stopped by this design.
- **Discovery is not protection.** A process list, an install path, or a hooks file with no receipt is not a protected agent.
- **Hook protection is not an OS sandbox.** Tool calls that never enter the hook are untouched. NMZP does not confine the agent process.
- **Hook protection is not a network firewall.** GitHub, OSS, and COS uploads are observed. The archive-size block control in the board is disabled. The experimental WFP filter is not in the ordinary pack.
- **Argument rewrite is not context erasure.** The model has already emitted the tool call. Rewrite changes the arguments the tool is about to run. `PostToolUse` and `AfterTool` return empty stdout and are not evaluated. A model gateway, if configured, inspects loopback chat/completions and does not recall a request already sent upstream.
- **Audit can be lost.** There is no durable receipt retry. The core ring keeps at most 2000 events and then drops older ones. `historyCompleteness` is stored as `unknown`. `receiptDelivery` is `best_effort`. An export is the current filter plus that window, not a complete day. Partial masking in `redacted` is not anonymity.
- **Shell coverage is textual.** Rules match tool arguments the hook can see. They do not recursively parse arbitrary scripts, archives, or installed plugin code.
- **`package.json` is `private`.** That disables npm publish. It is not a security boundary.
- **CLI help is stale.** `nmzp hook --agent` help text still lists `grok|claude|codex` only. The implementation accepts every id in `HOOK_AGENTS`.

## Reporting a Vulnerability

This repository does not publish a security email. On 2026-09-22 the GitHub API `repos/s-silt/nmzp-monitor/private-vulnerability-reporting` returned `enabled: false`. Do not treat the GitHub advisory form as an open channel until a maintainer confirms it is enabled.

Until a private contact exists, do not send vulnerability details, exploit steps, tokens, or real audit exports in a public issue. A maintainer still needs to choose a private contact and write it here.

If you already have a private channel the maintainer gave you, send impact and a minimized reproduction built from test fixtures. Do not include live `admin.token` values, join bundles, or raw tool-call bodies from a real machine.

## Responsible Disclosure

Please give the maintainer time to confirm and fix the issue before publishing details or exploit steps. This project does not advertise a bug bounty or a fixed response-time guarantee.

A report that describes impact and a plausible path is more useful than a scanner dump. Fixes that touch host adapters, rules, rewrite, or audit need tests. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Supported Versions

| Version | Security fixes |
| --- | --- |
| 0.2.3 | The maintained line. This is `package.json` and `core/constants.ts` |
| 0.2.2 and older tags | Not a maintained security branch |

There is no long-term support branch. `v0.1.0` was not a release of this repository. Existing tags start at `v0.2.2`.
