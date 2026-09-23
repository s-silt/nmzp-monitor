# Contributing to NMZP Monitor

NMZP Monitor is an open-source security guardrail for AI coding agents. Changes to host adapters, security rules, privacy-preserving rewrite, and audit change who gets blocked. Those changes need tests that show the new behavior.

[中文 README](README.md) · [English](README.en.md) · [Security policy](SECURITY.md)

## Development Setup

Install Node.js 24 or newer. `package.json` sets `"engines": { "node": ">=24" }`.

From a clean checkout:

```bash
npm ci
npm test
npm run typecheck
npm run build
npm run lint
```

| Script | What it runs |
| --- | --- |
| `npm test` | `node scripts/run-tests.mjs`. Collects `*.test.*` and `*.spec.*` under the repo, skipping `node_modules`, `dist`, and dot directories |
| `npm run typecheck` | `tsc --noEmit` |
| `npm run build` | `vite build` |
| `npm run lint` | `eslint .` |
| `npm run dev` | Vite dev server for the board UI. This does not install hooks and is not live enforcement |
| `npm run pack` | Builds `nmzp-core.tgz`. Do not pack as part of an ordinary documentation change |

`npm run format` exists (`prettier --write .`). Do not run it across the whole tree unless the change is a formatting change you were asked to make.

The package is `"private": true`. Do not remove that flag in a drive-by edit.

Do not commit `admin.token`, `join-bundle.json`, `.env` files, or a real `~/.nmzp` directory.

## Project Structure

| Path | Role |
| --- | --- |
| `core/hook-protocol.ts` | `HOOK_AGENTS` and the stdout shapes for deny, rewrite, and allow |
| `core/hook.ts` | Hook process: cache, evaluate, fail paths, receipts |
| `core/host-adapters.ts` | Install writers for Kimi, Trae, Qwen, Qoder, Lingma, CodeBuddy, Gemini CLI, Cursor |
| `core/codex-hooks.ts` | Codex `hooks.json` merge and read-only trust status |
| `core/*-hooks.ts` | ZCode, Antigravity, and the other dedicated installers |
| `core/install.ts` | `join` / `leave` |
| `core/serve.ts` | Core HTTP API, including policy rejection of protected-rule downgrades |
| `src/lib/monitor/rules.ts` | Built-in security rules |
| `src/lib/monitor/engine.ts` | Decision, correlate, privacy rewrite |
| `src/lib/monitor/overrides.ts` | Which block rules cannot be downgraded |
| `src/lib/monitor/privacy.ts` | Privacy patterns and custom rules |
| `src/routes/`, `src/components/` | Board UI |
| `docs/superpowers/specs/` | Design notes. They are history, not a second source of truth if code has moved |
| `docs/install.md`, `docs/agents.md`, `docs/audit.md`, `docs/limits.md` | Longer procedures. Home pages link here. English twins use the `.en.md` suffix |
| `docs/plans/local-semantic-review.md` | Planned local-model path. The model layer is not connected |

`core/cli.ts` help text for `nmzp hook --agent` still lists `grok|claude|codex` only. The accepted ids are `HOOK_AGENTS`. Fixing that help line is welcome. Do it with the test that prints usage, if one asserts the old string.

## Adding a Host Adapter

A new coding agent is supported only when the hook really runs.

1. Confirm the host's hook mechanism from its own documentation: event name, stdin JSON, deny stdout, rewrite stdout, and what happens on timeout or a non-zero exit.
2. Add the id to `HOOK_AGENTS` in `core/hook-protocol.ts` only if `nmzp hook --agent <id>` will be invoked by that host.
3. Add a `formatHookResponse` branch. Map deny, pass, and rewrite onto that host's fields. If the host cannot rewrite, deny with `rewrite_unsupported_host`. Do not invent an allow that the host will ignore.
4. Add the install writer. Extra hosts belong in `core/host-adapters.ts`. Write a config only when that host's directory or settings file already exists.
5. Add tests for: parsing a fixture payload, a deny response, a rewrite response or the explicit rewrite-to-deny, idempotent install, and leave removing only the NMZP-owned hook.
6. Document the adapter in both READMEs, including the fail-open or trust step. Do not list it under "Works with" before those tests exist.
7. A discovery-catalog name in `src/lib/monitor/agents.ts` is not an adapter. Copilot, Windsurf, Aider, and Cline are catalog names today.

Do not claim the host is an OpenAI, Google, Anthropic, or other official integration.

## Adding a Security Rule

1. Add one `RuleDef` in `src/lib/monitor/rules.ts`. Keep the id stable: `RULE_ID_RE` is `^[a-z][a-z0-9_]{0,63}$`.
2. Choose `action` and `family` deliberately. `action: "block"` plus family `exfil`, `tamper`, `isolate`, `poison`, or `secret` makes the rule non-downgradable (`isProtectedRule`). Do not put a rule in those families just to make a list look stricter.
3. Add a test that shows the decision on a minimal tool call, and a test that a near-miss does not match. Shell rules have a history of matching the sample string inside a script.
4. If the rule changes correlate, privacy rewrite, or audit redaction, test that path too.
5. Update the counts in `README.md`, `README.en.md`, and `SECURITY.md` from a fresh count of `RULES`. Do not copy a number from an older document.

Current counted set, for the tree this file was written against: 82 rules, 37 block, 44 log, 1 rewrite, 29 non-downgradable. Re-count before you repeat those numbers.

## Testing Requirements

- Run `npm test` for a behavior change. A docs-only change still needs `npm test` if it edits a string a test reads. `core/lan-viewer.test.ts` requires `README.md` to contain `nmzp viewer` and `nmzp-viewer.service`, and it rejects a specific private address and two hostnames. Keep those constraints if you touch `README.md`.
- Run `npm run typecheck` when TypeScript changes.
- Run `npm run build` when the board UI changes.
- Run `npm run lint` when you touch linted sources. New Markdown and GitHub forms are not in the ESLint set.

A pull request that changes any of the following must include a test that fails before the change and passes after it:

- security rules
- host adapters and hook stdout
- privacy-preserving rewrite
- audit export, redaction, receipt handling, or policy-proposal import

A test that only asserts a UI string is not enough for those four.

## Security-Sensitive Changes

- Do not log tokens, hook bodies, or raw commands in new diagnostics.
- Do not add telemetry, and do not upload tool-call bodies to a new endpoint.
- Do not weaken `protected_rule_override` or `protected_rule_exemption` to match a document.
- Do not describe observation paths as blocking.
- Say when a host can fail open. Hiding that makes the project less trustworthy, not more.
- Experimental native sandbox code reports `productionReady: false`. Do not flip that flag in a documentation pull request.

Report vulnerabilities through [SECURITY.md](SECURITY.md), not a public issue.

## Pull Request Guidelines

Use the pull request template.

- One change per pull request.
- Describe the security impact even when the answer is "none".
- Include how you ran tests. Paste the command, not a paraphrase of success.
- Update `README.md` and `README.en.md` together when the user-facing behavior changes.
- Do not attach `admin.token`, a join bundle, a real audit export, or an unsanitized tool-call log.
- Do not add an OpenAI logo, and do not write "official", "partner", "approved", or "certified" about Codex.
- Do not commit generated `dist/` or `nmzp-core.tgz`.
- Do not force-push `main`, and do not use `--no-verify`, unless a maintainer explicitly asks.

## Reporting Bugs

Open a [bug report](.github/ISSUE_TEMPLATE/bug_report.yml). Include the host adapter, the policy mode, and whether `hook-status.json` has a receipt. A receipt provides evidence that the hook ran; it does not by itself prove that the host enforced the decision. A missing receipt means that evidence is unavailable, not necessarily that the host never invoked NMZP. Check configuration, trust and loading, invocation, process errors, local receipt writing, and delivery before assigning a cause. Distinguish missing evidence from an incorrect policy decision.

Strip secrets before you paste a tool call.

## Security Vulnerabilities

Use [SECURITY.md](SECURITY.md). A public bug issue is the wrong channel for an unfixed vulnerability.
