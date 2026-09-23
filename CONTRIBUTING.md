# Contributing to NMZP Monitor

NMZP Monitor is an open-source security guardrail for AI coding agents. Changes to host adapters, security rules, privacy-preserving rewrite, and audit change who gets blocked. Those changes need tests that show the new behavior.

[中文 README](README.md) · [English](README.en.md) · [Security policy](SECURITY.md)

## Development Setup

Install Node.js 24 or newer. `package.json` sets `"engines": { "node": ">=24" }`.

For a published installation, use the [release installation guide](docs/install.en.md); npm and developer tests are not prerequisites. For source development, start from a checkout with Node 24 or newer:

```bash
npm ci
npm run typecheck
npm run build
npm run lint
```

| Script | What it runs |
| --- | --- |
| `npm test` | Broad `node scripts/run-tests.mjs` discovery of test/spec files, excluding `node_modules`, `dist`, and dot directories. Includes environment-sensitive tests; review prerequisites below before using it |
| `npm run typecheck` | `tsc --noEmit` |
| `npm run build` | `vite build` |
| `npm run lint` | `eslint .` |
| `npm run dev` | Vite dev server for the board UI. This does not install hooks and is not live enforcement |
| `npm run pack` | Builds `nmzp-core.tgz`. Do not pack as part of an ordinary documentation change |

Choose an explicit test-file list after reviewing imports and fixtures, as described in [Testing requirements](#testing-requirements). Only pack a runtime after the checks appropriate to that change pass.

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
| `core/serve.ts` | Core HTTP composition and legacy routes; delegates new policy and audit routes |
| `core/persist.ts` | `NmzpStore`: permissions, device state, policy and event coordination |
| `core/policy/` | Validated immutable snapshots, exclusive publication, revision history, recovery, proposal and history HTTP routes |
| `core/audit/` | Bounded recent projection, JSON codec, SQLite history, worker coordination, queries, export, retention and migration |
| `core/audit/outbox.ts` | Bounded persistent device event/receipt delivery queue |
| `src/lib/monitor/rules.ts` | Built-in security rules |
| `src/lib/monitor/engine.ts` | Decision, correlate, privacy rewrite |
| `src/lib/monitor/overrides.ts` | Which block rules cannot be downgraded |
| `src/lib/monitor/privacy.ts` | Privacy patterns and custom rules |
| `src/routes/`, `src/components/` | Board UI |
| `docs/superpowers/specs/` | Design notes. They are history, not a second source of truth if code has moved |
| `docs/install.md`, `docs/agents.md`, `docs/audit.md`, `docs/limits.md`, `docs/policy-*.md` | Installation, host behavior, audit, policy customization/protocol and runtime procedures. English guides use `.en.md` |
| `docs/plans/local-semantic-review.md` | Planned local-model path. The model layer is not connected |

### Where to make a change

| Goal | Start here and verify |
| --- | --- |
| Add a host adapter | Protocol parsing, response conversion, install ownership, adapter tests; then a real host invocation and receipt |
| Adjust custom rules | [Policy guide](docs/policy-customization.en.md), domain validation, synthetic matches and near misses |
| Change publication or restore | `core/policy/` writer coordination, snapshots, revision history and recovery; CAS and unknown-commit tests |
| Change audit storage or export | `core/audit/` store, worker and HTTP boundary; restart, retention, corruption and cancellation tests |
| Change a frontend/backend contract | Existing consumers and `tests/compat/` real-server tests; preserve permissions, fields, ordering and data scope |

Prefer data configuration for supported custom behavior. A new built-in detector, adapter protocol, or storage format still requires a program change. Keep domain computation, storage, host protocol conversion, and runtime coordination separate; see the [runtime guide](docs/policy-runtime.en.md) and [proposal contract](docs/policy-proposal-contract.en.md).

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

Inspect each selected test file and its imports before execution. Test-name filters do not prevent import-time side effects. `npm test` discovers the broad suite and does not forward a file-selection argument; it is not the default first-install or documentation check.

| Layer | Purpose and prerequisites |
| --- | --- |
| Domain/unit | Synthetic inputs and pure policy/protocol behavior. Use explicit filenames; review any filesystem/process helpers too |
| Real-server contract | Temporary data directories, generated test certificates, `127.0.0.1` random ports, and test-owned child processes. Verify real responses with existing consumers; mocked fetch alone is insufficient |
| Host/environment | Actual hook loading, trust, host enforcement, installation/uninstallation or Windows ACL. Requires a dedicated authorized environment and an explicit cleanup plan; synthetic stdout is not real-host proof |

Examples of scoped commands, from the repository root after reviewing the selected files:

```bash
node --experimental-strip-types --test core/policy/snapshot.test.mjs src/lib/monitor/policy-proposal.test.ts
node --experimental-strip-types --test tests/compat/customization.test.mjs tests/compat/policy-proposal-runtime.test.mjs
```

Select additional files according to the changed paths and risks. These examples are not a complete release check. `core/install.test.ts` and `core/snapshot-guard.test.ts` include Windows ACL operations; the snapshot flow can reject a running ZCode with `zcode_running`. Do not run such tests on a daily-use host as an installation step or remove safety guards to make them pass. Do not use real credentials, production data, or live tool execution as test fixtures. A broad release run is appropriate only after its complete file list and environment prerequisites have been reviewed; report exclusions explicitly.

For documentation-only changes, check relative links, examples, and source-backed values. If a test reads an edited document, run that explicit file after checking its side effects. `core/lan-viewer.test.ts` checks README viewer commands and accidental private deployment details; keep those constraints and use its temporary, loopback fixtures.

- Run `npm run typecheck` when TypeScript changes; `tsconfig` includes TypeScript under `src` and `core`; this does not type-check `.mjs` files or the separate `tests/` tree.
- Run `npm run build` when the board UI changes.
- Run `npm run lint` for linted-source changes. Markdown and GitHub forms are not in the ESLint set.
- Record Node version, explicit file lists, results, exclusions, and any unexplained failures. Do not call a scoped pass a full-suite pass.

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
- Do not force-push `main` or skip checks. Keep commit, push, merge, and deployment within the maintainer-approved scope.

## Reporting Bugs

Open a [bug report](.github/ISSUE_TEMPLATE/bug_report.yml). Include the host adapter, the policy mode, and whether `hook-status.json` has a receipt. A receipt provides evidence that the hook ran; it does not by itself prove that the host enforced the decision. A missing receipt means that evidence is unavailable, not necessarily that the host never invoked NMZP. Check configuration, trust and loading, invocation, process errors, local receipt writing, and delivery before assigning a cause. Distinguish missing evidence from an incorrect policy decision.

Strip secrets before you paste a tool call.

## Security Vulnerabilities

Use [SECURITY.md](SECURITY.md). A public bug issue is the wrong channel for an unfixed vulnerability.
