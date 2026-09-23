<p align="center">
  <img src="public/favicon.svg" width="64" alt="NMZP">
</p>

<h1 align="center">NMZP Monitor</h1>

<p align="center">
  A guard for coding agents on the LAN
  <br>
  <sub>Policy checks, argument rewriting, and audit records for tool calls submitted through host hooks.<br>No chat transcript collection. Blocking and rewriting depend on host support and policy settings.</sub>
</p>

<p align="center">
  <a href="README.md">中文</a>
  &nbsp;·&nbsp;
  <strong>English</strong>
</p>

<p align="center">
  <a href="#how">How it works</a>
  &nbsp;·&nbsp;
  <a href="#agents">Agents</a>
  &nbsp;·&nbsp;
  <a href="#start">Quick start</a>
  &nbsp;·&nbsp;
  <a href="#audit">Audit</a>
  &nbsp;·&nbsp;
  <a href="#limits">Limits</a>
</p>

<p align="center">
  <img alt="MIT" src="https://img.shields.io/badge/license-MIT-ecece6?labelColor=0A0B0D">
  <img alt="Node 24+" src="https://img.shields.io/badge/node-%3E%3D24-ecece6?labelColor=0A0B0D">
  <img alt="version" src="https://img.shields.io/badge/version-0.2.5-ecece6?labelColor=0A0B0D">
</p>

<p align="center">
  <img src="docs/screenshots/overview-fleet-dark.png" alt="NMZP dashboard showing joined machines, agent discovery, and hook receipts" width="920">
</p>

A dedicated CT runs the core. Guarded PCs run a probe. The core uses Node's own HTTPS and devices pin the self-signed certificate. No root CA is installed. Licensed [MIT](LICENSE). Current version 0.2.5.

This patch fixes audit-worker shutdown draining and adds scoped stability regression checks on Linux and Windows; frontend contracts and data formats are unchanged. After upgrading, rewrite retries tied to an older engine version still return `historical_policy_unavailable` when safe reconstruction is unavailable; old history is not rewritten. Publishing code and an archive does not automatically upgrade the core or devices.

| Capability | What it provides |
| --- | --- |
| **Pre-execution checks** | Policy decisions, argument rewriting, and audit for calls submitted through host hooks |
| **Online policy updates** | Validate JSON patches and publish new versions while preserving protected-rule constraints |
| **Optional persistent audit** | SQLite history queries, retention, and compressed export, explicitly enabled by an administrator |

<a id="how"></a>

## How it works

NMZP receives tool requests through host hooks. In enforcing mode, its rules and policy determine whether to request a denial, rewrite arguments, or allow and record the call. Protection requires the hook to be loaded and trusted where necessary, and the host to honor its response. Permissive and off modes do not enforce policy blocks.

```text
Coding agent → tool request → host hook
                                  │
                 not invoked ─────┴──► not checked by NMZP
                                  │
                            NMZP policy
                                  │
                 deny / rewrite arguments / record
```

Argument rewriting affects the tool input about to execute; it cannot erase model-generated content or recall a request already sent. Calls that bypass the hook are not checked by NMZP, though the host may still apply its own permission controls. See [SECURITY.md](SECURITY.md) for the full security model.

<a id="agents"></a>

## Agents

This repository maintains 13 host-hook adapters. `join` writes configuration only where the host directory already exists. The table describes implemented adapter capabilities; actual behavior depends on host loading, trust, and enforcement. These are NMZP-maintained adapters, not vendor certifications.

| Agent | Config | Block | Rewrite |
| --- | --- | :---: | :---: |
| Grok · Claude Code | Each host's hook file | yes | yes |
| Codex | `~/.codex/hooks.json` | yes | yes, after trust |
| ZCode | `~/.zcode/cli/config.json` | yes | yes, new session |
| Gemini CLI | `~/.gemini/settings.json` | yes | yes |
| Cursor · Antigravity | Each host's hooks file | yes | becomes ask |
| Kimi Code | `~/.kimi-code/config.toml` | yes | rewrite becomes deny |
| Trae · Qwen · Qoder · Lingma · CodeBuddy | Each host's config | yes | yes |

**Codex integration:** trust `NMZP PreToolUse v1` through `/hooks` inside Codex. NMZP does not write the trust table. The repository includes synthetic-input tests but no end-to-end verification record from a real Codex client. See [docs/agents.en.md](docs/agents.en.md) for host differences, verification scope, and the ZCode tripwire.

Copilot, Windsurf, Aider, and Cline currently have discovery entries only, not hook adapters.

The built-in set is 82 rules: 37 block, 44 log, 1 rewrite. Twenty-nine of the block rules cannot be downgraded from the board or a proposal while the mode is enforcing. The default mode is enforcing. Saving a policy, the device syncing it, and the host actually denying are three separate steps. Ordinary relay settings and MCP authorization are logged; dangerous download-and-execute or file-upload hooks remain guarded. See the [policy guide](docs/policy-customization.en.md) for JSON hot updates, privacy rewrites, and changes that require a core upgrade.

<a id="start"></a>

## Quick start

Node.js 24 or newer is required. Transfer join bundles and tokens as files through a secure channel; do not paste them into chat or commit them to the repository.

### 1. Download and deploy the release

Download `nmzp-core.tgz` and `SHA256SUMS.txt` from the [v0.2.5 release](https://github.com/s-silt/nmzp-monitor/releases/tag/v0.2.5). Follow the [installation guide](docs/install.en.md) to verify the archive, deploy the core, and issue a join bundle. Using a release does not require npm or development tests. To build from source, use the separate [development workflow](CONTRIBUTING.md#development-setup).

```bash
runuser -u nmzp -- env NMZP_DATA=/var/lib/nmzp NMZP_PUBLIC_URL=https://<CT-IP>:8787 \
  node /opt/nmzp/nmzp.mjs ticket --out /var/lib/nmzp/join-bundle.json
```

### 2. Guarded PC: join the device

On the target PC, prepare the runtime files and the join bundle issued for that device, then run:

```powershell
.\nmzp.cmd join .\join-bundle.json
```

Fully quit and reopen running desktop hosts after joining. For Codex, also trust `NMZP PreToolUse v1` through `/hooks` inside the host.

### 3. Admin PC: open the management board

**Keep `admin.token` with the administrator; do not distribute it as part of device enrollment.** On the admin PC, prepare the runtime files, the bundle needed by the board, and the admin token, then run:

```powershell
.\nmzp.cmd board --bundle join-bundle.json --token-file admin.token
```

Open `http://127.0.0.1:8788` and select the token file to sign in. One PC may serve both roles; complete each role's steps separately.

Other LAN users can visit `http://<CT-IP>:8789` for the read-only view. It requires no admin token and cannot change policy. The viewer command is `nmzp viewer --host <private-ip> --port 8789 --allow-cidr <CIDR>`, from the unit `nmzp-viewer.service`. `GET /health` reports service health, not proof of protection.

**Stop and uninstall:** `.\nmzp.cmd stop` stops only the probe; the hooks remain. Use `.\nmzp.cmd uninstall` to uninstall, then fully quit and reopen the hosts. If you enabled the ZCode directory ACL, restore it first as described in the [installation guide](docs/install.en.md).

<a id="audit"></a>

## Audit export and AI-assisted analysis

Export filtered audit records and policy context as JSON, then use an AI service you choose to help summarize risks, investigate possible false positives, and draft policy suggestions.

**Export JSON → Review and redact → AI drafts a proposal → Validate and preview → Admin approval**

A proposal must follow `nmzp-policy-proposal/1`. The existing importer validates and previews legacy suggestions without a catalog hash. Patches with `baseRulesHash` are preview-only there and require server validation and publication. After admin approval, the core validates again before saving policy. Proposals do not automatically become built-in rules. Some preview results are estimates, not substitutes for real execution tests.

This is a user-initiated export and analysis workflow, not automatic log upload or scheduled reporting. The default recent window retains at most 2000 events. CT administrators may explicitly enable SQLite history, pagination and compressed export, subject to time and capacity limits; history completeness remains `unknown`. Check sensitive data before sharing; analysis covers only the exported records.

See the [audit guide](docs/audit.en.md) for export fields, proposal constraints, prompt-injection precautions, and preview limitations.

Routine policy changes can be validated and published as JSON proposals without releasing the program each time. See the [policy customization guide](docs/policy-customization.en.md) for proposal creation and privacy rewriting, and the [runtime guide](docs/policy-runtime.en.md) for optional storage, migration and recovery. Code or protocol changes still require a program update.

<a id="limits"></a>

## Security boundaries

- A name in the bar is discovery. A receipt is evidence that the hook ran, not proof that the host enforced the decision. A missing receipt means that evidence is unavailable, not a finished diagnosis.
- The hook is not an operating-system sandbox and not a network firewall. GitHub, OSS, and COS uploads are observed.
- A local administrator can remove the hook. A fully controlled machine is outside this design.
- Receipts can be lost while the core is unreachable. Absence of an event is not absence of risk.

See [capability limits](docs/limits.en.md) for other known limitations, and [SECURITY.md](SECURITY.md) for the full security model and reporting guidance.

<a id="plan"></a>

## Local semantic check

**Planned / the model layer is not connected.**

The proposed design adds local semantic review alongside hard rules for operations that need contextual judgment: extract minimal context, call a local model, then let NMZP combine the risk assessment with policy. A model must not override a hard-rule denial; failures, timeouts, and uncertainty must remain unknown rather than safe.

This model-call and decision path is not implemented in the current version. See the [design note and discussion figure](docs/plans/local-semantic-review.md) for the architecture, deployment considerations, and coverage limits.

## Docs and contributing

| Topic | Guide |
| --- | --- |
| Install and upgrade | [docs/install.en.md](docs/install.en.md) |
| Connect an agent | [docs/agents.en.md](docs/agents.en.md) |
| Audit and AI-assisted analysis | [docs/audit.en.md](docs/audit.en.md) |
| Custom rules and policy patches | [Policy guide](docs/policy-customization.en.md) · [Proposal contract](docs/policy-proposal-contract.en.md) |
| History storage, migration and recovery | [Runtime guide](docs/policy-runtime.en.md) |
| Security model | [SECURITY.md](SECURITY.md) |
| Contributing | [CONTRIBUTING.md](CONTRIBUTING.md) |

For source development and scoped tests, see [Contributing](CONTRIBUTING.md#testing-requirements).

`npm run dev` is the board UI dev server. It is not a hook installed on a machine.

## License

[MIT](LICENSE).
