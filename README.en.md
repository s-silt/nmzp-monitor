<p align="center">
  <img src="public/favicon.svg" width="64" alt="NMZP">
</p>

<h1 align="center">NMZP Monitor</h1>

<p align="center">
  A guard for coding agents on the LAN
  <br>
  <sub>When the host hands over a tool call, NMZP checks it first: high-risk calls can be blocked, arguments can be rewritten, the rest is recorded.<br>Not you. No chat transcripts. A name on the bar is not a block.</sub>
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
  <img alt="version" src="https://img.shields.io/badge/version-0.2.3-ecece6?labelColor=0A0B0D">
</p>

<p align="center">
  <img src="docs/screenshots/overview-fleet-dark.png" alt="Overview of joined machines. A listed agent means discovery or a receipt, not that every call was blocked." width="920">
</p>

A dedicated CT runs the core. Guarded PCs run a probe. The core uses Node's own HTTPS and devices pin the self-signed certificate. No root CA is installed. Licensed [MIT](LICENSE). Current version 0.2.3.

<a id="how"></a>

## How it works

NMZP sits between a coding agent and tool execution, and only on the call the host actually submits. In enforcing mode it can deny the call, rewrite the arguments about to run, or record a security event. If the host never calls the hook, ignores the result, or the policy is permissive or off, that call is not blocked.

```text
Coding agent → tool request → host hook
                                  │
                 not invoked ─────┴──► tool runs
                                  │
                            NMZP policy
                                  │
                 deny / rewrite arguments / record
```

A rewrite does not erase text the model already generated, and it cannot recall a request already sent. Discovery, a hook firing, and the host honoring deny are three different facts. The full boundary is in [SECURITY.md](SECURITY.md).

<a id="agents"></a>

## Agents

Thirteen adapters are maintained in this repository. They call hook interfaces the hosts publish. They are not a vendor certification. `join` writes a config only where that directory already exists. Codex runs the hook only after you trust `NMZP PreToolUse v1` inside Codex. NMZP does not write that trust table. There is no end-to-end record from a real Codex client. The automated tests use synthetic input. Per-host notes and the ZCode tripwire are in [docs/agents.en.md](docs/agents.en.md).

| Agent | Config | Block | Rewrite |
| --- | --- | :---: | :---: |
| Grok · Claude Code | Each host's hook file | yes | yes |
| Codex | `~/.codex/hooks.json` | yes | yes, after trust |
| ZCode | `~/.zcode/cli/config.json` | yes | yes, new session |
| Gemini CLI | `~/.gemini/settings.json` | yes | yes |
| Cursor · Antigravity | Each host's hooks file | yes | becomes ask |
| Kimi Code | `~/.kimi-code/config.toml` | yes | rewrite becomes deny |
| Trae · Qwen · Qoder · Lingma · CodeBuddy | Each host's config | yes | yes |

Copilot, Windsurf, Aider, and Cline are catalog names only.

The built-in set is 81 rules: 37 block, 43 log, 1 rewrite. Twenty-nine of the block rules cannot be downgraded from the board or a proposal while the mode is enforcing. The default mode is enforcing. Saving a policy, the device syncing it, and the host actually denying are three separate steps.

<a id="start"></a>

## Quick start

Node.js 24 or newer. Move the token and the join bundle as files. Do not paste them into chat.

```bash
npm ci && npm test && npm run build && npm run pack
```

That produces `nmzp-core.tgz`. Nothing is watched until the core is installed on a dedicated CT and a bundle is issued. The systemd, certificate, and port detail is in [docs/install.en.md](docs/install.en.md).

```bash
runuser -u nmzp -- env NMZP_DATA=/var/lib/nmzp NMZP_PUBLIC_URL=https://<CT-IP>:8787 \
  node /opt/nmzp/nmzp.mjs ticket --out /var/lib/nmzp/join-bundle.json
```

On each guarded PC:

```powershell
.\nmzp.cmd join .\join-bundle.json
.\nmzp.cmd board --bundle join-bundle.json --token-file admin.token
```

The local board is `http://127.0.0.1:8788`. Pick the token file. The LAN read-only view is `http://<CT-IP>:8789`.

After join, fully quit and reopen desktop hosts. Inside Codex, trust `NMZP PreToolUse v1`. `.\nmzp.cmd stop` stops the probe only. The hooks stay. `.\nmzp.cmd uninstall` removes them.

The read-only viewer is `nmzp viewer --host <private-ip> --port 8789 --allow-cidr <CIDR>`, from the unit `nmzp-viewer.service`. It cannot change policy. `GET /health` is not proof of protection.

<a id="audit"></a>

## Audit, then an external assistant

The board does not contain a model that reads the audit for you. A person exports the current filter, reads it, and chooses whether to send it. The assistant should return only `nmzp-policy-proposal/1`. Import checks the document, replays stored events, and the core checks again after an admin confirms. A proposal does not become a built-in rule.

The export is not anonymous, and it is not the whole day. The ring holds 2000 events. Older rows are dropped after that, and history completeness is stored as `unknown`. Fields, what the preview only estimates, and the sentence missing from the copied prompt are in [docs/audit.en.md](docs/audit.en.md).

<a id="limits"></a>

## Keep these in view

- A name in the bar is discovery. A receipt means the hook ran. A receipt is not the host enforcing deny.
- The hook is not an operating-system sandbox and not a network firewall. GitHub, OSS, and COS uploads are observed.
- A local administrator can remove the hook. A fully controlled machine is outside this design.
- Receipts can be lost while the core is unreachable. Absence of an event is not absence of risk.

The rest of what this tree does not do, including screen capture, scheduled reports, and a local model, is in [docs/limits.en.md](docs/limits.en.md). The security model is [SECURITY.md](SECURITY.md).

<a id="plan"></a>

## Local semantic check

Planned / the model layer is not connected.

Hard rules already run. The figure's path — take a minimal context, call a local model, merge that score into the decision — is not in the code, and this round does not turn it on. A model must not override a hard rule, and a failure must not be treated as safe. Those are constraints for a later change, not switches that exist today. The note and the full figure are in [docs/plans/local-semantic-review.md](docs/plans/local-semantic-review.md).

## Docs and contributing

| | |
| --- | --- |
| Install and the CT | [docs/install.en.md](docs/install.en.md) |
| Adapters and Codex | [docs/agents.en.md](docs/agents.en.md) |
| Audit and proposals | [docs/audit.en.md](docs/audit.en.md) |
| Security model | [SECURITY.md](SECURITY.md) |
| Contributing | [CONTRIBUTING.md](CONTRIBUTING.md) |

```bash
npm ci
npm test
npm run typecheck
npm run build
npm run lint
```

`npm run dev` is the board UI dev server. It is not a hook installed on a machine.

## License

[MIT](LICENSE).
