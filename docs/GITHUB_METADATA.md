# GitHub About and topics

This file is a suggestion for the maintainer. Writing it did not change the GitHub website settings.

The public repository `s-silt/nmzp-monitor` was readable as a public repo when this note was written. Its About text at that time was still the older line: "局域网编码 Agent 监护 · LAN coding-agent guard". Replace that only by editing the repository settings yourself.

## About

Suggested About text:

```text
Open-source security guardrail for AI coding agents. Detect, block, rewrite, and audit risky tool calls before execution.
```

GitHub's About field limit is 350 characters. The suggestion above is measured in the character table at the bottom of this file.

Website field: **Description**.

Do not put "OpenAI partner", "OpenAI approved", "official security layer", or a user or download count in the About text.

## Topics

Suggested topics, in this order:

```text
ai-agents
coding-agents
agent-security
llm-security
security
devsecops
developer-tools
privacy
codex
```

`codex` is reasonable because this repository contains a Codex host adapter (`core/codex-hooks.ts`).

Do not add the topic `openai`. That topic reads as an affiliation. This project is vendor-neutral, and Codex support is not an OpenAI endorsement.

Optional later, only if you want discoverability for the other adapters that actually exist: `claude`, `cursor`, `gemini`. Those names are also easy to confuse with unrelated projects, so they are not in the default list.

## Website

Leave the website field empty unless you have a page you operate. Do not point it at an OpenAI URL.

## What not to change from this document

- Stars, forks, and watchers.
- Releases and tags. `v0.2.2` and `v0.2.3` already exist. Do not create a `v0.1.0` release to look like a first public version.
- The license. It is already MIT.
- Security policy text on the website. Putting `SECURITY.md` in the repo root is what GitHub uses. Enabling private vulnerability reporting is a separate website setting.

## Measured lengths

Counted on 2026-09-22 from the About `text` fence above.

| String | JavaScript length | Unicode code points | GitHub limit |
| --- | ---: | ---: | ---: |
| Suggested About | 121 | 121 | 350 |

121 is within 350. If you edit the sentence, count it again before pasting it into GitHub.
