# What not to expect

[English home](../README.en.md) · [中文](limits.md) · [Security model](../SECURITY.md)

Current version 0.2.4. The native sandbox and protected-session paths set `productionReady` to false. That flag is not a certificate for the hook, and the hook is not a sandbox.

| Not in this tree | Why it stays out |
| --- | --- |
| Screen-capture alerts | Built, then removed. Watching `Windows.Graphics.Capture` needs an administrator, spends CPU, and confuses the operator's own screenshots with an agent |
| Blocking an oversize archive | The board's block choice is disabled. Size is visible when one archive is explicit in the command |
| Per-agent rule scope | The agent id on a hook is self-reported. Scope is tool and field |
| Blocking GitHub, OSS, or COS uploads | Observe only. Cutting the network is a firewall's job |
| Generic upload blocking | Same limit |
| Clipboard or screenshot isolation | Easy to bypass, and it breaks ordinary work |
| A WFP kernel filter in the ordinary pack | Experimental. Not part of `npm run pack` |
| Full chat transcripts | Deliberate. Session stores are not collected |
| In-memory pack, a moved directory, pipes, or a custom domain | The ZCode directory tripwire does not cover them |
| Stopping a local administrator | Admin, SYSTEM, or the owner can undo a discretionary ACL |
| Tamper-proof audit, or lossless complete history | Not promised. Updated devices have bounded persistent retries, but capacity, expiry and failures still leave gaps. The default retains 2000 recent events; administrators can explicitly enable SQLite history subject to retention limits. `historyCompleteness` remains `unknown` |
| Scheduled export, an automatic model call, or a daily report | Not built. A person exports, then chooses an external assistant |
| Local semantic check | Planned. See [local-semantic-review.md](plans/local-semantic-review.md). The model layer is not connected |

Finding an install or a process is discovery. A receipt on the board comes from a fresh `hook-status.json`. An adapter running is not the host enforcing deny.
