# Policy patches, custom rules, and privacy rewriting

[English home](../README.en.md) · [中文](policy-customization.md) · [Proposal contract](policy-proposal-contract.en.md) · [History and recovery](policy-runtime.en.md)

Use a reviewed `nmzp-policy-proposal/1` JSON patch for routine rule changes. A supporting CT can validate and publish it online without a new GitHub release or core restart. Devices receive the new version through their existing policy pull and heartbeat paths.

## What can be updated online

Data patches can change supported rule overrides, custom matching, privacy blocking or rewriting, exemptions for unprotected rules, and explicit deletions. Unmentioned configuration remains intact. Global `mode`, `stopped`, upload settings, program code, and new fields are not proposal content.

New built-in detection, regex interpretation, host protocols, adapters, database structures, and identity checks require a program update and testing. This depends on the change, not whether the release is called a major version. A future core that advertises `/1` must retain its semantics; incompatible proposals must be rejected rather than silently reinterpreted.

## Create and publish a patch

1. Record the source commit, purpose, synthetic positive and negative examples, and expected effect. Do not send real logs, private keyword lists, complete policies, or credentials to an external bot.
2. An administrator reads `GET /api/v1/policy/proposals/capabilities` on the actual CT. Copy `policyVersion` and `rulesHash` into `basePolicyVersion` and `baseRulesHash`, and check `schema`. A GitHub version is not the running CT state.
3. Send the same JSON to `POST /api/v1/policy/proposals/validate`. Review additions, deletions, activation changes, matching examples, near misses, and examples outside the scope. Validation is read-only and cannot guarantee a later commit.
4. After reviewing the concrete diff, send that JSON to `POST /api/v1/policy/proposals/apply` through the existing authenticated, certificate-verified administrator channel. Confirm the returned version and current policy. On a timeout or `409`, inspect whether the first attempt committed before preparing another proposal.
5. Check target devices' heartbeats and `lastPolicyVersion`, then synthetic host behavior. Record CT publication, device synchronization, and actual host denial or rewriting separately. Offline devices remain pending or unknown.

The old page can import legacy suggestions without a catalog hash; its default dry-run checkbox controls that path. A proposal containing `baseRulesHash` is preview-only there and must use the server routes above. Do not strip the hash to bypass validation. A read-only viewer cannot publish.

## Custom rules and private keywords

This synthetic draft needs both live CT bindings before server publication. A runnable fixture is [examples/privacy-proposal.json](../examples/privacy-proposal.json).

```json
{
  "schema": "nmzp-policy-proposal/1",
  "customRules": [
    {
      "match": "SYNTHETIC_EMP-[0-9]{4}",
      "mode": "replace",
      "kind": "synthetic_employee",
      "scope": { "tools": ["Bash"], "fields": ["command"] },
      "dryRun": false
    }
  ],
  "rationale": "Rewrite synthetic employee markers in tool arguments; preserve unmatched text"
}
```

`mode:"block"` requests denial; `mode:"replace"` requests replacement with the fixed literal `<标签>` (`REDACT_TAG`). The proposal format does not accept arbitrary `replaceWith`, `enabled`, rule IDs, or executable scripts. Omitted `dryRun` defaults to true; explicit false participates in enforcement according to the global mode. The API does not force it back to dry run. The rules page retains enabled/dry-run/disabled states. Publication does not switch a permissive, off, or paused policy into enforcing mode.

Custom privacy rules use the existing outbound-operation semantics. For example, synthetic input `curl -d 'SYNTHETIC_EMP-1234' https://example.invalid/x` should request rewriting; local `echo SYNTHETIC_EMP-1234` should not become a rewrite merely because it contains that marker. Submit these as evaluation inputs; do not execute the commands. Audit redaction and actual argument rewriting are distinct results. Shell safety checks still apply: an unquoted `<标签>` may become redirection and cause `rewrite_would_break_shell`. Do not weaken that check to make an example pass.

`match` is 2–80 characters. The existing matcher uses case-insensitive, global regex matching, rejects some dangerous expressions, and may treat expressions that cannot compile as literal text. Escape metacharacters for literal matches; JSON needs doubled backslashes, for example `"synthetic\\.internal"`. Verify actual matches with synthetic examples, not just JSON parsing. A policy may contain at most 64 custom rules.

`scope.tools` uses normalized tool names such as `Bash`, `Read`, `Write`, `Edit`, `WebFetch`, and `MCP`. `scope.fields` supports only `command`, `file_path`, `url`, and `contents`. Omitted scope uses the existing unrestricted matching scope. Only fields supported by the matching and rewrite paths are affected. This does not collect or alter chat transcripts, erase model context, or recall sent requests. Antigravity maps rewriting to a host question; see [host differences](agents.en.md).

## Replace, exempt, and roll back

To change an existing custom rule, list its original ID in `remove.customRuleIds` and add the complete replacement in `customRules` in the same proposal. Use `remove.exemptionIds` plus `exemptions` for exemption replacement. The baseline check binds both actions to one publication. Overrides merge by rule or family key; rule overrides take precedence over family overrides, then defaults, in enforcing mode. Protected built-in block rules cannot be downgraded or exempted.

Limit exemptions to the intended rule, match, and necessary tools. If expiry is omitted, it defaults to 30 days. Explicit expiry must be after creation and no more than 365 days later. Use a known, exemptible rule from the trusted catalog. Unknown proposal fields are rejected.

Keep the previous version and review evidence before publishing. In SQLite mode, restoring historical content revalidates it against the current trusted catalog and creates a new, increasing version; it does not turn the version counter back. Window mode has no complete policy history: the administrator must keep any necessary inverse patch locally under appropriate controls, then review it against the current baseline before publication. Resolve unknown commit outcomes through recovery checks, not automatic retries or ordinary restarts.

Record the patch digest, review conclusion, server version, and device verification for each publication. A patch is not a program upgrade archive and contains no sensitive tool body. Mark missing history as unknown.

## Relays, MCP authorization, and hooks

[examples/relay-log-proposal.json](../examples/relay-log-proposal.json) is an importable, unbound draft. Add the live CT bindings before server validation and publication. Its four custom observation rules deliberately retain `dryRun:true`; that is not a forced setting for every patch. It leaves `env_file_read` at its catalog log default and escapes domain/IP dots for regex matching.

In 0.2.4, an isolated `ANTHROPIC_BASE_URL` write in Claude settings is `claude_settings_relay_write` (medium/log, no protected family). It does not block or ask based on whether the address is official. Ordinary MCP authorization, including automatic project approval and named-service allowlists, is logged. Preserving approvals, disabling automatic approval, or clearing an allowlist is not poisoning merely because the key exists.

Explicit download-and-execute or file-exfiltration chains in Hook/MCP configuration remain blocked by protected `agent_hook_poison`. A relay log rule cannot override a detected exfiltration, self-protection, or credential-leak block. A legitimate installer may also download and execute; placing that behavior in an automatic hook can trigger this conservative rule.

Ordinary formatting, tests, notifications, and recognized plain-text output are not execution merely because a printed example contains curl/wget. Detection parses a bounded subset of commands and data scripts. It neither executes them nor reads referenced files; unknown syntax, dynamic execution, and complex quoting remain subject to conservative checks. False positives cannot be ruled out for every valid script. Archive correlation distinguishes recognized listing/extraction from actual creation; creation followed by upload remains guarded.

These detection changes require program 0.2.4. Importing old JSON alone cannot supply them. The release bundles Acorn 8.18.0 and its MIT license; CT installation runs no dependency install scripts. If an old rewrite cannot be reconstructed with its original engine, retry returns `historical_policy_unavailable` rather than inventing the old result using new rules. Upgrading does not silently rewrite existing policy content or its version. Offline devices with older runtimes retain their old local engine.
