# Policy JSON proposals across compatible versions

[English home](../README.en.md) · [中文](policy-proposal-contract.md) · [Creating patches](policy-customization.en.md)

`nmzp-policy-proposal/1` is a data protocol, not a Git diff, JavaScript, or a replacement `policy.json`. Future cores advertising `/1` must preserve its fields and semantics. An incompatible catalog or protocol requires rejection and a reviewed replacement proposal; an old proposal is not guaranteed to work with every future version.

A bot may use GitHub source to draft a proposal, but GitHub `main` does not establish what the CT is running. An NMZP administrator must obtain the live capabilities before publication. Do not give external models administrator tokens, device credentials, real logs, or complete policy bodies. Use non-sensitive protocol metadata, the catalog hash, and reviewed requirements expressed with synthetic examples.

## Validate and publish

These routes require administrator authentication through the existing TLS channel. Viewer and device credentials cannot publish. They work in both `window` and `sqlite` storage modes.

| Request | Result |
| --- | --- |
| `GET /api/v1/policy/proposals/capabilities` | Current `schema`, `policyVersion`, `rulesHash`, `engineVersion`, `requiredBindings`, `newCustomRulesDefaultDryRun`, and `explicitActivationAllowed` |
| `POST /api/v1/policy/proposals/validate` | Read-only format, baseline, trusted catalog, merge, and complete-policy validation; does not save or increment a version |
| `POST /api/v1/policy/proposals/apply` | Repeats validation and commits through the sole `NmzpStore.casPolicy` writer; returns the new version |

The required bindings are `basePolicyVersion` and `baseRulesHash`. For the example below, replace both with values obtained from the same live CT capability response. The hash must be 64 lowercase hexadecimal SHA-256 characters.

```json
{
  "schema": "nmzp-policy-proposal/1",
  "basePolicyVersion": 12,
  "baseRulesHash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "overrides": { "rules": { "download_operation": "log" }, "families": {} },
  "customRules": [
    { "match": "SYNTHETIC_PATTERN", "mode": "block", "dryRun": true }
  ],
  "rationale": "Expected effects on synthetic examples; not instructions for the server"
}
```

Successful validation returns `{ok,policyVersion,rulesHash,candidateTotals,newCustomRulesDefaultDryRun}`; `candidateTotals` contains `overrideRules`, `customRules`, and `exemptions`. Successful application returns `{ok,version,rulesHash,newCustomRulesDefaultDryRun}`. Validation does not guarantee a later commit: another administrator may publish first, or storage may fail.

## Fields and merge behavior

Only `schema`, `basePolicyVersion`, `baseRulesHash`, `overrides`, `customRules`, `exemptions`, `remove`, and `rationale` are accepted. Global `mode`, `stopped`, upload settings, unknown fields, and executable code are rejected. Rule and family overrides merge by key. Omitting an existing item does not delete it; deletion must be explicit in `remove`.

New custom rules default to dry run when `dryRun` is omitted. Explicit `dryRun:false` is allowed, subject to trusted-rule constraints and administrator publication. It does not switch the global mode or override a pause. `rationale` is review text and is not persisted as policy.

An existing custom rule with the same `match`, or an exemption with the same `ruleId` plus `match`, is not silently skipped. To replace it, include the original ID in `remove.customRuleIds` or `remove.exemptionIds` and add the complete replacement in the same proposal. Other deletion lists are `remove.overrideRuleIds` and `remove.overrideFamilies`. Protected built-in block rules cannot be downgraded or exempted.

The existing **Import proposal** page can preview a bound proposal but disables application when `baseRulesHash` is present: that page does not validate the catalog binding. Publish it through the server `/validate` and `/apply` routes. Do not remove the binding to bypass this check. Legacy proposals without a catalog hash retain the existing page workflow.

## Failures and verification

| Status / error | Operator action |
| --- | --- |
| `400 bad_json` / `400 invalid_proposal` | Fix the JSON or reported schema/validation issues |
| `400 proposal_base_required` | Obtain both required bindings from the live capabilities |
| `400 proposal_existing_item` | Review the existing item and use an explicit remove-and-add replacement |
| `400 proposal_no_changes` | Review the proposal; there is no change to publish |
| `409 cas_conflict` | Reload the current policy and compare before preparing another publication |
| `409 rules_changed` | Reload capabilities and review against the actual rule catalog |

A successful publication increments the policy version. If the response is lost, retrying the same proposal encounters the old baseline. Read the current policy and version to determine whether the first attempt committed; do not blindly replace the baseline and retry. An uncertain commit requires the recovery path, not an ordinary restart to bypass checks.

Devices obtain policy through the existing pull/heartbeat path. A successful CT response does not prove that every device has applied it. Check `lastPolicyVersion`, recent receipts, and synthetic host behavior separately; offline devices remain unknown.

This protocol changes only data rules supported by the installed engine. New built-in detections, matcher/interpreter changes, host protocols, adapters, policy fields, storage formats, and authentication changes require a program update and separate tests. Each production proposal still needs review of its exact content, diff, test evidence, and rollback basis. A bot should not hold the administrator token or publish unattended.
