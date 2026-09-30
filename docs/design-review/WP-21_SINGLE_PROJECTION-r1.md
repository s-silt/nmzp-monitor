# WP-21: canonical input is projected once at CT ingress

## Accepted boundary

The V2 CT ingress now produces exactly one canonical-derived EvalInput. It does not call the legacy resolveEvalBody, resolvedEvalInput or toolInputToEvalFields to produce another input. V1 compatibility and producer-side genuine host parsing keep their existing resolver paths. No client/IC activation is included.

Source reconstruction remains necessary for truthful rewrite evidence. Graph, source reference, mapping, alias consistency, source-presence and byte checks are retained independently. Reject-only checks still compare trim-equivalent aliases and ordered/deduplicated content against the canonical projection; this is not a claim of zero compatibility-comparison work. Previously admitted blank/duplicate content relocation to retained extras remains admitted.

Only privately registered, cloned, validated and deeply frozen data snapshots can be reused. Arbitrarily frozen caller objects are not trusted. Durable evaluation captures ownership before hashing or asynchronous waits. Internal evidence/self-apply reuse their owned source; public apply and unregistered replay validate fresh. Callback/caller mutation cannot alter an already captured decision identity or rewrite source. Freeze and working-view copy are iterative; no new arbitrary depth limit is introduced. Existing legacy recursive-walker stack limitations are not represented as fixed.

## Verified evidence

- Eight-file frozen manifest SHA256: ea4c57640fe9be76f086d35b52209cccc099a062a2588e176d8d3188279ff09b
- Independent functional review: 69 tests passed, plus119 producer/101 ingress-evidence/267 historical-replay/505 admission comparisons and4138 frozen-object checks; no correctness blocker
- Exact structural execution checks: accepted HOOK/PROBE ingress canonical projection/contentLeavesToV1 each1, CT legacy resolver/resolvedEvalInput/toolInputToEvalFields each0. Owned fresh rewrite/self-apply adds no projection or materialization; replay retains independent validation
- Root aggregate:2086 total,2075 passed,11 explicit skips,0 failures/cancellations,283.8seconds
- The first aggregate failed because a task-created relative acorn dependency symlink was copied through a nested temporary fixture. Independent reproduction confirmed this environment cause. Replacing only that ignored dependency with a byte-identical package copy fixed the unchanged mutation suite; original failure and corrective evidence are retained. No product/test assertion was changed for that failure

Evidence remains in the coordinator's nmzp-validation/single-projection directory: FROZEN.json, REVIEW.md, REPORT.md, root-full-deps-fixed.log, dependency-layout-correction.json, baseline/differential/negative-control outputs and controlled benchmark data. These external evidence paths are not implied to be committed source files.

## Acceptance limits

One fixed500-pair/scenario/arm measurement completed with all6240 requests successful. Candidate V2/V1 wall-p95: allow1.167725, rewrite1.150287, PROBE1.055470, all above the required1.05. This change closes the audited CT duplicate-normalization implementation gap within the validated V2 boundary; it does not close the performance gate. No repeated-to-green run or threshold change was used.

New exact-SHA Windows/CI, G8 protocol freeze and HOST_REAL evidence remain separate. No Phase3 isolated candidate is included, and no merge/deployment/freeze or live V2 client switch is authorized by this note.
