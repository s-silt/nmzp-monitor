# WP-21 Immutable built-in rule snapshot

## Boundary and lifecycle

The shipped built-in catalog is module/runtime-lifetime data. There is no supported hot-update API. `rules.ts` now recursively freezes the entire catalog (including each rule and tools array) and its ID index. Engine compilation, overrides, exemption scope and other imported consumers all reference those same objects. `loadMonitor` returns a readonly, frozen façade, so a caller cannot replace its catalog or evaluator independently. Result rule references are immutable too.

A built-in update means replacing the shipped runtime and starting its complete module graph again. Importing only a changed `rules.ts`, editing a loaded object, or assigning a different `monitor.RULES` is not an update workflow. There is deliberately no new partial hot-swap API. Existing custom privacy rules, overrides, exemptions and mode updates continue through immutable, versioned policy snapshots; an in-flight request retains the policy it captured before body/mutex waits.

`NmzpPolicyService.open` initializes the catalog fingerprint at load. `policyRulesHash` reuses it only when the complete graph has been verified as frozen, plain JSON data without accessors, proxies or sparse arrays. The weak cache owns no permanent catalog retention. Mutable injected test/dependency sources and shallow-frozen arrays are never cached, so their existing per-call drift detection remains. A source replacement gets a distinct graph and fingerprint. Fingerprints remain identities, not signatures or authorization.

The original encoding and insertion order are preserved: JSON `{rules, rewriteRevision, engineRevision}` with SHA-256, without new wire fields or version bumps. No rule data, evaluation algorithm, override/exemption semantics or V1 responses are intentionally changed. Engine and rewrite revisions retain their existing meanings.

## Runtime replacement and historical policy binding

Runtime replacement does not silently rewrite policy history or auto-publish a new policy. A fresh V2 evaluation now verifies the captured policy-history row's policy hash, catalog hash and engine package version before creating a session stage or appending an evaluation. If the new runtime does not match the old history binding, it returns the existing fixed-message `evaluation_replay_unavailable` error (HTTP 409). Retry replay continues to require exact historical policy, catalog and implementation binding.

Operator workflow after an intentional built-in/engine update:

1. Before switching, review the built-in/engine change and check the existing policy against the new catalog. Removed or newly protected rules can invalidate overrides/exemptions; startup rejects these before serving HTTP. Prepare a compatible policy/runtime through the controlled upgrade process if needed; a post-start HTTP restore cannot fix failed startup
2. Replace/restart the complete compatible runtime using the normal controlled release process
3. Explicitly publish a new policy revision, or restore the desired historical policy as a new revision through the existing authenticated policy workflow
4. Verify that the new history revision carries the new runtime's catalog/engine binding before sending new V2 evaluations

Old policy rows and old evaluation identities are not rewritten. A new compatible runtime can reproduce an old result only when all existing replay binding checks match. Otherwise it honestly refuses replay. Returning to the matching old runtime can replay the old identity, but it likewise needs an explicitly published matching current policy before creating fresh evaluations. V1 keeps its previous behavior, including its historical rewrite guard.

## Safety and validation

No identity lookup, post-await fence, SQLite transaction check, compression or rewrite validation is removed. The additional fresh-evaluation history check is a correctness requirement, not a benchmark shortcut. It adds an actual read and its cost must remain in the controlled end-to-end measurement.

New tests cover nested mutation and escaped result references, loader replacement rejection, exact formula preservation, once-only serialization, mutable/shallow-frozen/accessor inputs, a complete isolated runtime replacement, compiled engine plus override/exemption lookup consistency, pre-publication refusal without effects, explicit restore and publish rebinding, honest replay across old/new runtimes, and queued requests holding their captured policy/catalog.

The existing actual 13-host offline-vs-V2 parity test, compatibility guard, related contract/regression tests and static/build checks remain required. Full aggregate, independent review and controlled performance results are reported separately and are not implied by this design note. The rejected gzip scheduling candidate is absent. No deployment, push, IC switch or G8 freeze is authorized by this work.
