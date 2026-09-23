# Audit stability tests

[中文](testing-stability.md) · [Contributing](../CONTRIBUTING.md) · [Runtime and storage (Chinese)](policy-runtime.md)

This is an explicit, small audit test lane, not a full-project acceptance suite or evidence that a coding-agent host enforced a hook denial. Start here for worker lifecycle, recent-event indexing and codecs; add server, policy and frontend contract tests for the actual change being released.

## Local execution

Use Node.js 24 or later. This lane uses only Node built-ins and project-local modules; frontend dependencies do not need to be installed first.

```bash
node --version
node scripts/run-stability-tests.mjs --list
node scripts/run-stability-tests.mjs
```

`--list` validates and prints the selected files without running tests. Execution uses file concurrency 2 and a 60-second per-file deadline, preserving a failing exit code. No recursive discovery, arbitrary extra arguments or symlinked tests outside the checkout are accepted.

| File | Evidence provided |
| --- | --- |
| `core/audit/worker-channel.test.mjs` | Synthetic transport events and mocked time; also real Node Worker drain, exit and exception cases. Not a SQLite test |
| `core/audit/runtime-drain.test.mjs` | The real AuditRuntime, production worker and temporary SQLite files: draining admitted writes, error propagation, receipts and reopening |
| `core/audit/runtime.test.mjs` | Existing real-worker ordering, queue-capacity, corrupt-row and startup-failure cases |
| `core/audit/json-codec.test.ts` | JSON/gzip round trips and input limits |
| `core/audit/recent-events.test.ts` | Bounded recent-event indexing |

Review imports and side effects before adding another file. A passing total is not a substitute for explaining coverage.

## No active-host changes

These tests use synthetic events, OS temporary directories and Node workers they create themselves. They do not install hooks, read real credentials, execute user commands, scan or terminate ZCode, touch real `.zcode`/`.codex`/`.nmzp` directories, or modify NTFS ACLs. There is no need to stop an active coding agent for this lane.

They open no HTTP listeners. Additional server tests need their own review of temporary directories, loopback ports, certificates and cleanup. A separate Git worktree is not operating-system isolation.

## Shutdown contract

AuditRuntime retains its storage methods and result shapes. Its internal AuditWorkerChannel owns communication lifecycle only, not policy decisions or another database implementation.

- Closing stops admission immediately, but accepted requests still settle successfully or fail.
- Worker errors, exits and original request deadlines still reject pending work while closing. A closing flag must not suppress failure settlement.
- Concurrent `close()` callers observe the same completion; later callers cannot return early.
- A per-operation error such as a corrupt row does not disable a healthy worker. Transport and protocol failures terminate the channel.
- A failed channel never automatically replays writes. Failure does not prove the disk transaction was not committed; recovery remains the storage/policy layer's responsibility.

A resolved `close()` means resources were released, not that every write succeeded. Callers must handle individual request results. The existing 32-call limit and 30-second request deadlines remain unchanged. Node's `Worker.terminate()` still awaits actual thread exit: these deadlines are not a hard real-time guarantee under stalled native I/O or hardware failure.

## Public CI

`.github/workflows/core-stability.yml` runs this same allowlist on GitHub-hosted Linux and Windows runners with Node 24. Repository access is read-only, checkout does not persist credentials, and the job uses no self-hosted runner, production secret, `pull_request_target`, npm lifecycle script or ACL test.

This limited CI is not verified until it actually runs. It does not replace whole-project typechecking, lint, building, packaging, HTTP authorization tests or real-host verification. CI selects the current Node 24 patch; record the actual version from its log. Local results must separately identify their OS and runtime.

## Before release

This lifecycle repair changes neither the storage format nor policy/HTTP contracts. A full checkout still needs consumer/server contract, type and build checks. Inspect the release package: `audit/worker-channel.ts` must be included, and tests must be excluded.

Keep the first failure and its conditions. Do not rerun indefinitely until green or count skipped, timed-out or import-failing tests as passes. Reopening a file after a normal shutdown is not a power-loss recovery test.
