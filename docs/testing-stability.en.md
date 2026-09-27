# Audit stability tests

[中文](testing-stability.md) · [Contributing](../CONTRIBUTING.md) · [Runtime and storage (Chinese)](policy-runtime.md)

This is an explicit, small audit test lane, not a full-project acceptance suite or evidence that a coding-agent host enforced a hook denial. Start here for worker lifecycle, recent-event indexing and codecs; add server, policy and frontend contract tests for the actual change being released.

The full quality gate below is a separate workflow with no path filter. That gate and this five-file path each cover only the commands they list.

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

`.github/workflows/core-stability.yml` runs the five files in the table above on GitHub-hosted Linux and Windows runners with Node 24. Repository access is read-only, checkout does not persist credentials, and the job uses no self-hosted runner, production secret, `pull_request_target`, npm lifecycle script or ACL test. `pull_request` and `push` to `main` are filtered to `core/audit/**`, `core/schema.ts`, the stability runner and the workflow file. A change that only touches something outside that list, such as `core/hook.ts`, does not start this narrow workflow.

This limited CI is not verified until it actually runs. CI selects the current Node 24 patch; record the actual version from its log. Local results must separately identify their OS and runtime.

## Full quality gate

`.github/workflows/quality.yml` adds `pull_request`, `push`, and `workflow_dispatch` with no `paths`, `branches`, or `tags` filter. The matrix is GitHub-hosted `ubuntu-latest` and `windows-latest`, with `node-version` `'24'`. That major is not a pin of one patch; the version printed in that run's log is the version under test. The only permission is `contents: read`. Checkout sets `persist-credentials: false` and `fetch-depth: 0`. The action pins are the same commits as the narrow workflow:

- `actions/checkout@11d5960a326750d5838078e36cf38b85af677262`
- `actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020`

Hosted steps, in order, are `npm ci --ignore-scripts`, `node --experimental-strip-types scripts/policy-compat-guard.mjs`, `node scripts/check-current-version.mjs`, `npm run typecheck`, `npm run lint`, `npm test`, and `npm run build`. A nonzero policy-compatibility or version check does not remove the later steps from the workflow, and that job does not continue past it. For `pull_request`, the candidate tree is the merge commit checked out by default, and the baseline is only `pull_request.base.sha`. For `push`, the baseline is only `before`; the all-zero `before` of a new branch fails instead of selecting HEAD. `workflow_dispatch` requires a 40-hex baseline. A pull request can still modify the workflow and the guard, so this check does not replace review or protected required checks. `--ignore-scripts` does not run dependency lifecycle scripts. `strategy.fail-fast` is false, so one operating system does not cancel the other job. The job limit is 30 minutes. A timeout is a failure, not a skip and not a pass.

The expanded job names are `Quality / ubuntu-latest / Node 24` and `Quality / windows-latest / Node 24`. Those names show up in the check list after the workflow is on the default branch and has run at least once. A maintainer has to require both checks in branch protection or a ruleset. Merging the workflow file does not turn that setting on, and there is no successful hosted run to cite until one is recorded.

The workflow does not set `NMZP_TEST_REAL_ACL`, install or uninstall a host, read production credentials, or use `pull_request_target` or a self-hosted runner. A pull request from a fork gets this same read-only permission. `push` has no path filter, so a tag push also starts this read-only workflow. It has no write permission, so it cannot create, move, or delete a tag, and it cannot retract a tag that was already pushed. The workflow file and the local script cannot replace repository rules.

Before release, compare the target commit and confirm the two action SHAs above are still the reviewed pins. An account with admin permission, or with an allowed ruleset bypass, can still push without these checks. Restricting that bypass, and restricting tags, is done in the repository's branch protection, rulesets, and tag rules.

## Explicit skips

An `npm test` exit code of 0 means the tests that ran did not fail. A skipped test did not run and is not a pass. Neither the quality workflow nor the local preflight sets `NMZP_TEST_REAL_ACL`, `NMZP_LIVE_NETWORK_PROOF`, or `NMZP_LIVE_PROOF_DIR`.

| Case | Linux job | Windows job |
| --- | --- | --- |
| `snapshot-guard real NTFS ACL` in `core/snapshot-guard.test.ts` | Skipped because it requires Windows | Skipped unless `NMZP_TEST_REAL_ACL=1` |
| Opt-in cases in `core/install.test.ts`, `core/host-files-carry.test.ts`, `core/codex-hooks.test.ts`, `core/antigravity-hooks.test.ts`, `core/host-adapters.test.ts`, and `core/zcode-hooks.test.ts` | They run. The skip is false, and the result is not Windows ACL evidence | Skipped unless `NMZP_TEST_REAL_ACL=1` |
| Real PowerShell hook command in `core/install-hooks.test.ts` | Skipped | Runs |
| Real loopback TCP observation in `core/network-collect.test.ts` | Skipped | Runs |
| `core/native-probe-service/verify-package.test.mjs` | Skipped | Runs |
| Windows missing-target status in `core/snapshot-guard.test.ts` | Skipped | Runs |
| Unsupported-platform status in `core/snapshot-guard.test.ts` | Runs | Skipped |
| Windows observation in `core/storage-firewall.test.ts` | Skipped | Runs. This is not the real NTFS opt-in above |
| Windows registry source parse in `core/agent-discovery-registry.test.ts` | Skipped | Runs |
| Windows TAP skip check in `scripts/test-gates.test.mjs` | Skipped | Runs |

`core/network-live-proof.test.ts` stays skipped unless both `NMZP_LIVE_NETWORK_PROOF=1` and `NMZP_LIVE_PROOF_DIR` are set. Even then, the test skips internally and records `not_verified` when the platform is not Windows, the independent binary hash is missing, or the positive control is unavailable. This gate does not set those variables.

A Linux success therefore does not include the rows that run only on Windows, and a Windows success does not include the unsupported-platform status that runs only off Windows. Neither runs the real NTFS ACL cases. A local pass is not evidence from the hosted Linux job and is not host certification. Host install, uninstall, and ZCode operations are outside this gate.

## Local preflight

When dependencies are already installed in the checkout, run this from the repository root:

```bash
node scripts/release-preflight.mjs
```

The script runs `npm run typecheck`, `npm run lint`, `npm test`, and `npm run build`, in that order. It does not run `npm ci`, and it does not create, move, or delete a tag or publish. A nonzero step exits with that status immediately. Later steps do not run. Starting it inside a `node:test` process is refused with exit 1, so `npm test` does not invoke the full preflight again.

On Windows the script does not spawn `npm.cmd` directly. Node returns `EINVAL` for a `.cmd` file when `shell` is false. It runs the `npm-cli.js` that the `npm` on `PATH` would select, using the current Node executable. A real `npm.exe` on `PATH` is executed directly. The only accepted arguments are the four checks above and `npm --version`. Linux and macOS still execute `npm` directly.

On `SIGINT` or `SIGTERM`, preflight stops only the checks it started, waits a bounded time for them to exit, and then exits nonzero. A timed-out or failed check is not success either. The parent's `exit` event is not a substitute: a default POSIX `SIGTERM` does not emit `exit`.

On Linux and macOS the started check is the leader of a new process group, and the signal is sent to that group's negative pid. Descendants remain in the group unless they leave it. If they are still alive when the deadline passes, the same group is sent `SIGKILL`. This change was not executed on Linux.

Windows has no POSIX process group. The script runs `taskkill /PID <pid> /T /F` for a pid it started. That stops that process tree only. It does not search by process name and does not stop any other process. That Windows behavior is not evidence that the Linux signal path has run.

If the operating system hard-terminates the preflight process itself, the handler does not run. This does not claim those child processes were cleaned up. On Windows, a separate local check sent `SIGTERM` from another process to a Node process that had a handler installed. The handler did not run, and the process exited with code 1. That check is not Linux evidence, and it did not measure a console Ctrl+C.

`scripts/quality-gates.test.mjs` injects a subprocess double to check command order and whether a failure stops the later checks. `npm test` collects that file and does not run typecheck, lint, the full test suite, or build again from that file. The same file does launch one real `npm --version`, which only prints the version and does not install or build. Its cancellation coverage uses temporary children that exit on their own timer, not the four checks.

The command really does run `npm test`, including temporary-directory and loopback contract tests. It does not install a host or turn on the real ACL opt-in. A local pass describes the current operating system and the current Node only.

## Before release

This lifecycle repair changes neither the storage format nor policy/HTTP contracts. Before release, read both hosted jobs for the target commit. Inspect the release package: `audit/worker-channel.ts` must be included, and tests must be excluded. `npm run pack` is not in the quality workflow and has to be run separately. `npm test` discovers contract tests under `tests/compat/`, apart from the platform and ACL cases skipped in the table above.

Keep the first failure and its conditions. Do not rerun indefinitely until green or count skipped, timed-out or import-failing tests as passes. Reopening a file after a normal shutdown is not a power-loss recovery test.
