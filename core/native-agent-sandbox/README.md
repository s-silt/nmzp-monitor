# native-agent-sandbox

Windows supervisor for a **new** Agent process tree. Not MXC. **Not production-ready**: private window station is `requires_admin` (unnamed `CWF_CREATE_ONLY` → 183), brokered WFP is not installed, Grok workspace/leader/model path is not wired. Self-test `overall=fail_production_unavailable`. Do not treat P0 regressions as a ship gate for live Grok.

## Production `--config`

- Kind is **LPAC only**. Regular AppContainer is an internal self-test comparison path.
- Required Job UI flags (cannot drop): `HANDLES|READCLIPBOARD|WRITECLIPBOARD|DESKTOP|DISPLAYSETTINGS`. Extra flags may be OR-ed.
- Profile prefix **`nmzp.agent.`** + nonce. Named job **`Local\<profile>.job`**. Collision (`ERROR_ALREADY_EXISTS`) retries a new nonce; never derives/deletes a pre-existing profile.
- Environment: empty block, fixed parent allowlist, reserved paths written last (`PATH`/`TEMP`/`GROK_HOME`/…). JSON cannot set reserved keys or soak parent env via `environment_allowlist`.
- `desktop` is rejected. Supervisor creates its own unnamed station (`CreateWindowStation(NULL, CWF_CREATE_ONLY)` + explicit current-user SD). If that is not a newly owned object, launch fails `requires_admin`. Named stations are Administrators-only per Microsoft; this component does not UAC-elevate and does not modify WinSta0/ACL/clipboard/screen.
- `network_mode=brokered` requires `gateway_port`, `controller_pid`, `controller_creation_time` and uses `OwnedNetworkJobLease` (same assembly). Real WFP apply is **forbidden this build**; non-admin `PrepareNetwork` returns `requires_admin`. Fake-world tests only. Not a complete protected Grok/workspace integration.
- stdin/stdout/stderr: three anonymous pipes, `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` whitelist only those handles; job handle is non-inheritable. Supervisor drains stdout/stderr through a **cross-chunk** OSC/DCS sanitizer. Cancel = terminate job + wait tree.
- Agent `deadline_ms` default 30 minutes, max 60 minutes. Fixture/self-test uses a separate ~20s bound.
- `--delete-profile` is not a production command.
- Elevated `--config` is refused (not an admin file deputy). `--privileged-init --dry-plan` is inspect-only stdout JSON. Do **not** run `--execute-payload` or UI/clipboard/screen capture until root final review. Screen pixels are not tested (`GetDC(NULL)` is never BitBlt/GetPixel). DXGI/WGC stay `not_tested`. `production_ready=false`.

Build outputs go to `%TEMP%\nmzp-nas-build` (never `core/`). Evidence: `acceptance/native-agent-sandbox/out`.

## Admin-only station fixture (do not run this round)

Microsoft: only Administrators may pass a name to `CreateWindowStation`. Named-station work waits on root final review. This tree must not call UAC, must not read physical display pixels, and must not use `FindWindow` title as HWND ownership.

## APIs

- https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-createwindowstationa
- https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer
- https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_ui_restrictions

## Failure-path revision

`--pure-self-test` exercises config and ResumeBarrier without any OS resource mutation. `controller_creation_time` is a decimal **string** containing exact GetProcessTimes creation FILETIME (100 ns ticks since 1601); JSON numbers are rejected. Unknown fields/test flags are rejected. Failed bind/prepare never resume; the sole resume rechecks held job membership, network-ready lease and controller liveness. Controller death is checked during pipe drains and descendant waits. Uncertain termination or cleanup retains constraints/profile and reports `cleanup_required`. These changes do not enable real WFP or complete the privileged entry.
