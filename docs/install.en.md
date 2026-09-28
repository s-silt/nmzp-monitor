# Install

[English home](../README.en.md) · [中文](install.md)

The quick start on the home page is enough to join one machine. This page is the full core and file layout. Version 0.2.6. Node.js 24 or newer. The core uses Node's own HTTPS. Devices pin the self-signed certificate. No root CA is installed into the operating system.

Copy `admin.token` and `join-bundle.json` as files. Do not paste them into chat or a URL, and do not commit them.

## Get a release

Download `nmzp-core.tgz` and `SHA256SUMS.txt` from the same [v0.2.6 release](https://github.com/s-silt/nmzp-monitor/releases/tag/v0.2.6) into one directory. No npm install or source tests are needed for the published package. Node.js 24 or newer is still required on the core and PCs.

On Linux, verify before extracting:

```bash
sha256sum -c SHA256SUMS.txt
```

On Windows, compare the archive hash with its entry in the checksum file:

```powershell
Get-FileHash -LiteralPath .\nmzp-core.tgz -Algorithm SHA256
Get-Content -LiteralPath .\SHA256SUMS.txt
```

Only after the hashes match, extract `nmzp-core.tgz` into a new staging directory. The archive contains `nmzp/`; run PC commands below from that extracted directory. A checksum verifies agreement with the published file, not the trustworthiness of a different download source.

### Build from source

Contributors use the [development setup and scoped verification](../CONTRIBUTING.md#development-setup), then `npm run pack` or `sh core/pack.sh` to create `nmzp-core.tgz`. Both commands call only `scripts/build.mjs`, which bundles the runtime with rolldown into single-file CJS (`nmzp-main.cjs` plus one `.cjs` per worker); the archive no longer ships `.ts` sources. The archive timestamp is a validated decimal `SOURCE_DATE_EPOCH`, or 0 when unset, so the same inputs produce identical tgz bytes. Recognized text in the archive is stored as LF, including runtime code, docs, config, scripts, and named license files. Bytes that contain a NUL stay unchanged. The tar mode is `0755` for `nmzp`, `nmzp.mjs`, shebang files, and `*.sh`. Extracting the archive on Windows does not show that Linux can execute it. `.pack/SHA256SUMS.txt` is one GNU sha256sum line: the digest is the bytes of `.pack/nmzp-core.tgz`, and the filename is written as `nmzp-core.tgz`. `.pack/nmzp-files.sha256` lists packed files with paths relative to `.pack`. The `nmzp-core.tgz` at the repository root is the same bytes as the archive inside `.pack`. `SHA256SUMS.txt` on the release page above still names the historical release asset. Host installation and Windows ACL tests have separate prerequisites; do not run the unfiltered test suite as part of first installation.

## Core

Extract to `/opt/nmzp` and start it with the existing `nmzp` user and systemd. See [Dedicated CT](#ct-install). No computer is watched yet. `GET /health` returns `{ok,name,version}` only. That is not proof of protection.

```bash
runuser -u nmzp -- env NMZP_DATA=/var/lib/nmzp NMZP_PUBLIC_URL=https://<CT-IP>:8787 \
  node /opt/nmzp/nmzp.mjs ticket --out /var/lib/nmzp/join-bundle.json
```

`ticket`, `status`, and `rules` must use the same user and data directory as the running service. Do not let root create a second tree under `~/.nmzp/ct-data`.

<a id="certificate-address-mismatch"></a>

## Certificate address mismatch

Subject alternative names are fixed when the core first creates `<dataDir>/tls/`. That certificate contains `127.0.0.1`, `localhost`, and any names in `NMZP_TLS_HOSTS` at that start. NMZP does not rotate the certificate later. `NMZP_BIND` of `0.0.0.0` or `::` is only the listen address. It is not written into the certificate, and NMZP does not guess a LAN address.

`NMZP_PUBLIC_URL` is the address advertised in the join bundle. It is not added to a certificate that already exists. `nmzp ticket` checks it only when the variable is set. The value must be a parseable `https` URL; otherwise the command fails and writes no bundle. When the host is not on the existing certificate, the command exits non-zero and writes one stderr line, `certificate_address_mismatch`, listing the certificate's DNS names and IP addresses. Offline, this happens before a ticket is stored, so no ticket is added. When the core is already running, the core issues the ticket first; this command then refuses to write the bundle and says that the ticket was not written and will expire. With `NMZP_PUBLIC_URL` unset, ticket still uses the loopback URL and does not compare the listen address.

If `<dataDir>/tls/` does not exist yet, an offline `ticket` creates a loopback certificate and then performs that check. A first ticket that sets a public URL can therefore leave a certificate that contains only loopback names. Changing `NMZP_TLS_HOSTS`, `NMZP_PUBLIC_URL`, or `NMZP_BIND` later does not alter that certificate while `tls/` remains in place.

Replacing the address is a manual maintenance-window procedure. Do not treat the following as a script to run: stop the CT; back up all of `<dataDir>/tls/` (`server.key`, `server.crt`, `pin.json`) and keep the private key on that machine, out of chat, join bundles, and the repository; move `<dataDir>/tls/` off its original path. Start again with the public names in `NMZP_TLS_HOSTS` and the bundle URL in `NMZP_PUBLIC_URL`. A new certificate is created only when no `tls/` directory is left at the original path.

Every device must join again and pin the new fingerprint. Old bundles and old pins no longer work. During the change, devices cannot reach the core, hooks fall back to the cached local policy, and probes show offline. Existing device identities on the core do not move to the new certificate. Keep the backup until the new fingerprint is confirmed. Moving the backup back restores the old certificate, and devices that already joined with the new one must join again.

## Guarded machine

```powershell
.\nmzp.cmd join .\join-bundle.json
```

Success prints the device id and autostart kind, never the token. Join writes a host config only where that host's directory already exists.

Fully quit and reopen desktop hosts or the new hook will not load. Inside Codex, trust `NMZP PreToolUse v1` with `/hooks`. NMZP does not write that trust table. A guarded PC does not need `admin.token`.

## Admin machine

Keep the admin token on the admin machine. Do not ship it as enrollment material for every guarded PC. A machine that is both runs both sets of steps.

```powershell
.\nmzp.cmd board --bundle join-bundle.json --token-file admin.token
```

Open `http://127.0.0.1:8788` and pick the token file. The token is not placed in the URL or in localStorage.

Other people on the LAN open `http://<CT-IP>:8789`. That view is read-only.

## Stop and uninstall

Use NMZP's own commands. An agent `pkill` or `Stop-Process` against this probe is in the self-protection rules.

`.\nmzp.cmd stop` stops the probe only. Hooks stay, and Startup can launch the probe again. `nmzp rights stop` pauses policy on the core. It does not stop the local probe. To stop enforcement, run `.\nmzp.cmd uninstall` (the same as `leave`), then fully quit and reopen desktop hosts.

`uninstall` / `leave` removes hooks and the probe on that machine only. It does not revoke the device credential on the core. Core revocation is an administrator confirmation on the board for that device. After revocation, further requests from the device are rejected. A hook that is already disconnected and still running on a cached policy is not stopped by that action. Revocation does not remotely stop offline execution. Coming back requires a new one-time join ticket.

```bat
for /d %I in ("%USERPROFILE%\.nmzp\runtime\*") do "%I\nmzp.cmd" uninstall
```

```bat
wscript //nologo "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\NMZP-probe.vbs"
```

The probe is a hidden Startup script. No console has to stay open. Only the local admin page needs `nmzp board`. If `nmzp snapshot apply` was used, quit ZCode and run `.\nmzp.cmd snapshot restore` before uninstall. Leave does not undo that directory ACL.

| File | Where | What |
| --- | --- | --- |
| `admin.token` | Core `/var/lib/nmzp/`, copied to the admin machine | Local board login. Not for git or chat |
| `join-bundle.json` | Issued on the core | Device join. Contains a one-time ticket |
| `credentials.json` | Guarded machine `%USERPROFILE%\.nmzp\` | Probe heartbeat credentials, not the admin token |
| `hook-status.json` | Guarded machine `%USERPROFILE%\.nmzp\` | Local receipt. Its absence is not, by itself, a diagnosis that the host never called NMZP |

The device file `~/.nmzp/.lock` is shared by the hook and local offline evaluation. After the holding process is interrupted, only a format version 2 lock on this same host whose owner is proven dead is renamed beside it to `.lock.stale-<milliseconds>-<random id>`: the pid is gone, the Linux boot id differs, or the pid was reused and its start time differs. Those archives are not deleted. A legacy or unreadable lock, a symlink, another hostname, a lock that is still held, and a leftover `.lock.recover` stay in place. When a lock is present, `nmzp status` adds one line to standard error: reclaimable, held, or unverifiable. If it is unverifiable, confirm that no nmzp hook is running, then delete that file manually.

## Upgrade and storage mode

Verify the new package and stage it separately. Before replacing a running core, record the core and `nmzp-viewer` service states and back up the runtime, data, policy, certificate, and service configuration. Use a maintenance window with the writer stopped; do not overwrite a running runtime. Restore both services that were previously running, then check health, board access, device heartbeats, and policy versions. A rollback must preserve the new data first; it must not bypass an uncertain policy commit.

A core-only upgrade keeps existing device identities and pinned certificates. It does not update device runtimes. For an adapter or local-engine update, explicitly update each device using the new runtime and the join/install flow; if enrollment is needed, issue a fresh one-time ticket rather than reusing an expired bundle. Reload the host and verify a synthetic call and its receipt. Do not distribute admin credentials to guarded PCs.

Default storage remains the 2,000-event window. SQLite is optional and uses Node's built-in database; no separate database server is required. **An existing data directory must pass preflight and migration before enabling `NMZP_STORAGE_MODE=sqlite`; changing only the environment variable is insufficient.** See [storage modes, migration and rollback](policy-runtime.en.md). A fresh, empty directory can initialize directly in the chosen mode.


<a id="ct-install"></a>

## Dedicated CT

This is the reference deployment: a dedicated PVE CT with systemd, no SSH inside the CT, management through `pct`, and no additional Docker layer. These are reference-environment choices, not universal protocol requirements. Other deployment layouts have not been validated here.

The supplied units expect `/usr/local/bin/node`, system user/group `nmzp`, runtime `/opt/nmzp`, and writable data `/var/lib/nmzp`. Before starting, create the service account and data directory with appropriate ownership; verify Node's version and path. If paths differ, adjust both service units deliberately. The commands below are for a new installation; use the upgrade procedure above for an existing core.

```bash
tar -C /opt -xzf nmzp-core.tgz
install -m 644 /opt/nmzp/nmzp.service /etc/systemd/system/nmzp.service
# If the certificate SAN needs the CT LAN address:
# mkdir -p /etc/systemd/system/nmzp.service.d
# echo -e '[Service]\nEnvironment=NMZP_TLS_HOSTS=192.168.x.x\nEnvironment=NMZP_PUBLIC_URL=https://192.168.x.x:8787' > /etc/systemd/system/nmzp.service.d/override.conf
systemctl daemon-reload
systemctl enable --now nmzp
```

### Read-only LAN viewer

LAN clients still do not hold an admin token. The viewer process pulls state from the core with a separate read-only credential. That file does not contain `admin.token`.

A viewer that has not been migrated keeps working through the core admin token. On startup it writes one stderr warning telling the operator to switch to `nmzp viewer-credential`. The account, file permission, and unit steps below are manual. None of them have been applied to a live CT.

```bash
install -d -m 755 /etc/nmzp
cat >/etc/nmzp/viewer.env <<'EOF'
NMZP_VIEWER_HOST=<CT-LAN-IPv4>
NMZP_VIEWER_PORT=8789
NMZP_VIEWER_ALLOW_CIDR=<LAN CIDR, for example 192.168.x.0/24>
EOF
chmod 600 /etc/nmzp/viewer.env
# 1. Create a dedicated system user. Do not reuse nmzp.
useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin nmzp-viewer
# 2. While the core is up and serve.json plus tls/server.crt are on disk, run this as the core user.
#    The command does not read admin.token and does not call the admin API.
nmzp viewer-credential --out /etc/nmzp/viewer-credential.json
# 3. Give the credential file to the viewer user only.
chown nmzp-viewer:nmzp-viewer /etc/nmzp/viewer-credential.json
chmod 600 /etc/nmzp/viewer-credential.json
# 4. Install the unit. 5. Then start or restart it.
install -m 644 /opt/nmzp/nmzp-viewer.service /etc/systemd/system/nmzp-viewer.service
systemctl daemon-reload
systemctl enable nmzp-viewer
systemctl restart nmzp-viewer
```

The unit is `nmzp viewer --host <private-ip> --port 8789 --allow-cidr <CIDR>`. It runs as `nmzp-viewer` with `NMZP_VIEWER_CREDENTIAL=/etc/nmzp/viewer-credential.json` and `InaccessiblePaths=/var/lib/nmzp`. Only source addresses inside the allow list pass. POST, PUT, PATCH, DELETE, and `/api/v1/session`, `/policy`, `/evaluate`, `/join`, `/receipt` are rejected even with an admin token.

| Role | Address | Token |
| --- | --- | --- |
| Core TLS | `https://<CT-IP>:8787` | Device credentials or the admin token |
| Local admin board | `http://127.0.0.1:8788` | Required. Pick the token file |
| LAN read-only | `http://<CT-IP>:8789` | None. Cannot change policy |

## Optional container

The reference deployment remains the dedicated CT above, with no extra Docker layer inside it. The image below uses the already packed runtime as its build context and runs as `nmzp`, not root. This change did not build or run the image. Do not pull `node:24-bookworm-slim` when it is not already local.

Run these from the repository root. Do not leave the shell inside `.pack`:

```bash
sh core/pack.sh
( cd .pack && sha256sum -c SHA256SUMS.txt )
docker build --network=none --pull=false -f core/Dockerfile -t nmzp-core:<version> .pack/nmzp
```

`<version>` is the `version` field in `package.json`. The build context is `.pack/nmzp`. `core/Dockerfile` stays outside that context. The data directory is `/var/lib/nmzp`. In the image that directory is owned by `nmzp:nmzp` with mode `0700`. A new named volume hides that directory and is usually owned by root; `nmzp` inside the container cannot change the owner. Bind a directory that is already owned by that numeric uid and is mode `0700`.

```bash
docker run --rm --network=none --entrypoint id nmzp-core:<version> -u
docker run -d --name nmzp-test -p 127.0.0.1:18787:8787 \
  --mount type=bind,source=<that-directory>,target=/var/lib/nmzp \
  nmzp-core:<version>
```

The listener is HTTPS. A health check trusts the new `tls/server.crt` in the data directory and requests `https://127.0.0.1:18787/health`. Until the maintainer offline checklist is filled in, these commands are not evidence that the image works.
