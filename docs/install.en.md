# Install

[English home](../README.en.md) · [中文](install.md)

The quick start on the home page is enough to join one machine. This page is the full core and file layout. Version 0.2.4. Node.js 24 or newer. The core uses Node's own HTTPS. Devices pin the self-signed certificate. No root CA is installed into the operating system.

Copy `admin.token` and `join-bundle.json` as files. Do not paste them into chat or a URL, and do not commit them.

## Pack

On a machine you trust:

```bash
npm ci && npm test && npm run build && npm run pack
```

That produces `nmzp-core.tgz`.

## Core

Extract to `/opt/nmzp` and start it with the existing `nmzp` user and systemd. See [Dedicated CT](#ct-install). No computer is watched yet. `GET /health` returns `{ok,name,version}` only. That is not proof of protection.

```bash
runuser -u nmzp -- env NMZP_DATA=/var/lib/nmzp NMZP_PUBLIC_URL=https://<CT-IP>:8787 \
  node /opt/nmzp/nmzp.mjs ticket --out /var/lib/nmzp/join-bundle.json
```

`ticket`, `status`, and `rules` must use the same user and data directory as the running service. Do not let root create a second tree under `~/.nmzp/ct-data`.

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

A probe that was not re-joined is still the old pack. The order for an adapter change is `npm run pack`, join again, fully quit and reopen desktop hosts, then one tool call to confirm a receipt.

<a id="ct-install"></a>

## Dedicated CT

Do not wrap this layout in Docker. The CT has no SSH. The host copies the pack with `pct exec`. Node is `/usr/local/bin/node`, the system user is `nmzp`, and data is `/var/lib/nmzp`.

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

```bash
install -d -m 755 /etc/nmzp
cat >/etc/nmzp/viewer.env <<'EOF'
NMZP_VIEWER_HOST=<CT-LAN-IPv4>
NMZP_VIEWER_PORT=8789
NMZP_VIEWER_ALLOW_CIDR=<LAN CIDR, for example 192.168.x.0/24>
EOF
chmod 600 /etc/nmzp/viewer.env
install -m 644 /opt/nmzp/nmzp-viewer.service /etc/systemd/system/nmzp-viewer.service
systemctl daemon-reload
systemctl enable --now nmzp-viewer
```

The unit is `nmzp viewer --host <private-ip> --port 8789 --allow-cidr <CIDR>`. Only source addresses inside the allow list pass. POST, PUT, PATCH, DELETE, and `/api/v1/session`, `/policy`, `/evaluate`, `/join`, `/receipt` are rejected even with an admin token.

| Role | Address | Token |
| --- | --- | --- |
| Core TLS | `https://<CT-IP>:8787` | Device credentials or the admin token |
| Local admin board | `http://127.0.0.1:8788` | Required. Pick the token file |
| LAN read-only | `http://<CT-IP>:8789` | None. Cannot change policy |
