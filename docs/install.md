# 安装

[中文首页](../README.md) · [English](install.en.md)

首页的「快速开始」够完成一次加入。这里是 CT 与本机文件的完整步骤。版本 0.2.3，Node.js 24 或更新。核心用 Node 自带 HTTPS，设备端固定信任自签证书，不往系统里装根证书。

`admin.token` 和 `join-bundle.json` 当文件拷贝。不要贴进聊天，不要放进 URL，不要提交进 git。

## 打包

在你信任的开发机上：

```bash
npm ci && npm test && npm run build && npm run pack
```

得到 `nmzp-core.tgz`。

## 核心

把包解到 `/opt/nmzp`，用已有 `nmzp` 用户和 systemd 起服务。详见 [专用 CT](#ct-install)。此时还不会检测任何电脑。`GET /health` 只返回 `{ok,name,version}`，不代表已经防护。

签发加入包：

```bash
runuser -u nmzp -- env NMZP_DATA=/var/lib/nmzp NMZP_PUBLIC_URL=https://<CT的IP>:8787 \
  node /opt/nmzp/nmzp.mjs ticket --out /var/lib/nmzp/join-bundle.json
```

`ticket`、`status`、`rules` 必须和正在跑的服务同一用户、同一数据目录。别用 root 默认的 `~/.nmzp/ct-data`。

## 被监护电脑

```powershell
.\nmzp.cmd join .\join-bundle.json
```

只打印设备号和自启方式，不打印口令。`join` 只给本机已经存在的宿主目录写配置。

加完之后，正在跑的桌面宿主要完全退出再打开，否则不会加载新 hook。Codex 还要在宿主里 `/hooks` 信任 `NMZP PreToolUse v1`。NMZP 不写 Codex 的信任表。被监护电脑不需要 `admin.token`。

## 管理员电脑

管理口令只放在管理员电脑上，不要当成加入材料发给每一台被监护电脑。同一台电脑兼任两种角色时，两组步骤都做。

```powershell
.\nmzp.cmd board --bundle join-bundle.json --token-file admin.token
```

浏览器开 `http://127.0.0.1:8788`，选口令文件登录。口令不进 URL，不进 localStorage。

局域网其他人开 `http://<CT的IP>:8789`，只读，改不了规则。

## 停和卸

用 NMZP 自己的命令。不要让 Agent 去 `pkill` 或 `Stop-Process`，自保规则会拦。

`.\nmzp.cmd stop` 只停探针。hook 还在，下次登录还会自启。`nmzp rights stop` 是核心上暂停政策，不是关本机进程。要彻底不拦，用 `.\nmzp.cmd uninstall`（与 `leave` 同义），然后把桌面宿主完全退出再打开。

找不到解包目录时：

```bat
for /d %I in ("%USERPROFILE%\.nmzp\runtime\*") do "%I\nmzp.cmd" uninstall
```

再开探针：

```bat
wscript //nologo "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\NMZP-probe.vbs"
```

探针由 Startup 里的 `NMZP-probe.vbs` 拉起，可以隐藏运行，不需要一直开着黑窗口。只有本机 8788 需要 `nmzp board` 还在跑。若用过 `nmzp snapshot apply`，卸之前先退出 ZCode，再 `.\nmzp.cmd snapshot restore`。卸载不解这项目录 ACL。

| 文件 | 位置 | 用途 |
| --- | --- | --- |
| `admin.token` | 核心 `/var/lib/nmzp/`，拷到管理员机 | 本机看板登录。别进 git，别贴聊天 |
| `join-bundle.json` | 核心签发目录 | 设备加入，内含一次性票据 |
| `credentials.json` | 被监护机 `%USERPROFILE%\.nmzp\` | 探针心跳凭据，不是管理口令 |
| `hook-status.json` | 被监护机 `%USERPROFILE%\.nmzp\` | 本机回执。没有这份文件还不能单凭这一点断定宿主没调用 |

没重新 `join` 的探针还是旧包。换适配器的顺序是 `npm run pack`，各机重新 join，桌面宿主完全退出再开，再跑一次工具看回执。

<a id="ct-install"></a>

## 专用 CT

不要套 Docker。CT 无 SSH，宿主用 `pct exec` 拷包。Node 在 `/usr/local/bin/node`，系统用户 `nmzp`，数据 `/var/lib/nmzp`。

```bash
tar -C /opt -xzf nmzp-core.tgz
install -m 644 /opt/nmzp/nmzp.service /etc/systemd/system/nmzp.service
# 证书 SAN 需要 CT 局域网地址时：
# mkdir -p /etc/systemd/system/nmzp.service.d
# echo -e '[Service]\nEnvironment=NMZP_TLS_HOSTS=192.168.x.x\nEnvironment=NMZP_PUBLIC_URL=https://192.168.x.x:8787' > /etc/systemd/system/nmzp.service.d/override.conf
systemctl daemon-reload
systemctl enable --now nmzp
```

### 局域网只读 viewer

```bash
install -d -m 755 /etc/nmzp
cat >/etc/nmzp/viewer.env <<'EOF'
NMZP_VIEWER_HOST=<CT局域网IPv4>
NMZP_VIEWER_PORT=8789
NMZP_VIEWER_ALLOW_CIDR=<本网段CIDR，例如 192.168.x.0/24>
EOF
chmod 600 /etc/nmzp/viewer.env
install -m 644 /opt/nmzp/nmzp-viewer.service /etc/systemd/system/nmzp-viewer.service
systemctl daemon-reload
systemctl enable --now nmzp-viewer
```

服务等价于 `nmzp viewer --host <private-ip> --port 8789 --allow-cidr <CIDR>`。只放行 allow-cidr 内的源地址。POST、PUT、PATCH、DELETE 以及 `/api/v1/session`、`/policy`、`/evaluate`、`/join`、`/receipt` 一律拒绝，带管理口令也不行。

| 角色 | 地址 | 口令 |
| --- | --- | --- |
| 核心 TLS | `https://<CT的IP>:8787` | 设备凭据或管理口令 |
| 本机管理看板 | `http://127.0.0.1:8788` | 要，选口令文件 |
| 局域网只读 | `http://<CT的IP>:8789` | 不要，也改不了策略 |

别把 SSH 进 CT 当成日常管理。
