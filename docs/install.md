# 安装

[中文首页](../README.md) · [English](install.en.md)

首页的「快速开始」够完成一次加入。这里是 CT 与本机文件的完整步骤。版本 0.2.4，Node.js 24 或更新。核心用 Node 自带 HTTPS，设备端固定信任自签证书，不往系统里装根证书。

`admin.token` 和 `join-bundle.json` 当文件拷贝。不要贴进聊天，不要放进 URL，不要提交进 git。

## 获取发布包

从同一个 [v0.2.4 发布页](https://github.com/s-silt/nmzp-monitor/releases/tag/v0.2.4) 下载 `nmzp-core.tgz` 和 `SHA256SUMS.txt`，放在同一目录。使用发布包不需要安装 npm 依赖或运行源码测试；核心与各电脑仍需要 Node.js 24 或更新。

Linux 先校验再解包：

```bash
sha256sum -c SHA256SUMS.txt
```

Windows 对照压缩包哈希与校验文件中对应的条目：

```powershell
Get-FileHash -LiteralPath .\nmzp-core.tgz -Algorithm SHA256
Get-Content -LiteralPath .\SHA256SUMS.txt
```

确认一致后才把 `nmzp-core.tgz` 解到新的暂存目录。包内目录为 `nmzp/`，下文电脑端命令均从解出的该目录运行。校验值只能验证文件与发布内容一致，不能替代对下载来源的信任。

### 从源码构建

开发者按 [开发环境与定向验证](../CONTRIBUTING.md#development-setup) 完成检查，再运行 `npm run pack` 生成 `nmzp-core.tgz`。宿主安装、Windows ACL 等测试有单独前提；首次安装不需要运行无筛选测试集。

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

## 升级与存储模式

先校验新包并在独立目录暂存。替换正在运行的核心前，记录核心与 `nmzp-viewer` 服务状态，备份程序、数据、策略、证书及服务配置。在排除写入者的维护窗口切换，不覆盖运行中的程序；随后恢复原先运行的两项服务，核对健康、看板访问、设备心跳和策略版本。回退前保留新数据，不能绕过提交不确定状态的恢复检查。

只升级核心时保留既有设备身份与证书；它不会更新设备端运行文件。修改适配器或本地引擎时，应使用新运行包，通过加入/安装流程显式更新各设备；需要重新加入时签发新的一次性票据，不复用过期加入包。重新加载宿主，再用合成调用及回执核对。被监护电脑不需要管理员口令。

默认仍是 2,000 条窗口。SQLite 为可选的 Node 内置数据库，无需单独安装数据库服务器。**已有数据目录必须先预检、迁移，不能只设置 `NMZP_STORAGE_MODE=sqlite` 就切换。** 具体启用与回退见 [存储模式、迁移与恢复](policy-runtime.md)。全新空目录可直接按所选模式初始化。


<a id="ct-install"></a>

## 专用 CT

以下是参考部署环境：专用 PVE CT、systemd、CT 内无 SSH、通过宿主 `pct` 管理，不再套 Docker。这些是参考环境约定，不是协议的通用技术要求；其他部署布局尚未在这里验证。

附带单元文件约定 `/usr/local/bin/node`、系统用户/组 `nmzp`、程序 `/opt/nmzp`、可写数据 `/var/lib/nmzp`。启动前先准备服务账号与数据目录及所属权限，核实 Node 版本与路径；路径不同时需明确调整两份服务单元。下面的命令适用于新安装，已有核心按上面的升级步骤处理。

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

参考环境通过 PVE 宿主管理 CT，不依赖 CT 内 SSH。
