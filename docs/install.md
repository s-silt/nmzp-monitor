# 安装

[中文首页](../README.md) · [English](install.en.md)

首页的「快速开始」够完成一次加入。这里是 CT 与本机文件的完整步骤。版本 0.2.5，Node.js 24 或更新。核心用 Node 自带 HTTPS，设备端固定信任自签证书，不往系统里装根证书。

`admin.token` 和 `join-bundle.json` 当文件拷贝。不要贴进聊天，不要放进 URL，不要提交进 git。

## 获取发布包

从同一个 [v0.2.5 发布页](https://github.com/s-silt/nmzp-monitor/releases/tag/v0.2.5) 下载 `nmzp-core.tgz` 和 `SHA256SUMS.txt`，放在同一目录。使用发布包不需要安装 npm 依赖或运行源码测试；核心与各电脑仍需要 Node.js 24 或更新。

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

开发者按 [开发环境与定向验证](../CONTRIBUTING.md#development-setup) 完成检查，再运行 `npm run pack` 或 `sh core/pack.sh` 生成 `nmzp-core.tgz`。两条命令都只走 `core/pack.ts`。归档时间戳取已校验的十进制 `SOURCE_DATE_EPOCH`，未设置时为 0，同一输入得到的 tgz 字节相同。打包时把已识别的文本收成 LF，包括运行时代码、文档、配置、脚本和具名许可证；含 NUL 的二进制不改。`nmzp`、`nmzp.mjs`、shebang 文件和 `*.sh` 的 tar 模式为 `0755`。在 Windows 上解包不能证明 Linux 能直接执行。`.pack/SHA256SUMS.txt` 只有一行 GNU sha256sum，摘要是 `.pack/nmzp-core.tgz` 的字节，文件名写作 `nmzp-core.tgz`。`.pack/nmzp-files.sha256` 是包内文件清单，路径相对 `.pack`。仓库根目录的 `nmzp-core.tgz` 与 `.pack` 里的归档字节相同。上文发布页里的 `SHA256SUMS.txt` 仍指历史发布资产。宿主安装、Windows ACL 等测试有单独前提；首次安装不需要运行无筛选测试集。

## 核心

把包解到 `/opt/nmzp`，用已有 `nmzp` 用户和 systemd 起服务。详见 [专用 CT](#ct-install)。此时还不会检测任何电脑。`GET /health` 只返回 `{ok,name,version}`，不代表已经防护。

签发加入包：

```bash
runuser -u nmzp -- env NMZP_DATA=/var/lib/nmzp NMZP_PUBLIC_URL=https://<CT的IP>:8787 \
  node /opt/nmzp/nmzp.mjs ticket --out /var/lib/nmzp/join-bundle.json
```

`ticket`、`status`、`rules` 必须和正在跑的服务同一用户、同一数据目录。别用 root 默认的 `~/.nmzp/ct-data`。

<a id="certificate-address-mismatch"></a>

## 证书地址不匹配

证书里的 SAN 只在核心第一次创建 `<dataDir>/tls/` 时写定，用的是那一次启动给出的名字：固定有 `127.0.0.1` 和 `localhost`，再加上当时的 `NMZP_TLS_HOSTS`。NMZP 不会自动换证。`NMZP_BIND` 设成 `0.0.0.0` 或 `::` 只表示监听，不会写进证书，程序也不去猜本机局域网地址。

`NMZP_PUBLIC_URL` 只决定加入包里公布的地址，不会补进已经生成的证书。`nmzp ticket` 仅在设置了这个变量时检查它。值必须是能解析的 `https` URL，否则命令失败，不写加入包。主机不在现有证书里时，命令非零退出，标准错误只有一行 `certificate_address_mismatch`，并列出证书上的 DNS 和 IP。离线路径在写入票据之前拒绝，不会多出一张票据。核心已经在跑时，票据由核心先签发，这条命令拒绝把加入包写到磁盘，并说明该票据没有写出、会在有效期后过期。未设置 `NMZP_PUBLIC_URL` 时，仍按原来的回环地址签发，不拿监听地址做比对。

数据目录里还没有 `tls/` 时，离线 `ticket` 会先按回环地址建证，再做上面的检查。第一次就带上对外 URL，也可能留下一张只有回环名字的证书。之后只改 `NMZP_TLS_HOSTS`、`NMZP_PUBLIC_URL` 或 `NMZP_BIND`，只要原来的 `tls/` 还在，启动和签发都继续用这张旧证。

要换成正确地址，只能在维护窗口里手工处理。下面是步骤说明，不要当成脚本执行：停掉 CT；把 `<dataDir>/tls/` 整份备份下来（`server.key`、`server.crt`、`pin.json`），私钥留在这台机器上，不要放进聊天、加入包或仓库；再把 `<dataDir>/tls/` 从原路径移开。用正确地址重新启动，对外名字放进 `NMZP_TLS_HOSTS`，加入包地址放进 `NMZP_PUBLIC_URL`。原路径没有旧的 `tls/` 时，启动才会生成新证书。

每台设备都要重新加入，并固定信任新证书指纹。旧加入包和旧 pin 不能再用。换证期间设备连不上核心，hook 退回本机缓存策略，探针显示离线。核心上的旧设备身份不会跟着新证书迁过去。新指纹确认可用之前留着备份。把备份移回原路径会回到旧证书，已经用新证书加入的设备要再加入一次。

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

`uninstall` / `leave` 只清这台电脑上的 hook 和探针。它不在核心上吊销设备凭据。核心吊销要管理员在看板里对这台设备确认。吊销之后，这台设备再发来的请求会被拒绝。已经断开、拿着缓存策略继续跑的 hook 不会因此马上停下。吊销不能远程停掉离线执行。要再接入，用新的一次性票据重新加入。

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

设备端 `~/.nmzp/.lock` 是 hook 和本机离线评估共用的文件锁。持有进程被中断后，同一台主机上只有格式版本 2、且能证明持有者已经死亡的锁会自动改名留在同目录，文件名是 `.lock.stale-<毫秒时间>-<随机标识>`：进程不存在、Linux 上启动标识不同，或进程号被复用且起始时间不同。程序不会删除这些归档。旧格式、无法解析、符号链接、其他主机名、仍被占用的锁，以及残留的 `.lock.recover`，不会自动清掉。`nmzp status` 看到锁时会向标准错误多打印一行：可回收、占用中，或无法确认。无法确认时，先确认没有 nmzp hook 在运行，再手动删除该文件。

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

局域网客户端仍然不持有管理口令。viewer 进程向核心拉取状态时使用单独的只读凭据，凭据文件里没有 `admin.token`。

还没迁移的 viewer 继续走核心管理员口令，可以工作。启动时标准错误多一行警告，提示改用 `nmzp viewer-credential`。下面的账号、文件权限和单元安装是人工步骤。本仓库没有对任何正在运行的 CT 执行过这些变更。

```bash
install -d -m 755 /etc/nmzp
cat >/etc/nmzp/viewer.env <<'EOF'
NMZP_VIEWER_HOST=<CT局域网IPv4>
NMZP_VIEWER_PORT=8789
NMZP_VIEWER_ALLOW_CIDR=<本网段CIDR，例如 192.168.x.0/24>
EOF
chmod 600 /etc/nmzp/viewer.env
# 1. 单独的系统用户，不要复用 nmzp。
useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin nmzp-viewer
# 2. 核心正在运行、数据目录里已有 serve.json 与 tls/server.crt 时，用核心用户执行。
#    这条命令不读取 admin.token，也不调用管理 API。
nmzp viewer-credential --out /etc/nmzp/viewer-credential.json
# 3. 凭据只交给 viewer 用户。
chown nmzp-viewer:nmzp-viewer /etc/nmzp/viewer-credential.json
chmod 600 /etc/nmzp/viewer-credential.json
# 4. 安装单元。5. 再启动或重启。
install -m 644 /opt/nmzp/nmzp-viewer.service /etc/systemd/system/nmzp-viewer.service
systemctl daemon-reload
systemctl enable nmzp-viewer
systemctl restart nmzp-viewer
```

服务等价于 `nmzp viewer --host <private-ip> --port 8789 --allow-cidr <CIDR>`。单元用户是 `nmzp-viewer`，`NMZP_VIEWER_CREDENTIAL=/etc/nmzp/viewer-credential.json`，`InaccessiblePaths=/var/lib/nmzp`。只放行 allow-cidr 内的源地址。POST、PUT、PATCH、DELETE 以及 `/api/v1/session`、`/policy`、`/evaluate`、`/join`、`/receipt` 一律拒绝，带管理口令也不行。

| 角色 | 地址 | 口令 |
| --- | --- | --- |
| 核心 TLS | `https://<CT的IP>:8787` | 设备凭据或管理口令 |
| 本机管理看板 | `http://127.0.0.1:8788` | 要，选口令文件 |
| 局域网只读 | `http://<CT的IP>:8789` | 不要，也改不了策略 |

参考环境通过 PVE 宿主管理 CT，不依赖 CT 内 SSH。

## 可选容器

参考部署仍是上面的专用 CT，不在里面再套一层 Docker。下面的镜像用已经打好的运行目录做构建上下文，进程用户是 `nmzp`，不是 root。这次修改没有构建，也没有运行镜像。本机没有 `node:24-bookworm-slim` 时不要拉取。

在仓库根目录执行，不要先把当前目录留在 `.pack`：

```bash
sh core/pack.sh
( cd .pack && sha256sum -c SHA256SUMS.txt )
docker build --network=none --pull=false -f core/Dockerfile -t nmzp-core:<version> .pack/nmzp
```

`<version>` 与 `package.json` 的 `version` 相同。构建上下文是 `.pack/nmzp`。`core/Dockerfile` 留在上下文外面。数据目录是 `/var/lib/nmzp`，镜像里该目录属于 `nmzp:nmzp`，权限 `0700`。新建的命名卷会盖住这个目录，并且通常属于 root；容器里的 `nmzp` 不能再改所有者。运行时绑定一个已经属于该用户数字 id、权限为 `0700` 的目录。

```bash
docker run --rm --network=none --entrypoint id nmzp-core:<version> -u
docker run -d --name nmzp-test -p 127.0.0.1:18787:8787 \
  --mount type=bind,source=<该目录>,target=/var/lib/nmzp \
  nmzp-core:<version>
```

监听是 HTTPS。健康检查要信任数据目录里新生成的 `tls/server.crt`，访问 `https://127.0.0.1:18787/health`。维护者离线清单填完之前，这些命令不是镜像可用的证据。
