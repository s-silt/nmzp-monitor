<p align="center">
  <img src="public/favicon.svg" width="64" alt="NMZP">
</p>

<h1 align="center">NMZP Monitor</h1>

<p align="center">
  局域网编码 Agent 监护
  <br>
  <sub>工具调用执行前过一遍规则：高危拦掉，隐私词改写，其余记账。<br>只审计已接入设备上的 Agent，不看你本人，不采集聊天。</sub>
</p>

<p align="center">
  <strong>中文</strong>
  &nbsp;·&nbsp;
  <a href="README.en.md">English</a>
</p>

<p align="center">
  <img alt="MIT" src="https://img.shields.io/badge/license-MIT-ecece6?labelColor=0A0B0D">
  <img alt="Node 24+" src="https://img.shields.io/badge/node-%3E%3D24-ecece6?labelColor=0A0B0D">
  <img alt="version" src="https://img.shields.io/badge/version-0.2.2-ecece6?labelColor=0A0B0D">
</p>

<p align="center">
  <img src="docs/screenshots/overview-fleet-dark.png" alt="总览：三台已接入电脑与 Agent hook 状态" width="920">
</p>

一台专用 CT 当核心，被监护电脑跑探针。核心只用 Node 自带 HTTPS，设备端固定信任自签证书，**不往系统里装根证书**。许可 [MIT](LICENSE)，可自编译、可改写。

> 建议让 Agent 帮你部署：它会知道为什么有的行为会被拦。

---

## 支持的 Agent

13 个官方 PreToolUse 协议适配器。`join` 时**只给本机已存在的宿主目录**写配置，不给没装的产品伪造文件。

每个适配器做同一件事：工具调用执行前送规则引擎 → 拦截 / 改写参数 / 放行记账 → 写本机回执 `hook-status.json` → 上报 CT 看板。差异只在各宿主的退出码、JSON 键名和 deny 语义。

| Agent | join 写入 | 拦截 | 改写 | 记账 | 额外条件 |
| --- | --- | :---: | :---: | :---: | --- |
| **Grok** | `~/.grok/hooks/nmzp.json` | ✅ | ✅ | ✅ | 官方 fail-open |
| **Claude Code** | `~/.claude/settings.json` | ✅ | ✅ | ✅ | 官方 fail-open |
| **Codex** | `~/.codex/hooks.json` | ✅ | ✅ | ✅ | 须在宿主里 `/hooks` 信任；NMZP 不代写信任表 |
| **ZCode** | `~/.zcode/cli/config.json` | ✅ | ✅ | ✅ | 自动开 `hooks.enabled`；**新会话**才生效 |
| **Antigravity** | `~/.gemini/config/hooks.json` | ✅ | ⚠️ 转 ask | ✅ | 须**重启 IDE**；Windows 有不触发的公开报告 |
| **Gemini CLI** | `~/.gemini/settings.json` | ✅ | ✅ | ✅ | 挂 `BeforeTool`；须可用账号 |
| **Cursor** | `~/.cursor/hooks.json` | ✅ | ⚠️ 转 ask | ✅ | 放行须显式 `permission: allow`；2.1.x 有不触发报告 |
| **Kimi Code** | `~/.kimi-code/config.toml` | ✅ | ❌ 改写即拒绝 | ✅ | TOML 按块行切，不是完整解析器 |
| **Trae** | `~/.trae/hooks.json`、`~/.trae-cn/` | ✅ | ✅ | ✅ | 会 import Claude 配置，已做防重复上报 |
| **通义千问 Qwen Code** | `~/.qwen/settings.json` | ✅ | ✅ | ✅ | — |
| **Qoder** | `~/.qoder/settings.json` | ✅ | ✅ | ✅ | — |
| **通义灵码 Lingma** | `~/.lingma/`、`~/.qoder-cn/` | ✅ | ✅ | ✅ | — |
| **CodeBuddy（腾讯）** | `~/.codebuddy/settings.json` | ✅ | ✅ | ✅ | 改写键为 `modifiedInput` |

---

## 安装

### 1. 打包

在你信任的开发机上：

```bash
npm ci && npm test && npm run build && npm run pack
```

得到 `nmzp-core.tgz`。

### 2. 核心装到专用 CT

把包解到 `/opt/nmzp`，用已有 `nmzp` 用户和 systemd 起服务（[展开细节](#ct-install)）。此时还不会检测任何电脑。

### 3. 签发加入包

```bash
runuser -u nmzp -- env NMZP_DATA=/var/lib/nmzp NMZP_PUBLIC_URL=https://<CT的IP>:8787 \
  node /opt/nmzp/nmzp.mjs ticket --out /var/lib/nmzp/join-bundle.json
```

把 `join-bundle.json` 和 `admin.token` **当文件拷贝**到管理员电脑。U 盘或本机目录都行，别发聊天、别放 URL。

### 4. 被监护电脑加入

```powershell
.\nmzp.cmd join .\join-bundle.json
```

只打印设备号和自启方式，不打印口令。join 会按本机已有目录写对应宿主配置。

> **加完必须做一件事**：正在跑的桌面宿主（ZCode / Antigravity / Cursor / Trae 等）**完全退出再打开**，否则不会加载新 hook。Codex 还要在宿主里 `/hooks` 信任 `NMZP PreToolUse v1`。

### 5. 看板

本机管理（能改策略）：

```powershell
.\nmzp.cmd board --bundle join-bundle.json --token-file admin.token
```

浏览器开 `http://127.0.0.1:8788`，选口令文件登录。口令不进 URL、不进 localStorage。

局域网其他人开 `http://<CT的IP>:8789` 看脱敏总览，**只读，改不了规则**。

### 6. 临时关闭 / 卸载本机

用 NMZP 自己的命令，不要让 Agent 去 `pkill` / `Stop-Process`（自保规则会拦）。

临时关闭只停探针进程，**hook 还在**，工具调用仍会过规则；下次登录还会自启。要彻底不拦，用卸载，然后把桌面宿主完全退出再打开。

`nmzp rights stop` 是 CT 上暂停政策，不是关本机进程。

```bat
.\nmzp.cmd stop
.\nmzp.cmd uninstall
```

`uninstall` 与 `leave` 同义：停探针、删自启、只摘 NMZP 写过的 hook。找不到解包目录时：

```bat
for /d %I in ("%USERPROFILE%\.nmzp\runtime\*") do "%I\nmzp.cmd" uninstall
```

再开探针：

```bat
wscript //nologo "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\NMZP-probe.vbs"
```

若曾 `nmzp snapshot apply`，卸载前先退出 ZCode，再 `.\nmzp.cmd snapshot restore`。`uninstall` / `leave` 不解这项目录 ACL。本机若还开着 `nmzp board`，把那个窗口关掉即可。

探针走用户 Startup 的 `NMZP-probe.vbs`，可隐藏运行，**不需要一直开着黑窗口**。LAN 看板是 CT 上的 systemd 服务。只有本机 8788 管理页需要 `nmzp board` 进程在跑。

| 文件 | 位置 | 用途 |
| --- | --- | --- |
| `admin.token` | CT `/var/lib/nmzp/`，拷到管理员机 | 本机看板登录，**别进 git、别贴聊天** |
| `join-bundle.json` | CT 签发目录 | 设备加入，内含一次性票据 |
| `credentials.json` | 被监护机 `%USERPROFILE%\.nmzp\` | 探针心跳凭据，**不是**管理口令 |
| `hook-status.json` | 被监护机 `%USERPROFILE%\.nmzp\` | 宿主到底有没有真调过 NMZP |

---

## 已实现的功能

### 拦截与改写

| 功能 | 默认 | 说明 |
| --- | --- | --- |
| 内置规则引擎 | **执行**（看板显示「静默」） | 75 条：33 拦截、41 记账、1 改写 |
| 高危强制拦截 | 开，**不可降级** | 外泄 / 篡改 / 隔离监护 / 投毒 / 密钥五族一律拦，看板和导入都改不掉（26 条） |
| 单条规则覆盖 | 8 条默认提升为拦截 | 规则页把任意非受保护规则设成 拦截 / 记账 / 停用；单条 > 威胁族 > 内置默认 |
| 威胁族覆盖 | 默认不设 | 一键把 `destructive`（rm -rf / dd / DROP / force push…）或 `recon` 整族改成拦截或记账 |
| 豁免 | 需自己加 | 审计页「这条是误报」→ `规则 + 命中文本 + 工具`，默认 30 天到期；受保护规则不能豁免 |
| 项目隐私词改写 | 9 条建议 | 最多 64 条，本地编译，命中的词**不会送给模型**；可限定工具 / 字段，可试运行 |
| 自定义词拦截 | 需自己加 | `db.prod.internal \| block` 形式，出网时拦；`Bash,url: …` 前缀限定作用域 |
| 三档政策 | 执行 | 执行（照规则表拦）/ 观察（全部只记账）/ 关闭（全放行）。覆盖与豁免只在执行档生效 |
| 静默暂停 | 关 | 暂停后 hook 只问政策、不再上传工具正文 |

默认提升为拦截的 8 条：写 SSH 授权密钥、关闭安全防护、增删系统用户、C2 框架、读浏览器密码、fork 炸弹、递归 777、setuid 位。sudo / pip / npm -g / docker / force push / DROP 这类日常操作默认仍只记账，想拦自己在规则页点。

**覆盖只在「执行」模式下生效；策略保存 ≠ 设备已同步 ≠ 宿主真拦了**，规则页每行都有这三段状态。

### 观察与取证

| 功能 | 默认 | 说明 |
| --- | --- | --- |
| 审计流水 | 开 | 最多 2000 条，带风险等级、决策、层次、会话 |
| 工具调用记录 | 开 | 只记已接入 hook 的**工具调用**，不是聊天 transcript |
| TCP 对端观察 | 开 | 只看已证实 Agent 进程的对端元数据 |
| OSS/COS 外传观察 | 开 | **只提醒不拦**（不是防火墙） |
| 压缩包大小提醒 | 200 MiB / 提醒 | 阈值可调 1–1048576 MiB |
| GitHub 上传观察名单 | 名单模式 | 可切「无限制」跳过名单与大小提醒 |
| Agent 发现扫描 | 开 | Windows 桌面/CLI/扩展元数据，歧义登记不乱授信 |
| Hook 回执覆盖 | 开 | 多机聚合「N/M 台有回执」+ 按机器明细 |

### 本机专属（看板远程改不了）

| 功能 | 默认 | 说明 |
| --- | --- | --- |
| ZCode checkpoints NTFS 绊索 | **关**（手动 apply） | 只认 `~/.zcode/v2/checkpoints`；`nmzp snapshot apply\|restore` |
| 发现路径补录 | 关 | 管理员给本机补绝对路径，不上传 CT/LAN，不启动程序 |
| 网络所有权授权 | 关 | `nmzp network-owner approve`，发现到的 PID 永远不算可信身份 |

### 导出审计 JSON 交给 AI 分析

审计页右上角「导出 JSON」，导出的是**当前筛选结果**（可先按高危 / 已拦截 / 威胁 / OSS 高危过滤），含证据字段、时间窗，以及 `policyContext`（当前覆盖 / 豁免 / 隐私词、75 条内置规则目录、受保护规则清单、上限）。

闭环四步：**导出 → 让 AI 产出 `nmzp-policy-proposal/1` JSON →「导入建议」预览 → 确认应用**。「复制 AI 提示词」已经写明：只输出这个格式、不碰受保护规则、不含 `mode`、新规则默认试运行。

导入预览会拿历史审计**回放**一遍：覆盖部分精确（只看规则 id），隐私词和豁免部分按脱敏摘要估算并标「估算」。提案里任何对受保护规则的降级、任何 `mode / stopped / github / archive` 字段，整包拒绝。应用时就是一次普通的策略保存，服务端再校验一遍。

> 导出前自己过一眼：里面有你项目的命令与路径（隐私词本身在只读 viewer 导出里是打码的）。别传给不该看的服务。

---

## 能做但没做的

`production_ready=false`。下面这些不是路线图，是明确告诉你现在**别指望**什么。

| 没做的 | 为什么 |
| --- | --- |
| **屏幕捕获提醒** | 做出来又拆了。ETW 监听 `Windows.Graphics.Capture` 要管理员权限，普通用户下每 30 秒白烧一次 CPU，还容易误伤你自己截图。 |
| **压缩包超阈值拦截** | 看板里「拦截」是 `disabled` 的，只有「提醒」。大小只能看到命令里显式写出的单个压缩包——覆盖不全的拦截比没有更危险。 |
| **按 Agent 限定规则作用域** | hook 里的 agent 身份是自报的，不可信；作用域只支持工具和字段。 |
| **GitHub / OSS / COS 上传阻断** | 只观察不拦。真要断网该用防火墙，不该让 hook 装成防火墙。 |
| **通用上传阻断** | 同上。 |
| **剪贴板 / 截屏隔离** | 打断正常工作，且绕过方式太多。 |
| **WFP 内核网络拦截** | 实验模块，不进普通包。 |
| **完整聊天 transcript 采集** | 刻意不做。不读 `grok.db` / Claude projects / Codex sessions。 |
| **内存打包 / 换目录 / 管道 / 自定义域名** | ZCode 目录绊索覆盖不到这些，不假装能拦。 |
| **防本机管理员篡改** | 管理员 / SYSTEM / 属主改 DAC 就能解开 ACL。这是绊索不是牢笼。 |
| **审计历史完整性、回执持久重传** | 未做，断网期间的回执会丢。 |

---

## 重要边界：发现 ≠ Hook ≠ 拦住

顶栏出现 Agent 名字，只说明本机**发现到安装或进程**。看板只有 `hook-status.json` 有新鲜回执才显示「已回执」；**未配置、未信任、未回执，一律不画成已保护**。

同理，适配器被调用 ≠ 宿主真的执行了 deny。各家 fail-open 策略不同，hook 崩了大多数宿主会放行。

上线一批适配器的完整动作：`npm run pack` → 各机重新 `join` → 桌面宿主完全退出再开 → 各跑一次工具确认回执。**没重新 join 的探针还是旧包。**

---

## ZCode 静默打包怎么防

两条**独立**机制，别混：

1. **Hook（工具前）**：join 写了 `~/.zcode/cli/config.json` 之后，**新开的**会话才跑 `nmzp hook --agent zcode`。没 join、没重启，`ZCode.exe` 在跑也没回执。
2. **NTFS 绊索（目录）**：针对旧版「把 checkpoints 打包传 OSS」。不依赖 Hook。

绊索的边界：

- 只认 `~/.zcode/v2/checkpoints`，命令 `nmzp snapshot status|apply|restore`
- ZCode 在跑时拒绝 apply/restore，先退出客户端
- 不接管你在别处已有的 ACL；管理员 / SYSTEM / 属主仍能解开
- 拦不住内存打包、换目录、管道、自定义域名
- ZCode 3.14.0 已去掉上传管线；这是给残留 3.12.3 风格客户端的绊索，**不是「所有版本都还在外传」**
- `zcode.z.ai` 的**文档页**不算外传；`/v2/oss-credentials` 仍拦
- `rights stop` 不解这项 ACL，只能 `nmzp snapshot restore`

---

<a id="ct-install"></a>

## 装到专用 CT（不要套 Docker）

CT 无 SSH。宿主用 `pct exec` 拷包解到 `/opt/nmzp`。Node 在 `/usr/local/bin/node`，系统用户 `nmzp`，数据 `/var/lib/nmzp`。

```bash
tar -C /opt -xzf nmzp-core.tgz
install -m 644 /opt/nmzp/nmzp.service /etc/systemd/system/nmzp.service
# 证书 SAN 需要 CT 局域网 IP 时：
# mkdir -p /etc/systemd/system/nmzp.service.d
# echo -e '[Service]\nEnvironment=NMZP_TLS_HOSTS=192.168.x.x\nEnvironment=NMZP_PUBLIC_URL=https://192.168.x.x:8787' > /etc/systemd/system/nmzp.service.d/override.conf
systemctl daemon-reload
systemctl enable --now nmzp
```

`GET /health` 只返回 `{ok,name,version}`，**不代表已经防护**。

ticket / status / rules 必须和正在跑的服务同一用户和数据目录：`runuser -u nmzp`、`NMZP_DATA=/var/lib/nmzp`。别用 root 默认的 `~/.nmzp/ct-data`。

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

服务等价于 `nmzp viewer --host <private-ip> --port 8789 --allow-cidr <CIDR>`。只放行 allow-cidr 内的源 IP。POST/PUT/PATCH/DELETE 以及 `/api/v1/session`、`/policy`、`/evaluate`、`/join`、`/receipt` 一律拒绝（带管理口令也不行）。

### 三个端口

| 角色 | 地址 | 口令 |
| --- | --- | --- |
| 核心 TLS | `https://<CT的IP>:8787` | 设备凭据 / 管理口令 |
| 本机管理看板 | `http://127.0.0.1:8788` | 要，选口令文件登录 |
| 局域网只读 | `http://<CT的IP>:8789` | 不要，也改不了策略 |

别 SSH 进 CT 当日常管理。

---

## 开发

```bash
npm ci
npm test
npm run typecheck
npm run build
npm run dev
```

`npm test` 扫描仓库内全部 `*.test.ts`（不含 `node_modules` / `dist`）。各适配器的协议细节以 `core/hook-protocol.ts` 与 `core/host-adapters.ts` 的实现和测试为准。

---

## 许可

[MIT](LICENSE)。可自编译，可改写。

<sub>适配器对照 FABLE · 核心 ASTRA · 实现 Grok · 前端 Gemini。国产在哪里——工信部投诉里。</sub>
