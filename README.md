<p align="center">
  <img src="public/favicon.svg" width="64" alt="NMZP">
</p>

<h1 align="center">NMZP Monitor</h1>

<p align="center">
  局域网编码 Agent 监护
  <br>
  <sub>宿主把工具调用交过来时，先过一遍规则：高危可拦，参数可改写，其余记账。<br>不看你本人，不采集聊天。发现到名字，还不等于已经拦住。</sub>
</p>

<p align="center">
  <strong>中文</strong>
  &nbsp;·&nbsp;
  <a href="README.en.md">English</a>
</p>

<p align="center">
  <a href="#how">怎么工作</a>
  &nbsp;·&nbsp;
  <a href="#agents">适配器</a>
  &nbsp;·&nbsp;
  <a href="#start">快速开始</a>
  &nbsp;·&nbsp;
  <a href="#audit">审计</a>
  &nbsp;·&nbsp;
  <a href="#limits">边界</a>
</p>

<p align="center">
  <img alt="MIT" src="https://img.shields.io/badge/license-MIT-ecece6?labelColor=0A0B0D">
  <img alt="Node 24+" src="https://img.shields.io/badge/node-%3E%3D24-ecece6?labelColor=0A0B0D">
  <img alt="version" src="https://img.shields.io/badge/version-0.2.3-ecece6?labelColor=0A0B0D">
</p>

<p align="center">
  <img src="docs/screenshots/overview-fleet-dark.png" alt="总览：已接入的电脑。列出的 Agent 只表示发现或回执，不表示每一次调用都已拦住。" width="920">
</p>

一台专用 CT 当核心，被监护的电脑跑探针。核心用 Node 自带 HTTPS，设备端钉住自签证书，不往系统里装根证书。许可 [MIT](LICENSE)。当前版本 0.2.3。

<a id="how"></a>

## 怎么工作

NMZP 站在 coding agent 和工具执行之间，而且只站在宿主真正交过来的那一次调用上。策略在执行档时，可以拒绝、改写即将执行的参数，或记一条安全事件。宿主不调用 hook、不执行拒绝，或者策略处于观察或关闭，这次调用就不会被拦住。

```text
Coding agent → 工具请求 → 宿主 hook
                              │
              没调用 ─────────┴──► 直接执行
                              │
                         NMZP 规则
                              │
                    拒绝 / 改写参数 / 记账
```

改写不抹掉模型已经生成的原文，也不能撤回已经送出的请求。发现、hook、宿主是否执行 deny，是三件不同的事。完整边界在 [SECURITY.md](SECURITY.md)。

<a id="agents"></a>

## 支持的 Agent

13 个适配器由本仓库维护，对接宿主公开的 hook。不是厂商认证。`join` 只给已经存在的目录写配置。Codex 要在宿主里 `/hooks` 信任 `NMZP PreToolUse v1`，NMZP 不代写信任表。真实 Codex 客户端的端到端记录还没有，自动化测试用的是合成输入。细节、各家差异和 ZCode 绊索见 [docs/agents.md](docs/agents.md)。

| Agent | 配置 | 拦截 | 改写 |
| --- | --- | :---: | :---: |
| Grok · Claude Code | 各自的 hook 配置 | 能 | 能 |
| Codex | `~/.codex/hooks.json` | 能 | 能，须先信任 |
| ZCode | `~/.zcode/cli/config.json` | 能 | 能，新会话 |
| Gemini CLI | `~/.gemini/settings.json` | 能 | 能 |
| Cursor · Antigravity | 各自的 hooks 配置 | 能 | 变成询问 |
| Kimi Code | `~/.kimi-code/config.toml` | 能 | 改写即拒绝 |
| Trae · Qwen · Qoder · Lingma · CodeBuddy | 各自的配置 | 能 | 能 |

Copilot、Windsurf、Aider、Cline 只在发现目录里，没有 hook。

内置规则 81 条：37 条默认拦截，43 条记账，1 条改写。其中 29 条在执行档不能被看板或提案降级。默认档位是执行。策略保存、设备同步、宿主真的拒绝，是三步，规则页分开显示。

<a id="start"></a>

## 快速开始

需要 Node.js 24 或更新。口令和加入包当文件传递，不要贴进聊天。

```bash
npm ci && npm test && npm run build && npm run pack
```

得到 `nmzp-core.tgz`。核心装到专用 CT 之后才签发加入包，此时还不会看任何电脑。完整的 systemd、证书和端口说明在 [docs/install.md](docs/install.md)。

```bash
runuser -u nmzp -- env NMZP_DATA=/var/lib/nmzp NMZP_PUBLIC_URL=https://<CT的IP>:8787 \
  node /opt/nmzp/nmzp.mjs ticket --out /var/lib/nmzp/join-bundle.json
```

被监护的电脑：

```powershell
.\nmzp.cmd join .\join-bundle.json
.\nmzp.cmd board --bundle join-bundle.json --token-file admin.token
```

本机看板是 `http://127.0.0.1:8788`，选口令文件登录。局域网只读是 `http://<CT的IP>:8789`。

加入之后把正在跑的桌面宿主完全退出再打开。Codex 还要在里面信任 `NMZP PreToolUse v1`。`.\nmzp.cmd stop` 只停探针，hook 还在。要卸掉用 `.\nmzp.cmd uninstall`。

只读 viewer 等价于 `nmzp viewer --host <private-ip> --port 8789 --allow-cidr <CIDR>`，单元文件是 `nmzp-viewer.service`。它改不了策略。`GET /health` 不代表已经防护。

<a id="audit"></a>

## 审计，然后交给外部 AI

看板上没有一个会自己读完审计的模型。人导出当前筛选，自己看过，再决定要不要给外部 AI。AI 只应返回 `nmzp-policy-proposal/1`。导入端校验、预览已保存的事件，管理员确认后核心再查一次。提案不会变成内置规则。

导出不是匿名的，也不等于这一天的事件都还在。环上限 2000 条，超出的旧记录会被丢掉，历史完整度记为 `unknown`。字段、预览里哪些是估算、提示词还缺哪一句，写在 [docs/audit.md](docs/audit.md)。

<a id="limits"></a>

## 先记住这几条

- 顶栏上的名字是发现。已回执才表示 hook 跑过。回执也不等于宿主执行了拒绝。
- Hook 不是操作系统沙箱，也不是网络防火墙。GitHub、OSS、COS 的上传只观察。
- 本机管理员可以卸掉 hook。完全被控制的机器不在这套设计里。
- 断网时回执会丢。不要把「没看到事件」读成「没有风险」。

其余没做的事，包括屏幕捕获、定时报告和本地模型，列在 [docs/limits.md](docs/limits.md)。安全模型在 [SECURITY.md](SECURITY.md)。

<a id="plan"></a>

## 本地语义检查

规划中 / 模型层尚未接入。

硬规则已经在跑。图里的「抽出最小上下文、调用本地模型、再把模型结果并进决策」还没有写进代码，这轮也不打开。模型不能推翻硬规则，失败也不能当成安全。这两条是以后的约束，不是现在的开关。说明和整张讨论图在 [docs/plans/local-semantic-review.md](docs/plans/local-semantic-review.md)。

## 文档与参与

| | |
| --- | --- |
| 安装与 CT | [docs/install.md](docs/install.md) |
| 适配器与 Codex | [docs/agents.md](docs/agents.md) |
| 审计与提案 | [docs/audit.md](docs/audit.md) |
| 安全模型 | [SECURITY.md](SECURITY.md) |
| 参与 | [CONTRIBUTING.md](CONTRIBUTING.md) |

```bash
npm ci
npm test
npm run typecheck
npm run build
npm run lint
```

`npm run dev` 是看板的开发服务器，不是已经装上的 hook。

## 许可

[MIT](LICENSE)。可自编译，可改写。
