<p align="center">
  <img src="public/favicon.svg" width="64" alt="NMZP">
</p>

<h1 align="center">NMZP Monitor</h1>

<p align="center">
  局域网编码 Agent 监护
  <br>
  <sub>对经宿主 Hook 接入的工具调用，进行规则检查、参数改写与审计记录。<br>不采集聊天记录；拦截与改写取决于宿主支持和策略配置。</sub>
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
  <img src="docs/screenshots/overview-fleet-dark.png" alt="NMZP 看板：已接入设备、Agent 发现状态与 Hook 回执" width="920">
</p>

专用 CT 运行核心服务，被监护电脑运行探针。核心使用 Node 自带 HTTPS，设备端固定信任自签证书，不向系统安装根证书。许可 [MIT](LICENSE)，当前版本 0.2.3。

<a id="how"></a>

## 怎么工作

NMZP 通过宿主 Hook 接收工具请求。在执行模式下，规则与策略决定是请求宿主拒绝调用、改写参数，还是放行记账。保护生效需要 Hook 已加载、完成必要的信任配置，并由宿主执行返回结果；观察或关闭模式不执行策略拦截。

```text
Coding agent → 工具请求 → 宿主 hook
                              │
              没调用 ─────────┴──► 未经过 NMZP 检查
                              │
                         NMZP 规则
                              │
                    拒绝 / 改写参数 / 记账
```

参数改写只影响即将执行的工具输入，不能抹去模型已生成的内容或撤回已发送的请求。未进入 Hook 的调用不受 NMZP 检查，但仍可能受宿主自身的权限控制。完整安全模型见 [SECURITY.md](SECURITY.md)。

<a id="agents"></a>

## 支持的 Agent

本仓库维护 13 个宿主 Hook 适配器，`join` 仅为本机已存在的宿主目录写入配置。下表说明适配器实现的能力，实际效果需满足各宿主的加载、信任与执行条件；适配器由 NMZP 项目维护，不代表厂商认证。

| Agent | 配置 | 拦截 | 改写 |
| --- | --- | :---: | :---: |
| Grok · Claude Code | 各自的 hook 配置 | 能 | 能 |
| Codex | `~/.codex/hooks.json` | 能 | 能，须先信任 |
| ZCode | `~/.zcode/cli/config.json` | 能 | 能，新会话 |
| Gemini CLI | `~/.gemini/settings.json` | 能 | 能 |
| Cursor · Antigravity | 各自的 hooks 配置 | 能 | 变成询问 |
| Kimi Code | `~/.kimi-code/config.toml` | 能 | 改写即拒绝 |
| Trae · Qwen · Qoder · Lingma · CodeBuddy | 各自的配置 | 能 | 能 |

**Codex 接入：**在宿主中通过 `/hooks` 信任 `NMZP PreToolUse v1`；NMZP 不代写信任表。仓库提供合成输入测试，尚无真实 Codex 客户端的端到端验证记录。各家差异、验证范围与 ZCode 绊索说明见 [docs/agents.md](docs/agents.md)。

Copilot、Windsurf、Aider、Cline 目前仅支持发现，没有 Hook 适配器。

内置规则 81 条：37 条默认拦截，43 条记账，1 条改写。其中 29 条在执行档不能被看板或提案降级。默认档位是执行。策略保存、设备同步、宿主真的拒绝，是三步，规则页分开显示。

<a id="start"></a>

## 快速开始

需要 Node.js 24 或更新。加入包和口令应通过安全渠道作为文件传递，不要贴进聊天或提交到仓库。

### 1. 打包与部署核心

在可信开发机上打包：

```bash
npm ci && npm test && npm run build && npm run pack
```

得到 `nmzp-core.tgz`。先按 [安装文档](docs/install.md) 将核心部署到专用 CT，再签发设备加入包。完整的 systemd、证书与端口说明也在该文档中。

```bash
runuser -u nmzp -- env NMZP_DATA=/var/lib/nmzp NMZP_PUBLIC_URL=https://<CT的IP>:8787 \
  node /opt/nmzp/nmzp.mjs ticket --out /var/lib/nmzp/join-bundle.json
```

### 2. 被监护电脑：加入设备

在目标电脑准备好运行文件与为该设备签发的加入包后执行：

```powershell
.\nmzp.cmd join .\join-bundle.json
```

加入后，完全退出并重新打开正在运行的桌面宿主。Codex 还需在宿主内通过 `/hooks` 信任 `NMZP PreToolUse v1`。

### 3. 管理员电脑：打开管理看板

**管理口令 `admin.token` 仅交给管理员保管，不应作为设备加入材料分发。**在管理员电脑准备好运行文件、看板所需的加入包与管理口令后执行：

```powershell
.\nmzp.cmd board --bundle join-bundle.json --token-file admin.token
```

打开 `http://127.0.0.1:8788`，选择口令文件登录。同一台电脑可以兼任管理员电脑与被监护电脑，分别完成对应步骤即可。

局域网其他用户访问 `http://<CT的IP>:8789` 查看只读看板，无需管理口令，也不能修改策略。只读 viewer 等价于 `nmzp viewer --host <private-ip> --port 8789 --allow-cidr <CIDR>`，单元文件是 `nmzp-viewer.service`。`GET /health` 仅表示服务健康，不代表保护已生效。

**停止与卸载：**`.\nmzp.cmd stop` 只停止探针，Hook 仍保留；卸载使用 `.\nmzp.cmd uninstall`，随后完全退出并重新打开宿主。若启用过 ZCode 目录 ACL，请先按 [安装文档](docs/install.md) 恢复该 ACL。

<a id="audit"></a>

## 审计导出与 AI 辅助分析

将筛选后的审计记录和策略上下文导出为 JSON，交给你选择的 AI 辅助整理风险、分析疑似误报并起草策略建议。

**导出 JSON → 检查与脱敏 → AI 起草提案 → 校验与预览 → 管理员确认**

用于导入的提案须符合 `nmzp-policy-proposal/1`。导入端先校验并预览对已保存事件的影响；管理员确认后，核心再次校验并保存策略。提案不会自动成为内置规则。预览中的部分结果属于估算，不能代替真实执行验证。

当前流程由用户主动导出并选择分析服务，不会自动上传日志或定时生成报告。导出不保证匿名或全天完整：审计环最多保留 2000 条事件，超出后旧记录会被丢掉，历史完整度标记为 `unknown`。分享前请检查敏感信息；分析范围以实际导出的记录为准。

导出字段、提案约束、提示注入注意事项与预览估算范围见 [审计文档](docs/audit.md)。

<a id="limits"></a>

## 安全边界

- 顶栏上的名字是发现。回执是 hook 跑过的证据，不等于宿主执行了拒绝。没有回执只说明这份证据还没有，不能单凭这一点断定原因。
- Hook 不是操作系统沙箱，也不是网络防火墙。GitHub、OSS、COS 的上传只观察。
- 本机管理员可以卸掉 hook。完全被控制的机器不在这套设计里。
- 核心不可达时回执可能丢失。缺少事件或回执不能被当成没有风险的证明。

其他已知限制见 [能力边界](docs/limits.md)，完整安全模型与报告方式见 [SECURITY.md](SECURITY.md)。

<a id="plan"></a>

## 本地语义检查

**规划中 / 模型层尚未接入。**

计划在现有硬规则之外，为需要上下文判断的操作增加本地语义复核：提取最小必要上下文、调用本地模型，再由 NMZP 合并风险判断。模型不能推翻硬规则拒绝结果，失败、超时与不确定应记为“未知”，不能当成安全。

当前版本尚未实现这条模型调用与决策链路。架构设想、部署注意事项及覆盖边界见 [设计说明与讨论图](docs/plans/local-semantic-review.md)。

## 文档与参与

| 内容 | 文档 |
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
