# 静默快照防护与多 Agent 通用加固

基线：NMZP e016583。替代外部 nmzp-zcode-rules-20260921 补丁，不直接应用其旧上下文。

## 产品边界

NMZP 保护所有已接入 Agent。ZCode 静默整库上传是其中一个专项；通用隐私、配置防篡改和 hook 协议加固同时保留。

1. 历史静默上传的加密包、额外清单、capture 标记和精确快照凭证接口继续阻断。规则命中表示防护决策，不表示服务端已收到数据。
2. 普通本地 checkpoint 和无快照证据的 OSS 表单分别记录；反馈附件凭证请求因授权不可验证而默认阻断，可独立配置，不称为已证实偷传。不能凭 TCP 对端、probe 来源或同时间窗出网认定整库上传。不扩大或停用现有目录 ACL；它仍覆盖已知 checkpoints 目录，并可能影响该目录内的本地功能。
3. 普通配置修改保持记账。信任库的直接修改以及配置中明确的恶意 hook 声明拦截，覆盖 Write/Edit/MultiEdit 与可解析的 shell/PowerShell 写入；只读操作不拦。调用者所属 Agent 不作为豁免条件。
4. X-Client-Timezone/Language 的隐私改写适用于所有接入 Agent 的出网工具明文，沿用当前可配置 persona_cloak 政策；不修改本地文件，不承诺改写应用内部 TLS。
5. ZCode 注册 PreToolUse、PermissionRequest 与 SessionStart/UserPromptSubmit/Stop。工具事件按各自协议返回；生命周期只记录事件回执，不读取/持久化/上报 prompt 或 transcript。生命周期回执不能点亮 PreToolUse 的防护覆盖。
6. PermissionRequest 的放行不替宿主批准操作；需要改写但该事件无法保留宿主审批时拒绝并说明原因。其他 Agent 协议保持原语义。
7. join/leave 对上述事件幂等管理，只删除 NMZP 自有条目，保留用户和插件配置。示例与安装器同源。
8. 插件名称、官方身份声明与域名不是豁免依据。已知插件清单、标准 hook/MCP 配置中的显式文件上传、下载执行和管道外送受检查；命令型工具可见的源码、Git 数据、已知诊断日志包上传参数独立阻断。
9. 不把声明检查当成插件沙箱：自定义引用文件、外部脚本、压缩包安装、远程 MCP 与宿主内置反馈 HTTP 可能绕过工具 hook。本次无真实宿主网络约束部署，不能宣称覆盖这些路径。

## 验收

- 历史 snapshot/upload-credential 与已支持的 v2/oss-credentials 命中；登录、文档、反馈、域名伪装及查询串引用不误中。
- 旧加密包含普通 .enc 布局受保护；本地 JSON/ref/index 不升级为外传；不将 checkpoint 和无关 POST 拼接为已知外传。
- 其他 Agent 的打包外传、敏感凭据、投毒、自保、观察/关闭模式和覆盖规则回归通过。
- 配置/信任库的 Windows/POSIX 写入反例、正常读取和普通配置修改通过。
- 实际 join/leave、ZCode 事件输入输出、生命周期回执隔离和 PermissionRequest 审批语义通过。
- 反馈默认阻断及配置覆盖、不同 Agent/官方域名一致决策、插件 hook/MCP 内联声明、process 字面参数/正常插件反例、真实离线 hook 输出通过。
- 复核全仓 lint：修正错误断言与无效/多余声明；有意拒绝控制字符的安全正则保留并用局部说明消除误报，不关闭全局校验。
- 运行针对性与全量测试、类型检查和构建；如实报告已有失败、环境限制和未进行的真实宿主联调。

## 证据来源

- https://blog.ferstar.org/en/posts/zcode-silent-workspace-snapshot-upload/ （2026-09-19 更新；历史客户端行为是作者报告，本项目未独立复核该安装包）。
- ZCode 源码 872ad960：gitCheckpointRepo、feedbackHttpClient、hooks/output、configured-runner。
- 不修改真实用户 hook/信任库、ACL 或服务，不部署、不推送。
