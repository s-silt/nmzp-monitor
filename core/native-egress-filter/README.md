# NMZP native egress filter helper

管理员 helper：只给 `nmzp.agent.<nonce>` AppContainer SID 装 WFP 精确出站过滤，并在确认过滤后添加该 SID 的 loopback exemption。不执行 payload、不 runas、不处理模型正文。

## 命令

```
NmzpNativeEgressFilter.exe prepare --spec-file spec.json
NmzpNativeEgressFilter.exe plan    --spec-file spec.json
NmzpNativeEgressFilter.exe status  --spec-file spec.json
NmzpNativeEgressFilter.exe apply   --spec-file spec.json
NmzpNativeEgressFilter.exe cleanup --spec-file cleanup.json
NmzpNativeEgressFilter.exe selftest
```

apply spec：

```json
{"profileName":"nmzp.agent.0123456789abcdef","gatewayAddress":"127.0.0.1","gatewayPort":12345}
```

cleanup spec：

```json
{
  "profileName":"nmzp.agent.0123456789abcdef",
  "journalId":"<plan.journalId>",
  "jobEmptyProof":{"kind":"named_job","jobName":"Local\\nmzp.agent.0123456789abcdef.job"}
}
```

Job 名契约：`Local\\nmzp.agent.<nonce>.job` 或 `Global\\...`。sandbox worker 须把整棵进程树放进该 named job。

## 顺序

1. 检查 journal 固定根（非 reparse；已存在的 `native-egress-filter`/`journal` 须 SY/BA/当前管理员所有，不跟 junction、不改外来目录 ACL）
2. 先读并校验已有 journal，保留 `loopbackExemptionAddedByUs`；无 journal 则先持久化 `planned`（Flush(true)）再任何 WFP/exemption 写
3. 预检：外部 exemption / 未知现有 filter / 外来 provider·sublayer → 拒绝，不 adopt，AlreadyExists 必须 Get+owner/flags/weight 核验
4. 装本 SID filters → journal `filters_installed` → `exemption_pending` → 保留他人 `SID_AND_ATTRIBUTES` 后加本 SID → reread；并发丢 SID **不** union 写回 → `ready`

cleanup：named job 必须能打开；核对 job owner、禁 breakaway、process-id list 完整且 0。SID 扫描 0 命中。任何不可读 PID（含 session0/PPL）=`sid_scan_inconclusive`，**不能** verified=true，保留 block。缺 job ≠ 空。实际 exemption 仍在且不能证明本轮 owned 并验证 absent → **不删 filter**。成功仅当 exemption absent、filter absent、journal 删除并回读确认。

## OwnedNetworkJobLease（同程序集 supervisor API）

同程序集 API，**不是**跨进程信任边界；不接受外部 JSON / `trusted` 开关 / `AcceptExisting`。standalone CLI apply/cleanup 仍走全局 unknown 拒绝。

`OwnedNetworkJobLease.TryCreate` 是唯一生产 factory：新建 `nmzp.agent.<crypto nonce>` profile（仅 HRESULT 0 视为 owned）和 `Local\\nmzp.agent.<nonce>.job`（`ERROR_ALREADY_EXISTS` 拒绝）。CreateJobObject 一开始就带受限 SD，GetSecurityInfo 读回 owner/DACL/ACE（拒绝 NULL DACL、未知 owner、额外 ACE）。设置并读回 KillOnClose、禁止 BREAKAWAY/SILENT_BREAKAWAY、以及要求的 UI restriction bits。`ProfileFolder` 必须取到且非 reparse，否则 TryCreate 失败。本 helper **不**把任意源路径以管理员身份拷进 profile；native 接线用 limited-token I/O。

Supervisor 接线（本 helper 不 launch payload）：

1. `OwnedNetworkJobLease.TryCreate(out lease, out error)` → `ProfileName` / `PackageSid` / `DangerousGetJobHandle()` / `ProfileFolder`
2. supervisor 自己用 limited token 做 LPAC + `CREATE_SUSPENDED` 的 `CreateProcess`，再 `AssignProcessToJobObject(lease.DangerousGetJobHandle(), proc)`。`DangerousGetJobHandle` 可被 supervisor 改 job 信息，因此 bind / CloseSession 都会再读回 limits+UI+禁 breakaway。
3. `BindSuspendedProcess(proc)` 校验：仍在本 job、package SID、`TokenIsLessPrivilegedAppContainer`、`TokenElevation=false`、TokenUser/TokenSessionId 与 lease 创建者一致、管理员组未 enabled。**不**查询 `CREATE_SUSPENDED`；名字不构成挂起证明。失败不得进入 `NetworkReady`。
4. `PrepareNetwork(gatewayPort)` 仅 `Bound`：在任何 WFP/exemption 调用前把 `networkModified` 与不可变 `preparedPlan` 置位；异常/不确定 mutation 也保持该标志。走 ApplyMachine。非管理员立即 `requires_admin` 且不留下“已改网络”标志。
5. supervisor resume payload（本 helper 无 resume API）。
6. `CloseSession` / `Dispose`：TerminateJob，等到 ActiveProcesses 与 process-id list 均为 0 且 breakaway/UI 仍正确，再把 **lease 持有的 handle proof** 交给 CleanupMachine（不扫无关 PPL）。cleanup 用当初的 `preparedPlan`（真实 gateway port），不重建 port=1。未改网络则可只删本轮 profile。已改网络而 FilterGet 失败/不能证明 absent：留 journal+profile+job handle，不报成功。

状态：`Created` → `Bound` → `NetworkReady` → `Closed`，失败 `Faulted`。禁止未 Bind 安装、重复 Bind、未 ready 当可 resume。丢 lease 不能用 job 名字符串伪造恢复。WFP 正负 control 非管理员 `not_tested`。FilterGet 查询失败 ≠ 滤镜不存在。

## 非管理员

apply/cleanup 返回 `requires_admin`，`changed=false`，不调 WFP 写、不调 SetAppContainerConfig。

## 范围限制（给 root）

- 只覆盖 `ALE_AUTH_CONNECT_V4/V6` 出站。入站 listen 不在本 helper。
- x64 结构体布局；WOW64 拒绝。
- exemption 整表写，fresh-read + compare/re-read，**不是 CAS**；并发撤销不恢复别人的项。
- 不可读 PID 一律 inconclusive，不用 session0 推断排除。真实机含 PPL 时 cleanup 通常保持 block，这是诚实限制而非已证明空树。
- live-admin-test.ps1 的 ExecuteLive 硬拒绝 `requires_reviewed_nonadmin_coordinator`；payload 必须普通用户 coordinator，helper 另走 OS 管理员步骤。
- `planned` 后已有 filter、journal 尚未 `filters_installed`：拒绝 adopt，留下 block，需维护。
- 不声称能拦模型 prompt 隐蔽信道；正文检查在 gateway。
- 工作负载必须继续 zero network cap。
