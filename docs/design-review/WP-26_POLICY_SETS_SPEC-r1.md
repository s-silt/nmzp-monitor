# WP-26 策略集与客户端模式 后端规格 r1（2026-10-01）

依据：`USER_DECISIONS-2026-10-01.md` U8。前端由 Antigravity 另做，本文只定后端行为与接口。
分四个子包，26a/26b 可并行，26c 依赖 26a 的集合模型，26d 依赖 26c。

## 26a 受保护规则拆分

- `src/lib/monitor/overrides.ts` 新增冻结常量 `LOCKED_RULE_IDS`（12 条），以及
  `protectionLevel(rule): "locked" | "adjustable" | "none"`：
  - locked：`isolate_cut_board` `isolate_delete_binary` `isolate_kill_monitor` `isolate_stop_container`
    `agent_hook_disable` `kill_monitor_process` `monitor_self_tamper` `monitor_self_tamper_cmd`
    `zcode_trust_store_tamper` `agent_hook_poison` `credential_file_upload` `env_piped_outbound`
  - adjustable：其余 `isProtectedRule` 为真的 17 条（15 条 exfil 加 `poison_instruction_file` `poison_relay_payload`）
  - 清单写死在代码里，不进策略文件，不受订阅影响。启动时断言 locked 加 adjustable 正好等于 `protectedRuleIds(RULES)`，
    规则表变化而清单没跟上时测试失败。
- 覆盖语义：
  - locked：任何规则覆盖或族覆盖都不生效，行为同今天。
  - adjustable：规则覆盖只接受 `block` / `log`。族覆盖 `log` 生效，族覆盖 `off` 对它不生效，保持原动作。
  - 豁免：29 条一律不可豁免，行为同今天，最大防护。
  - `ruleDisabled`：29 条都不能关闭，行为同今天。
- 写入校验（`core/serve.ts` 策略 PUT 与 `policy-proposal.ts`）：
  - 对 locked 写 `log`/`off`：400 `protected_rule_override`，返回 `ruleIds`，行为同今天。
  - 对 adjustable 写 `off`：同样 400 `protected_rule_override`。
  - 对 adjustable 写 `log`：接受。
  - 族覆盖 `log`/`off` 写到受保护族：接受，实际效果按上面的覆盖语义。
  - `protectedDowngrades` 改为只报"不允许的降级"，名字不变，避免牵动 doctor 等调用方。
- 全局 `permissive` 不改（`applyPolicyDecision` 仍对所有规则返回 log），等用户另行决定。
- 引擎：`ENGINE_REVISION` 2 → 3。预期翻转的语料是 17 个 `protected/<adjustable>/downgrade`，可能还有
  `protected/family-exfil-log-example`。`disable`、`exempt` 以及 locked 的三类案例不得变化。实际变化集合必须与此一致，
  多出或缺少都按缺陷处理。`INTENDED_CHANGES.md` 新增一条 entry，用户重新验收后才能合入。

## 26b 客户端模式

- `PolicyState.clients?: ClientMode[]`，`ClientMode = { deviceId: string; agent?: string; mode: "log_only" }`。
  - 不存条目即"跟随全局"，所以不存 `follow`。
  - 上限 256 条，`(deviceId, agent)` 唯一。
  - `agent` 省略表示该设备全部 agent。命中时精确 `deviceId + agent` 优先于仅 `deviceId`。
- 只有管理员能写，走策略 PUT 的 CAS（新增可选字段 `clients`），设备 token 不能写。
  `GET /api/v1|v2/policy` 给设备看的投影不含 `clients`。设备不需要知道自己被设为只记录，因为判定在核心做。
- 生效点：`core/eval-bridge.ts` `applyPreparedEvaluation` 得到 `result.decision` 之后、组装响应之前。
  当前设备与 agent 命中 `log_only`，且决策是 `block` / `confirm` / `rewrite` 时：
  - 规则是 locked：保持原决策。
  - 否则：决策改为 `log`，不改写入参。
  - 事件记录 `clientMode: "log_only"` 与 `wouldHave: <原决策>`，让审计与 UI 能看到"本应拦截"。
- `allow` / `log` 不变。global `off` / `permissive` 下照旧先由引擎决定，客户端模式只会把决策往宽里放，
  对已经是 log 的不再动。
- 这是核心侧的部署策略，不是引擎规则，不改 `ENGINE_REVISION`，不改语料。v2 响应的 action 随之为 `LOG`，
  其 `userMessage` 是 LOG 的常量。

## 26c 自定义规则集（依赖 26a）

- `PolicyState.customSets?: CustomRuleSet[]`，`CustomRuleSet = { id; name; enabled: boolean; source: "local" | { subscriptionId } }`。
  每条 `CustomPrivacyRule` 增加可选 `setId`。
- 迁移：读到无 `customSets` 的旧状态时，构造一个 `id: "default"`、`enabled: true` 的本地集合，现有规则全部归入它。
  写回旧格式的客户端仍可工作。
- 求值：只取 `enabled` 集合里的规则。单条规则沿用现有 `mode`（`block` / `replace`），另加可选 `enabled`。
- 内置族集合：内置规则按 `family` 自然成集合，UI 的"开关集合"就是写族覆盖（受 26a 语义约束），单条规则写规则覆盖。
  不新增数据结构。

## 26d 远程订阅（依赖 26c）

- `PolicyState.subscriptions?: { id; url; enabled; intervalMinutes; lastFetchedAt?; lastEtag?; lastDigest?; lastError? }[]`，
  上限 16。
- 只由核心拉取，只用 HTTPS，响应上限 256 KiB。内容按现有 `sanitizeCustomRules` 校验，单个订阅最多 `MAX_CUSTOM_RULES` 条。
  订阅只能产出自定义隐私规则，不能触及内置规则、覆盖、豁免与客户端模式。
- 网络边界：
  - 解析后的地址是回环、链路本地、私网或保留网段时拒绝（防 SSRF）。
  - 不跟随跨主机重定向。
  - 超时 10 s。
- 失败时保留上一次成功的快照，记录 `lastError`，不清空规则。内容摘要变化写一条管理审计事件。
- 新增订阅与手动刷新只有管理员可做。自动刷新间隔不少于 60 分钟。
- 实施时补定（2026-10-03，协调者按 U4 决定）：
  - 每个订阅对应一个 `source: { subscriptionId }` 集合，集合 id 就是订阅 id。订阅规则仍存在 `customRules` 里，
    id 加订阅前缀，`setId` 固定为该集合，所以评估、设备投影和回放都不用改。
  - 自定义规则总数仍以 `MAX_CUSTOM_RULES`（64）为上限，与本地规则合并计算，因为设备端的 sanitize 会截断到 64 条。
    超限或与已有规则 match 重复时，这次拉取按失败处理，保留旧快照。
  - 只在内容摘要或错误状态变化时发布新版本，内容没变的定时拉取不写策略，避免版本写放大和设备重新下载。
    `lastFetchedAt` 是最近一次写入策略的成功拉取时间，每次实际尝试的时间只放在运行时状态里。
  - 通用 PUT 不能写 `subscriptions`，也不能新增订阅集合或修改订阅规则。请求里省略的订阅集合和订阅规则会被保留。
    订阅自身的 `enabled` 同时控制刷新和规则是否生效，订阅集合的 `enabled` 始终与它一致，通用 PUT 不能单独改。
    审计事件在策略发布之后写入；写入失败时留在内存里，下次刷新或定时检查时补写。残余：发布后、补写前进程退出会丢这一条审计，
    对应版本仍在策略历史里。CAS 连续冲突时保留已拉到的结果，下一分钟只重试写入，不重新请求。
  - 订阅地址不进设备投影和 LAN viewer。审计事件只记录订阅 id、新旧摘要和规则数。

## 文案（zh / en）

26a–26d 落地后由 grok 起草每个集合与规则的名称和一句话说明，中英各一份，放
`src/lib/monitor/rule-copy.{zh,en}.ts`。由协调者审校，UI 只显示当前语言。

## 不在本包

前端页面（Antigravity）、全局 permissive 的去留、订阅签名（随 WP-12 签名密钥再定）。
