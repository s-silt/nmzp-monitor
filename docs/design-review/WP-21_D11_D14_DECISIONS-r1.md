# WP-21 D11–D14 收口裁决 r1（2026-10-01）

依据：用户 2026-10-01 授权协调者"按最大防护、对用户最便利"决定 D11–D14 剩余项。前序：
`WP-21_SEMANTIC_DECISIONS-r3.md`（设计目录）、`WP-21_D8_D9_D14_DECISIONS-r1.md`（设计目录）。
本文只关闭"待选方案"，不宣称 G8 冻结；每项的运行时证明仍以测试落地为准。

## D11 证据 VERIFIED 的版本范围与回执绑定（关闭）

- **版本范围**：HOST_REAL 产物逐个 action（BLOCK / ASK / REWRITE）记录实测的精确 `hostVersion`。
  VERIFIED 只覆盖同一 `major.minor`、patch 不低于实测值的版本。`hostVersion` 不是
  `数字.数字.数字` 形式时，只认精确相等。超出范围退回 HOOK_OBSERVED，并带 `verification: "STALE"`
  标注，UI 显示"已观测，未在此版本实测"。理由：patch 升级不需要用户重测（便利），minor 升级要求重测（防护）。
- **action 粒度**：三个 action 分别判定；某 action 没有实测产物时，该 action 不得标 VERIFIED。
- **回执绑定**：回执被接受的条件是同时满足
  1. 设备来自 bearer token，`eventId` 属于该设备（已有 `store.getEvent(d.id, …)`）；
  2. 回执声明的决策与存储的 evaluation 一致（已有 `receiptEvaluationChanges`）。
  不满足 1 → 404 `not_found`（事件按 `设备 + eventId` 取键，不泄露别的设备有无该事件）；
  不满足 2 → 409 `evaluation_immutable`。两者都是 `core/serve.ts` 回执路由的现有行为，不另设错误码。运行时证明：两条负例已在 `tests/contract/device-routes.test.mjs` 的回执差分测试中（"决策被改写 → 409"、
  "设备 b 回执设备 a 独有的 eventId → 404"），回执绑定部分可由 PENDING 改为 PASS；版本范围部分待 HOST_REAL 产物。

## D12 设备 token 与正文身份（关闭）

- 维持 r3：正文 `device.id` 出现时必须等于 token 的设备 id，否则 401 `unauthorized`。
- r3 旁证中的 `persist.ts` `===` 比较已在当前代码改为 `storedDigestMatches` → `safeEqualHex`（`core/persist.ts:80-86`），
  此项关闭。
- 现状：v2 evaluate 已校验并有测试（`tests/contract/evaluate-routes.test.mjs:63`）。v2 receipts / backfill /
  heartbeat 的解析器是开放对象，正文 `device.id` 目前被忽略，不校验。
- 实现义务：这三条 v2 路由在正文含 `device` 成员时，要求它是只含字符串 `id` 的对象且 `id` 等于 token 设备，
  否则 401 `unauthorized`；v1 路由不变。每条路由一条正例（相符照常处理）和一条负例（不符 → 401 且不落库）。
  全部通过后验证器 PENDING → PASS。

## D13 userMessage 不回显秘密（关闭）

- 维持固定模板，不加运行时秘密扫描。理由：现有代码已在两端锁死文案。服务端的 `userMessage` 来自
  `core/protocol/evaluate-response.ts:23` 的 `as const` 字面量表，按 action 取值，不接受任何请求数据；
  响应 schema 对五个 action 各钉一个 `const` 文案，客户端 `applyCanonicalEvaluateResponse` 先过
  `validateEvaluateResponse`，文案稍有不同即 `evaluation_response_invalid`，失败关闭。今后有人往模板里加插值，
  客户端会整体拒收，秘密到不了宿主。再加一层扫描不增加防护，只增加热路径耗时。
- 测试义务：每份 rewrite / privacy fixture 的服务端响应 `userMessage` 等于该 action 的常量；一条变异测试，
  把合法响应的 `userMessage` 改成拼了 fixture 秘密的文本后，`applyCanonicalEvaluateResponse` 返回
  `evaluation_response_invalid`。

## D14 剩余路由（关闭）

- ETag、`GET /api/v2/policy` 正文、hookBlind：沿用 `WP-21_D8_D9_D14_DECISIONS-r1.md` 的裁决，不变。
- **receipts / backfill / heartbeat 的 v2 请求正文**：闭合对象，成员与 v1 请求正文逐字段相同，外加可选
  `device.id`（按 D12）。未知成员、重复键、非精确字符串的处理跟随 IC-10 严格入口开关：开关关闭时与 v1 一致；
  打开后失败关闭。开关随 Gate A 切换，不单独设开关。
- `host.id` 保持开放字符串，不做 13 值封闭枚举。

## 仍未完成（不因本文关闭）

PROTOCOL §8 三项证明（13 宿主 v1→v2 决策等价、RenderDecision 字节 golden、Kiro-Q2）；上面列出的运行时测试义务；
G8 冻结审查。
