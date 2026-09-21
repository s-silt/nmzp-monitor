# 前端：多机聚合的 hook 覆盖计数 + 相对时间不出现负数 — 设计与验收

状态：验收测试已写好（`src/lib/monitor/hook-coverage.test.ts`，红灯）。只改展示层与两个纯函数。
禁止：改 core/**；改 engine.ts / rules.ts / snapshot.ts / correlate.ts / ingest.ts / agents.ts / types.ts；改任何 *.test.ts；git；npm run pack；联网。

## 1. 相对时间（`src/lib/monitor/format.ts`）
`formatRelative(ts, locale, now = Date.now())` 现在在 `ts > now` 时会算出负数。改为：
- `now - ts > -8_000`（含过去与 8 秒以内的未来）：行为不变（刚刚 / N 秒前 / N 分钟前 / N 小时前）。
- `ts - now > 8_000`（设备时钟快于浏览器）：返回 `formatDateTime(ts, locale)`，不再返回相对文案。
- 其它函数不动。

## 2. 覆盖计数（`src/lib/monitor/stats.ts`）
新增纯函数：
```ts
export interface HookCoverage {
  active: number;      // 该 agent 的 hook_<agent>.active === true 的机器数
  reporting: number;   // capabilities 里存在 hook_<agent> 键的机器数（supported 为 false 也算上报）
  perMachine: Array<{ machineId: string; hostname: string; cap?: DeviceCapability }>; // 可见机器按输入顺序全部列出，没上报该能力的 cap 为 undefined
}
export function hookCoverage(
  machines: Array<{ id: string; hostname: string; capabilities?: Record<string, DeviceCapability> }>,
  host: string,                // "all" 或某台机器 id
  agents: readonly string[],   // 要统计的 agent id 列表
): Record<string, HookCoverage>;
```
- `host !== "all"`：只看 `id === host` 的那一台；找不到则每个 agent 都是 `{ active: 0, reporting: 0, perMachine: [] }`。
- 传入的每个 agent 都必须有返回项。
- `scopedCapabilities` 不改。

## 3. 总览页（`src/routes/index.tsx`）
- 「Agent hook」卡片的 chip：当 `host === "all"` 且该 agent `reporting > 1` 时，在名字后追加 `active/reporting`（例如「Grok 1/5」），字体 font-mono；单机视图不显示分数。
- chip 的分组仍以 `scopedCapabilities` 的聚合结果经 `hookCapMsg` 决定（保持现状）；分数只是补充信息，不能改变颜色规则（只有 `hookCapActive` 用绿色）。
- 点开 chip 的详情面板新增「按机器」列表：用 `hookCoverage(...).perMachine`，每行显示 hostname、`tx(hookCapMsg(cap))`、有 lastSuccess 时显示 `formatDateTime` 与 `formatRelative`；行内颜色规则同 chip。`useMachineViews()` 返回的机器视图里有 hostname 与 capabilities，可直接用；筛选范围与 `useScopedCapabilities` 保持一致（同一批可见机器）。
- 单机视图下详情面板只有一行（那台机器）。
- 新文案（i18n.ts 新增键，zh/en 成对）：`hookCoverageTitle`（按机器 / By machine）、`hookCoverageCount`（已回执 {active}/{reporting} 台 / {active} of {reporting} hosts with receipts，实现时可用简单字符串替换）。不删不改已有键。

## 4. 验收（全部通过）
```
node --experimental-strip-types --test --test-timeout=60000 src/lib/monitor/*.test.ts     # 含新增 hook-coverage.test.ts
npx tsc --noEmit
npx eslint src        # 不新增 error / warning
npm run build
```
- 手工：用 `src/lib/monitor/seed.ts` 的多机种子数据或本地 dev 服务，截总览页「全部电脑」视图与单机视图各一张（深色），保存到 docs/screenshots/ 并给出路径。
- 最后用中文输出：改了哪些文件、四条命令结果、没做的事、风险。
