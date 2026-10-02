# G8 Canonical Protocol 冻结审查 r2（2026-10-02，签署稿）

起草：协调者（Claude）。r2–r7 的复核由互不共享上下文的独立 Claude 子代理只读执行，本文汇总它们的结论和协调者的修订，不替代复核本身。签署方式：用户回复"不否决"，并对 §4 的三项做出选择。

## 1. 对象与命令

- worktree `C:\Users\sxl\Desktop\NMZP\nmzp-wt\P2-WP21B`，分支 `codex/nmzp-1-p2-wp21b`，HEAD `8e6df900998ede1e1f9285fded4ddbadd3a1459c`，外加以下未提交改动（均未 commit）：
  - 修改：`contract/protocol/DECISIONS_REQUIRED.md`（G8 r2 修订、IC-13/14/15 登记、B2 冻结范围）；`core/protocol/v2-adapter.ts`（两处注释，标注旧候选仅供测试，无运行时改动）。
  - 新增：`scripts/gen-golden-v026.mjs`、`tests/compat/fixtures/hook-bytes-v026.json`、`tests/compat/hook-bytes-v026.test.mjs`、`tests/contract/legacy-canonical-decision-scope.test.mjs`、`docs/design-review/G8_FREEZE-r1.md`、本文件。
  - 不纳入：`GROK_REPORT.md`（未跟踪，不提交）。
- v0.2.6 基线树：`nmzp-wt/BASE-0.2.6` @ `e9ac5a3`，只读。
- 机器：win32-arm64，node v24.15.0。

| # | 命令（cwd = worktree） | 结果 |
|---|---|---|
| 1 | `node --experimental-strip-types --test tests/compat/hook-bytes-golden.test.mjs tests/compat/hook-bytes-v026.test.mjs tests/contract/legacy-canonical-decision-scope.test.mjs` | 289 pass / 0 fail / 0 skipped（日志 `nmzp-wp21b-evidence/g8/r8-test.log`） |
| 2 | `npm run -s typecheck` | exit 0 |
| 3 | `npm run -s lint` / `lint:layers` / `lint:contract` | 均 exit 0 |
| 4 | `node scripts/gen-golden-v026.mjs --base ../BASE-0.2.6 --check` | `check ok`，fixture 与重新采集字节一致；r5 起连续多次稳定 |

没有运行全量 `npm test`。没有联网，没有读取凭据文件。

## 2. r1 阻断项的关闭

- **B1（§8.3 缺 0.2.x 基线、别名语义变化未登记）：已关闭，剩用户决定。**
  - 新 fixture `hook-bytes-v026.json` 用 v0.2.6 树真实采集：104 例 golden 加 179 条别名探针，每条同时记录 v0.2.6 与 HEAD 字节。
  - 测试断言全部差异恰好等于登记的三组：`ic13` 55 条、`ic14` 18 条、`ic15` 1 条；未登记的差异会让测试失败。
  - fixture 只证明所列探针，不证明某类差异不存在（`DECISIONS_REQUIRED.md` G8 r2 修订节已写明）。
- **B2（D5 未实现、CanonicalRewrite 占位）：已关闭，按"排除出冻结范围"处理。**
  - 旧 `CanonicalDecision`/`CanonicalRewrite` 及其 schema 只有测试调用方，排除在冻结范围外；实际 wire 是 `CanonicalEvaluateResponseV2` + `CompactRenderedRewrite`。
  - 守护测试 `legacy-canonical-decision-scope.test.mjs` 防止非测试模块引用旧候选、防止 OpenAPI path operation 经 `$ref` 到达旧 schema。已知缺口（不阻塞）：整个 `v2-adapter.ts` 豁免，字符串匹配可被动态 import 绕过。
  - D5 本身仍未实现，属于后续冻结批次。
- **B3（登记表过期）：已关闭。** `DECISIONS_REQUIRED.md:3` 状态行、D11/D13 关闭状态、evaluate 路由描述已与 HEAD 对齐。

## 3. 复核历史（r2–r7）

| 轮 | 主要发现 | 处理 |
|---|---|---|
| r2 | v0.2.6 fixture 覆盖不足；857f3eb 未登记 | 补探针；登记 IC-14 |
| r3 | 空/空白/null/非字符串宿主键、`edits[]` 行内别名缺探针 | 补探针 |
| r4 | IC-14 不止 6 条字节，按类出现；深层嵌套差异未登记 | IC-14 按类重写；新增 IC-15 |
| r5 | 改映射后的 AbsolutePath 与字面 path/filePath 冲突；非字符串 TargetFile 放宽；IC-15 O(深度²) 耗时与宿主 8 s 超时 | 收紧类三、3 条放宽探针；耗时登记；deep(50000) 不稳定改为 6000 |
| r6 | 服务端 `/api/v1/evaluate` 同一遍历阻塞事件循环；target_file 冲突；行号；混合版本 | 文档补服务端与混合版本；补 target_file 探针 |
| r7 | 无新阻断，"仅剩用户决定" | 非阻断 N1–N3 已补进 `DECISIONS_REQUIRED.md`（配对路径预算阈值为推断、Antigravity 探针计数、IC-14 选项二/三连带改 v2 adapter）；N4 即 `GROK_REPORT.md` 不提交 |

r7 的判断：`hook.ts`、`rules.ts`、`engine.ts` 与 eval-bridge 键集合在决策意义上未变；v1 serve 不调用 `remapAntigravityArgs`；探查已基本饱和。

## 4. 需要用户决定的三项

详细机制、探针 id 与影响见 `contract/protocol/DECISIONS_REQUIRED.md` 的 IC-13、IC-14、IC-15 三节。

1. **IC-13 别名冲突改判 `bad_hook_json`（收紧，55 条）**：协调者已按"最大防护、对用户最便利"保留。你可以否决；否决需同时恢复 hook 与服务端（`resolveEvalBody` 的 `conflicting_aliases`）两处判定。
2. **IC-14 Antigravity 无效 TargetFile 不再占住 file_path（857f3eb，放宽 + 三类收紧，18 条）**：
   - 选项一：整体保留 HEAD，接受放宽类。
   - **选项二（协调者倾向）**：AbsolutePath 补位时同时当内容扫描，取两版并集。需新代码、新探针、再复核；v2 adapter 随之改变。
   - 选项三：回退 857f3eb，连同 `.nmzp` 自保护等收紧一起撤销，不推荐。
3. **IC-15 深层嵌套不再栈溢出拒绝（放宽，1 条；O(深度²) 耗时）**：
   - 选项一：保留 HEAD，接受宿主超时暴露与服务端事件循环阻塞。
   - **选项二（协调者倾向）**：hook parse 阶段与服务端两个 evaluate 路由在首次遍历前加确定深度上限（建议 64，与 IC-10 对齐；或 1024），超过失败关闭。需新代码、新探针、再复核。

## 5. 总判定：待用户决定

- 三项都选"保留 HEAD"（IC-13 不否决、IC-14 选项一、IC-15 选项一）：本稿即可签为 **FREEZE_WITH_CONDITIONS**，条件见 §6。
- 任一项选需新代码的选项：先由 grok 实现，补探针，独立子代理 r8 复核通过后再签。fixture、测试的期望字节会随之更新，届时本稿作废、另出 r3。

## 6. 未验证项与冻结条件

- HOST_REAL 未做：宿主超时后放行还是拒绝；antigravity/cursor 的 REWRITE ask 载体是否弹窗（r1 N5）。
- 服务端 RangeError 之后外层 catch（`serve.ts:1222`）的 HTTP 响应未实测；`/api/v2/evaluate` 深层嵌套耗时未单独计时。
- IC-15 hook 计时只在未配对路径实测；配对路径（`hook.ts:525`）阈值更低是读码推断。
- r1 非阻断 N2（11 个 schema 无 manifest fixture）、N3（risk 枚举 `critical` 不一致）、N8（`no_cache_low_risk`/`budget_low_risk` 无测试）、N11（性能 r2 只绑定 6e0c1b5 与本机，需在最终 SHA 重跑）仍开放，作为冻结条件。
- `DECISIONS_REQUIRED.md` 中「候选（未实现）：Antigravity 空宿主键压过字面键」仍为候选，不在本次冻结内。

## 7. 范围声明

- 不批准任何 IC 开关切换（IC-01/02/10/11/12 仍 NOT_SWITCHED）。
- 不批准 commit、推送、合并到 main 或部署。
- 签署行（用户填写）：

```
G8 r2：不否决 / 否决
IC-13：保留 / 否决
IC-14：选项一 / 选项二 / 选项三
IC-15：选项一 / 选项二（上限 64 / 1024）
```
