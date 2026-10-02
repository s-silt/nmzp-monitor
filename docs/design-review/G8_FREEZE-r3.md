# G8 Canonical Protocol 冻结审查 r3（2026-10-02）

起草：协调者（Claude）。本文接替 r2（`G8_FREEZE-r2.md` §5：选了需新代码的选项即作废 r2、另出 r3）。r8 复核由独立 Claude 子代理只读执行。

## 1. 用户签署

用户对 r2 回复"按你建议来"（2026-10-02），即：

```
G8 r2：不否决
IC-13：保留
IC-14：选项二
IC-15：选项二（上限 64）
```

## 2. 实现

由协调者直接实现，没有交给 grok。机制、行号、探针 id 见 `contract/protocol/DECISIONS_REQUIRED.md` 的 IC-14、IC-15 节末「选项二实现」。

- IC-14：`remapAntigravityArgs` 补位的非首个宿主键同时留作内容叶，取 v0.2.6 与 857f3eb 的并集。v1 hook 与 v2 adapter 共用。
- IC-15：容器深度 > 64 失败关闭，检查点为 hook parse、v2 adapter 开关关闭路径、两条 evaluate 路由、v2 rewriteLayout 物化。最后一处是实现中发现的缺口：v2 wire 自身很浅，深度藏在 layout 节点里，路由层检查看不到。
- fixture 重采：别名探针 181 条，差异 `ic13` 55 / `ic14` 9 / `ic15` 3。原 IC-14 放宽类 9 条逐条断言恢复为 v0.2.6 字节。

## 3. 对象与命令

- worktree `C:\Users\sxl\Desktop\NMZP\nmzp-wt\P2-WP21B`，分支 `codex/nmzp-1-p2-wp21b`，HEAD `8e6df900998ede1e1f9285fded4ddbadd3a1459c`外加当时未提交的改动（下表即对此状态所跑）；用户同意后提交为 `fcc8353`（B2 守护）、`542fd13`（IC-14/15 实现与 v0.2.6 基线）和本文档所在的 docs commit。`GROK_REPORT.md` 不纳入。
- v0.2.6 基线树 `nmzp-wt/BASE-0.2.6` @ `e9ac5a3`，只读。机器 win32-arm64，node v24.15.0。日志在 `nmzp-wp21b-evidence/g8/`。

| # | 命令（cwd = worktree） | 结果 |
|---|---|---|
| 1 | `node --experimental-strip-types --test tests/compat/hook-bytes-golden.test.mjs tests/compat/hook-bytes-v026.test.mjs tests/contract/legacy-canonical-decision-scope.test.mjs` | 291 pass / 0 fail（`r8b-test.log`） |
| 2 | `node scripts/gen-golden-v026.mjs --base ../BASE-0.2.6 --check` | `check ok` |
| 3 | `npm run -s typecheck` / `lint` / `lint:layers` / `lint:contract` | 均 exit 0（`r8c-static.log`） |
| 4 | `node --experimental-strip-types --test tests/contract/protocol-failure-mutations.test.mjs tests/contract/single-projection-mutations.test.mjs` | 2 pass / 0 fail（`r8c-mut.log`） |
| 5 | `npm test` | 2294 tests / 2251 pass / 0 fail / 43 skipped（`r8c-fulltest.log`） |

没有联网，没有读取凭据文件。

## 4. r8 复核

结论：**NO_BLOCKER**。没有发现深度计法差一、首次遍历早于深度检查的生产入口、IC-14 新放宽或别名冲突误判/漏判。复核者日志在 `nmzp-wp21b-evidence/g8/r8-review/`：`--check` ok；8 个目标测试文件 273/273 pass；protocol-failure-mutations 1/1 pass；3000 个随机形状里 `jsonDepthExceeds` 与参考深度计算 0 处不一致；`structuredClone` 在 64 层正常、3000 层抛 RangeError，所以删掉的 clone-depth 变异体在准入范围（≤ 64 层）内等价。

非阻断项及处理：

| # | 发现 | 处理 |
|---|---|---|
| N1 | IC-14「机制」写的是选项二之前的行为，没有标注 | 已标为 8e6df90 的历史描述 |
| N2 | 若干行号过期 | 已更正 |
| N3 | `prepareHookTransport`/`prepareProbeTransport` 在深度检查前遍历，没有生产调用方 | 登记为「接入前须补」 |
| N4 | v2 正文 deviceId 不匹配且超深时返回 400，不再是 401 | 登记；两种结果都失败关闭 |
| N5 | 测试名 "no hidden nesting ceiling" 名不副实 | 已改名 |
| N6 | IC-14 并集的单调性是推断，没有逐条规则证明 | 文档原已如实标注 |
| N7 | 复核者没有复跑 single-projection-mutations（它会在 worktree 写临时目录） | 以协调者日志 `r8c-mut.log` 为准 |

## 5. 总判定

**FREEZE_WITH_CONDITIONS**，条件见 §6。本判定由协调者根据用户签署和 r8 NO_BLOCKER 作出，不批准 §7 所列任何操作。

## 6. 未验证项与冻结条件（沿用 r2 §6，按本次实现更新）

- HOST_REAL 未做：antigravity/cursor 的 REWRITE ask 载体是否弹窗（r1 N5）；深度上限后宿主超时问题不再可达，不再列为条件。
- IC-14 并集只由 fixture 探针证明，未逐条枚举以 file_path 缺失为条件的规则。
- `ingestObservation` 未加深度检查；当前无运行时调用方，接入前须补。
- r1 非阻断 N2、N3、N8、N11（性能需在最终 SHA 重跑）仍开放。
- 「候选（未实现）：Antigravity 空宿主键压过字面键」仍为候选，不在本次冻结内。

## 7. 范围声明

- 不批准任何 IC 开关切换（IC-01/02/10/11/12 仍 NOT_SWITCHED）。
- 不批准 commit、推送、合并到 main 或部署。
