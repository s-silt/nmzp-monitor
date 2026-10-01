# WP-21 性能门 r2 预声明（2026-10-01）

依据：`USER_DECISIONS-2026-10-01.md` U2。本声明写于任何 r2 运行之前。

- 被测提交：`6e0c1b565297432dfb94c59d450dd4dbd2d70fe1`（运行时记录 `git rev-parse HEAD`，不同则作废）。
- 命令：`node --experimental-strip-types scripts/bench-evaluate-v2.mjs 500`，脚本不改。
- 每个平台连续 3 个独立进程，本机运行时不并行其他测试或构建。
- 判定：allow / rewrite / probe 各取 3 次 `ratio` 的中位数，三个中位数都 ≤ 1.20 为 PASS，任一 > 1.20 为 FAIL。
  脚本输出里的 `within105Percent` 是旧门槛字段，r2 不用它判定，原样保留在产物中。
- 平台：本机 Windows ARM64（Node v24.15.0）；CI ubuntu-latest、windows-latest 在推送获批后补跑，规则相同。
- 不重跑：3 次结果全部落盘并计入，FAIL 也照实记录；只有进程崩溃或提交不符才作废重跑，并写明原因。
- 产物：`nmzp-wp21b-evidence/perf-r2-<平台>/run-{1,2,3}.json` 与 `VERDICT.txt`。
