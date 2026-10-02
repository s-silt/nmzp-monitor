# WP-26a 语料变更验收

结论：接受 `INTENDED_CHANGES.md` 中 WP-26a 条目（`a2588f36…` → `39da57c8…`，ENGINE_REVISION 2 → 3）列出的 18 条 expected 变更。

授权：用户于 2026-10-02 原话「你验收语料吧」，把这次验收委托给 Claude 执行。这不是用户本人逐条复核；`ADMISSION.json` 记录的 443 条首次准入（用户原话「确认接受」）不变，本文件不改写它。

依据：`b6bdfb5` 引入变更，在 `7350749` 上复核。

- 分类：`overrides.ts` 导出 `LOCKED_RULE_IDS` 12 条，其余受保护规则 17 条为 adjustable，与 WP-26 设计（locked 恒拦截；adjustable 只能 block 或 log，不能 off）一致。
- 17 条 adjustable 的 `downgrade`（规则覆盖为 log）：16 条由 block 变为 log，`overrideSource=rule`。`anonymous_drop_host/downgrade` 的命令 `curl https://transfer.sh/abc` 同时命中未被覆盖的 `anonymous_drop_url`，结果仍为 block，命中规则改报 `anonymous_drop_url`；这符合"取最严决定"。
- `family-exfil-log-example`：族覆盖 `exfil=log` 只作用于 adjustable 的 `curl_post_local_file`，由 block 变为 log，`overrideSource=family`。locked 的 exfil 规则忽略族覆盖。
- 未变更、仍为 block：11 条有案例的 locked 规则的 `downgrade`/`disable`/`exempt`（`kill_monitor_process` 无案例，属已披露的 catalog alias gap）；17 条 adjustable 的 `disable`（off 被忽略）与 `exempt`（受保护规则不吃豁免）。
- 机器核对：`spec-run.mjs run --corpus policy-spec` 443 条全过；`policy-compat-guard.mjs --base 6e0c1b5…` 为 compare 模式通过，`changedCases` 与 `INTENDED_CHANGES.md` 的 18 条 case 行完全相等，前后 bundle anchor 与条目一致。

不在范围：`PROPOSED_DIGEST.txt` 按 runner 约定保持 `status=PROPOSED`/`humanAccept=false`/`frozen=false`；V2、HOST_REAL、Linux、重启验收仍未通过。
