# policy-spec

当前准入：用户已确认接受这 443 条，作为带已披露限制的 0.x 兼容性参考。授权记录是本目录 `ADMISSION.json`，对应外部 `WP-02_HUMAN_ACCEPT.json`，用户原话是「确认接受」。基线 `0ea8f6eac4457c5e13b22b7130f64d48e3613927`。expected 摘要 `a2588f36346e64f2dc8283f3f549f130dd4b152cd8017b8733adb9bbaa6ce3cd`。批准文件 1776 个，清单是外部 `WP-02-independent-r4-candidate-hashes.json`。这不表示 V2、HOST_REAL、Linux、重启验收或整个阶段通过。

之后的变更：WP-26a 把 18 条 expected 改为当前摘要 `39da57c8b0fcc3c77819208dce1a72e9072ab0f2b15b0545b72542e674037151`（ENGINE_REVISION 3），条目见 `INTENDED_CHANGES.md`。用户委托 Claude 验收，记录在 `docs/design-review/WP-26a_CORPUS_ACCEPT.md`；`ADMISSION.json` 仍只记录首次准入。

已披露限制：

- 20 privacy medium findings retained
- 2 realistic protected exemption attempts unproven
- 2 evaluator-only cases not real host evidence
- kill_monitor_process catalog alias gap
- no V2/HOST_REAL/Linux/reboot acceptance

每条 `context.json` 的 `provenance.status` 和 `provenance.acceptance` 仍是生成时来源标签，取值为 `PROPOSED` / `NOT_ACCEPTED`，或 `SOURCE_INDEPENDENT` / `CITED_NOT_CORPUS_ACCEPT`。这些字段没有改写。批次授权只在 `ADMISSION.json`。`PROPOSED_DIGEST.txt` 保留为生成时证据；当前 runner 仍要求其中 `status=PROPOSED`、`humanAccept=false`、`frozen=false` 与 expected 摘要一致。`fixture.schema.json` 保持原文件，描述里的生成时措辞未改。

G3、G4、G5 仍是 OPEN。V2 的 negative HIGH/MEDIUM = 0 是未来门槛。expected 记录当前 0.x `evaluate` 观测，不改业务语义去凑门槛。

引擎调用固定为 `evaluate(input, intervention, customRules, policy)`，`policy.now` 必须显式给出。类型或必填嵌套不符合 `fixture.schema.json` 时，runner 在 `evaluate` 之前失败。受保护规则的 exempt 只有 `compileMatch` 命中该规则在引擎里的受试字符串，才计入绕过尝试。Runner 不发 HTTP，不执行 fixture 里的命令字符串。

```text
node --experimental-strip-types scripts/spec-run.mjs run --corpus policy-spec
node --experimental-strip-types scripts/spec-run.mjs generate --corpus <external-root> --write-expected
node --experimental-strip-types scripts/spec-run.mjs mutate --corpus <external-root> --evidence <file>
```

生成器是 `scripts/spec-run.generate.mjs`。`run` 拒绝 `--write-expected`。`generate` 拒绝写进本仓库。

Host 案例走 `parseHookEvent` 的类型化 `toolInput`，再 `toolInputToEvalFields` 和 `detectHookAgent`，然后 `evaluate`。比较的是解析结果，不是 raw 子串。这不是 HOST_REAL，也不是 `structuredRewrite`。

变异先要求未改动的语料全过，再把五条内置规则分别改到隔离副本上，用该副本的引擎重跑同一语料。检出标准是指定案例的 expected 失配。import/语法错误不算检出。

Rewrite 案例只记录引擎 `action/decision`。不调用 `formatHookResponse`。
