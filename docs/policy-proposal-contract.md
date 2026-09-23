# 可跨兼容版本使用的策略 JSON 提案

[中文首页](../README.md) · [English](policy-proposal-contract.en.md) · [制作补丁](policy-customization.md)

`nmzp-policy-proposal/1` 是数据协议，不是 Git diff、JavaScript 或 `policy.json` 的直接替换。未来核心版本只要继续声明支持 `/1`，就必须维持这里的字段和语义；如果规则目录或协议语义变了，明确拒绝旧提案并重新生成。不能保证同一份旧提案适用于任意未来版本。

Grok Bot 可按 GitHub 源码生成提案，但 GitHub `main` 不证明 CT 正运行相同代码。发布前应由持有管理员权限的 NMZP 操作者读取 CT 的能力信息，核对实际规则目录和当前策略版本。不要把管理员令牌、设备凭证、真实日志或完整策略正文交给外部模型。Bot 可只接收非敏感的协议版本、规则目录摘要和经人确认的改动要求。

## 运行接口

所有路径只接受管理员凭证，使用现有 TLS 和鉴权；只读用户或设备凭证不能发布。window 和 sqlite 两种存储模式均可使用。

- `GET /api/v1/policy/proposals/capabilities` 返回当前 `schema`、`policyVersion`、`rulesHash`、`engineVersion`、必需绑定字段、`newCustomRulesDefaultDryRun` 和 `explicitActivationAllowed`。
- `POST /api/v1/policy/proposals/validate` 对同一份 JSON 做只读格式、基线、可信规则目录、合并及完整策略校验；不保存、不变更版本。它不能保证稍后的提交一定成功，因为其他管理员可能先发布、磁盘也可能失效。
- `POST /api/v1/policy/proposals/apply` 重做上述校验，再调用唯一的 `NmzpStore.casPolicy` 写入者。成功返回新策略版本；`409 cas_conflict` 或 `409 rules_changed` 必须重新获取能力信息并人工复核，不能自行替换基线重试。

示例（`baseRulesHash` 必须替换为能力接口给出的 64 位小写 SHA-256；版本也必须取自同一次 CT 状态）：

```json
{
  "schema": "nmzp-policy-proposal/1",
  "basePolicyVersion": 12,
  "baseRulesHash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "overrides": { "rules": { "download_operation": "log" }, "families": {} },
  "customRules": [
    { "match": "SYNTHETIC_PATTERN", "mode": "block", "dryRun": true }
  ],
  "rationale": "对合成案例的预期影响；非服务器执行指令"
}
```

允许的提案键为 `schema`、`basePolicyVersion`、`baseRulesHash`、`overrides`、`customRules`、`exemptions`、`remove`、`rationale`。`mode`、`stopped`、上传策略、未知字段和可执行代码均被拒绝。覆盖按规则/家族键合并；删除必须写入 `remove`，不会因为提案未提及某条现有规则就删除它。自定义规则未写 `dryRun` 时默认试运行；明确 `dryRun:false` 时沿用项目原有允许启用语义，仍须经可信规则约束和管理员发布。`rationale` 仅用于审阅，不随策略保存。

新发布接口不会默默跳过与现有自定义规则相同的 `match`，或与现有豁免相同的 `ruleId` 加 `match`；这种提案返回 `400 proposal_existing_item`。要替换已有项，先在同一提案的 `remove.customRuleIds` 或 `remove.exemptionIds` 写明原 ID，再添加新项。旧页面的“导入建议”仍可预览；它不核对 `baseRulesHash`，所以含此绑定的 Bot 提案在旧页面禁用“应用”，应使用上述服务端 `/validate` 和 `/apply` 路径。未绑定摘要的旧格式提案维持原页面行为。

预检成功响应为 `{ok,policyVersion,rulesHash,candidateTotals,newCustomRulesDefaultDryRun}`，其中 `candidateTotals` 包含 `overrideRules`、`customRules`、`exemptions`；发布成功响应为 `{ok,version,rulesHash,newCustomRulesDefaultDryRun}`。

| 状态 / 错误 | 处理 |
| --- | --- |
| `400 bad_json` / `400 invalid_proposal` | 修正 JSON 或返回的校验问题 |
| `400 proposal_base_required` | 从实际 CT 能力信息补齐两个绑定字段 |
| `400 proposal_existing_item` | 核对已有项，使用明确删除并添加的替换提案 |
| `400 proposal_no_changes` | 核对提案，没有可发布的变更 |
| `409 cas_conflict` | 重新读取当前策略并比较后再准备发布 |
| `409 rules_changed` | 重新读取能力信息并按实际规则目录复核 |

对同一提案的成功发布生成递增版本。网络超时后的重试会遇到旧基线 `409`，操作者应先读当前版本和策略，核实首次发布是否成功；不要把 `409` 直接当失败而强行改成新版本。设备通过现有策略拉取/心跳路径逐步获得新版本；CT 返回发布成功不代表所有设备已经应用。查看设备的 `lastPolicyVersion` 和近期回执，离线设备保持未知。

此协议只能修改现有核心已经支持的数据规则。新增内置规则、改匹配器/解释器、Hook 协议、Agent 适配器、策略字段或存储格式仍是代码变更，需要单独测试和部署；不因 JSON 提案而热替换。任何发布到生产 CT 的具体提案仍需带原文、差异、测试与回退依据逐次审阅，不由 Bot 自动持有管理员令牌执行。
