# INTENDED_CHANGES

策略兼容守卫读取本文件里唯一的 `policy-compat-v1` 区块。区块外的文字不参与判断。初次原样准入的区块没有 `entry`。四个案例文件与引擎版本都未变化的提交不必新增 `entry`，也不必清空已经留下的历史条目。

区块内每个条目从一行 `entry` 开始，随后七行顺序固定，再跟零行或多行 `case`：

    entry
    oldDigest=<64 位小写十六进制>
    newDigest=<64 位小写十六进制>
    oldRevision=<非负整数，不含前导零>
    newRevision=<非负整数，不含前导零>
    oldBundleAnchor=<64 位小写十六进制>
    newBundleAnchor=<64 位小写十六进制>
    reason=<一行，去掉首尾空白后仍非空，最长 400>
    case=<case id>

`case` 可重复出现。case id 至少两段，段与段用 `/` 连接，每段匹配 `[A-Za-z0-9][A-Za-z0-9._-]*`。同一条目里的 case id 不能重复。条目之间可以有空行，不能有其他行。重复签名是 `oldDigest`、`newDigest`、`oldRevision`、`newRevision`、`oldBundleAnchor`、`newBundleAnchor` 这六项，包含前后 bundle anchor。reason 和 case 行不在签名里；六项相同而 reason 不同仍算重复。两个 anchor 不同时，同一对摘要和版本的历史条目可以留在同一区块。

摘要是 `scripts/spec-run.mjs` 的 `expectedDigest()`：按目录路径的 `localeCompare` 顺序，拼接 `caseId/expected.json`、换行和 `expected.json` 原始字节后做 SHA-256。守卫用显式 `en` collation 复算，并要求与 `zh-CN`、`zh-TW`、`und` 的顺序一致。这套 ICU 顺序不是 UTF-8 码元顺序；`protected/monitor_self_tamper_cmd/disable` 排在 `protected/monitor_self_tamper/disable` 之前。不能为了改成码元顺序而更换已批准摘要。

`oldBundleAnchor` 与 `newBundleAnchor` 是完整 bundle anchor。它覆盖每个 case 的 `input.json`、`policy.json`、`context.json`、`expected.json`，路径写成 `caseId/文件名`，只用 `/`。排序使用 JavaScript 字符串小于号，也就是 UTF-16 码元顺序；expected 摘要仍用上一节的 ICU `en`。每个文件先写路径的 UTF-8 字节，再写一个 NUL，再写该文件原始字节的 SHA-256 小写十六进制，再写一个换行；最后对整段拼接做 SHA-256。旧值来自基线提交里这些路径的 Git blob，新值来自当前工作树的原始字节。命中这次转换的条目，其两个 anchor 必须等于这次算出的两个值；历史条目保留它们各自那次转换的 anchor。

变更 case 集合按基线 Git blob 与当前工作树的原始字节计算，覆盖这四个文件。新增、删除、改名（旧 id 与新 id 都算）和仅格式变化都计入。命中条目的 case 集合必须与该集合相等。`expected` 摘要变化时，`newRevision` 必须大于 `oldRevision`。版本下降直接失败。只有版本增加、摘要和四个文件都没变时，仍要有一条 reason，两个 anchor 相同，case 行可以不写。四个文件和版本都没变时，六项签名正好等于这次未变化转换的条目会失败；其他历史条目可以保留，这次不必新增。

当前准入相对 `0ea8f6eac4457c5e13b22b7130f64d48e3613927` 是首次入库：该提交的树没有语料，当前 443 条、已批准 expected 摘要、版本 2 和 1772 个案例文件的 bundle anchor 必须与守卫常量完全一致。1776 份批准清单里的另外四个文件是 `COVERAGE.json`、`PROPOSED_DIGEST.txt`、`REVIEW_INDEX.md`、`review-index.json`，其整文件 SHA-256 固定在守卫常量里，用来核对这四份字节仍是当时批准的内容。`PROPOSED_DIGEST.txt` 里的历史摘要只是这份一致性证据。比较用的旧摘要、旧版本和旧 anchor 来自事件给出的 Git 基线。基线树没有语料时，首次入库仍只接受守卫常量。基线必须是 `0ea8f6eac4457c5e13b22b7130f64d48e3613927`，或者该提交是基线的祖先（`git merge-base --is-ancestor`，包含相等）且该提交自己的树也没有语料。基线正好等于该提交时，沿用原来的读取方式：该提交的树里没有 `core/policy/engine-revision.ts`，守卫不从 Git 另取一份旧 `ENGINE_REVISION` 代替守卫常量，候选工作树的导出必须等于常量 2。后代基线要让这份文件的存在性和解析值都与该提交相同。当前该提交没有这份文件，所以无语料后代也必须没有它；多出文件、缺少文件或数值不同都拒绝，code 是 `bootstrap_baseline_revision_mismatch`。这样基线上已经发生的版本变化会留下。输出里的 `baseline` 是实际基线，`bootstrapFrom` 是上述固定提交。基线已有语料时走比较。`ADMISSION.json` 不是依据。首次入库不在本区块里解释预期变化，下面的机器区块保持为空。

本地初次准入在仓库根目录运行：

```bash
node --experimental-strip-types scripts/policy-compat-guard.mjs --base 0ea8f6eac4457c5e13b22b7130f64d48e3613927
```

之后的本地运行把 `--base` 换成一条显式可信祖先 SHA。该修订要能解析成提交，并且是 HEAD 的祖先。本地 `--base` 仍只使用这个参数，不改用 merge-base。

GitHub `pull_request` 的候选树是 checkout 默认的合并提交，基线只取事件中的 `pull_request.base.sha`。`push` 的 `before` 为 40 个 0 时，基线取 `git merge-base HEAD origin/<default_branch>`。`default_branch` 只取事件里的 `repository.default_branch`，缺失则失败。`origin/<default_branch>` 不存在或没有 merge-base 时失败。这时 `baselineSource` 为 `push.before=zero→merge-base:origin/<分支>`。其他 `before` 仍必须是 40 位十六进制。`workflow_dispatch` 的 `inputs.baseline` 可空。为空时用同一条 merge-base，`baselineSource` 为 `workflow_dispatch.inputs.baseline=empty→merge-base:origin/<分支>`。非空时仍须是 40 位十六进制，全 0 拒绝。merge-base 得到的提交仍须是 HEAD 的祖先。删除分支的 push（`deleted` 为 true）成功跳过，不检查语料。CI 步骤是 `node --experimental-strip-types scripts/policy-compat-guard.mjs`，不传 `--base`，不把 baseline 拼进 shell，该步退出码直接决定成败。删除分支的作业带 `if`，避免 checkout 失败。守卫和 workflow 可以被同一个 PR 修改。这项检查核对语料相对基线是否兼容，不能自己证明检查脚本未被改过，仍依赖代码审查和受保护的必需检查。

```policy-compat-v1
```
