# core：重 join 时保留早先写入的宿主 hook 文件记录，保证 leave 能清理 — 设计与验收

状态：验收测试已写好（`core/host-files-carry.test.ts`，红灯）。只改 `core/install.ts`。
禁止：改任何 *.test.ts；git；npm run pack；联网；读写用户主目录下的真实配置（测试用临时 HOME）。

## 问题
`joinDevice` 每次只把本轮命中门槛的目标文件写进 manifest（`zcodePath` / `antigravityPath` / `hostFiles`）。
门槛消失但文件仍在时（典型：卸载 Antigravity 删掉 `~/.gemini/antigravity`，而 `~/.gemini/config/hooks.json` 还在），
重 join 后 manifest 丢掉该路径，`leaveDevice` 就不再清理它。

## 修改（`core/install.ts` 的 joinDevice）
在计算 manifest 之前读取 `prevManifest = readManifest(home)`（现有代码已读），然后：
1. `hostFiles`：
   - 当前 `hostJobs` 生成的条目照旧；
   - 追加 `prevManifest.hostFiles` 中满足「路径不在本轮 hostJobs 里」且 `existsSync(path)` 的条目，原样保留其 `agent / created / writtenSha256`；
   - 路径已不存在的旧条目丢弃；同一路径只保留一条（本轮条目优先）。
2. `antigravityPath` / `antigravity`：当 `writeAntigravity === false` 且 `prevManifest.antigravityPath` 存在且该文件仍在磁盘上时，原样沿用 `prevManifest.antigravityPath` 与 `prevManifest.antigravity`。
3. `zcodePath`：同样规则，`writeZcode === false` 且旧路径文件仍在 → 沿用。
4. `files` 数组同步加入被沿用的路径。
5. `leaveDevice` 不需要改：它已按 `antigravityPath`、`zcodePath`、`hostFiles` 逐项处理（created 且 sha 未变 → 删除文件；否则剔除自有条目）。
6. 旧 manifest 没有这些字段时必须兼容；回滚逻辑（`rb.rollback()`）不变。

## 验收（全部通过）
```
node --experimental-strip-types --test --test-timeout=60000 core/host-files-carry.test.ts core/host-adapters.test.ts core/antigravity-hooks.test.ts core/zcode-hooks.test.ts core/codex-hooks.test.ts core/install.test.ts core/install-hooks.test.ts core/probe.test.ts
npx tsc --noEmit
npx eslint core       # 不新增 error（既有 19 条不用管）
```
最后用中文输出：改了哪些文件、命令结果、没做的事、风险。
