# WP-21 cwd格式投影一致性：协调者技术裁决 r1

2026-09-30；实现基线23e35f50a82684e23a58e0aa3ca274c63d4ce302。
前包layout13文件已独立接受，父协调者static/build/guard通过；第一次aggregate被环境网络策略中断（npm版本查询的notifier访问registry），无完整测试总结，不计通过。源码/测试未变，仅禁用偶发网络的离线重跑1976项、1965通过、11明确skip、0失败。本包不复用该数字冒充自己的aggregate。

## 已实施的最小修正

- core/hook-protocol.ts 抽出selectHookEnvelopeCwd，保留原parser返回值，附exact值及已选来源。parseHookEvent自身调用它，canonical adapter只在tool-input cwd未命中时共用它。
- Generic顺序保持cwd→workspaceRoot→真正数组workspace_roots[0]，每项按原str()判断；忽略workspacePaths。
- toolCall格式顺序保持args.Cwd→真正数组workspacePaths[0]；后者只要求string，空字符串/空白/未trim值都是旧parser返回。忽略信封cwd/workspaceRoot。格式由原始toolCall形状确定，与agent flag无关。
- Canonical字段只在原引擎投影存在非空cwd时保存精确字段/provenance；不借此改变空白scalar的既有边界。未选值仍在extras中。Tool-input cwd继续优先，v1逻辑不变。
- layout builder从真实raw选择envelopeCwd，再核对选中ref的exact值；materializer只验证声明ref属于该格式允许的来源，并绑定canonical投影。它不从extra的/0路径猜测未传输的外层容器是数组。外层容器没有加入layout，也没有新增原始信封传输。

修复两个旧差异：Antigravity args={}、cwd=/generic、workspacePaths=[/actual]现在canonical选择/actual；普通hook仅workspacePaths=/ignored现在canonical忽略。另覆盖workspace_roots/workspacePaths为对象{'0':...}的helper误推断。真实v1 parser行为保持不变，不切换IC。

## 信任界限

materializer的envelopeCwd是有界声明，不是原始host输入认证。完全修改canonical声明可以保持自洽；rawPayloadHash不能证明诚实。builder依赖真实adapter ParseEventResult，不作为任意攻击者事件的完整重新认证器；本包仅增加实际选中cwd的raw exact核对。renderer原始输入绑定、完整wire验证仍需要后续实现。

## 本地transport边界设计（未实施）

未来HOOK传输准备结果应是闭合两分支：request{event:CanonicalToolEvent}或local_denial{failure:AdapterParseFailure|{aliasConflict:true}}。原始信封aliasConflict不能成为可发送的成功事件；沿用原ParseEventResult供兼容渲染，冲突走现有renderHookFailure与v1 bad_hook_json字节。

不向wire添加一个调用方可伪造的aliasConflict布尔来冒充证明。服务器仍必须校验声明的canonical/layout内部一致性和选中bag的真实alias规则，但无法复核未传输的完整原信封。这一边界不得被描述成原stdin完整性证明。

PROBE/direct-v1-body与HOOK的parser/别名集合不同，其规范生产路径需在evaluate设计中单独闭合。以上只是候选transport设计，没有新增函数、hook/HTTP激活、失败HTTP码、D5、迁移/replay或存储。

## 定向证据

- 独立literal旧parser oracle覆盖540种null/非string/空白/Unicode/数组-vs-object/多候选组合，防止共用helper一起改错；再检查agent flag、tool cwd优先、layout实际view与两个精确反例。
- 两个修复样例在13宿主各走真实离线runHook，共26次输出字节比较；不冒充真实宿主安装。
- 三个真实source变异：恢复generic cwd优先、trim Antigravity原返回值、从extras猜数组；各要求实际行为断言失败，原始bytes/hash恢复后目标1/1。
- 不修改request-contracts.test.mjs；父协调者可与独立的Windows CRLF测试修复合并。最终计数见checkpoint，G8 OPEN，IC均NOT_SWITCHED。
