# WP-21 真实渲染改写证据：协调者技术裁决 r1

2026-09-30；基线d120149e5c95739b979962f16ae9183e554f95f5。
前包cwd9文件已独立接受；父协调者static/build/guard通过，完整1984项、1973pass、11明确skip、0fail。本包是独立候选，不是冻结或evaluate接线。G8 OPEN，所有IC NOT_SWITCHED。

## 明确采用的类型修订

RenderedRewriteEvidence/version1 与旧CanonicalRewrite的detector-union D5候选是不同类型，不用新坐标偷偷解释旧patch。新edit.type=rendered_composite_v1，coordinate=effective_view_utf16：

- span是**现有legacy projection之后、任何变换之前的精确effective view叶**的UTF-16区间；首版固定整段非空[0,length]。它不是原host detector区间，也不是合并后的探测器span。
- originalHash=SHA256(UTF8(该完整effective叶))；sourceHash与sourceBindingHash另绑定原fragment值及其物理来源；sourceRef只引用已有field/content-leaf/extra。
- viewLeafIndex+derivation(identity/legacy_fallback)区分同一source的不同有效副本。真实例：host=' X TOKEN '及其trim派生dest='X TOKEN'，规则TOKEN|^[ ]→SAFE，实际输出host='SAFEX SAFE '、dest='X SAFE'。不能强迫二者共享一个结果。
- replacement为实际渲染结果，允许空字符串。这是有意的候选类型修订；它可能含大量未变原文，**绝不是可安全持久化的patch内容**。
- Detector overlap/touching/secret优先级仍全部由原resolveSpans处理。新复合编辑只描述其后完整变换结果；不从整段edit猜detector kind。

## 真实执行与观察

core/rewrite.ts增加可选observer，由core/rewrite-observer.ts隔离。默认v1仍执行同一规则/变换；observer异常被吞掉，callback只拿独立元数据副本，不得修改真实hits/输出。测试核对有/无observer的真实调用文本与顺序，包含short-circuit和回调抛错/改副本。

记录只来自实际执行：
- scanSecrets/scanCustom真实返回的hit与其实际输入坐标空间；包括effective leaf、URL API component、decoded path/query/fragment、带key前缀的query、serialized/full residue及decoded residue。
- persona只记录真实cloak调用的changed；不发明不存在的span。
- shell_piece和unquoted_redirect只是现有检查，不宣称完整shell parser。
- URL catch走text fallback会明确记录fallback，不声称结果已通过URL验证；即使前面的new URL成功，之后catch也保留真实事件顺序。
- findings只引用实际观测hit/persona变化，不表示每个hit都被实际应用（例如query过滤）；完整输出由复合edit+result binding另证。
- 成功artifact必须有真实residue通过；persona没有实际检查则not_run。原本refused仍返回其原reason及观察，不变成假成功。

## 生成、应用与结构投影

buildRenderedRewriteEvidence只执行一次真实structuredRewrite，使用accepted layout构造的完整view；不执行engine/session policy decision。materializer额外返回的rawToolInput只用于瞬态来源映射，禁止持久化。

applyRenderedRewrite校验完整版本、封闭edit、source/ref/副本绑定、完整叶span、findings/observations对应关系与前后hash，然后用固定legacy_object_assignment_v1结构投影产生updatedInput。

- base/resultFieldsHash是值域JCS：scalar原值、contents有序值数组；identity源更新同步共有canonical表示，派生副本单独有edit，不能覆盖原source片段。
- base/resultViewHash绑定UTF8(JSON.stringify完整effective view))，涵盖nonstring、顺序、extras及真实结构投影；layoutHash绑定引用结构。
- 旧walker的out[key]=value对__proto__等的本地原型/ownership行为原样保留。hash只证明序列化字节，不证明prototype equality；专测独立对照own keys、原型内容与global prototype未变。
- 空edit列表可是真实noop或结构投影结果，不等于dummy REWRITE；此类型不包含API action。没有使用旧patches:[]/空hash/revision0生成器作为证明。

apply校验是绑定和一致性校验，不是对不可信发送者“确实执行了扫描”的密码学证明。真实性来自本地真实执行记录与可信服务端调用路径；生产鉴权/renderer最终绑定仍须在evaluate接线时证明。

## 只含metadata的重放见证

rewriteReplayWitness输出固定字段：版本、固定结构算法、rulesHash、layout/fields/view/observations hashes、editCount。没有replacement、updated string、source、任意key、provenance或sourceRef。输入hash形状不合法时拒绝输出witness，避免类型cast把明文塞进hash字段。

replayRenderedRewrite在版本/rules绑定匹配后只重跑历史rewrite过程，比较全部结果及observations witness；没有engine/session重评价。测试使用JSON保存/重新载入该metadata见证，证明不需要保存原文或replacement。

这不是已落地的持久化重放协议：真实历史policy/catalog/engine实现可用性、immutable decision记录、原子事件写入、重试策略和版本迁移都仍待共享evaluate包证明。调用方不能拿当前规则替代历史规则；witness不提供授权或自动重放权。

## 验证与剩余门

覆盖真实URL编码与重复query、shell引用/拒绝、生产persona、注入的合法PrivacyFns删除边界、Unicode、detector overlap/touching/优先级、重复leaf与共享query来源、派生副本、nonstring residue、篡改与元数据无原文、结构/prototype差分。AJV验证真实helper artifact，而非声称HTTP响应已接线。

负变异移除最终结果hash、副本derivation绑定、原residue拒绝，要求真实断言失败并逐次恢复。原rewrite测试同时回归。

CanonicalDecision/旧CanonicalRewrite schema和其旧兼容转换器没有在本包被暗换；未来evaluate必须显式接入这个有版本的真实artifact并完成wire裁决。尚无evaluate HTTP、p95、持久化/历史决策重放或完整协议冻结结论。新observations可能较大，其HTTP预算与紧凑投影需在实际接线时测量，不能截断后声称完整证据。最终实测计数见checkpoint。
