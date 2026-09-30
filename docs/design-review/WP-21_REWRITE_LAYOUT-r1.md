# WP-21 瞬态 rewrite-layout helper：协调者技术裁决 r1

2026-09-30；基线166a3bdded0f1a0104b1c8d5c89a96c93bef1fe8。
前包四路由已独立接受14文件；父协调者static/build/guard通过，完整1963项、1952通过、11明确skip、0失败。本包是未冻结候选，G8 OPEN，IC-01/02/10/11/12均NOT_SWITCHED。

## 已授权方向与本包边界

用户已接受：V1事件继续走V1重试，升级后新事件走V2，跨版本误投明确不兼容；以及可以传输瞬态结构描述（keys、数组位置、非string literals），字符串复用现有精确片段，不发送原始stdin、不审计持久化layout。

本包只实现第二方向的候选结构/helper及alias计账修正。没有新HTTP入口、runHook激活、迁移标记、指纹/持久化、D5 patch或evaluate实现。不能把helper通过当作HTTP路由、原始stdin完整性或协议冻结证明。

## 相对设计草案的已批准收敛

最初草案的nodes代表effective rewriteSource，允许客户端v1_trim。实际source中的非string节点缺少remap前来源，无法完整重演Antigravity claimant与被覆盖成员；因此改为：

1. nodes只描述真实parser选中的原始tool参数bag（不是整个host信封，更不是raw stdin union）。
2. 服务端helper安全复原bag后调用现有remapAntigravityArgs、resolveEvalBody与原位export的rewriteSource。它们决定trim、alias、补dest等行为。没有任意map或客户端projection/trim指令。
3. sourcePresent显式说明真正rewriteSource结果是否存在：空bag结果为undefined，不伪装成{}；含空容器成员则仍为对象。
4. mapping绑定实际parser格式，不绑定host.id。toolCall即使显式agent为grok，也走Antigravity映射。
5. envelopeCwd仅引用现有精确片段，按真实parser已知优先顺序选择；不是新string值或通用信封扩展。

## 候选结构

CanonicalToolEvent.rewriteLayout可选，旧fixtures和默认adapter不主动生成它。调用buildRewriteLayout(raw, ParseEventResult)才能得到候选layout；它不原位修改event，也不执行工具。

layout={version:1,mapping,sourceRoot,sourcePresent,envelopeCwd?,nodes}；mapping为generic-hook-v1或antigravity-toolCall-v1。sourceRoot为对应的/tool_input、/toolInput、/input、/toolCall/args或null（没有参数bag）。nodes[0]是object。

节点为闭合union：object entries[{key,child}]、array items[index]、string{ref,source}、null、boolean{value}、finite number{value}或numberSpecial（negative_zero/positive_infinity/negative_infinity）。JSON.parse允许-0与数值溢出；通过tag保持实际值，不放非finite JSON数值，不引入NaN/undefined/function。

string ref只允许scalar field、contents leafIndex或extraIndex。source必须等于该ref的provenance/path，以及sourceRoot+树位置的RFC6901拼写。不得内联string value、调用方提供的trim或未声明投影。对象/数组顺序保留，数字对象key遵循真实Object.entries顺序。

## 校验与不作出的保证

- runtime闭合属性、索引、确定性DFS顺序、单父节点/全访问、无重复key、空容器、引用和值/来源一致性、mapping/sourceRoot、已声明bag内string覆盖、actual helper的alias结果、canonical引擎字段投影、sourcePresent及展开后canonical BODY_LIMIT。
- 迭代构造/遍历，不新增默认深度、节点数或pointer限制。expanded canonical可能超过现有262144字节，opt-in helper明确失败且不裁剪；默认旧adapter与IC-10状态不变。
- 字符串只进既有collectContentLeaves路径的引擎投影；extra不增加引擎内容扫描。完整对象仅恢复现有structuredRewrite/residue原有观察范围。
- dataProperty用普通对象上的own data-property构造__proto__/constructor/toString，不调用setter。没有改structuredRewrite里out[k]=value的历史行为，测试同时核对它的序列化与原型结果。
- builder用真实raw hash/逐string引用值检查传入raw与候选事件关联。materializer仅验证已声明的布局和片段一致性；不能证明不诚实发送者没有删改原host输入，rawPayloadHash不是服务端认证/完整性证据。renderer对保留原输入的最终绑定仍待实现。
- 固定typed失败{code:invalid_rewrite_layout,reason}只用于本地helper；没有新增HTTP ErrorCode或伪造BLOCK。错误不带keys、pointer、值或异常文本。
- 该helper不是完整CanonicalToolEvent验证器，也没有解决顶层session/tool/eventId/bag信封别名冲突在HTTP wire中的绑定。原ParseEventResult.aliasConflict仍保留；builder不将冲突事件包装成成功layout。

## alias精确计账修正

原take()把scalar所有alias标记mapped，只保留胜者；cwd工具alias同样如此，信封cwd循环还在判非空前把空白候选标记mapped。现在只认领实际保存的provenance，未保存string落入既有extras遍历。

这是未冻结canonical wire/extras数量/序列化大小变化。赢家、trim冲突、contents枚举、canonicalToEvalInput和v1输出不变。严格extra上限仍在IC-10后：256个旧extra再加未被保存alias现在是257，strict拒绝/default不新拒绝。没有发送新的layout文本值或启用IC。

## 真实证据与后续未决

专测使用真正parseHookEvent/resolveEvalBody/rewriteSource/structuredRewrite与privacy.sanitizeCustomRules。TOKEN|"flag":true规则的true/false两对象拥有相同canonical strings，却有不同真实residue结果；layout保留该差别。覆盖原型同名keys、顺序/空容器、数值special、fallback、精确/trim-equal/blank alias、引用注入、深度80、字节预算、13宿主真实离线hook输出。

负变异修改真实实现：丢失boolean、取消来源绑定、重新丢弃非赢家alias、忽略sourcePresent；每项要求行为断言失败、恢复原始字节/hash后目标1/1。只接受唯一LF/CRLF锚点；不弱化生产检查。

D5的逐源patch、encoded URL/shell/persona坐标、更新字段与安全patch持久化、历史replay和完整evaluate/AJV HTTP/p95仍未做；须单独证明，不能把layout当作这些问题已经解决。

### 新核实的旧cwd投影残余（未修）

真实probe：toolCall.args={}、cwd=/generic、workspacePaths=[/actual]时，parseHookEvent选择/actual，旧canonical adapter选择/generic；普通hook只有workspacePaths=[/ignored]时，v1忽略而旧adapter采纳。materializer按真实parser格式解析，明确返回projection失败；没有改旧adapter的候选优先序，也没有猜一个view掩盖差异。回归钉住此结果。完整evaluate接线前必须另行处理该格式特定投影缺口；helper候选不因此宣称覆盖全部有效宿主输入。
