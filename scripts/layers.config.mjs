/**
 * 逻辑分层（TARGET §4）。第一条命中的 pattern 决定层，文件必须命中恰好一条。
 *
 * 划分（以代码为准，不是把目录物理搬成 domain/）：
 * - contract/：OpenAPI / JSON Schema 目录。当前没有 .ts。
 * - domain：engine、rules、privacy、proposal、evidence 及其纯 TS 闭包（无 node:*）。
 *   src/lib/monitor 里只把这个闭包标成 domain；展示、store、i18n、api 留在 ui。
 * - core/constants.ts、core/policy/engine-revision.ts、core/hook-alias-keys.ts：无 I/O 的纯常量。
 *   constants 必须留在 core/constants.ts：release-archive 用正则读
 *   `export const NMZP_VERSION`，hooks-config-version 测试禁止该文件出现 import，
 *   并钉死 hooks-config 对它的相对路径。
 * - adapters：今天只有 examples/local-adapter.mjs 这种无 I/O 的宿主映射。
 *   core 里的 *-hooks / hook-protocol / host-adapters 会读 fs 或装配置，归 app。
 *   纯适配器注册表是 WP-22，不是把安装器改名。
 * - app：serve、doctor、install、probe、hook、audit 编排、policy 服务。
 * - infra：sqlite、fs、tls、http、crypto、路径与持久化。
 * - cli：core/cli.ts、core/nmzp.mjs、snapshot-guard-cli.ts。eslint.config.mjs 是仓库入口，无产品依赖。
 * - ui：src 下 React、vite.config.ts，以及 monitor 里不在 domain 闭包中的文件。
 *
 * 模糊边界：
 * - path-scope.ts 是词法路径分类，但调用 node:path 的 normalize。它在 engine 闭包里，
 *   不能改成手写 normalize（那是行为变更），所以留在 domain，违规进 allowlist。
 * - hooks-config.ts / join.ts / zcode-hook-config.ts 无 I/O，被 UI 和 core 共用，归 domain。
 *   UI 对它们的 import 进 allowlist，目标 WP-24（UI 不再 import 引擎代码）。
 * - core/policy/** 除 engine-revision 外整包归 app：sqlite/history 会 import publisher、snapshot、
 *   nmzp-service，拆开就是 infra→app 的环。guard 按路径绑定，本 WP 不搬这些文件。
 * - core/device-creds.ts、core/probe-binding.ts 是从 hook.ts、probe-auth.ts 抽出的纯类型，
 *   原处 re-export。它们打断 probe-auth(infra)→hook(app) 与 schema(domain)→probe-auth(infra)。
 *   domain 文件留在 core/ 不搬进 src/lib/monitor：hook 快速路径与 guard 夹具只复制 core/。
 * - persist、audit/events、audit/outbox 同样编排了 app 服务，归 app。
 *   metrics、store、tls、http 客户端仍是 infra。audit/http 与 export-stream 会 import persist，归 app。
 */
const DOMAIN_MONITOR = [
  "actor.ts",
  "agent-catalog.ts",
  "agent-discovery-schema.ts",
  "agent-discovery.ts",
  "agents.ts",
  "cli.ts",
  "cloak.ts",
  "command-intent.ts",
  "correlate.ts",
  "dangerous-delete.ts",
  "disk-overwrite.ts",
  "egress-evidence.ts",
  "egress-schema.ts",
  "engine.ts",
  "evidence-window.ts",
  "exemption-scope.ts",
  "fingerprint.ts",
  "hook-config-guard.ts",
  "hooks-config.ts",
  "ingest.ts",
  "intercept.ts",
  "join.ts",
  "map-event.ts",
  "network-evidence.ts",
  "network-owner-schema.ts",
  "node-data.ts",
  "overrides.ts",
  "path-scope.ts",
  "policy-proposal.ts",
  "policy-schema.ts",
  "privacy.ts",
  "probe-protection.ts",
  "relay.ts",
  "response-evidence.ts",
  "rights.ts",
  "rules.ts",
  "schema.ts",
  "self-protection.ts",
  "session-window.ts",
  "snapshot.ts",
  "storage-target.ts",
  "trust.ts",
  "types.ts",
  "upload-operands.ts",
  "watch.ts",
  "zcode-hook-config.ts",
];

const INFRA = [
  "core/atomic-file.ts",
  "core/audit/json-codec.ts",
  "core/audit/store.ts",
  "core/audit/worker-channel.ts",
  "core/auth.ts",
  "core/config/posix.ts",
  "core/file-lock.ts",
  "core/http-util.ts",
  "core/https-client.ts",
  "core/https-stream.ts",
  "core/install-fs.ts",
  "core/metrics.ts",
  "core/native-probe-service/package.mjs",
  "core/paths.ts",
  "core/policy-cache.ts",
  "core/policy/writer-lease.ts",
  "core/probe-auth.ts",
  "core/probe-mailbox.ts",
  "core/runtime-layout.ts",
  "core/tls.ts",
];

const DOMAIN_CORE = [
  "core/agent-catalog.ts",
  "core/agent-discovery-schema.ts",
  "core/audit/backfill.ts",
  "core/audit/evaluation-record.ts",
  "core/audit/public-event.ts",
  "core/audit/recent-events.ts",
  "core/constants.ts",
  "core/device-creds.ts",
  "core/egress-schema.ts",
  "core/evidence-window.ts",
  "core/heartbeat-schema.ts",
  "core/hook-alias-keys.ts",
  "core/network-evidence.ts",
  "core/network-owner-schema.ts",
  "core/policy-schema.ts",
  "core/policy/engine-revision.ts",
  "core/probe-binding.ts",
  "core/response-evidence.ts",
  "core/schema.ts",
  "core/subscription-schema.ts",
];

export const layers = [
  { layer: "contract", patterns: ["contract/**"] },
  { layer: "domain", patterns: DOMAIN_MONITOR.map((name) => `src/lib/monitor/${name}`) },
  { layer: "domain", patterns: DOMAIN_CORE },
  {
    layer: "cli",
    patterns: ["core/cli.ts", "core/nmzp.mjs", "core/snapshot-guard-cli.ts", "eslint.config.mjs"],
  },
  { layer: "adapters", patterns: ["examples/local-adapter.mjs"] },
  { layer: "infra", patterns: INFRA },
  { layer: "ui", patterns: ["src/**", "vite.config.ts"] },
  { layer: "app", patterns: ["core/**"] },
];
