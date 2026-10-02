/** Deployment-time floor for per-client log-only. Parallel 26a owns the same ids in overrides.ts. */
export const LOCKED_RULE_IDS: ReadonlySet<string> = Object.freeze(new Set([
  "isolate_cut_board",
  "isolate_delete_binary",
  "isolate_kill_monitor",
  "isolate_stop_container",
  "agent_hook_disable",
  "kill_monitor_process",
  "monitor_self_tamper",
  "monitor_self_tamper_cmd",
  "zcode_trust_store_tamper",
  "agent_hook_poison",
  "credential_file_upload",
  "env_piped_outbound",
]));
