export const NMZP_VERSION = "0.2.5";
export const NMZP_NAME = "nmzp";

/** Probe interval. */
export const HEARTBEAT_INTERVAL_MS = 30_000;
/** Host with no heartbeat for this long is dark. */
export const OFFLINE_AFTER_MS = 90_000;
/** Dark host folded off overview. */
export const ARCHIVE_AFTER_MS = 7 * 24 * 60 * 60 * 1000;

/** Evaluate / hook body ceiling. Over → 413, never truncated-allow. */
export const BODY_LIMIT = 262_144;
/** Admin state/export may hold MAX_EVENTS rows; larger than device BODY_LIMIT. */
export const ADMIN_BODY_LIMIT = 8 * 1024 * 1024;

export const MAX_EVENTS = 2000;
export const MAX_DEDUP = 4096;
export const JOIN_TICKET_TTL_MS = 15 * 60 * 1000;
export const HOOK_TIMEOUT_MS = 8_000;
/** Total hook wall budget so we stay under host fail-open. */
export const HOOK_BUDGET_MS = 6_500;
export const HOOK_CT_MS = 1_500;
export const HOOK_LOCK_MS = 400;
export const HOOK_RECEIPT_MS = 800;

export const TASK_NAME = "NMZPProbe";
export const HOOK_MARK = "hook --agent";
export const GROK_HOOK_FILE = "nmzp.json";

export const NEED_CHECK_TOOLS = new Set([
  "Bash",
  "Write",
  "Edit",
  "MultiEdit",
  "WebFetch",
  "MCP",
  "run_terminal_command",
  "search_replace",
  "write_file",
  "edit_file",
  "run_command",
  "write_to_file",
  "replace_file_content",
  "multi_replace_file_content",
  "read_url_content",
  "RunCommand",
  "run_shell_command",
  "run_in_terminal",
  "create_file",
  "replace",
  "Shell",
  "Delete",
  "FetchURL",
  "web_fetch",
]);
