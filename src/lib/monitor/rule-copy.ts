import { RULE_COPY_EN } from "./rule-copy.en.ts";
import { RULE_COPY_ZH } from "./rule-copy.zh.ts";

export interface CopyLine {
  readonly name: string;
  readonly summary: string;
}

export interface CustomSetCopy {
  readonly name: string;
  readonly summary: string;
  readonly defaultSetName: string;
}

/** Setting-page copy. Keys are fixed so zh and en stay the same shape. */
export interface RuleCopy {
  readonly families: {
    readonly exfil: CopyLine;
    readonly secret: CopyLine;
    readonly tamper: CopyLine;
    readonly isolate: CopyLine;
    readonly poison: CopyLine;
    readonly destructive: CopyLine;
    readonly recon: CopyLine;
  };
  readonly protection: {
    readonly locked: CopyLine;
    readonly adjustable: CopyLine;
  };
  readonly actions: {
    readonly block: CopyLine;
    readonly log: CopyLine;
  };
  readonly clientMode: {
    readonly follow: CopyLine;
    readonly log_only: CopyLine;
  };
  readonly customSets: CustomSetCopy;
  readonly subscription: CopyLine;
  readonly rules: {
    readonly isolate_cut_board: CopyLine;
    readonly isolate_delete_binary: CopyLine;
    readonly isolate_kill_monitor: CopyLine;
    readonly isolate_stop_container: CopyLine;
    readonly agent_hook_disable: CopyLine;
    readonly kill_monitor_process: CopyLine;
    readonly monitor_self_tamper: CopyLine;
    readonly monitor_self_tamper_cmd: CopyLine;
    readonly zcode_trust_store_tamper: CopyLine;
    readonly agent_hook_poison: CopyLine;
    readonly credential_file_upload: CopyLine;
    readonly env_piped_outbound: CopyLine;
    readonly clipboard_pipe_upload: CopyLine;
    readonly screenshot_then_upload: CopyLine;
    readonly screenshot_file_upload: CopyLine;
    readonly poison_instruction_file: CopyLine;
    readonly poison_relay_payload: CopyLine;
    readonly zcode_checkpoint_path: CopyLine;
    readonly zcode_snapshot_host: CopyLine;
    readonly zcode_capture_event: CopyLine;
    readonly source_file_upload: CopyLine;
    readonly pack_pipe_upload: CopyLine;
    readonly anonymous_drop_host: CopyLine;
    readonly scp_rsync_tree: CopyLine;
    readonly rclone_cloud_copy: CopyLine;
    readonly curl_post_local_file: CopyLine;
    readonly wget_post_file: CopyLine;
    readonly nc_redirect_file: CopyLine;
    readonly anonymous_drop_url: CopyLine;
  };
}

/** "en" selects English. Any other locale selects Chinese, same as t(). */
export function ruleCopy(locale: string): RuleCopy {
  return locale === "en" ? RULE_COPY_EN : RULE_COPY_ZH;
}
