import type { RuleCopy } from "./rule-copy.ts";

export const RULE_COPY_EN = {
  families: {
    exfil: {
      name: "Data exfiltration",
      summary: "When project files, screenshots, or the clipboard leave the machine, the upload often never shows in the chat.",
    },
    secret: {
      name: "Credential leak",
      summary: "When a secret file is sent out, the screen often shows only the command, not the body.",
    },
    tamper: {
      name: "Tamper",
      summary: "Editing or turning off the installed guard stops checks, and the page may not warn first.",
    },
    isolate: {
      name: "Gone dark",
      summary: "After this guard's process, service, or network is cut, the board gets no new events.",
    },
    poison: {
      name: "Semantic poison",
      summary: "Override text in a rule file, relay reply, or hook is followed, and it does not look like an alert.",
    },
    destructive: {
      name: "Destructive",
      summary: "A disk wipe, database clear, history rewrite, and similar commands change data as soon as they run.",
    },
    recon: {
      name: "Telemetry and profile",
      summary: "Session telemetry, or timezone and language tags, can leave with a request and show nothing locally.",
    },
  },
  protection: {
    locked: {
      name: "Always block",
      summary: "These stay on block, including on a log-only client. They cannot be switched to log or turned off.",
    },
    adjustable: {
      name: "Adjustable",
      summary: "Choose block or log. These rules cannot be turned off.",
    },
  },
  actions: {
    block: {
      name: "Block",
      summary: "Return a deny and keep an audit row. Whether the call is stopped depends on the host applying the deny.",
    },
    log: {
      name: "Log",
      summary: "Let this call proceed and keep one audit row.",
    },
  },
  clientMode: {
    follow: {
      name: "Follow global",
      summary: "This client is not relaxed on its own. Block or log matches the global policy.",
    },
    log_only: {
      name: "Log only",
      summary: "Adjustable rules are log only; locked rules still block on this client.",
    },
  },
  customSets: {
    name: "Custom rule sets",
    summary: "Privacy-word rules you define, enabled as a group, without changing builtin block rules.",
    defaultSetName: "Default",
  },
  subscription: {
    name: "Remote subscription",
    summary: "Adds only custom privacy rules. The core fetches on a timer and keeps the last rules if a fetch fails.",
  },
  rules: {
    isolate_cut_board: {
      name: "Cut the guard off the network",
      summary: "A firewall or hosts entry naming this guard takes the board offline with no local prompt.",
    },
    isolate_delete_binary: {
      name: "Delete the guard program",
      summary: "Deleting the installed guard stops later checks, often with no prompt on screen.",
    },
    isolate_kill_monitor: {
      name: "Stop the guard process",
      summary: "Stopping this guard process ends new events, so the board only looks suddenly quiet.",
    },
    isolate_stop_container: {
      name: "Stop the guard service",
      summary: "Stopping this guard's service or container halts checks, and the page may show no error.",
    },
    agent_hook_disable: {
      name: "Turn user hooks off",
      summary: "Setting ZCode's hook switch to off lets later tool calls skip this check.",
    },
    kill_monitor_process: {
      name: "Kill the monitor process",
      summary: "A command that stops the monitor probe removes the check, and new audit rows stop too.",
    },
    monitor_self_tamper: {
      name: "Overwrite the installed guard",
      summary: "Overwriting installed guard files can stop checks with no prompt. A source tree is not this case.",
    },
    monitor_self_tamper_cmd: {
      name: "Remove the guard from a shell",
      summary: "A shell rename or delete of the installed path swaps guard files out in the background.",
    },
    zcode_trust_store_tamper: {
      name: "Edit hook trust records",
      summary: "Rewriting a hook trust record can mark a hook you have not reviewed as already trusted.",
    },
    agent_hook_poison: {
      name: "Executable chain in a hook",
      summary: "A hook set to download-and-run, or to send data out, runs before the tool call.",
    },
    credential_file_upload: {
      name: "Upload a credential file",
      summary: "Uploading a .env or private key puts the secret in the request, and the page often hides the body.",
    },
    env_piped_outbound: {
      name: "Pipe a secret file out",
      summary: "Piping a .env or key file into an outbound command sends it off the machine with no body on screen.",
    },
    clipboard_pipe_upload: {
      name: "Send the clipboard out",
      summary: "An agent that reads the clipboard and sends it on can leak a fresh copy, with no separate prompt.",
    },
    screenshot_then_upload: {
      name: "Screenshot, then upload",
      summary: "A screen capture and an upload in the same command can send the screen before you confirm.",
    },
    screenshot_file_upload: {
      name: "Upload a screenshot file",
      summary: "Uploading a just-taken desktop image sends what was on screen out with the request.",
    },
    poison_instruction_file: {
      name: "Poison an agent rule file",
      summary: "Override text written into an agent rule file steers later chats, and the editor does not flag it.",
    },
    poison_relay_payload: {
      name: "Override text in a relay reply",
      summary: "Override text in an unofficial relay reply is followed, and the chat does not show it as a system note.",
    },
    zcode_checkpoint_path: {
      name: "Legacy workspace upload bundle",
      summary: "An encrypted bundle or extra manifest from the old silent upload can appear with no packing step in chat.",
    },
    zcode_snapshot_host: {
      name: "Legacy snapshot upload credential",
      summary: "Fetching a legacy snapshot upload credential can queue a workspace send with no chat confirmation.",
    },
    zcode_capture_event: {
      name: "Legacy silent capture",
      summary: "A legacy silent-capture event name can mean collection started before any prompt was shown.",
    },
    source_file_upload: {
      name: "Upload source or a log bundle",
      summary: "Uploading source, Git data, or a diagnostic bundle puts it in the request, usually not in the chat.",
    },
    pack_pipe_upload: {
      name: "Pipe a packed project out",
      summary: "Piping an archive into an outbound command can send the project in that one command, with no second confirm.",
    },
    anonymous_drop_host: {
      name: "Send to an anonymous drop",
      summary: "A send to an anonymous drop, paste site, or webhook often leaves the body out of the chat.",
    },
    scp_rsync_tree: {
      name: "Copy a tree to another host",
      summary: "Copying the project or home tree elsewhere often leaves only a flash of that command in the window.",
    },
    rclone_cloud_copy: {
      name: "Sync the workspace to cloud storage",
      summary: "Syncing the workspace to object storage moves the tree to the cloud, often with no progress in the chat.",
    },
    curl_post_local_file: {
      name: "POST a file from disk",
      summary: "Putting a file from disk into a POST body sends it out, while the page usually shows only the command.",
    },
    wget_post_file: {
      name: "wget posts a local file",
      summary: "wget sending a local file as POST takes it off the machine, and the output often omits the body.",
    },
    nc_redirect_file: {
      name: "Hand a file to netcat",
      summary: "Sending a file through netcat leaves the browser, and the terminal rarely shows the body.",
    },
    anonymous_drop_url: {
      name: "Open an anonymous drop URL",
      summary: "A tool opening an anonymous drop, paste site, or webhook is aimed outside your account.",
    },
  },
} as const satisfies RuleCopy;
