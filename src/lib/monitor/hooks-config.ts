/** Complete pack from the repo root. Build UI first. */
export const CORE_PACK = `npm run build
npm run pack
# or ./core/pack.sh`;

/** Dedicated CT: extract the complete tree. Node is already on the CT. */
export const CORE_INSTALL = `tar -C /opt -xzf nmzp-core.tgz
install -m 644 /opt/nmzp/nmzp.service /etc/systemd/system/nmzp.service
systemctl enable --now nmzp
# CT: node /opt/nmzp/nmzp.mjs`;

/** One ticket/pin bundle on the CT. Same user and data dir as the running service. */
export const JOIN_COPY = `runuser -u nmzp -- env NMZP_DATA=/var/lib/nmzp NMZP_PUBLIC_URL=<CT的https地址> node /opt/nmzp/nmzp.mjs ticket --out /var/lib/nmzp/join-bundle.json`;

/**
 * Ordinary user, once. Windows uses the local cmd, not a PATH nmzp.
 * Unix line kept so join is still `nmzp join`.
 */
export const JOIN_CMD = `.\\nmzp.cmd join .\\join-bundle.json
nmzp join ./join-bundle.json`;

export const ATTACH_CMD = JOIN_CMD;
export const SSH_CMD = ".\\nmzp.cmd board --bundle join-bundle.json --token-file admin.token";

export const ATTACH_HINT_ZH =
  "在要接入的电脑上执行 join。13 个适配器；Codex 需宿主内信任；ZCode 需 hooks.enabled=true 且新会话生效；Antigravity 需重启 IDE，Windows 有不触发的公开报告；回执只证明适配器被调用";

export const PROBE_CONFIG = `{
  "watch": {
    "processes": ["grok", "claude", "codex", "zcode", "antigravity", "kimi", "trae", "qwen", "qoder", "lingma", "codebuddy", "gemini", "cursor"],
    "note": "confirmed agent pid/ppid/basename only; no CommandLine; no background file or NIC capture"
  }
}`;

/** What join writes into ~/.zcode/cli/config.json (process argv, no shell). */
export const ZCODE_HOOK = `{
  "hooks": {
    "enabled": true,
    "events": {
      "PreToolUse": [
        {
          "hooks": [
            {
              "type": "process",
              "command": "node",
              "args": ["--experimental-strip-types", "~/.nmzp/runtime/0.1.0/nmzp.mjs", "hook", "--agent", "zcode"],
              "timeoutMs": 8000,
              "statusMessage": "NMZP PreToolUse v1"
            }
          ]
        }
      ]
    }
  }
}`;

/** What join writes to ~/.gemini/config/hooks.json under the named hook nmzp. */
export const ANTIGRAVITY_HOOK = `{
  "nmzp": {
    "enabled": true,
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "node ~/.nmzp/runtime/0.1.0/nmzp.mjs hook --agent antigravity",
            "timeout": 8
          }
        ]
      }
    ]
  }
}`;

/**
 * What join actually writes to ~/.codex/hooks.json (Windows: the command is a PowerShell
 * -EncodedCommand wrapper around the same node invocation). statusMessage marks NMZP ownership.
 */
export const CODEX_HOOK = `{
  "hooks": {
    "PreToolUse": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "node ~/.nmzp/runtime/0.1.0/nmzp.mjs hook --agent codex",
            "timeout": 8,
            "statusMessage": "NMZP PreToolUse v1"
          }
        ]
      }
    ]
  }
}`;

/**
 * Codex (codex-cli >= 0.154) keeps hooks on by default and skips any non-managed hook until it is
 * trusted. Trust is written by Codex itself under [hooks.state] after /hooks → Trust.
 * NMZP never writes that table; the board shows "配置存在，Codex 未信任" until Codex records it.
 */
export const CODEX_TOML = `[features]
hooks = true

# 首次 join 后在 Codex 里执行 /hooks，信任 "NMZP PreToolUse v1"。
# Codex 会自行写入 [hooks.state."<~/.codex/hooks.json>:pre_tool_use:<group>:<handler>"] trusted_hash。
# 未信任前 Codex 不执行该 hook；hooks.json 改动后需重新信任。`;

/** What join writes to ~/.grok/hooks/nmzp.json (Windows: PowerShell -EncodedCommand wrapper). */
export const GROK_HOOK = `{
  "hooks": {
    "PreToolUse": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "node ~/.nmzp/runtime/0.1.0/nmzp.mjs hook --agent grok",
            "timeout": 8
          }
        ]
      }
    ]
  }
}`;

/**
 * What join merges into ~/.claude/settings.json (Windows: PowerShell -EncodedCommand wrapper).
 * Grok also loads this file; the adapter no-ops under a Grok host so the Grok entry owns the event.
 */
export const CLAUDE_HOOK = `{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "node ~/.nmzp/runtime/0.1.0/nmzp.mjs hook --agent claude"
          }
        ]
      }
    ]
  }
}`;

/** What join writes to ~/.kimi-code/config.toml. Only event/command/timeout — no matcher. */
export const KIMI_HOOK = `[[hooks]]
event = "PreToolUse"
command = 'node ~/.nmzp/runtime/0.1.0/nmzp.mjs hook --agent kimi'
timeout = 8
`;

/** What join writes to ~/.trae/hooks.json and ~/.trae-cn/hooks.json. */
export const TRAE_HOOK = `{
  "version": 1,
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "node ~/.nmzp/runtime/0.1.0/nmzp.mjs hook --agent trae",
            "timeout": 8
          }
        ]
      }
    ]
  }
}`;

/** What join writes to ~/.qwen/settings.json. */
export const QWEN_HOOK = `{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "node ~/.nmzp/runtime/0.1.0/nmzp.mjs hook --agent qwen",
            "timeout": 8
          }
        ]
      }
    ]
  }
}`;

/** What join writes to ~/.qoder/settings.json. */
export const QODER_HOOK = `{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "node ~/.nmzp/runtime/0.1.0/nmzp.mjs hook --agent qoder",
            "timeout": 8
          }
        ]
      }
    ]
  }
}`;

/** What join writes to ~/.lingma/settings.json and ~/.qoder-cn/settings.json. */
export const LINGMA_HOOK = `{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "node ~/.nmzp/runtime/0.1.0/nmzp.mjs hook --agent lingma",
            "timeout": 8
          }
        ]
      }
    ]
  }
}`;

/** What join writes to ~/.codebuddy/settings.json. Rewrite key is modifiedInput. */
export const CODEBUDDY_HOOK = `{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "node ~/.nmzp/runtime/0.1.0/nmzp.mjs hook --agent codebuddy",
            "timeout": 8
          }
        ]
      }
    ]
  }
}`;

/** What join writes to ~/.gemini/settings.json (file must already exist). timeout is milliseconds. */
export const GEMINI_HOOK = `{
  "hooks": {
    "BeforeTool": [
      {
        "matcher": "",
        "hooks": [
          {
            "name": "nmzp",
            "type": "command",
            "command": "node ~/.nmzp/runtime/0.1.0/nmzp.mjs hook --agent gemini",
            "timeout": 8000
          }
        ]
      }
    ]
  }
}`;

/** What join writes to ~/.cursor/hooks.json. Flat preToolUse entries, no inner hooks array. */
export const CURSOR_HOOK = `{
  "version": 1,
  "hooks": {
    "preToolUse": [
      {
        "command": "node ~/.nmzp/runtime/0.1.0/nmzp.mjs hook --agent cursor",
        "timeout": 8,
        "matcher": ".*"
      }
    ]
  }
}`;
