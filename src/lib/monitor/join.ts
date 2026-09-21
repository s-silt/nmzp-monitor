import { ZCODE_HOOK, CODEX_HOOK, GROK_HOOK, CLAUDE_HOOK } from "./hooks-config.ts";

/** Join is a one-shot on the computer. After that the probe starts at login, hidden. */

const LAN_HTTP = /^http:\/\/(127\.0\.0\.1|localhost|\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})$/;

export function parseJoinUrl(raw: string): string | null {
  const t = (raw ?? "").trim().replace(/\/$/, "");
  const m = LAN_HTTP.exec(t);
  if (!m) return null;
  const port = Number(m[2]);
  if (port < 1 || port > 65535) return null;
  return t;
}

export interface AutostartPlan {
  os: "win32" | "darwin" | "linux";
  files: Array<{ path: string; body: string; mode?: number }>;
  /** Command that registers the unit. Empty if writing the file is enough. */
  register: string[];
}

export function autostartPlan(
  os: NodeJS.Platform,
  opts: { node: string; self: string; home: string },
): AutostartPlan {
  const { node, self, home } = opts;
  if (os === "win32") {
    const vbs = `${home}\\.nmzp\\run.vbs`;
    const body = `Set s = CreateObject("WScript.Shell")\ns.Run """${node}"" ""${self}"" probe", 0, False\n`;
    return {
      os: "win32",
      files: [{ path: vbs, body }],
      register: [
        "schtasks",
        "/create",
        "/tn",
        "NMZPProbe",
        "/sc",
        "onlogon",
        "/rl",
        "limited",
        "/f",
        "/tr",
        `wscript.exe //B //Nologo "${vbs}"`,
      ],
    };
  }
  if (os === "darwin") {
    const plist = `${home}/Library/LaunchAgents/local.nmzp.probe.plist`;
    const body = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>local.nmzp.probe</string>
  <key>ProgramArguments</key><array>
    <string>${node}</string><string>${self}</string><string>probe</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/dev/null</string>
  <key>StandardErrorPath</key><string>/dev/null</string>
</dict></plist>
`;
    return { os: "darwin", files: [{ path: plist, body, mode: 0o644 }], register: ["launchctl", "load", "-w", plist] };
  }
  const unit = `${home}/.config/systemd/user/nmzp-probe.service`;
  const body = `[Unit]
Description=NMZP probe
[Service]
Type=simple
ExecStart=${node} --experimental-strip-types ${self} probe
Restart=always
[Install]
WantedBy=default.target
`;
  return {
    os: "linux",
    files: [{ path: unit, body, mode: 0o644 }],
    register: ["systemctl", "--user", "enable", "--now", "nmzp-probe.service"],
  };
}


export interface JoinHookFile {
  /** Absolute path where the template should land after join. */
  path: string;
  body: string;
}

/** Hook templates join writes under ~/.nmzp/hooks (agent-agnostic copies). */
export function joinHookTemplates(home: string): JoinHookFile[] {
  const sep = home.includes("\\") && !home.includes("/") ? "\\" : "/";
  const root = home.replace(/[\\/]$/, "") + sep + ".nmzp" + sep + "hooks";
  return [
    { path: `${root}${sep}zcode.json`, body: ZCODE_HOOK },
    { path: `${root}${sep}codex.json`, body: CODEX_HOOK },
    { path: `${root}${sep}grok.json`, body: GROK_HOOK },
    { path: `${root}${sep}claude.json`, body: CLAUDE_HOOK },
  ];
}

/** After join writes, confirm expected files exist. Missing → clear warning list. */
export function verifyJoinArtifacts(
  paths: string[],
  exists: (p: string) => boolean = () => false,
): { ok: boolean; missing: string[] } {
  const missing = paths.filter((p) => !exists(p));
  return { ok: missing.length === 0, missing };
}

/** Marker file join writes. Probe refuses to run until this exists. */
export function joinedMarkerPath(home: string): string {
  const sep = home.includes("\\") && !home.includes("/") ? "\\" : "/";
  return home.replace(/[\\/]$/, "") + sep + ".nmzp" + sep + "core";
}

/** True only after this computer has run join. Unjoined hosts are never scanned. */
export function hasJoined(home: string, exists: (p: string) => boolean): boolean {
  return exists(joinedMarkerPath(home));
}

/** Paths join must leave behind: core url + autostart files + hook templates. */
export function expectedJoinPaths(
  home: string,
  plan: AutostartPlan,
): string[] {
  return [joinedMarkerPath(home), ...plan.files.map((f) => f.path), ...joinHookTemplates(home).map((h) => h.path)];
}
