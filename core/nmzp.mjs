#!/usr/bin/env node
/**
 * Entry only. Body limit: 413 when n > INGEST_MAX_RAW (core/constants.ts BODY_LIMIT).
 * Probe: hasJoined; otherwise fail("not joined"). Join is one-shot, no popup.
 * Hook bootstrap failures use EMERGENCY_DENY and do not import protocol modules.
 */
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const BOOTSTRAP_REASON = "nmzp_hook_bootstrap_failed";
const HOOK_EVENT = "PreToolUse";

function jsonLine(body) {
  return `${JSON.stringify(body)}\n`;
}

const specificOutput = jsonLine({
  hookSpecificOutput: {
    hookEventName: HOOK_EVENT,
    permissionDecision: "deny",
    permissionDecisionReason: BOOTSTRAP_REASON,
  },
});
const decisionDeny = jsonLine({ decision: "deny", reason: BOOTSTRAP_REASON });
const reasonLine = `${BOOTSTRAP_REASON}\n`;

function deny(stdout, exitCode, stderr) {
  return stderr === undefined ? { stdout, exitCode } : { stdout, exitCode, stderr };
}

const genericDeny = deny(decisionDeny, 2, reasonLine);

const EMERGENCY_DENY = {
  claude: deny(specificOutput, 2, reasonLine),
  codex: deny(specificOutput, 0),
  zcode: deny(specificOutput, 0),
  antigravity: deny(decisionDeny, 0),
  qwen: deny(specificOutput, 2, reasonLine),
  qoder: deny(specificOutput, 2, reasonLine),
  lingma: deny(specificOutput, 2, reasonLine),
  trae: deny(specificOutput, 2, reasonLine),
  codebuddy: deny(specificOutput, 2, reasonLine),
  kimi: deny(
    jsonLine({
      hookSpecificOutput: {
        permissionDecision: "deny",
        permissionDecisionReason: BOOTSTRAP_REASON,
      },
    }),
    2,
    reasonLine,
  ),
  gemini: deny(decisionDeny, 2, reasonLine),
  cursor: deny(
    jsonLine({
      permission: "deny",
      user_message: BOOTSTRAP_REASON,
      agent_message: BOOTSTRAP_REASON,
    }),
    2,
    reasonLine,
  ),
  grok: genericDeny,
};

function agentFromArgv(argv) {
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--agent") return argv[i + 1];
  }
  return undefined;
}

function emergencyDeny(argv) {
  const agent = agentFromArgv(argv);
  if (typeof agent === "string" && Object.hasOwn(EMERGENCY_DENY, agent))
    return EMERGENCY_DENY[agent];
  return genericDeny;
}

async function emitEmergency(denial) {
  await new Promise((resolve) => {
    process.stdout.write(denial.stdout, () => {
      if (!denial.stderr) return resolve();
      process.stderr.write(denial.stderr, () => resolve());
    });
  });
  process.exit(denial.exitCode);
}

const flagged =
  process.execArgv.some((a) => a.includes("strip-types")) ||
  /\bstrip-types\b/.test(process.env.NODE_OPTIONS ?? "");

if (!flagged) {
  const self = fileURLToPath(import.meta.url);
  const child = spawn(
    process.execPath,
    ["--experimental-strip-types", self, ...process.argv.slice(2)],
    {
      stdio: "inherit",
      windowsHide: true,
    },
  );
  child.on("exit", (code, signal) => {
    if (signal) process.kill(process.pid, signal);
    process.exit(code ?? 1);
  });
} else {
  try {
    const { main } = await import("./cli.ts");
    await main(process.argv.slice(2));
  } catch (err) {
    const argv = process.argv.slice(2);
    if (argv[0] === "hook") await emitEmergency(emergencyDeny(argv));
    else throw err;
  }
}
