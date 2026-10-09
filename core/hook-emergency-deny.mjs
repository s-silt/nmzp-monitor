/**
 * Hook bootstrap deny bytes. nmzp.mjs and the Windows hook wrapper share this table.
 * No protocol imports: the bootstrap catch must stay usable when cli.ts fails to load.
 */
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

export const EMERGENCY_DENY = {
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

export function emergencyDeny(argv) {
  const agent = agentFromArgv(argv);
  if (typeof agent === "string" && Object.hasOwn(EMERGENCY_DENY, agent))
    return EMERGENCY_DENY[agent];
  return genericDeny;
}
