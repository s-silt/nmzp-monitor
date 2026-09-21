import { compilePrivacyDraft } from "./privacy.ts";
import type { CustomPrivacyRule } from "./types.ts";

export const SSH_CMD = ".\\nmzp.cmd board --bundle join-bundle.json --token-file admin.token";

export const SSH_HELP = `.\\nmzp.cmd board --bundle join-bundle.json --token-file admin.token
runuser -u nmzp -- env NMZP_DATA=/var/lib/nmzp node /opt/nmzp/nmzp.mjs status
runuser -u nmzp -- env NMZP_DATA=/var/lib/nmzp node /opt/nmzp/nmzp.mjs rules add 'EMP-\\d{4} => emp_id'`;

export type CliResult =
  | { ok: true; op: "add"; draft: string; rules: CustomPrivacyRule[] }
  | { ok: true; op: "list" | "status" | "help" | "reload" | "rights-export" | "rights-wipe" | "rights-stop" }
  | { ok: true; op: "rm"; id: string }
  | { ok: false; error: string };

/**
 * Parser for the in-container CLI. Same grammar as the rules page.
 * Intended to be driven over SSH: `docker exec -it nmzp nmzp rules add '…'`
 */
export function parseNmzpCli(argv: string[]): CliResult {
  const args = argv[0] === "nmzp" ? argv.slice(1) : argv;
  const cmd = args[0] ?? "help";
  if (cmd === "help" || cmd === "-h" || cmd === "--help") return { ok: true, op: "help" };
  if (cmd === "status") return { ok: true, op: "status" };
  if (cmd === "rights") {
    const sub = args[1] ?? "help";
    if (sub === "export") return { ok: true, op: "rights-export" };
    if (sub === "wipe") return { ok: true, op: "rights-wipe" };
    if (sub === "stop") return { ok: true, op: "rights-stop" };
    return { ok: false, error: "usage: nmzp rights export|wipe|stop" };
  }
  if (cmd === "rules") {
    const sub = args[1] ?? "list";
    if (sub === "list") return { ok: true, op: "list" };
    if (sub === "reload") return { ok: true, op: "reload" };
    if (sub === "rm" || sub === "remove") {
      const id = (args[2] ?? "").trim();
      if (!id) return { ok: false, error: "usage: nmzp rules rm <id>" };
      return { ok: true, op: "rm", id };
    }
    if (sub === "add") {
      const draft = args.slice(2).join(" ").trim().replace(/^['"]|['"]$/g, "");
      if (!draft) return { ok: false, error: "usage: nmzp rules add '<pattern>'" };
      const rules = compilePrivacyDraft(draft);
      if (!rules.length) return { ok: false, error: "pattern too broad or empty" };
      return { ok: true, op: "add", draft, rules };
    }
    return { ok: false, error: "usage: nmzp rules add|list|rm|reload" };
  }
  return { ok: false, error: "nmzp rules add|list|rm · nmzp rights export|wipe|stop · nmzp status · nmzp help" };
}
