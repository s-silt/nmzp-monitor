import { posix, win32 } from "node:path";

/** Metadata label only. This does not grant access and does not read the filesystem. */
export type WorkdirScope = "project" | "home" | "system" | "other";

const POSIX_SYSTEM = ["/etc", "/usr", "/var", "/opt"] as const;
const POSIX_HOME = ["/home", "/Users"] as const;

type PathStyle = "win" | "posix";

function hasBoundary(path: string, root: string, sep: string, insensitive: boolean): boolean {
  const left = insensitive ? path.toLowerCase() : path;
  const right = insensitive ? root.toLowerCase() : root;
  if (left === right) return true;
  const prefix = right.endsWith(sep) ? right : right + sep;
  return left.startsWith(prefix);
}

function anyBoundary(path: string, roots: readonly string[], sep: string, insensitive: boolean): boolean {
  return roots.some((root) => hasBoundary(path, root, sep, insensitive));
}

/** `~` and `~/...` only. `~other` is a relative name, not an expanded username. */
function isTildeHome(input: string): boolean {
  return input === "~" || input.startsWith("~/") || input.startsWith("~\\");
}

function stripExtended(input: string): string {
  if (input.startsWith("\\\\?\\UNC\\")) return `\\\\${input.slice("\\\\?\\UNC\\".length)}`;
  if (input.startsWith("//?/UNC/")) return `//${input.slice("//?/UNC/".length)}`;
  if (input.startsWith("\\\\?\\")) return input.slice("\\\\?\\".length);
  if (input.startsWith("//?/")) return input.slice("//?/".length);
  return input;
}

function isUnc(input: string): boolean {
  return input.startsWith("\\\\") || input.startsWith("//");
}

function isDrive(input: string): boolean {
  return /^[A-Za-z]:[\\/]/.test(input);
}

function absoluteStyle(input: string): PathStyle | undefined {
  const stripped = stripExtended(input);
  if (isDrive(stripped) || isUnc(stripped)) return "win";
  if (stripped.startsWith("/")) return "posix";
  return undefined;
}

function normalizeAbs(input: string, style: PathStyle): string {
  const stripped = stripExtended(input);
  return style === "win" ? win32.normalize(stripped) : posix.normalize(stripped);
}

function isChild(root: string, candidate: string, style: PathStyle): boolean {
  const sep = style === "win" ? "\\" : "/";
  return hasBoundary(candidate, root, sep, style === "win");
}

function isWindowsUsers(normalized: string): boolean {
  const match = /^[A-Za-z]:(.*)$/.exec(normalized);
  if (!match) return false;
  return hasBoundary(match[1] ?? "", "\\Users", "\\", true);
}

function classifyAbs(normalized: string, style: PathStyle): WorkdirScope {
  if (style === "posix") {
    if (anyBoundary(normalized, POSIX_SYSTEM, "/", false)) return "system";
    if (anyBoundary(normalized, POSIX_HOME, "/", false)) return "home";
    return "other";
  }
  if (isWindowsUsers(normalized)) return "home";
  return "other";
}

/**
 * Lexical scope label. Separator boundaries are required.
 * Does not touch the host filesystem or the account home directory.
 */
export function classifyWorkdir(path: string | undefined, cwd: string | undefined): WorkdirScope {
  if (!path) return "project";
  if (isTildeHome(path)) return "home";
  const pathStyle = absoluteStyle(path);
  const cwdStyle = cwd ? absoluteStyle(cwd) : undefined;
  if (pathStyle) {
    const normalized = normalizeAbs(path, pathStyle);
    if (cwd && cwdStyle === pathStyle && isChild(normalizeAbs(cwd, cwdStyle), normalized, pathStyle)) return "project";
    return classifyAbs(normalized, pathStyle);
  }
  if (cwd && cwdStyle) {
    const root = normalizeAbs(cwd, cwdStyle);
    const api = cwdStyle === "win" ? win32 : posix;
    const joined = api.normalize(api.join(root, path));
    if (isChild(root, joined, cwdStyle)) return "project";
    return classifyAbs(joined, cwdStyle);
  }
  return "project";
}
