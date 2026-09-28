import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

declare const NMZP_BUNDLE: boolean | undefined;
declare const __filename: string | undefined;

function modulePath(metaUrl: string): string {
  if (typeof __filename === "string" && __filename.length > 0) return __filename;
  return fileURLToPath(metaUrl);
}

/** Bundle builds set NMZP_BUNDLE and emit .cjs. Source runs stay .ts. */
export function isBundledRuntime(metaUrl = import.meta.url): boolean {
  if (typeof NMZP_BUNDLE !== "undefined" && NMZP_BUNDLE === true) return true;
  return modulePath(metaUrl).endsWith(".cjs");
}

export function runtimeRoot(metaUrl = import.meta.url): string {
  return dirname(modulePath(metaUrl));
}

export function runtimeExecArgv(metaUrl = import.meta.url): string[] {
  return isBundledRuntime(metaUrl) ? [] : ["--experimental-strip-types"];
}

export function workerEntry(name: string, metaUrl = import.meta.url): string {
  const ext = isBundledRuntime(metaUrl) ? ".cjs" : ".ts";
  return join(runtimeRoot(metaUrl), `${name}${ext}`);
}

export function runtimeLayout(metaUrl = import.meta.url): {
  bundled: boolean;
  execArgv: string[];
  extension: ".cjs" | ".ts";
  root: string;
} {
  const bundled = isBundledRuntime(metaUrl);
  return {
    bundled,
    execArgv: bundled ? [] : ["--experimental-strip-types"],
    extension: bundled ? ".cjs" : ".ts",
    root: runtimeRoot(metaUrl),
  };
}
