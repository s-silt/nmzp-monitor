export function resolveInsidePackDir(repoRoot: string, target: string): string;
export function isPackEntrypoint(metaUrl: string, argv1?: string, cwd?: string): boolean;
export function normalizeShippedText(relPath: string, buf: Buffer): Buffer;
export function archiveTimestamp(): number;
export function createTarGz(
  entries: Array<{ name: string; data: Buffer; dir?: boolean }>,
  mtime?: number,
): Buffer;
export function readAcornVersion(): string;
export function hasImportMetaSyntax(code: string): boolean;
export function packRelease(
  repoRoot: string,
  hooks?: { readAcornVersion?: () => string },
): Promise<{
  dir: string;
  tgz: string;
  files: Array<{ path: string; sha256: string; bytes: number }>;
  releaseChecksum: string;
  fileManifest: string;
  runtimeDeps: string[];
}>;
