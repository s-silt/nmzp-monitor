import { randomBytes, X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { lstat, open, readFile, rename, unlink, type FileHandle } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { newSecret, safeEqualHex, sha256Hex } from "./auth.ts";
import { AtomicWriteOutcomeUnknownError, atomicWrite } from "./atomic-file.ts";
import { assertNoSymlinkAncestry } from "./install-fs.ts";
import { readServePointer } from "./persist.ts";
import { fingerprintSha256Pem } from "./tls.ts";

const HASH_FILE = "viewer-token.sha256";
const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;
const PIN_RE = /^[0-9a-f]{64}$/;
const BUNDLE_KEYS = ["v", "url", "caPem", "fingerprintSha256", "token"] as const;
const PROTECTED_RELATIVE = [
  "admin.token",
  HASH_FILE,
  "serve.json",
  "meta.json",
  "devices.json",
  "events.jsonl",
  "network.jsonl",
  "policy.json",
  "nmzp.db",
  ".policy-writer.lock",
  ".nmzp-migration.json",
  join("tls", "server.key"),
  join("tls", "server.crt"),
  join("tls", "pin.json"),
  join("tls", "incomplete.json"),
];

export interface ViewerCredentialTestHooks {
  /** Runs before the final bundle rename. The server hash is still the previous one. */
  beforeBundlePublish?: () => void | Promise<void>;
  /** Same point as beforeBundlePublish. */
  beforeBundleInstall?: () => void | Promise<void>;
  /** Runs after the final bundle is in place and before the server hash is activated. */
  beforeHashPublish?: () => void | Promise<void>;
  /** Runs immediately after the final rename, before the published file is read back. */
  afterBundlePublish?: () => void | Promise<void>;
}

let testHooks: ViewerCredentialTestHooks | undefined;

/** Test-only. Production code never calls this. */
export function setViewerCredentialHooksForTesting(hooks?: ViewerCredentialTestHooks): void {
  testHooks = hooks;
}

export interface ViewerCredentialBundle {
  v: 1;
  url: string;
  caPem: string;
  fingerprintSha256: string;
  token: string;
}

export interface CreateViewerCredentialOpts {
  dataDir: string;
  out: string;
  replace?: boolean;
}

function invalid(): never {
  throw new Error("viewer_credential_invalid");
}

function errno(error: unknown): string | undefined {
  if (!error || typeof error !== "object") return undefined;
  const code = (error as { code?: unknown }).code;
  return typeof code === "string" ? code : undefined;
}

function httpsUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && url.username === "" && url.password === "" && url.hostname !== "";
  } catch {
    return false;
  }
}

function certificatePem(value: string): boolean {
  if (!value.includes("-----BEGIN CERTIFICATE-----") || !value.includes("-----END CERTIFICATE-----")) return false;
  if (value.includes("\0")) return false;
  try {
    return new X509Certificate(value).raw.length > 0;
  } catch {
    return false;
  }
}

function parseBundle(value: unknown): ViewerCredentialBundle {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid();
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length !== BUNDLE_KEYS.length || BUNDLE_KEYS.some((key) => !Object.prototype.hasOwnProperty.call(record, key))) {
    invalid();
  }
  if (record.v !== 1) invalid();
  if (typeof record.url !== "string" || !httpsUrl(record.url)) invalid();
  if (typeof record.caPem !== "string" || !certificatePem(record.caPem)) invalid();
  if (typeof record.fingerprintSha256 !== "string") invalid();
  const pin = record.fingerprintSha256.toLowerCase().replace(/:/g, "");
  if (!PIN_RE.test(pin)) invalid();
  if (typeof record.token !== "string" || !TOKEN_RE.test(record.token)) invalid();
  return { v: 1, url: record.url, caPem: record.caPem, fingerprintSha256: pin, token: record.token };
}

export function readViewerCredential(path: string): ViewerCredentialBundle {
  try {
    return parseBundle(JSON.parse(readFileSync(path, "utf8")));
  } catch (error) {
    if (error instanceof Error && error.message === "viewer_credential_invalid") throw error;
    invalid();
  }
}

/** Reads the hash file on every call. Removal or rotation applies without a process restart. */
export function viewerTokenMatches(dataDir: string, bearer: string): boolean {
  try {
    if (typeof bearer !== "string" || bearer.length === 0) return false;
    const raw = readFileSync(join(dataDir, HASH_FILE), "utf8").trim();
    if (!PIN_RE.test(raw.toLowerCase())) return false;
    return safeEqualHex(sha256Hex(bearer), raw.toLowerCase());
  } catch {
    return false;
  }
}

async function destinationMode(path: string, replace: boolean): Promise<"create" | "replace"> {
  try {
    const stat = await lstat(path);
    if (stat.isSymbolicLink() || !stat.isFile()) invalid();
    if (!replace) throw new Error("viewer_credential_exists");
    return "replace";
  } catch (error) {
    if (error instanceof Error && (error.message === "viewer_credential_invalid" || error.message === "viewer_credential_exists")) {
      throw error;
    }
    if (errno(error) === "ENOENT") return "create";
    throw error;
  }
}

async function writeExclusive(path: string, data: string): Promise<void> {
  let handle: FileHandle;
  try {
    handle = await open(path, "wx", 0o600);
  } catch (error) {
    if (errno(error) === "EEXIST") throw new Error("viewer_credential_exists");
    throw error;
  }
  try {
    await handle.writeFile(data, "utf8");
    await handle.sync();
  } catch (error) {
    await handle.close().catch(() => undefined);
    await unlink(path).catch(() => undefined);
    throw error;
  }
  await handle.close();
}

function pathKey(path: string): string {
  return resolve(path).replace(/[\\/]+/g, "/").replace(/\/$/, "").toLowerCase();
}

function isInside(parent: string, child: string): boolean {
  const root = pathKey(parent);
  const target = pathKey(child);
  return target === root || target.startsWith(`${root}/`);
}

function refused(): never {
  throw new Error("viewer_credential_refused");
}

type FileId = { dev: bigint; ino: bigint; mtimeNs: bigint; size: bigint; bytes: string };
type OwnedStaging = { path: string; dev: bigint; ino: bigint };

async function readRegular(path: string): Promise<FileId | "absent" | "other"> {
  try {
    const st = await lstat(path, { bigint: true });
    if (st.isSymbolicLink() || !st.isFile()) return "other";
    return {
      dev: st.dev,
      ino: st.ino,
      mtimeNs: st.mtimeNs,
      size: st.size,
      bytes: await readFile(path, "utf8"),
    };
  } catch (error) {
    if (errno(error) === "ENOENT") return "absent";
    throw error;
  }
}

function sameFile(left: FileId, right: FileId): boolean {
  if ((left.ino !== 0n || right.ino !== 0n) && (left.dev !== right.dev || left.ino !== right.ino)) return false;
  return left.mtimeNs === right.mtimeNs && left.size === right.size && left.bytes === right.bytes;
}

function sameSnapshot(before: FileId | "absent" | "other", current: FileId | "absent" | "other"): boolean {
  if (before === "other" || current === "other" || before === "absent" || current === "absent") return before === current;
  return sameFile(before, current);
}

async function assertOutputAllowed(dataDir: string, out: string): Promise<void> {
  try {
    assertNoSymlinkAncestry(out);
  } catch (error) {
    if (error instanceof Error && error.message === "unsafe_symlink") refused();
    if (!(error instanceof Error) || error.message !== "atomic_write_failed") throw error;
  }
  if (pathKey(out) === pathKey(dataDir) || isInside(join(dataDir, "tls"), out)) refused();
  let outStat: { dev: bigint; ino: bigint; file: boolean; link: boolean } | "absent" = "absent";
  try {
    const st = await lstat(out, { bigint: true });
    outStat = { dev: st.dev, ino: st.ino, file: st.isFile(), link: st.isSymbolicLink() };
  } catch (error) {
    if (errno(error) !== "ENOENT") throw error;
  }
  if (outStat !== "absent" && outStat.link) refused();
  for (const rel of PROTECTED_RELATIVE) {
    const protectedPath = join(dataDir, rel);
    if (pathKey(protectedPath) === pathKey(out)) refused();
    if (outStat === "absent" || !outStat.file) continue;
    try {
      const st = await lstat(protectedPath, { bigint: true });
      if (!st.isFile() || st.isSymbolicLink() || st.ino === 0n || outStat.ino === 0n) continue;
      if (st.dev === outStat.dev && st.ino === outStat.ino) refused();
    } catch (error) {
      if (errno(error) === "ENOENT") continue;
      throw error;
    }
  }
}

async function writeStaging(path: string, data: string): Promise<OwnedStaging> {
  const staging = join(dirname(path), `.${randomBytes(8).toString("hex")}.${process.pid}.viewer.tmp`);
  await writeExclusive(staging, data);
  const st = await lstat(staging, { bigint: true });
  if (st.isSymbolicLink() || !st.isFile()) throw new Error("viewer_credential_unpublished");
  return { path: staging, dev: st.dev, ino: st.ino };
}

async function stagingStillOurs(file: OwnedStaging): Promise<boolean> {
  try {
    const st = await lstat(file.path, { bigint: true });
    if (st.isSymbolicLink() || !st.isFile()) return false;
    if (file.ino === 0n || st.ino === 0n) return true;
    return st.dev === file.dev && st.ino === file.ino;
  } catch (error) {
    if (errno(error) === "ENOENT") return false;
    throw error;
  }
}

async function discardOwned(file: OwnedStaging): Promise<boolean> {
  try {
    const st = await lstat(file.path, { bigint: true });
    if (st.isSymbolicLink() || !st.isFile()) return false;
    if (file.ino !== 0n && st.ino !== 0n && (st.dev !== file.dev || st.ino !== file.ino)) return false;
    await unlink(file.path);
    return true;
  } catch (error) {
    if (errno(error) === "ENOENT") return true;
    return false;
  }
}

function retainedError(path: string): Error {
  return new Error(`viewer_credential_retained ${path}`);
}

async function restorePublished(
  out: string,
  prior: FileId | "absent" | "other",
  identity: OwnedStaging,
  expectedBody: string,
): Promise<"restored" | "external" | "retained"> {
  let st;
  try {
    st = await lstat(out, { bigint: true });
  } catch {
    return "retained";
  }
  if (st.isSymbolicLink() || !st.isFile()) return "retained";
  const inodeKnown = identity.ino !== 0n && st.ino !== 0n;
  const inodeMatches = inodeKnown && st.dev === identity.dev && st.ino === identity.ino;
  let bytes: string | undefined;
  try {
    bytes = await readFile(out, "utf8");
  } catch {
    bytes = undefined;
  }
  if (bytes === undefined && !inodeMatches) return "retained";
  if (bytes !== undefined && bytes !== expectedBody) return "external";
  if (prior === "absent") {
    return (await discardOwned({ path: out, dev: st.dev, ino: st.ino })) ? "restored" : "retained";
  }
  if (prior === "other") return "retained";
  let backup: OwnedStaging;
  try {
    backup = await writeStaging(out, prior.bytes);
  } catch {
    return "retained";
  }
  try {
    const again = await lstat(out, { bigint: true });
    if (again.dev !== st.dev || again.ino !== st.ino || again.isSymbolicLink() || !again.isFile()) {
      await discardOwned(backup);
      return again.dev === st.dev && again.ino === st.ino ? "retained" : "external";
    }
    await rename(backup.path, out);
    return "restored";
  } catch {
    await discardOwned(backup);
    return "retained";
  }
}

export async function createViewerCredential(opts: CreateViewerCredentialOpts): Promise<ViewerCredentialBundle> {
  if (!opts.out) invalid();
  const pointer = await readServePointer(opts.dataDir).catch(() => invalid());
  if (!pointer) invalid();
  let caPem = "";
  try {
    caPem = await readFile(join(opts.dataDir, "tls", "server.crt"), "utf8");
  } catch {
    invalid();
  }
  let certPin = "";
  try {
    certPin = fingerprintSha256Pem(caPem);
  } catch {
    invalid();
  }
  const pin = pointer.fingerprintSha256.toLowerCase().replace(/:/g, "");
  if (pin !== certPin) invalid();
  // Not a multi-file atomic publish. The final bundle is renamed into place
  // before the server hash is activated. A failed final rename leaves the old hash.
  await assertOutputAllowed(opts.dataDir, opts.out);
  const mode = await destinationMode(opts.out, opts.replace === true);
  const destinationBefore = await readRegular(opts.out);
  if (mode === "create" && destinationBefore !== "absent") throw new Error("viewer_credential_exists");
  if (mode === "replace" && destinationBefore === "other") invalid();
  if (mode === "replace" && destinationBefore === "absent") throw new Error("viewer_credential_exists");
  const bundle = parseBundle({
    v: 1,
    url: pointer.url,
    caPem,
    fingerprintSha256: pin,
    token: newSecret(32),
  });
  const hashPath = join(opts.dataDir, HASH_FILE);
  const hashBefore = await readRegular(hashPath);
  const body = JSON.stringify(bundle);
  let staging: OwnedStaging | undefined;
  let phase: "staging" | "published" | "hash-uncertain" = "staging";
  let publishedId: OwnedStaging | undefined;
  const known = (message: string) =>
    message === "viewer_credential_conflict" ||
    message === "viewer_credential_unpublished" ||
    message === "viewer_credential_durability_unknown" ||
    message.startsWith("viewer_credential_retained ");
  try {
    try {
      staging = await writeStaging(opts.out, body);
    } catch (error) {
      if (error instanceof Error && error.message === "viewer_credential_unpublished") throw error;
      throw new Error("viewer_credential_unpublished", { cause: error });
    }
    await testHooks?.beforeBundlePublish?.();
    await testHooks?.beforeBundleInstall?.();
    const hashUnchanged = sameSnapshot(hashBefore, await readRegular(hashPath));
    const destinationUnchanged = sameSnapshot(destinationBefore, await readRegular(opts.out));
    if (!hashUnchanged || !destinationUnchanged || !(await stagingStillOurs(staging))) {
      throw new Error(hashUnchanged && destinationUnchanged ? "viewer_credential_unpublished" : "viewer_credential_conflict");
    }
    const staged = staging;
    try {
      await rename(staged.path, opts.out);
    } catch {
      throw new Error("viewer_credential_unpublished");
    }
    phase = "published";
    publishedId = { path: opts.out, dev: staged.dev, ino: staged.ino };
    await testHooks?.afterBundlePublish?.();
    const published = await readRegular(opts.out);
    if (published === "absent" || published === "other" || published.bytes !== body) {
      throw new Error(published !== "absent" && published !== "other" && published.bytes !== body ? "viewer_credential_conflict" : "viewer_credential_retained_pending");
    }
    await testHooks?.beforeHashPublish?.();
    if (!sameSnapshot(hashBefore, await readRegular(hashPath))) throw new Error("viewer_credential_conflict");
    const again = await readRegular(opts.out);
    if (again === "absent" || again === "other" || again.bytes !== body) throw new Error("viewer_credential_conflict");
    try {
      await atomicWrite(hashPath, sha256Hex(bundle.token), 0o600);
    } catch (error) {
      if (error instanceof AtomicWriteOutcomeUnknownError) {
        phase = "hash-uncertain";
        throw new Error("viewer_credential_durability_unknown");
      }
      throw error;
    }
    return bundle;
  } catch (error) {
    const message = error instanceof Error ? error.message : "";
    if ((phase as "staging" | "published" | "hash-uncertain") === "hash-uncertain") throw error;
    if (phase === "published" && publishedId && !known(message)) {
      const recovered = await restorePublished(opts.out, destinationBefore, publishedId, body);
      if (recovered === "external") throw new Error("viewer_credential_conflict");
      if (recovered !== "restored") throw retainedError(publishedId.path);
      throw new Error("viewer_credential_unpublished", { cause: error });
    }
    if (message === "viewer_credential_retained_pending" && publishedId) throw retainedError(publishedId.path);
    if (phase === "staging" && staging && (await stagingStillOurs(staging).catch(() => false))) {
      const cleaned = await discardOwned(staging);
      if (!cleaned && (message === "viewer_credential_unpublished" || message === "")) throw retainedError(staging.path);
    }
    throw error;
  }
}
