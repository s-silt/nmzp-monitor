import {parseArchivePolicy,parseGithubPolicy} from "./egress-schema.ts";
import { parsePolicyExemptions, parsePolicyOverrides } from "./policy-schema.ts";
import {atomicWrite} from "./persist.ts";
import { mkdir, readFile } from "node:fs/promises";
import { dirname } from "node:path";
import { sha256Hex } from "./auth.ts";
import type { PolicyState } from "./schema.ts";

export interface PolicyCacheFile {
  policy: PolicyState;
  sha256: string;
  savedAt: number;
}

export async function writePolicyCache(path: string, policy: PolicyState): Promise<void> {
  const body = JSON.stringify(policy);
  const file: PolicyCacheFile = { policy, sha256: sha256Hex(body), savedAt: Date.now() };
  await mkdir(dirname(path), { recursive: true });
  await atomicWrite(path, JSON.stringify(file), 0o600);
}

export async function readPolicyCache(path: string): Promise<PolicyState | null> {
  try {
    const raw = await readFile(path, "utf8");
    const parsed = JSON.parse(raw) as PolicyCacheFile;
    if (!parsed?.policy || typeof parsed.sha256 !== "string") return null;
    if (sha256Hex(JSON.stringify(parsed.policy)) !== parsed.sha256) return null;
    if (!Number.isInteger(parsed.policy.version) || parsed.policy.version < 1 || !["enforcing","permissive","off"].includes(parsed.policy.mode) || typeof parsed.policy.stopped !== "boolean" || !Array.isArray(parsed.policy.customRules)) return null;
    if (!Number.isFinite(parsed.savedAt) || parsed.savedAt <= 0 || parsed.savedAt > Date.now()+60_000) return null;
    if(parsed.policy.githubUpload!==undefined&&!parseGithubPolicy(parsed.policy.githubUpload))return null;
    if(parsed.policy.archiveUpload!==undefined&&!parseArchivePolicy(parsed.policy.archiveUpload))return null;
    if (parsed.policy.overrides !== undefined && !parsePolicyOverrides(parsed.policy.overrides)) return null;
    if (parsed.policy.exemptions !== undefined && !parsePolicyExemptions(parsed.policy.exemptions)) return null;
    return parsed.policy;
  } catch {
    return null;
  }
}
