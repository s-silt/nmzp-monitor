/** Official model APIs vs 中转站. Poison patterns only apply on a relay channel. */

import { extractHosts, isModelApiHost } from "./snapshot.ts";

export type RelayKind = "official" | "relay" | "poison" | "none";

const OFFICIAL_HOST =
  /(?:^|\.)(api\.z\.ai|open\.bigmodel\.cn|api\.openai\.com|chatgpt\.com|api\.x\.ai|api\.anthropic\.com|generativelanguage\.googleapis\.com|aiplatform\.googleapis\.com|api\.deepseek\.com|dashscope\.aliyuncs\.com|api\.moonshot\.(cn|ai)|api\.mistral\.ai|api\.groq\.com)$/i;

const RELAY_HOST =
  /(?:^|\.)(openrouter\.ai|api\.together\.(xyz|ai)|together\.ai|openai-sb\.com|closeai\.net|ohmygpt\.com|one-api\.|new-api\.|relay\.|openai-proxy\.)/i;

const CHAT_PATH = /\/v1\/(chat\/completions|messages|responses)\b/i;

const POISON_RE =
  /\bignore (?:all )?(?:previous|prior|above) (?:instructions|rules|prompts)\b|\byou are now (?:dan|unrestricted|jailbroken)\b|\b\[INST\]\b|<<\s*SYS\s*>>/i;

export function isOfficialModelHost(host: string) {
  const h = host.toLowerCase();
  return OFFICIAL_HOST.test(h) || isModelApiHost(h);
}

export function isKnownRelayHost(host: string) {
  return RELAY_HOST.test(host.toLowerCase());
}

export function hostsOf(input: { dest?: string; url?: string; command?: string }): string[] {
  const out: string[] = [];
  if (input.dest) out.push(input.dest.toLowerCase());
  for (const h of extractHosts(input.url ?? "")) if (!out.includes(h)) out.push(h);
  for (const h of extractHosts(input.command ?? "")) if (!out.includes(h)) out.push(h);
  return out;
}

export function classifyRelay(input: { dest?: string; url?: string; command?: string }): RelayKind {
  const blob = `${input.command ?? ""} ${input.url ?? ""}`;
  const hosts = hostsOf(input);
  if (!hosts.length && !CHAT_PATH.test(blob)) return "none";

  let relay = false;
  for (const host of hosts) {
    if (isOfficialModelHost(host)) continue;
    if (isKnownRelayHost(host)) {
      relay = true;
      continue;
    }
    if (CHAT_PATH.test(blob) || CHAT_PATH.test(input.url ?? "")) relay = true;
  }

  if (!relay) return hosts.some((h) => isOfficialModelHost(h)) ? "official" : "none";
  if (POISON_RE.test(blob)) return "poison";
  return "relay";
}
