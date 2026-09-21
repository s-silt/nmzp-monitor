/** Bounded, advisory inspection of chat/completions responses. Never changes forwarded bytes. */
export const RESPONSE_RULE_VERSION = "nmzp-response-1";
export type ResponseCoverage =
  "complete" | "malformed" | "truncated" | "interrupted" | "unsupported";
export interface ResponseObservation {
  ruleVersion: string;
  coverage: ResponseCoverage;
  findings: Array<{
    category: "suspected_instruction_hijack" | "suspected_secret_upload";
    position: number;
    source: "text" | "tool";
  }>;
  action: "alert_only";
}
export class ResponseRiskObserver {
  private decoder = new TextDecoder("utf-8", { fatal: true });
  private pending = "";
  private bytes = 0;
  private texts = new Map<number, string>();
  private calls = new Map<string, string>();
  private ended = false;
  private valid = false;
  private coverage: ResponseCoverage;
  private result?: ResponseObservation;
  private kind: "json" | "sse" | "text";
  private cap: number;
  constructor(kind: "json" | "sse" | "text", cap = 262144) {
    this.kind = kind;
    this.cap = cap;
    this.coverage = kind === "text" ? "unsupported" : "complete";
  }
  push(chunk: Uint8Array): void {
    if (this.result || this.coverage !== "complete") return;
    this.bytes += chunk.length;
    if (this.bytes > this.cap) {
      this.coverage = "truncated";
      return;
    }
    try {
      this.pending += this.decoder.decode(chunk, { stream: true });
      if (this.kind === "sse") this.frames();
    } catch {
      this.coverage = "malformed";
    }
  }
  private frames(): void {
    let m: RegExpExecArray | null;
    while ((m = /\r?\n\r?\n/.exec(this.pending))) {
      const frame = this.pending.slice(0, m.index);
      this.pending = this.pending.slice(m.index + m[0].length);
      const lines = frame
        .split(/\r?\n/)
        .filter((l) => l.startsWith("data:"))
        .map((l) => l.slice(5).replace(/^ /, ""));
      if (!lines.length) continue;
      const data = lines.join("\n");
      if (data === "[DONE]") {
        this.ended = true;
        continue;
      }
      if (this.ended) throw Error("data_after_done");
      this.envelope(JSON.parse(data), true);
    }
  }
  private envelope(value: unknown, stream: boolean): void {
    const v = value as any;
    if (!v || !Array.isArray(v.choices) || v.choices.length > 32) throw Error("invalid_choices");
    // usage-only terminal frames may carry an empty choices array.
    for (let i = 0; i < v.choices.length; i++) {
      const choice = v.choices[i];
      const index = choice?.index ?? i;
      if (!Number.isInteger(index) || index < 0 || index > 31) throw Error("choice_index");
      const message = stream ? choice.delta : choice.message;
      if (!message || typeof message !== "object" || Array.isArray(message))
        throw Error("invalid_message");
      this.valid = true;
      if (message.content !== null && message.content !== undefined) {
        if (typeof message.content !== "string") throw Error("content_type");
        this.texts.set(index, (this.texts.get(index) ?? "") + message.content);
      }
      if (message.tool_calls !== undefined) {
        if (!Array.isArray(message.tool_calls) || message.tool_calls.length > 32)
          throw Error("tool_calls");
        for (let j = 0; j < message.tool_calls.length; j++) {
          const call = message.tool_calls[j];
          const ci = stream ? call.index : j;
          if (!Number.isInteger(ci) || ci < 0 || ci > 31) throw Error("call_index");
          const args = call.function?.arguments;
          if (args !== undefined) {
            if (typeof args !== "string") throw Error("call_arguments");
            const key = index + ":" + ci;
            this.calls.set(key, (this.calls.get(key) ?? "") + args);
          }
        }
      }
    }
  }
  finish(interrupted = false): ResponseObservation {
    if (this.result) return this.result;
    if (this.coverage === "complete") {
      try {
        this.pending += this.decoder.decode();
        if (this.kind === "json") this.envelope(JSON.parse(this.pending), false);
        else {
          this.frames();
          if (!this.ended || this.pending.trim()) this.coverage = "interrupted";
        }
        if (!this.valid) this.coverage = "malformed";
      } catch {
        this.coverage = interrupted ? "interrupted" : "malformed";
      }
      if (interrupted) this.coverage = "interrupted";
    }
    const findings: ResponseObservation["findings"] = [];
    const secret =
      /(?:api[_ -]?key|credentials?|password|private[_ -]?key|\.env\b|\.ssh\b|密钥|凭据|密码)/i;
    const upload = /(?:https?:\/\/|\bcurl\b|\bwget\b|upload|exfiltrat|发送到|上传)/i;
    for (const text of this.texts.values()) {
      let fenced = false;
      let position = 0;
      for (const line of text.split("\n")) {
        if (/^\s*```/.test(line)) {
          fenced = !fenced;
          position += line.length + 1;
          continue;
        }
        const quoted =
          /^\s*(?:>|["'“])/.test(line) ||
          /\b(?:example|quoted|test case|do not|never)\b|例如|示例|不要|测试样本/i.test(line);
        if (
          !fenced &&
          !quoted &&
          /(?:ignore|bypass|override|disable).{0,50}(?:instructions?|approvals?|permissions?|rules?|safety)|绕过.{0,20}(?:权限|审批)|忽略.{0,20}(?:指令|规则)/i.test(
            line,
          ) &&
          secret.test(line) &&
          upload.test(line)
        ) {
          findings.push({ category: "suspected_instruction_hijack", position, source: "text" });
        }
        position += line.length + 1;
      }
    }
    for (const text of this.calls.values()) {
      try {
        JSON.parse(text);
      } catch {
        if (this.coverage === "complete") this.coverage = "malformed";
      }
      if (
        secret.test(text) &&
        upload.test(text) &&
        /(?:--data|\s-T\s|Invoke-(?:RestMethod|WebRequest)|requests\.post|fetch\s*\()/i.test(text)
      )
        findings.push({ category: "suspected_secret_upload", position: 0, source: "tool" });
    }
    this.pending = "";
    this.texts.clear();
    this.calls.clear();
    this.result = {
      ruleVersion: RESPONSE_RULE_VERSION,
      coverage: this.coverage,
      findings: findings.slice(0, 16),
      action: "alert_only",
    };
    return this.result;
  }
}
