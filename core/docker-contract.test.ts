import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { packRelease } from "../scripts/release-archive.mjs";

const coreDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = dirname(coreDir);

type CopyInstruction = { src: string; dest: string };

function dockerfileInstructions(text: string): string[] {
  const instructions: string[] = [];
  let pending = "";
  for (const raw of text.split(/\r?\n/)) {
    const trimmed = raw.trim();
    if (!pending && (trimmed === "" || trimmed.startsWith("#"))) continue;
    const continues = /\\\s*$/.test(raw.trimEnd());
    const piece = continues ? trimmed.replace(/\\\s*$/, "").trim() : trimmed;
    pending = pending ? `${pending} ${piece}` : piece;
    if (!continues) {
      if (pending) instructions.push(pending);
      pending = "";
    }
  }
  if (pending) instructions.push(pending);
  return instructions;
}

function fromImage(instruction: string): string {
  const parts = instruction.replace(/^FROM\s+/, "").split(/\s+/);
  const index = parts[0]?.startsWith("--") ? 1 : 0;
  return parts[index] ?? "";
}

function parseCopy(instruction: string): CopyInstruction {
  const tokens = instruction
    .replace(/^COPY\s+/, "")
    .split(/\s+/)
    .filter((token) => token.length > 0 && !token.startsWith("--"));
  const src = tokens[0];
  const dest = tokens[tokens.length - 1];
  if (!src || !dest || tokens.length < 2) throw new Error("COPY needs a source and a destination");
  return { src, dest };
}

function parseCmd(instruction: string): string[] {
  const raw: unknown = JSON.parse(instruction.replace(/^CMD\s+/, ""));
  if (!Array.isArray(raw) || raw.some((part) => typeof part !== "string")) {
    throw new Error("source contract: CMD is not a string array");
  }
  return raw as string[];
}

function serviceText(): string {
  return readFileSync(join(coreDir, "nmzp.service"), "utf8").replace(/\r\n/g, "\n");
}

function unitValue(unit: string, pattern: RegExp): string {
  const match = unit.match(pattern);
  if (!match?.[1]) throw new Error(`nmzp.service missing ${pattern}`);
  return match[1];
}

function imageHasPackPath(packRel: string, copies: CopyInstruction[]): boolean {
  for (const copy of copies) {
    if (copy.src === "." || copy.src === "./") return true;
    if (copy.src.replace(/^\.\//, "") === packRel) return true;
  }
  return false;
}

function packRelFromImage(imagePath: string, copies: CopyInstruction[]): string {
  for (const copy of copies) {
    const dest = copy.dest.endsWith("/") ? copy.dest : `${copy.dest}/`;
    if ((copy.src === "." || copy.src === "./") && imagePath.startsWith(dest)) return imagePath.slice(dest.length);
  }
  throw new Error(`image path is not copied: ${imagePath}`);
}

function resolveRelative(fromRel: string, spec: string): string {
  const base = fromRel.split("/").slice(0, -1);
  for (const part of spec.split("/")) {
    if (part === "." || part === "") continue;
    if (part === "..") {
      if (base.length === 0) throw new Error(`import escapes the pack: ${spec}`);
      base.pop();
      continue;
    }
    base.push(part);
  }
  return base.join("/");
}

function relativeImportSpecs(source: string): string[] {
  const specs: string[] = [];
  const patterns = [
    /\bimport\s*\(\s*["'](\.[^"']+)["']\s*\)/g,
    /\bfrom\s+["'](\.[^"']+)["']/g,
    /\bimport\s+["'](\.[^"']+)["']/g,
  ];
  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) {
      if (match[1]) specs.push(match[1]);
    }
  }
  return specs;
}

describe("docker runtime contract", () => {
  // source contract: static Dockerfile text, not a built image
  it("Dockerfile uses the node 24 runtime and a non-root user", () => {
    const dockerfile = readFileSync(join(coreDir, "Dockerfile"), "utf8");
    const instructions = dockerfileInstructions(dockerfile);
    const unit = serviceText();
    const engines = JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8")) as { engines?: { node?: string } };
    const enginesMajor = /(\d+)/.exec(engines.engines?.node ?? "")?.[1];
    assert.ok(enginesMajor, "package.json engines.node has no major");
    const image = fromImage(instructions.filter((line) => line.startsWith("FROM ")).at(-1) ?? "");
    const major = Number(/^node:(\d+)/.exec(image)?.[1]);
    assert.ok(image.startsWith("node:"), "source contract: runtime image is not node");
    assert.ok(Number.isInteger(major) && major >= Number(enginesMajor), "source contract: node major is below engines");
    const users = instructions.filter((line) => /^USER\s+/.test(line)).map((line) => line.slice(5).trim());
    assert.ok(users.length > 0, "Dockerfile has no USER");
    const lastUser = users[users.length - 1];
    assert.notEqual(lastUser, "root", "Dockerfile USER is root");
    assert.notEqual(lastUser, "0", "Dockerfile USER is root");
    assert.equal(lastUser, unitValue(unit, /^User=(.*)$/m), "Dockerfile USER is not the service user");
    for (const key of ["NODE_OPTIONS", "NMZP_BIND", "NMZP_PORT", "NMZP_DATA"]) {
      const value = unitValue(unit, new RegExp(`^Environment=${key}=(.*)$`, "m"));
      assert.ok(instructions.some((line) => line === `ENV ${key}=${value}`), `source contract: missing ENV ${key}`);
    }
    const workdir = unitValue(unit, /^WorkingDirectory=(.*)$/m);
    assert.ok(instructions.some((line) => line === `WORKDIR ${workdir}`), "source contract: WORKDIR does not match the unit");
    assert.ok(instructions.some((line) => line === "EXPOSE 8787"), "source contract: EXPOSE 8787 missing");
    const runs = instructions.filter((line) => line.startsWith("RUN ")).join("\n");
    assert.match(runs, /chmod\s+0700\s+\/var\/lib\/nmzp(?:\s|$)/, "source contract: data dir mode is not 0700");
    assert.match(runs, /chown\s+nmzp:nmzp\s+\/var\/lib\/nmzp(?:\s|$)/, "source contract: data dir owner is not nmzp");
    assert.match(runs, /--shell\s+\/usr\/sbin\/nologin/, "source contract: nmzp login shell is not nologin");
    const exec = unitValue(unit, /^ExecStart=(.*)$/m).split(/\s+/);
    const cmd = parseCmd(instructions.filter((line) => line.startsWith("CMD ")).at(-1) ?? "");
    assert.deepEqual(cmd, exec, "source contract: CMD does not match nmzp.service ExecStart");
  });

  // Behavior: packRelease fixture. Source contract: Dockerfile COPY/CMD. Not a running container.
  it("Dockerfile copies the complete packed runtime that its entry imports", async () => {
    const repo = await mkdtemp(join(tmpdir(), "nmzp-docker-pack-"));
    try {
      await mkdir(join(repo, "core", "native-agent-sandbox"), { recursive: true });
      await writeFile(
        join(repo, "core", "nmzp.mjs"),
        "import { createRequire } from \"node:module\";\nimport { dirname, join } from \"node:path\";\nimport { fileURLToPath } from \"node:url\";\nconst loaded = createRequire(import.meta.url)(join(dirname(fileURLToPath(import.meta.url)), \"nmzp-main.cjs\"));\nvoid loaded.main;\nvoid loaded.hookMain;\n",
      );
      await writeFile(
        join(repo, "core", "cli.ts"),
        "import { value } from \"./schema.ts\";\nimport { hookMain } from \"./hook.ts\";\nexport { value, hookMain };\nexport async function main() { return value; }\n",
      );
      await writeFile(
        join(repo, "core", "hook.ts"),
        "import { engine } from \"../src/lib/monitor/engine.ts\";\nexport { engine };\nexport async function hookMain() { return engine; }\n",
      );
      await writeFile(join(repo, "core", "schema.ts"), "export const value = 1;\n");
      await writeFile(join(repo, "core", "Dockerfile"), "FROM node:22-bookworm-slim\nUSER root\n");
      await writeFile(join(repo, "core", "native-agent-sandbox", "unfinished.exe"), "synthetic\n");
      await writeFile(join(repo, "core", "model-gateway.ts"), "throw new Error(\"unfinished\");\n");
      await mkdir(join(repo, "src", "lib", "monitor"), { recursive: true });
      await writeFile(join(repo, "src", "lib", "monitor", "engine.ts"), "export const engine = 1;\n");
      await mkdir(join(repo, "dist"), { recursive: true });
      await writeFile(join(repo, "dist", "index.html"), "<html></html>\n");
      const packed = await packRelease(repo);
      assert.ok(packed.files.some((file) => file.path === "nmzp.mjs"));
      assert.ok(packed.files.some((file) => file.path === "nmzp-main.cjs"));
      assert.ok(!packed.files.some((file) => file.path === "cli.ts" || file.path === "monitor/engine.ts"));
      assert.ok(packed.files.some((file) => file.path === "ui/index.html"));
      assert.ok(!packed.files.some((file) => file.path === "Dockerfile" || file.path.endsWith("/Dockerfile")));
      assert.ok(!packed.files.some((file) => file.path.startsWith("native-") || file.path.includes("model-gateway")));
      const bundled = createRequire(import.meta.url)(join(packed.dir, "nmzp-main.cjs")) as {
        main: () => Promise<number>;
        hookMain: () => Promise<number>;
      };
      assert.equal(await bundled.main(), 1);
      assert.equal(await bundled.hookMain(), 1);
      assert.equal((await readFile(join(packed.dir, "nmzp-main.cjs"), "utf8")).includes("import.meta"), false);
      const dockerfile = readFileSync(join(coreDir, "Dockerfile"), "utf8");
      const instructions = dockerfileInstructions(dockerfile);
      const copies = instructions.filter((line) => line.startsWith("COPY ")).map(parseCopy);
      const whole = copies.find((copy) => copy.src === "." || copy.src === "./");
      assert.ok(whole, "packed entry import is missing from the image");
      const cmd = parseCmd(instructions.filter((line) => line.startsWith("CMD ")).at(-1) ?? "");
      const imageEntry = cmd.find((part) => part.endsWith("nmzp.mjs"));
      assert.ok(imageEntry, "source contract: CMD has no nmzp.mjs entry");
      const entryRel = packRelFromImage(imageEntry, [whole]);
      const seen = new Set<string>();
      const queue = [entryRel];
      while (queue.length > 0) {
        const rel = queue.pop();
        if (!rel || seen.has(rel)) continue;
        seen.add(rel);
        assert.equal(existsSync(join(packed.dir, rel)), true, "packed entry import is missing from the pack");
        assert.equal(imageHasPackPath(rel, copies), true, "packed entry import is missing from the image");
        const source = await readFile(join(packed.dir, rel), "utf8");
        for (const spec of relativeImportSpecs(source)) queue.push(resolveRelative(rel, spec));
      }
      assert.equal(seen.has("nmzp.mjs"), true, "packed entry import is missing from the pack");
      assert.equal(existsSync(join(packed.dir, "nmzp-main.cjs")), true, "packed entry import is missing from the pack");
      assert.equal(imageHasPackPath("nmzp-main.cjs", copies), true, "packed entry import is missing from the image");
      for (const copy of copies) {
        assert.equal(
          copy.src.startsWith("core/") || copy.src.startsWith("src/"),
          false,
          "source contract: COPY source is outside the packed context",
        );
      }
    } finally {
      await rm(repo, { recursive: true, force: true });
    }
  });

  // source contract: static Dockerfile text, not a built image
  it("Dockerfile fetches nothing over the network", () => {
    const dockerfile = readFileSync(join(coreDir, "Dockerfile"), "utf8");
    const forbidden = [/ADD\s+https?:/i, /\bcurl\b/, /\bwget\b/, /\bnpm\s+(?:install|ci)\b/];
    for (const pattern of forbidden) {
      assert.equal(pattern.test(dockerfile), false, "source contract: Dockerfile fetches over the network");
    }
  });
});
