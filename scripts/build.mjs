import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { isPackEntrypoint, packRelease } from "./release-archive.mjs";

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));

if (isPackEntrypoint(import.meta.url, process.argv[1])) {
  const packed = await packRelease(repoRoot);
  const deps = packed.runtimeDeps.length > 0 ? packed.runtimeDeps.join(",") : "(none)";
  process.stdout.write(`packed ${packed.dir} files=${packed.files.length} tgz=${packed.tgz} runtimeDeps=${deps}\n`);
}
