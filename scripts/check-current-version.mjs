// Named current-version markers only. Historical version sentences are not markers and are not rewritten.
import { readFileSync, realpathSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const defaultRoot = dirname(dirname(fileURLToPath(import.meta.url)));

export const CURRENT_MARKERS = [
  {
    file: "SECURITY.md",
    pattern: /^Current release: \*\*(\d+\.\d+\.\d+)\*\*\./m,
    label: "security-current-release",
  },
  {
    file: "SECURITY.md",
    pattern: /^\| (\d+\.\d+\.\d+) \| Current source tree/m,
    label: "security-support-current",
  },
  {
    file: "docs/limits.md",
    pattern: /^当前版本 (\d+\.\d+\.\d+)。/m,
    label: "limits-zh",
  },
  {
    file: "docs/limits.en.md",
    pattern: /^Current version (\d+\.\d+\.\d+)\./m,
    label: "limits-en",
  },
  {
    file: ".github/ISSUE_TEMPLATE/bug_report.yml",
    pattern: /placeholder: (\d+\.\d+\.\d+)/,
    label: "bug-report-placeholder",
  },
  {
    file: "docs/GITHUB_METADATA.md",
    pattern: /source tree package\.json version is (\d+\.\d+\.\d+)/,
    label: "github-metadata-package",
  },
  {
    file: "docs/install.md",
    pattern: /^首页的「快速开始」够完成一次加入。这里是 CT 与本机文件的完整步骤。版本 (\d+\.\d+\.\d+)，/m,
    label: "install-zh-current",
  },
  {
    file: "docs/install.md",
    pattern: /从同一个 \[v(\d+\.\d+\.\d+) 发布页\]\(https:\/\/github\.com\/s-silt\/nmzp-monitor\/releases\/tag\/v\1\)/,
    label: "install-zh-release",
  },
  {
    file: "docs/install.en.md",
    pattern: /^The quick start on the home page is enough to join one machine\. This page is the full core and file layout\. Version (\d+\.\d+\.\d+)\./m,
    label: "install-en-current",
  },
  {
    file: "docs/install.en.md",
    pattern: /from the same \[v(\d+\.\d+\.\d+) release\]\(https:\/\/github\.com\/s-silt\/nmzp-monitor\/releases\/tag\/v\1\)/,
    label: "install-en-release",
  },
];

export function readPackageVersion(root) {
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  if (typeof pkg.version !== "string" || !/^\d+\.\d+\.\d+$/.test(pkg.version)) {
    throw new Error("package.json version is not a dotted numeric version");
  }
  return pkg.version;
}

export function checkCurrentMarkers(root, version = readPackageVersion(root)) {
  const errors = [];
  for (const marker of CURRENT_MARKERS) {
    let text = "";
    try {
      text = readFileSync(join(root, marker.file), "utf8");
    } catch {
      errors.push(`${marker.label}: missing`);
      continue;
    }
    const match = marker.pattern.exec(text);
    if (!match || match[1] !== version) {
      errors.push(`${marker.label}: expected ${version}, found ${match?.[1] ?? "missing"}`);
    }
  }
  return errors;
}

function invokedDirectly() {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return realpathSync(fileURLToPath(import.meta.url)) === realpathSync(entry);
  } catch {
    return import.meta.url === pathToFileURL(resolve(entry)).href;
  }
}

if (invokedDirectly()) {
  const rootFlag = process.argv.indexOf("--root");
  const root = rootFlag >= 0 ? process.argv[rootFlag + 1] : defaultRoot;
  if (!root) {
    process.stderr.write("missing --root value\n");
    process.exit(2);
  }
  const errors = checkCurrentMarkers(root);
  if (errors.length) {
    process.stderr.write(`${errors.join("\n")}\n`);
    process.exit(1);
  }
}
