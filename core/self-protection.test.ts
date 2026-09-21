import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { evaluate } from "../src/lib/monitor/engine.ts";
import { SELF_PROTECTION_RULE_IDS } from "../src/lib/monitor/self-protection.ts";
import {
  detectSelfProtection,
  isProtectedInstallPath,
  resolveToolPath,
} from "../src/lib/monitor/self-protection.ts";

function ev(input: Parameters<typeof evaluate>[0]) {
  return evaluate({ agent: "grok", ...input }, "enforcing");
}

function notGuard(r: ReturnType<typeof evaluate>) {
  assert.notEqual(r.decision, "block", r.rule?.id ?? r.category);
  assert.notEqual(r.threat, "tamper");
  assert.notEqual(r.threat, "isolate");
  assert.equal(SELF_PROTECTION_RULE_IDS.has(r.rule?.id ?? ""), false);
}

describe("home-relative install locations, not repo fixtures", () => {
  it("protects home /opt /var/lib and dedicated hook only", () => {
    assert.equal(isProtectedInstallPath("C:/Users/dev/.nmzp/runtime/0.1.0/nmzp.mjs"), true);
    assert.equal(isProtectedInstallPath("/home/max/.nmzp/credentials.json"), true);
    assert.equal(isProtectedInstallPath("/Users/max/.nmzp/manifest.json"), true);
    assert.equal(isProtectedInstallPath("/root/.nmzp/core.json"), true);
    assert.equal(isProtectedInstallPath("~/.nmzp/runtime/x"), true);
    assert.equal(isProtectedInstallPath("~/.grok/hooks/nmzp.json"), true);
    assert.equal(isProtectedInstallPath("C:\\Users\\dev\\.grok\\hooks\\nmzp.json"), true);
    assert.equal(isProtectedInstallPath("/opt/nmzp/nmzp.mjs"), true);
    assert.equal(isProtectedInstallPath("/var/lib/nmzp/join-bundle.json"), true);
  });

  it("does not treat source fixtures or nested .nmzp as installations", () => {
    assert.equal(isProtectedInstallPath("C:/Users/dev/Desktop/NMZP/nmzp-monitor/.nmzp/runtime/x"), false);
    assert.equal(
      isProtectedInstallPath("/home/max/work/nmzp-monitor/.nmzp/credentials.json"),
      false,
    );
    assert.equal(isProtectedInstallPath("/tmp/.nmzp/runtime/x"), false);
    assert.equal(isProtectedInstallPath("/home/max/.nmzp-backup/runtime"), false);
    assert.equal(isProtectedInstallPath("/opt/nmzp-extra/bin"), false);
    assert.equal(
      isProtectedInstallPath("C:/Users/dev/Desktop/NMZP/nmzp-monitor/.grok/hooks/nmzp.json"),
      false,
    );
    assert.equal(isProtectedInstallPath("/home/max/work/project/.grok/hooks/nmzp.json"), false);
    notGuard(
      ev({
        nativeTool: "Write",
        filePath: "C:/Users/dev/Desktop/NMZP/nmzp-monitor/.nmzp/runtime/x",
        contents: "fixture",
      }),
    );
  });

  it("joins relative paths with cwd against home install, not repo .nmzp", () => {
    assert.equal(isProtectedInstallPath(resolveToolPath("runtime/x", "C:\\Users\\dev\\.nmzp")), true);
    assert.equal(
      isProtectedInstallPath(resolveToolPath("runtime/x", "C:\\Users\\dev\\Desktop\\NMZP\\nmzp-monitor\\.nmzp")),
      false,
    );
  });
});

describe("command verb vs data strings", () => {
  it("does not deny read-only commands whose filename or quoted text mentions mutation verbs", () => {
    notGuard(ev({ nativeTool: "Bash", command: 'Get-Content "Remove-Item ~/.nmzp/runtime notes.md"' }));
    notGuard(ev({ nativeTool: "Bash", command: 'cat "how-to-rm-nmzp-runtime.md"' }));
    notGuard(ev({ nativeTool: "Bash", command: 'echo "rm -rf ~/.nmzp/runtime"' }));
    notGuard(ev({ nativeTool: "Bash", command: 'echo "systemctl stop nmzp"' }));
    notGuard(ev({ nativeTool: "Bash", command: "Write-Output 'pkill nmzp-probe'" }));
    notGuard(ev({ nativeTool: "Bash", command: "Get-Content C:\\Users\\dev\\.nmzp\\credentials.json" }));
  });

  it("still blocks the actual mutating verb with a protected operand", () => {
    const rm = ev({ nativeTool: "Bash", command: "rm -rf ~/.nmzp/runtime" });
    assert.equal(rm.decision, "block");
    assert.equal(rm.rule?.id, "isolate_delete_binary");
  });
});

describe("write target flags vs value/content", () => {
  it("does not treat a protected path in -Value as the write target", () => {
    notGuard(
      ev({
        nativeTool: "Bash",
        command:
          "Set-Content -Path C:\\Users\\dev\\Desktop\\NMZP\\nmzp-monitor\\notes.md -Value C:\\Users\\dev\\.nmzp\\runtime\\x",
      }),
    );
  });

  it("blocks when -Path itself is the installed object", () => {
    const r = ev({
      nativeTool: "Bash",
      command: "Set-Content -Path C:\\Users\\dev\\.nmzp\\runtime\\0.1.0\\x.txt -Value pwn",
    });
    assert.equal(r.decision, "block");
    assert.equal(r.rule?.id, "monitor_self_tamper_cmd");
  });
});

describe("Force switch does not consume the next target", () => {
  it("still blocks Remove-Item -Force of the install dir", () => {
    const r = ev({ nativeTool: "Bash", command: "Remove-Item -Force ~/.nmzp/runtime" });
    assert.equal(r.decision, "block");
    assert.equal(r.rule?.id, "isolate_delete_binary");
  });

  it("allows copy from installed file to a normal backup with -Force", () => {
    notGuard(
      ev({
        nativeTool: "Bash",
        command: "Copy-Item -Force ~/.nmzp/credentials.json C:\\backup\\credentials.json",
      }),
    );
    notGuard(
      ev({
        nativeTool: "Bash",
        command: "Copy-Item ~/.nmzp/credentials.json -Force C:\\backup\\out.json",
      }),
    );
  });
});

describe("exact service/process names, not prefixes or quoted docs", () => {
  it("blocks exact nmzp stop/kill and allows nmzp-test / quoted documentation", () => {
    const unit = ev({ nativeTool: "Bash", command: "systemctl stop nmzp" });
    assert.equal(unit.decision, "block");
    assert.equal(unit.rule?.id, "isolate_stop_container");
    assert.equal(unit.threat, "isolate");

    const sudo = ev({ nativeTool: "Bash", command: "sudo systemctl stop nmzp" });
    assert.equal(sudo.decision, "block");
    assert.equal(sudo.rule?.id, "isolate_stop_container");

    const svc = ev({ nativeTool: "Bash", command: "systemctl stop nmzp.service" });
    assert.equal(svc.decision, "block");

    notGuard(ev({ nativeTool: "Bash", command: "systemctl stop nmzp-test" }));
    notGuard(ev({ nativeTool: "Bash", command: "docker stop nmzp-test" }));

    const dock = ev({ nativeTool: "Bash", command: "docker stop nmzp" });
    assert.equal(dock.decision, "block");
    assert.equal(dock.rule?.id, "isolate_stop_container");

    const probe = ev({ nativeTool: "Bash", command: "pkill nmzp-probe" });
    assert.equal(probe.decision, "block");
    assert.equal(probe.rule?.id, "isolate_kill_monitor");

    notGuard(ev({ nativeTool: "Bash", command: "pkill nmzp-monitor-test" }));
    notGuard(ev({ nativeTool: "Bash", command: 'echo "systemctl stop nmzp"' }));
    notGuard(ev({ nativeTool: "Bash", command: 'echo "pkill nmzp-probe"' }));

    const win = ev({ nativeTool: "Bash", command: "Stop-Service nmzp" });
    assert.equal(win.decision, "block");
    assert.equal(win.rule?.id, "isolate_stop_container");
  });
});

describe("localStorage is display cache, not tamper", () => {
  it("does not treat quoted JS removeItem as monitor tampering", () => {
    notGuard(ev({ nativeTool: "Bash", command: "localStorage.removeItem('nmzp-monitor')" }));
    notGuard(
      ev({
        nativeTool: "Bash",
        command: 'node -e "localStorage.removeItem(\'nmzp-monitor\')"',
      }),
    );
    notGuard(
      ev({
        nativeTool: "Write",
        filePath: "/home/max/work/nmzp-monitor/src/lib/monitor/store.ts",
        contents: "localStorage.removeItem('nmzp-monitor')",
      }),
    );
  });
});

describe("normal grok / build / source work is not self-tamper", () => {
  it("allows grok --cwd pointing at the source repo", () => {
    notGuard(
      ev({
        nativeTool: "run_terminal_command",
        command: "grok --cwd C:\\Users\\dev\\Desktop\\NMZP\\nmzp-monitor",
      }),
    );
    notGuard(ev({ nativeTool: "Bash", command: "grok --cwd /home/max/work/nmzp-monitor --help" }));
  });

  it("allows Get-Content, npm test/build, list/grep of install dirs", () => {
    notGuard(
      ev({
        nativeTool: "Bash",
        command: "Get-Content C:\\Users\\dev\\Desktop\\NMZP\\nmzp-monitor\\README.md",
      }),
    );
    notGuard(ev({ nativeTool: "Bash", command: "npm test" }));
    notGuard(ev({ nativeTool: "Bash", command: "npm run build" }));
    notGuard(ev({ nativeTool: "list_dir", filePath: "C:\\Users\\dev\\.nmzp\\runtime" }));
    notGuard(ev({ nativeTool: "Grep", filePath: "/home/max/.nmzp", command: "deviceId" }));
  });

  it("allows Write/Edit of source even when the body mentions protected paths", () => {
    const body = [
      "install to ~/.nmzp/runtime/0.1.0 and ~/.grok/hooks/nmzp.json",
      "rm ~/.nmzp/credentials.json",
      "systemctl stop nmzp",
      "localStorage.removeItem('nmzp-monitor')",
    ].join("\n");
    notGuard(
      ev({
        nativeTool: "Write",
        filePath: "C:\\Users\\dev\\Desktop\\NMZP\\nmzp-monitor\\src\\lib\\monitor\\engine.ts",
        contents: body,
        cwd: "C:\\Users\\dev\\Desktop\\NMZP\\nmzp-monitor",
      }),
    );
    notGuard(
      ev({
        nativeTool: "search_replace",
        filePath: "/home/max/work/nmzp-monitor/src/lib/monitor/rules.ts",
        contents: body,
      }),
    );
  });
});

describe("real install-object writes/deletes/stops still block", () => {
  it("blocks Write of runtime, credentials, manifest, dedicated hook, deploy paths", () => {
    for (const filePath of [
      "C:\\Users\\dev\\.nmzp\\runtime\\0.1.0\\engine.ts",
      "/home/max/.nmzp/credentials.json",
      "/home/max/.nmzp/manifest.json",
      "C:\\Users\\dev\\.grok\\hooks\\nmzp.json",
      "/opt/nmzp/nmzp.mjs",
      "/var/lib/nmzp/policy-cache.json",
    ]) {
      const r = ev({ nativeTool: "Write", filePath, contents: "x" });
      assert.equal(r.decision, "block");
      assert.equal(r.threat, "tamper");
      assert.equal(r.rule?.id, "monitor_self_tamper");
    }
  });

  it("blocks Set-Content / rm / Remove-Item of installed objects", () => {
    const hook = ev({
      nativeTool: "Bash",
      command: "Remove-Item -LiteralPath C:\\Users\\dev\\.grok\\hooks\\nmzp.json",
    });
    assert.equal(hook.decision, "block");
    assert.equal(hook.rule?.id, "isolate_delete_binary");
  });

  it("blocks relative write when cwd is the home install dir", () => {
    const r = ev({
      nativeTool: "Write",
      filePath: "runtime/0.1.0/nmzp.mjs",
      cwd: "C:\\Users\\dev\\.nmzp",
      contents: "x",
    });
    assert.equal(r.decision, "block");
    assert.equal(r.rule?.id, "monitor_self_tamper");
  });

  it("does not treat obfuscated or variable-only commands as confirmed tamper", () => {
    const hit = detectSelfProtection({
      tool: "Bash",
      command: "node -e \"require('fs').rmSync(process.env.HOME+'/.nmzp/runtime',{recursive:true})\"",
    });
    assert.equal(hit, undefined);
    notGuard(
      ev({
        nativeTool: "Bash",
        command: "$p = Join-Path $env:USERPROFILE '.nmzp'; Remove-Item $p",
      }),
    );
    notGuard(ev({ nativeTool: "Bash", command: "Get-Content ~/.nmzp/credentials.json > /tmp/out.txt" }));
    notGuard(ev({ nativeTool: "Bash", command: "Copy-Item ~/.nmzp/credentials.json /tmp/out.json" }));
  });
});
