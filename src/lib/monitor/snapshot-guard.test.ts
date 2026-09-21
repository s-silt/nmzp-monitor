import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { t } from "./i18n.ts";
import {
  SNAPSHOT_CLOCK_SKEW_MS,
  SNAPSHOT_STALE_MS,
  buildSnapshotView,
  parseSnapshotGuard,
  snapshotHosts,
} from "./snapshot-guard.ts";

function ext(over: Record<string, unknown> = {}) {
  return {
    supported: true,
    active: false,
    managed: false,
    targetPresent: true,
    writeBlocked: true,
    existingArchiveCoverage: "unknown",
    error: "external_restriction",
    lastVerified: 1_700_000_000_000,
    ...over,
  };
}

function owned(over: Record<string, unknown> = {}) {
  return {
    supported: true,
    active: true,
    managed: true,
    targetPresent: true,
    writeBlocked: true,
    existingArchiveCoverage: "protected",
    lastVerified: 1_700_000_000_000,
    ...over,
  };
}

describe("parseSnapshotGuard", () => {
  it("treats missing as not collected, not active", () => {
    assert.equal(parseSnapshotGuard(undefined).status, "missing");
    assert.equal(parseSnapshotGuard(null).status, "missing");
  });

  it("rejects illegal objects and non-string error instead of ignoring them", () => {
    assert.equal(parseSnapshotGuard([]).status, "invalid");
    assert.equal(parseSnapshotGuard("yes").status, "invalid");
    assert.equal(parseSnapshotGuard({ supported: true }).status, "invalid");
    assert.equal(parseSnapshotGuard(ext({ error: { code: 1 } })).status, "invalid");
    assert.equal(parseSnapshotGuard(ext({ error: 500 })).status, "invalid");
    const noActive = parseSnapshotGuard({
      supported: true,
      managed: true,
      targetPresent: true,
      writeBlocked: true,
      existingArchiveCoverage: "protected",
      lastVerified: 1,
    });
    assert.equal(noActive.status, "invalid");
    const parsed = parseSnapshotGuard(ext({ active: false }));
    assert.equal(parsed.status, "ok");
    if (parsed.status === "ok") assert.equal(parsed.guard.active, false);
  });

  it("rejects active=true unless the full confirmation set is present", () => {
    assert.equal(parseSnapshotGuard(owned({ supported: false })).status, "invalid");
    assert.equal(parseSnapshotGuard(owned({ managed: false })).status, "invalid");
    assert.equal(parseSnapshotGuard(owned({ targetPresent: false })).status, "invalid");
    assert.equal(parseSnapshotGuard(owned({ writeBlocked: false })).status, "invalid");
    assert.equal(parseSnapshotGuard(owned({ existingArchiveCoverage: "unknown" })).status, "invalid");
    assert.equal(parseSnapshotGuard(owned({ existingArchiveCoverage: "partial" })).status, "invalid");
    assert.equal(parseSnapshotGuard(owned({ lastVerified: 0 })).status, "invalid");
    assert.equal(parseSnapshotGuard(owned({ error: "timeout" })).status, "invalid");
    const good = parseSnapshotGuard(owned());
    assert.equal(good.status, "ok");
    if (good.status === "ok") assert.equal(good.guard.active, true);
    const none = parseSnapshotGuard(owned({ existingArchiveCoverage: "none" }));
    assert.equal(none.status, "ok");
  });

  it("rejects SDDL or path-like error strings", () => {
    assert.equal(parseSnapshotGuard(ext({ error: "D:(A;;FA;;;BA)" })).status, "invalid");
    assert.equal(parseSnapshotGuard(ext({ error: "C:\\Users\\max\\.zcode\\checkpoints" })).status, "invalid");
  });
});

describe("snapshot display facts", () => {
  it("shows external restriction without claiming NMZP install or full coverage", () => {
    const state = parseSnapshotGuard(ext());
    const view = buildSnapshotView(state, "online", 1_700_000_010_000);
    assert.equal(view.write.key, "sgWriteLimited");
    assert.equal(view.coverage.key, "sgCoverageUnknown");
    assert.equal(view.provenance.key, "sgProvenanceExternal");
    assert.notEqual(view.coverage.tone, "ok");
    assert.notEqual(view.provenance.key, "sgProvenanceNmzp");
    const zh = `${t("zh", view.write.key)}；${t("zh", view.coverage.key)}；${t("zh", view.provenance.key)}`;
    assert.equal(zh, "新快照写入已限制；旧包覆盖未确认；已有外部限制");
  });

  it("does not paint none/partial/unknown coverage as full protection", () => {
    const none = buildSnapshotView(parseSnapshotGuard(owned({ existingArchiveCoverage: "none" })), "online", 1_700_000_010_000);
    assert.equal(none.coverage.key, "sgCoverageNone");
    assert.equal(none.coverage.tone, "muted");
    const partial = buildSnapshotView(
      parseSnapshotGuard(ext({ existingArchiveCoverage: "partial", error: undefined })),
      "online",
      1_700_000_010_000,
    );
    assert.equal(partial.coverage.tone, "warn");
    const unknown = buildSnapshotView(parseSnapshotGuard(ext()), "online", 1_700_000_010_000);
    assert.notEqual(unknown.coverage.tone, "ok");
  });

  it("does not show protected coverage as green when unsupported, failed, unverified, or target missing", () => {
    const now = 1_700_000_010_000;
    const unsupported = buildSnapshotView(
      parseSnapshotGuard(ext({ supported: false, error: "unsupported_platform", existingArchiveCoverage: "protected", writeBlocked: false })),
      "online",
      now,
    );
    assert.notEqual(unsupported.coverage.tone, "ok");
    assert.notEqual(unsupported.coverage.key, "sgCoverageProtected");
    const failed = buildSnapshotView(
      parseSnapshotGuard(ext({ error: "status_failed", existingArchiveCoverage: "protected", writeBlocked: false })),
      "online",
      now,
    );
    assert.notEqual(failed.coverage.tone, "ok");
    const timeout = buildSnapshotView(
      parseSnapshotGuard(ext({ error: "timeout", existingArchiveCoverage: "protected", writeBlocked: false })),
      "online",
      now,
    );
    assert.notEqual(timeout.coverage.tone, "ok");
    const denied = buildSnapshotView(
      parseSnapshotGuard(ext({ error: "access_denied", existingArchiveCoverage: "protected", writeBlocked: false })),
      "online",
      now,
    );
    assert.notEqual(denied.coverage.tone, "ok");
    const reparse = buildSnapshotView(
      parseSnapshotGuard(ext({ error: "reparse_rejected", existingArchiveCoverage: "protected", writeBlocked: false })),
      "online",
      now,
    );
    assert.notEqual(reparse.coverage.tone, "ok");
    const missing = buildSnapshotView(
      parseSnapshotGuard(ext({ targetPresent: false, error: "target_missing", existingArchiveCoverage: "protected", writeBlocked: false })),
      "online",
      now,
    );
    assert.notEqual(missing.coverage.tone, "ok");
    const never = buildSnapshotView(
      parseSnapshotGuard(ext({ lastVerified: 0, error: "not_verified", existingArchiveCoverage: "protected", writeBlocked: false })),
      "online",
      now,
    );
    assert.notEqual(never.coverage.tone, "ok");
    const covUnknown = buildSnapshotView(
      parseSnapshotGuard(ext({ error: "coverage_unknown", existingArchiveCoverage: "protected", writeBlocked: false })),
      "online",
      now,
    );
    assert.notEqual(covUnknown.coverage.tone, "ok");
    assert.equal(failed.errorKey, "sgErrorGeneric");
  });

  it("keeps last confirmation when host is dark, lastVerified is stale, or lastVerified is far in the future", () => {
    const state = parseSnapshotGuard(owned());
    const dark = buildSnapshotView(state, "dark", 1_700_000_010_000);
    assert.equal(dark.stale, true);
    assert.equal(dark.write.tone, "stale");
    assert.notEqual(dark.coverage.tone, "ok");
    const stale = buildSnapshotView(state, "online", 1_700_000_000_000 + SNAPSHOT_STALE_MS + 1);
    assert.equal(stale.stale, true);
    assert.notEqual(stale.write.tone, "ok");
    const future = buildSnapshotView(state, "online", 1_700_000_000_000 - 60 * 60 * 1000);
    assert.equal(future.stale, true);
    assert.notEqual(future.coverage.tone, "ok");
    const skew = buildSnapshotView(ownedState(), "online", 1_700_000_000_000 - SNAPSHOT_CLOCK_SKEW_MS / 2);
    assert.equal(skew.stale, false);
    assert.equal(skew.coverage.tone, "ok");
  });

  it("marks target_missing / unsupported / failed / not_verified explicitly", () => {
    const missing = buildSnapshotView(
      parseSnapshotGuard(ext({ active: false, targetPresent: false, error: "target_missing", writeBlocked: false })),
      "online",
      1_700_000_010_000,
    );
    assert.equal(missing.write.key, "sgTargetMissing");
    const uns = buildSnapshotView(
      parseSnapshotGuard(ext({ supported: false, error: "unsupported_platform", writeBlocked: false })),
      "online",
      1_700_000_010_000,
    );
    assert.equal(uns.write.key, "sgUnsupported");
    const failed = buildSnapshotView(
      parseSnapshotGuard(ext({ error: "status_failed", writeBlocked: false })),
      "online",
      1_700_000_010_000,
    );
    assert.equal(failed.write.key, "sgErrorGeneric");
    const never = buildSnapshotView(
      parseSnapshotGuard(ext({ lastVerified: 0, error: "not_verified", writeBlocked: false })),
      "online",
      1_700_000_010_000,
    );
    assert.equal(never.write.key, "sgNotVerified");
    assert.equal(never.lastVerified, 0);
  });

  it("does not treat a failed inspection as a missing target directory", () => {
    const now = 1_700_000_010_000;
    const inspectionFailed = {
      supported: true,
      active: false,
      managed: false,
      targetPresent: false,
      writeBlocked: false,
      existingArchiveCoverage: "unknown",
      lastVerified: 0,
    };
    for (const error of ["status_failed", "timeout"] as const) {
      const view = buildSnapshotView(parseSnapshotGuard({ ...inspectionFailed, error }), "online", now);
      assert.notEqual(view.write.key, "sgTargetMissing");
      assert.equal(view.write.key, "sgErrorGeneric");
      assert.notEqual(view.write.tone, "ok");
      assert.notEqual(view.coverage.tone, "ok");
      assert.notEqual(view.coverage.key, "sgCoverageProtected");
      assert.equal(view.lastVerified, 0);
      assert.notEqual(t("zh", view.write.key), t("zh", "sgTargetMissing"));
    }
    const missing = buildSnapshotView(
      parseSnapshotGuard({ ...inspectionFailed, error: "target_missing" }),
      "online",
      now,
    );
    assert.equal(missing.write.key, "sgTargetMissing");
    const never = buildSnapshotView(
      parseSnapshotGuard({ ...inspectionFailed, error: "not_verified" }),
      "online",
      now,
    );
    assert.equal(never.write.key, "sgNotVerified");
    assert.notEqual(never.write.key, "sgTargetMissing");
    const knownDir = buildSnapshotView(parseSnapshotGuard(ext()), "online", now);
    assert.equal(knownDir.write.key, "sgWriteLimited");
    assert.notEqual(knownDir.write.tone, "muted");
    assert.equal(knownDir.coverage.key, "sgCoverageUnknown");
    assert.equal(knownDir.provenance.key, "sgProvenanceExternal");
  });

  it("does not invent hosts from an empty list, and does not leak another device", () => {
    assert.deepEqual(snapshotHosts([], "all"), []);
    const rows = snapshotHosts(
      [
        { id: "dev_a", hostname: "a" },
        { id: "dev_b", hostname: "b" },
      ],
      "dev_b",
    );
    assert.equal(rows.length, 1);
    assert.equal(rows[0]?.id, "dev_b");
  });
});

function ownedState() {
  return parseSnapshotGuard(owned());
}
