import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  adaptSnapshotGuardLibraryStatus,
  parseSnapshotGuardReport,
  type SnapshotGuardReport,
} from "./schema.ts";

function valid(p: Partial<SnapshotGuardReport> = {}): Record<string, unknown> {
  return {
    supported: true,
    active: false,
    managed: false,
    targetPresent: true,
    writeBlocked: true,
    existingArchiveCoverage: "none",
    lastVerified: 1_700_000_000_000,
    ...p,
  };
}

describe("parseSnapshotGuardReport", () => {
  it("keeps only public keys and drops nested/unknown fields", () => {
    const p = parseSnapshotGuardReport({
      ...valid({ active: true, managed: true, existingArchiveCoverage: "protected" }),
      zcodeRunning: true,
      sddl: "O:BAG:SYD:(A;;FA;;;WD)",
      paths: ["C:\\Users\\u\\.zcode\\v2\\checkpoints"],
      nested: { target: "C:\\secret", aces: [{ sid: "S-1-5-21" }] },
    });
    assert.ok(p);
    assert.equal(p!.active, true);
    assert.equal(p!.existingArchiveCoverage, "protected");
    assert.equal("zcodeRunning" in p!, false);
    assert.equal("sddl" in p!, false);
    assert.equal("paths" in p!, false);
    assert.equal("nested" in p!, false);
    assert.equal(JSON.stringify(p).includes("S-1-5"), false);
    assert.equal(JSON.stringify(p).includes(".zcode"), false);
  });

  it("rejects wrong types, negative lastVerified, and inconsistent active", () => {
    assert.equal(parseSnapshotGuardReport(null), undefined);
    assert.equal(parseSnapshotGuardReport([]), undefined);
    assert.equal(parseSnapshotGuardReport(valid({ supported: "yes" as unknown as boolean })), undefined);
    assert.equal(parseSnapshotGuardReport(valid({ lastVerified: -1 })), undefined);
    assert.equal(parseSnapshotGuardReport(valid({ lastVerified: Number.NaN })), undefined);
    assert.equal(parseSnapshotGuardReport(valid({ lastVerified: Number.POSITIVE_INFINITY })), undefined);
    assert.equal(parseSnapshotGuardReport(valid({ existingArchiveCoverage: "unprotected" as never })), undefined);
    assert.equal(
      parseSnapshotGuardReport(valid({ active: true, writeBlocked: true, existingArchiveCoverage: "partial" })),
      undefined,
    );
    assert.equal(
      parseSnapshotGuardReport(valid({ active: true, writeBlocked: true, existingArchiveCoverage: "unknown" })),
      undefined,
    );
    assert.equal(parseSnapshotGuardReport(valid({ active: true, supported: false, writeBlocked: true })), undefined);
    assert.equal(parseSnapshotGuardReport(valid({ active: true, writeBlocked: false, existingArchiveCoverage: "none" })), undefined);
    assert.equal(parseSnapshotGuardReport(valid({ active: true, managed: false, existingArchiveCoverage: "none" })), undefined);
    assert.equal(parseSnapshotGuardReport(valid({ active: true, managed: true, targetPresent: false, existingArchiveCoverage: "none" })), undefined);
    assert.equal(parseSnapshotGuardReport(valid({ active: true, managed: true, lastVerified: 0, existingArchiveCoverage: "none" })), undefined);
    assert.equal(
      parseSnapshotGuardReport(valid({ active: true, managed: true, existingArchiveCoverage: "none", error: "apply_failed" })),
      undefined,
    );
    assert.equal(parseSnapshotGuardReport(valid({ error: "O:BAG:SYD:(A;;FA;;;WD)" })), undefined);
    assert.equal(parseSnapshotGuardReport(valid({ error: "C:\\\\Users\\\\u\\\\.zcode" })), undefined);
  });

  it("accepts short error codes and coverage none/protected with active", () => {
    const none = parseSnapshotGuardReport(valid({ active: true, managed: true, existingArchiveCoverage: "none" }));
    assert.ok(none);
    assert.equal(none!.active, true);
    const err = parseSnapshotGuardReport(valid({ error: "external_restriction", writeBlocked: true, active: false }));
    assert.ok(err);
    assert.equal(err!.error, "external_restriction");
    assert.equal(err!.active, false);
  });

  it("maps library unprotected coverage without leaking private keys", () => {
    const mapped = adaptSnapshotGuardLibraryStatus({
      supported: true,
      active: false,
      managed: false,
      targetPresent: true,
      writeBlocked: false,
      existingArchiveCoverage: "unprotected",
      zcodeRunning: false,
      lastVerified: 9,
    });
    assert.ok(mapped);
    assert.equal(mapped!.existingArchiveCoverage, "partial");
    assert.equal(mapped!.active, false);
    assert.equal("zcodeRunning" in mapped!, false);
  });

  it("does not fabricate lastVerified; missing verification is 0 + not_verified", () => {
    const before = Date.now();
    const mapped = adaptSnapshotGuardLibraryStatus({
      supported: true,
      active: true,
      managed: true,
      targetPresent: true,
      writeBlocked: true,
      existingArchiveCoverage: "protected",
    });
    const after = Date.now();
    assert.ok(mapped);
    assert.equal(mapped!.lastVerified, 0);
    assert.equal(mapped!.active, false);
    assert.equal(mapped!.error, "not_verified");
    assert.equal(mapped!.lastVerified >= before && mapped!.lastVerified <= after, false);
  });
});
