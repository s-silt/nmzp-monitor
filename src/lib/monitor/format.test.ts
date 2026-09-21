import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { formatDateTime, formatTime } from "./format.ts";

const DASH = "—";
const LOCALES = ["zh", "en"] as const;

/** 2024-01-01 00:00:00Z → 08:00:00 UTC+8, same calendar day. */
const UTC_MIDNIGHT = Date.UTC(2024, 0, 1, 0, 0, 0);
/** 2024-01-01 16:00:00Z → 2024-01-02 00:00:00 UTC+8 (day rollover). */
const DAY_ROLLOVER = Date.UTC(2024, 0, 1, 16, 0, 0);
/** 2023-12-31 16:00:00Z → 2024-01-01 00:00:00 UTC+8 (year rollover). */
const YEAR_ROLLOVER = Date.UTC(2023, 11, 31, 16, 0, 0);
/** Seconds must appear on the full stamp. */
const WITH_SECONDS = Date.UTC(2024, 5, 15, 16, 5, 7);

describe("formatTime / formatDateTime UTC+8", () => {
  it("formats wall clock in fixed UTC+8 for both locales", () => {
    for (const locale of LOCALES) {
      assert.equal(formatTime(UTC_MIDNIGHT, locale), "08:00:00");
      assert.equal(formatDateTime(UTC_MIDNIGHT, locale), "2024-01-01 08:00:00");

      assert.equal(formatTime(DAY_ROLLOVER, locale), "00:00:00");
      assert.equal(formatDateTime(DAY_ROLLOVER, locale), "2024-01-02 00:00:00");

      assert.equal(formatTime(YEAR_ROLLOVER, locale), "00:00:00");
      assert.equal(formatDateTime(YEAR_ROLLOVER, locale), "2024-01-01 00:00:00");

      assert.equal(formatTime(WITH_SECONDS, locale), "00:05:07");
      assert.equal(formatDateTime(WITH_SECONDS, locale), "2024-06-16 00:05:07");
    }
  });

  it("returns em dash for nonfinite or non-positive timestamps and does not throw", () => {
    const bad = [NaN, Infinity, -Infinity, 0, -1, Number.NaN];
    for (const locale of LOCALES) {
      for (const ts of bad) {
        assert.equal(formatTime(ts, locale), DASH);
        assert.equal(formatDateTime(ts, locale), DASH);
      }
    }
  });

  it("returns em dash for finite values outside Date range after UTC+8 and does not throw", () => {
    const utc8 = 8 * 60 * 60 * 1000;
    const clip = 8.64e15;
    const justOutside = clip - utc8 + 1;
    const justInside = clip - utc8;
    for (const locale of LOCALES) {
      assert.doesNotThrow(() => {
        assert.equal(formatTime(1e100, locale), DASH);
        assert.equal(formatDateTime(1e100, locale), DASH);
        assert.equal(formatTime(Number.MAX_SAFE_INTEGER, locale), DASH);
        assert.equal(formatDateTime(Number.MAX_SAFE_INTEGER, locale), DASH);
        assert.equal(formatTime(clip, locale), DASH);
        assert.equal(formatDateTime(clip, locale), DASH);
        assert.equal(formatTime(justOutside, locale), DASH);
        assert.equal(formatDateTime(justOutside, locale), DASH);
        formatTime(justInside, locale);
        formatDateTime(justInside, locale);
      });
    }
  });

  it("sanitizes URL credentials and sensitive signature/token query parameters", async () => {
    const { sanitizeDisplayUrl } = await import("./format.ts");
    assert.equal(
      sanitizeDisplayUrl("curl https://user:secret123@example.com/file.tar.gz"),
      "curl https://example.com/file.tar.gz",
    );
    assert.equal(
      sanitizeDisplayUrl("curl https://bucket.oss-cn-hangzhou.aliyuncs.com/data?OSSAccessKeyId=LTAI123&Signature=abc123xyz"),
      "curl https://bucket.oss-cn-hangzhou.aliyuncs.com/data",
    );
    assert.equal(
      sanitizeDisplayUrl("https://s3.amazonaws.com/b/k.zip?X-Amz-Signature=def456"),
      "https://s3.amazonaws.com/b/k.zip",
    );
    assert.equal(sanitizeDisplayUrl(""), "");
  });
});
