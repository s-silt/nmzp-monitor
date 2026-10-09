import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { it } from "node:test";
import { CT_BREAKER_OPEN_MS } from "./constants.ts";
import {
  CLOSED_BREAKER,
  applyHttpStatus,
  breakerPath,
  effectOfHttpStatus,
  nextAfterConnectFailure,
  readBreaker,
  shouldSkipCt,
} from "./ct-breaker.ts";

it("breaker invariant: third connect failure opens", () => {
  const now = 1_000_000;
  let state = CLOSED_BREAKER;
  state = nextAfterConnectFailure(state, now);
  assert.equal(shouldSkipCt(state, now), false);
  state = nextAfterConnectFailure(state, now);
  assert.equal(shouldSkipCt(state, now), false);
  state = nextAfterConnectFailure(state, now);
  assert.equal(shouldSkipCt(state, now), true);
  assert.equal(state.openUntil, now + CT_BREAKER_OPEN_MS);
});

it("breaker invariant: http 5xx resets", () => {
  const now = 5_000;
  let state = CLOSED_BREAKER;
  state = nextAfterConnectFailure(state, now);
  state = nextAfterConnectFailure(state, now);
  state = nextAfterConnectFailure(state, now);
  assert.equal(shouldSkipCt(state, now), true);
  assert.equal(effectOfHttpStatus(500), "reset");
  assert.equal(effectOfHttpStatus(503), "reset");
  const next = applyHttpStatus(state, 500, now);
  assert.deepEqual(next, CLOSED_BREAKER);
  assert.equal(shouldSkipCt(next, now), false);
});

it("breaker invariant: corrupt file is closed", async () => {
  const home = await mkdtemp(join(tmpdir(), "nmzp-ct-inv-"));
  try {
    const now = Date.now();
    const path = breakerPath(home);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, "{", "utf8");
    const state = readBreaker(home, now);
    assert.deepEqual(state, CLOSED_BREAKER);
    assert.equal(shouldSkipCt(state, now), false);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});
