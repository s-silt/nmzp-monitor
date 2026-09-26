import assert from "node:assert/strict";
import { it } from "node:test";
import { historyViewState } from "./history-view.ts";

it("error state never renders as empty results", () => {
  assert.equal(historyViewState({ loading: false, error: "network", count: 0 }), "error");
  assert.notEqual(
    historyViewState({ loading: false, error: "network", count: 0 }),
    "empty",
    "error state never renders as empty results",
  );
  assert.equal(historyViewState({ loading: false, error: "network", count: 3 }), "error");
});

it("history view precedence is loading, then error, then empty, then results", () => {
  const cases: Array<{
    loading: boolean;
    error?: string | null;
    count: number;
    want: "loading" | "error" | "empty" | "results";
  }> = [
    { loading: true, error: "boom", count: 0, want: "loading" },
    { loading: true, error: "boom", count: 3, want: "loading" },
    { loading: true, error: null, count: 0, want: "loading" },
    { loading: true, error: undefined, count: 2, want: "loading" },
    { loading: false, error: "boom", count: 0, want: "error" },
    { loading: false, error: "boom", count: 3, want: "error" },
    { loading: false, error: null, count: 0, want: "empty" },
    { loading: false, error: undefined, count: 0, want: "empty" },
    { loading: false, error: "", count: 0, want: "empty" },
    { loading: false, error: null, count: 1, want: "results" },
    { loading: false, error: undefined, count: 4, want: "results" },
  ];
  for (const row of cases) {
    assert.equal(
      historyViewState({ loading: row.loading, error: row.error, count: row.count }),
      row.want,
      `loading=${String(row.loading)} error=${String(row.error)} count=${row.count}`,
    );
  }
});
