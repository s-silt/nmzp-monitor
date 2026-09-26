export type HistoryBranch = "loading" | "error" | "empty" | "results";

export function historyViewState(input: {
  loading: boolean;
  error?: string | null;
  count: number;
}): HistoryBranch {
  if (input.loading) return "loading";
  if (input.error) return "error";
  if (input.count === 0) return "empty";
  return "results";
}
