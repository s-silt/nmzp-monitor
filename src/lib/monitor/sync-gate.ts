export type SyncGate = {
  begin: () => number;
  noteMutation: () => void;
  accept: (token: number) => boolean;
};

export function createSyncGate(): SyncGate {
  let latestToken = 0;
  let mutationEpoch = 0;
  let epochAtLatestBegin = 0;

  return {
    begin(): number {
      latestToken += 1;
      epochAtLatestBegin = mutationEpoch;
      return latestToken;
    },
    noteMutation(): void {
      mutationEpoch += 1;
    },
    accept(token: number): boolean {
      const latest = token === latestToken && token !== 0;
      const epochMatches = epochAtLatestBegin === mutationEpoch;
      return latest && epochMatches;
    },
  };
}
