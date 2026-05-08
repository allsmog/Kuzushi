export interface ResumeDiffData {
  previousRunDate?: string;
  previousFindingCount: number;
  previousTriagedCount: number;
  newFindings: number;
  skipped: number;
  pendingRetriage: number;
  verdictChanges: Array<{
    fingerprint: string;
    fromVerdict: string;
    toVerdict: string;
    reason?: string;
  }>;
}
