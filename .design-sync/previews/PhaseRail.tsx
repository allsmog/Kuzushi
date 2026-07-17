import { PhaseRail, TerminalFrame } from "@kuzushi/tui-kit";

export const A_ReviewIsCurrent = () => (
  <TerminalFrame title="journey · review" cols={80} rows={8}>
    <PhaseRail
      current="review"
      statuses={{ map: "done", scan: "done", review: "current", prove: "pending", fix: "pending" }}
    />
  </TerminalFrame>
);

export const B_PartialScanNeedsSelection = () => (
  <TerminalFrame title="journey · scan" cols={80} rows={8}>
    <PhaseRail
      current="scan"
      statuses={{ map: "done", scan: "current", review: "pending", prove: "pending", fix: "pending" }}
    />
  </TerminalFrame>
);

export const C_SkippedProveIsExplicit = () => (
  <TerminalFrame title="journey · fix" cols={80} rows={8}>
    <PhaseRail
      current="fix"
      statuses={{ map: "done", scan: "done", review: "done", prove: "skipped", fix: "current" }}
    />
  </TerminalFrame>
);
