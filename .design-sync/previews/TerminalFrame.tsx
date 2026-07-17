import {
  PhasePrompt,
  PhaseRail,
  TerminalFrame,
} from "@kuzushi/tui-kit";

export const A_CurrentShellFrame = () => (
  <TerminalFrame title="kuzushi · review" cols={80} rows={24}>
    <div>KUZUSHI · VIEW REVIEW · target:./Kuzushi · ○ idle · ctx:✓ built</div>
    <PhaseRail
      current="review"
      statuses={{ map: "done", scan: "done", review: "current", prove: "pending", fix: "pending" }}
    />
    <div>▸ NEXT record terminal dispositions for 5 remaining candidates</div>
    <div>Review owns the queue and selected finding; exact evidence opens in Prove.</div>
    <PhasePrompt phase="review" placeholder="describe what to review" />
  </TerminalFrame>
);

export const B_NarrowFallbackFrame = () => (
  <TerminalFrame title="kuzushi · map" cols={40} rows={12}>
    <div>KUZUSHI · VIEW MAP · REALITY MAP</div>
    <div>▸ NEXT build target context</div>
    <div>│▸ PROJECT CONTEXT</div>
    <div>│./Kuzushi · rev:ccb29fa</div>
    <div>│context:not built</div>
    <PhasePrompt phase="map" mode="navigate" />
  </TerminalFrame>
);
