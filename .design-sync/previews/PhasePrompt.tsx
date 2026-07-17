import { PhasePrompt, TerminalFrame } from "@kuzushi/tui-kit";

export const A_MapPrompt = () => (
  <TerminalFrame title="composer · map" cols={80} rows={6}>
    <PhasePrompt phase="map" placeholder="describe what to map" />
  </TerminalFrame>
);

export const B_ScanNavigateMode = () => (
  <TerminalFrame title="composer · scan" cols={80} rows={6}>
    <PhasePrompt phase="scan" mode="navigate" />
  </TerminalFrame>
);

export const C_FixIntent = () => (
  <TerminalFrame title="composer · fix" cols={80} rows={6}>
    <PhasePrompt phase="fix" value="draft the smallest patch for F-0001" />
  </TerminalFrame>
);
