import { TermFrame, AutonomyDial, Row, Glyph } from "@kuzushi/tui-kit";

// The four posture rungs, one per line — the primary axis. Each kanji is the rung's
// ceiling phase (組 recon · 崩 hunt · 作 confirm · 掛 fix); the gear ⛭ is constant.
export function Rungs() {
  return (
    <TermFrame chromeless cols={40}>
      <Row cols={40}>{"  "}<AutonomyDial rung="recon" /></Row>
      <Row cols={40}>{"  "}<AutonomyDial rung="hunt" /></Row>
      <Row cols={40}>{"  "}<AutonomyDial rung="confirm" /></Row>
      <Row cols={40}>{"  "}<AutonomyDial rung="fix" /></Row>
    </TermFrame>
  );
}

// The throttled marker — a trailing ⚠ warns the dial is capping the walker below the
// phase the engagement has actually reached. Shown against its un-throttled twin.
export function Throttled() {
  return (
    <TermFrame chromeless cols={40}>
      <Row cols={40}>{"  "}<AutonomyDial rung="recon" throttled /></Row>
      <Row cols={40}>{"  "}<AutonomyDial rung="hunt" throttled /></Row>
      <Row cols={40}>{"  "}<AutonomyDial rung="confirm" /></Row>
    </TermFrame>
  );
}

// In a footer-like line — the always-visible posture chip beside the phase chip, the
// way it rides the cockpit status row.
export function InFooter() {
  return (
    <TermFrame chromeless cols={56}>
      <Row cols={56}>
        {" "}<Glyph tone="muted">作 confirm 3/4</Glyph>
        {"   "}<AutonomyDial rung="fix" />
      </Row>
    </TermFrame>
  );
}
