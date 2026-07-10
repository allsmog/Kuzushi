import { TermFrame, Row, MeterBar } from "@kuzushi/tui-kit";

// The auto-tone ramp, low end — well under 70% fill reads accent. The budget
// line early in a scan.
export function Accent() {
  return (
    <TermFrame chromeless cols={48}>
      <Row cols={48}>
        {" "}
        <MeterBar label="budget" value={0.42} max={2} width={16} readout="$0.42 / $2.00" />
      </Row>
    </TermFrame>
  );
}

// Mid ramp — coverage crossing 70% flips the fill to warn without any caller
// wiring.
export function Warn() {
  return (
    <TermFrame chromeless cols={48}>
      <Row cols={48}>
        {" "}
        <MeterBar label="coverage" value={9} max={12} width={16} readout="9 / 12 files" />
      </Row>
    </TermFrame>
  );
}

// Near-cap — 90%+ fill reads danger so the operator sees the budget running
// hot before it halts the run.
export function Danger() {
  return (
    <TermFrame chromeless cols={48}>
      <Row cols={48}>
        {" "}
        <MeterBar label="budget" value={1.9} max={2} width={16} readout="$1.90 / $2.00" />
      </Row>
    </TermFrame>
  );
}
