import { TermFrame, Row, Glyph, SeverityBadge } from "@kuzushi/tui-kit";

// The full severity scale — the primary variant axis, including the info band.
export function Levels() {
  return (
    <TermFrame chromeless cols={64}>
      <Row cols={64}>
        {"  "}
        <SeverityBadge level="critical" />
        {"  "}
        <SeverityBadge level="high" />
        {"  "}
        <SeverityBadge level="medium" />
        {"  "}
        <SeverityBadge level="low" />
        {"  "}
        <SeverityBadge level="info" />
      </Row>
    </TermFrame>
  );
}

// Compact glyph mode — the single-letter form (C/H/M/L/I/?) the review queue
// falls back to in narrow rows. The whole scale plus the unknown band.
export function Glyphs() {
  return (
    <TermFrame chromeless cols={40}>
      <Row cols={40}>
        {"  "}
        <SeverityBadge level="critical" glyph />
        {" "}
        <SeverityBadge level="high" glyph />
        {" "}
        <SeverityBadge level="medium" glyph />
        {" "}
        <SeverityBadge level="low" glyph />
        {" "}
        <SeverityBadge level="info" glyph />
        {" "}
        <SeverityBadge level="unknown" glyph />
      </Row>
    </TermFrame>
  );
}

// In context — a finding line marked with its severity.
export function InFinding() {
  return (
    <TermFrame chromeless cols={72}>
      <Row cols={72}>
        {" "}
        <Glyph tone="primary">F-0001</Glyph>
        {" · "}
        <SeverityBadge level="critical" />
        {" · sql injection via order_id   orders.rs:142"}
      </Row>
      <Row cols={72}>
        {" "}
        <Glyph tone="primary">F-0021</Glyph>
        {" · "}
        <SeverityBadge level="low" label="LOW · accepted" />
        {" · verbose error page   app.ts:9"}
      </Row>
    </TermFrame>
  );
}
