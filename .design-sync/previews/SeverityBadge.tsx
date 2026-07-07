import { TermFrame, Row, Glyph, SeverityBadge } from "@kuzushi/tui-kit";

// The full severity scale — the primary variant axis.
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
