import { TermFrame, Row, Glyph, SeverityBadge } from "@kuzushi/tui-kit";

// Plain console rows — the unit the transcript grows by.
export function Plain() {
  return (
    <TermFrame chromeless cols={72}>
      <Row cols={72}>{" target  ~/work/acme-checkout"}</Row>
      <Row cols={72}>{" ctx     fresh · 3 files reparsed"}</Row>
      <Row cols={72}>{" model   openai:gpt-4.1"}</Row>
    </TermFrame>
  );
}

// The selected row — the j/k cursor highlight (inverse accent), full width.
export function Selected() {
  return (
    <TermFrame chromeless cols={72}>
      <Row cols={72}>
        {"   "}
        <Glyph tone="accent">F-0002</Glyph>
        {"  prompt-injection — concierge.ts:88"}
      </Row>
      <Row selected cols={72}>
        {"  ▌ F-0001  CRITICAL  sql injection   orders.rs:142"}
      </Row>
      <Row cols={72}>
        {"   "}
        <Glyph tone="accent">F-0007</Glyph>
        {"  ssrf via webhook url — hooks.rs:54"}
      </Row>
    </TermFrame>
  );
}

// A finding row composed from Glyph + SeverityBadge spans.
export function FindingRow() {
  return (
    <TermFrame chromeless cols={72}>
      <Row cols={72}>
        {" "}
        <Glyph tone="primary">F-0012</Glyph>
        {" · "}
        <SeverityBadge level="critical" />
        {" · model reads "}
        <Glyph tone="warn">review.body</Glyph>
        {" in sysmsg"}
      </Row>
      <Row tone="muted" cols={72}>
        {"        canonical $-loss shape · refund tool reachable"}
      </Row>
    </TermFrame>
  );
}
