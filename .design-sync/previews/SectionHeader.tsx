import { TermFrame, SectionHeader, Row, Glyph } from "@kuzushi/tui-kit";

// A header grouping the console output beneath it.
export function Default() {
  return (
    <TermFrame chromeless cols={72}>
      <SectionHeader label="FINDINGS · 11 triaged · 7 pending" cols={72} />
      <Row cols={72}>
        {"   "}
        <Glyph tone="accent">F-0001</Glyph>
        {"  CRITICAL  sql injection   orders.rs:142"}
      </Row>
      <Row cols={72}>
        {"   "}
        <Glyph tone="accent">F-0002</Glyph>
        {"  CRITICAL  prompt-injection   concierge.ts:88"}
      </Row>
    </TermFrame>
  );
}

// Several headers — the dividers that structure a scan transcript.
export function Sections() {
  return (
    <TermFrame chromeless cols={72}>
      <SectionHeader label="SCAN" cols={72} />
      <Row cols={72}>{"   semgrep · 612/612 · done"}</Row>
      <SectionHeader label="TRIAGE · 18 candidates" cols={72} />
      <Row cols={72}>{"   11 kept · 7 dismissed"}</Row>
      <SectionHeader label="VERIFY" cols={72} />
      <Row cols={72}>{"   2 confirmed exploitable"}</Row>
    </TermFrame>
  );
}
