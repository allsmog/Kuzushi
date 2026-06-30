import {
  TermFrame,
  StatusStrip,
  SectionHeader,
  Row,
  Glyph,
  LogLine,
  SeverityBadge,
  Footer,
} from "@kuzushi/tui-kit";

// The hero: a full sast scan screen composed from every primitive.
export function ScanScreen() {
  return (
    <TermFrame title="kuzushi · sast" cols={100}>
      <StatusStrip
        target="~/work/acme-checkout"
        ctx="fresh"
        module="sast"
        cost="$0.41"
        cols={100}
      />
      <Row> </Row>
      <SectionHeader label="SCAN · semgrep + agentic-sast" cols={100} />
      <LogLine kind="run" time="14:31:55">
        {" sast:scan · tasks "}
        <Glyph tone="accent">semgrep, secrets</Glyph>
        {" · triage on"}
      </LogLine>
      <LogLine kind="ok" time="14:32:40">
        {" semgrep · 612/612 · "}
        <Glyph tone="success">done</Glyph>
      </LogLine>
      <LogLine kind="agent" time="14:33:42">
        {" two CRITICALs share a sink — "}
        <Glyph tone="accent">F-0001</Glyph>
        {" and "}
        <Glyph tone="accent">F-0002</Glyph>
        {" both end at "}
        <Glyph tone="warn">orders.rs:142</Glyph>
      </LogLine>
      <LogLine kind="find" time="14:33:42">
        {" "}
        <Glyph tone="primary">F-0012</Glyph>
        {" · "}
        <SeverityBadge level="critical" />
        {" · refund-bot.ts:127"}
      </LogLine>
      <Row> </Row>
      <Footer
        stage="sast:scan · agentic 73%"
        findings={11}
        module="sast"
        keybinds={[
          { key: "/findings", hint: "browse" },
          { key: "/open", hint: "F-0001" },
          { key: "/use", hint: "verify" },
        ]}
        cols={100}
      />
    </TermFrame>
  );
}

// A findings list view with the j/k cursor on the first row.
export function FindingsList() {
  return (
    <TermFrame title="kuzushi · findings" cols={112}>
      <StatusStrip target="~/work/acme-checkout" module="findings" cost="$0.41" cols={112} />
      <Row> </Row>
      <SectionHeader label="FINDINGS · 11 triaged · 7 pending" cols={112} />
      <Row selected cols={112}>
        {"  ▌ F-0001  CRITICAL  sql injection via order_id concat      orders.rs:142"}
      </Row>
      <Row cols={112}>
        {"    "}
        <Glyph tone="accent">F-0002</Glyph>
        {"  "}
        <SeverityBadge level="critical" />
        {"  prompt-injection — model reads body   concierge.ts:88"}
      </Row>
      <Row cols={112}>
        {"    "}
        <Glyph tone="accent">F-0007</Glyph>
        {"  "}
        <SeverityBadge level="high" />
        {"  ssrf via unvalidated webhook url       hooks.rs:54"}
      </Row>
      <Row cols={112}>
        {"    "}
        <Glyph tone="accent">F-0012</Glyph>
        {"  "}
        <SeverityBadge level="medium" />
        {"  weak jwt signing secret                auth.ts:31"}
      </Row>
    </TermFrame>
  );
}

// The chromeless variant — an embedded panel with no window controls.
export function Chromeless() {
  return (
    <TermFrame chromeless cols={100}>
      <StatusStrip target="~/scan/payments-api" ctx="fresh" module="recon" cost="$0.08" cols={100} />
      <Row> </Row>
      <LogLine kind="log" time="09:12:03">
        {" embedded panel — no window chrome"}
      </LogLine>
      <LogLine kind="ok" time="09:12:04">
        {" httpx · 240 hosts · "}
        <Glyph tone="success">live</Glyph>
      </LogLine>
    </TermFrame>
  );
}
