import { TermFrame, Row, Glyph } from "@kuzushi/tui-kit";

// The 8-role text theme — every semantic tone the kit exposes.
export function Tones() {
  return (
    <TermFrame chromeless cols={64}>
      <Row cols={64}>
        {" "}
        <Glyph tone="heading">heading</Glyph>
        {"  "}
        <Glyph tone="primary">primary</Glyph>
        {"  "}
        <Glyph tone="label">label</Glyph>
        {"  "}
        <Glyph tone="accent">accent</Glyph>
      </Row>
      <Row cols={64}>
        {" "}
        <Glyph tone="muted">muted</Glyph>
        {"    "}
        <Glyph tone="subtle">subtle</Glyph>
        {"   "}
        <Glyph tone="success">success</Glyph>
        {"  "}
        <Glyph tone="warn">warn</Glyph>
        {"  "}
        <Glyph tone="danger">danger</Glyph>
      </Row>
    </TermFrame>
  );
}

// The console line glyphs — each kind's status marker in its tone.
export function StatusGlyphs() {
  return (
    <TermFrame chromeless cols={64}>
      <Row cols={64}>
        {" "}
        <Glyph tone="accent">●</Glyph>
        {" in   "}
        <Glyph tone="primary">⏵</Glyph>
        {" run   "}
        <Glyph tone="success">✓</Glyph>
        {" ok   "}
        <Glyph tone="danger">✗</Glyph>
        {" err"}
      </Row>
      <Row cols={64}>
        {" "}
        <Glyph tone="accent">◆</Glyph>
        {" agent "}
        <Glyph tone="muted">…</Glyph>
        {" flow "}
        <Glyph tone="warn">▸</Glyph>
        {" find "}
        <Glyph tone="subtle">·</Glyph>
        {" log"}
      </Row>
    </TermFrame>
  );
}

// Inline emphasis — finding ids and file:line citations inside prose.
export function InlineEmphasis() {
  return (
    <TermFrame chromeless cols={64}>
      <Row cols={64}>
        {" two CRITICALs share a sink — "}
        <Glyph tone="accent">F-0001</Glyph>
      </Row>
      <Row cols={64}>
        {" both end at "}
        <Glyph tone="warn">orders.rs:142</Glyph>
      </Row>
    </TermFrame>
  );
}
