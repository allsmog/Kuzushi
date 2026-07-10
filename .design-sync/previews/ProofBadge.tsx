import { TermFrame, Row, Glyph, ProofBadge } from "@kuzushi/tui-kit";

// The full confidence ladder — the primary variant axis. Confirmed (green) and
// Likely (blue) uppercase as strong bands; the honest lower bands stay lower-case.
export function Confidences() {
  return (
    <TermFrame chromeless cols={40}>
      <Row cols={40}>{"  "}<ProofBadge state="confirmed" /></Row>
      <Row cols={40}>{"  "}<ProofBadge state="likely" /></Row>
      <Row cols={40}>{"  "}<ProofBadge state="unverified" /></Row>
      <Row cols={40}>{"  "}<ProofBadge state="dismissed" /></Row>
    </TermFrame>
  );
}

// On finding rows — the confidence chip sits beside each finding so the ledger
// reads confirmed-vs-guess at a glance.
export function InFindings() {
  return (
    <TermFrame chromeless cols={76}>
      <Row cols={76}>
        {" "}<Glyph tone="accent">F-0012</Glyph>{"  "}
        <ProofBadge state="confirmed" label="CONFIRMED · runtime" />
        {"  sql injection   refund-bot.ts:127"}
      </Row>
      <Row cols={76}>
        {" "}<Glyph tone="accent">F-0007</Glyph>{"  "}
        <ProofBadge state="likely" label="LIKELY · source→sink" />
        {"  path traversal   files.ts:44"}
      </Row>
      <Row cols={76}>
        {" "}<Glyph tone="accent">F-0031</Glyph>{"  "}
        <ProofBadge state="unverified" />
        {"     open redirect   auth.ts:88"}
      </Row>
      <Row cols={76}>
        {" "}<Glyph tone="accent">F-0044</Glyph>{"  "}
        <ProofBadge state="dismissed" label="dismissed · by-design" />
        {"  verbose error   app.ts:9"}
      </Row>
    </TermFrame>
  );
}

// Glyph-only markers — the compact form for a dense list column.
export function Markers() {
  return (
    <TermFrame chromeless cols={40}>
      <Row cols={40}>
        {"  "}<ProofBadge state="confirmed" glyphOnly />{"  "}
        <ProofBadge state="likely" glyphOnly />{"  "}
        <ProofBadge state="unverified" glyphOnly />{"  "}
        <ProofBadge state="dismissed" glyphOnly />
      </Row>
    </TermFrame>
  );
}
