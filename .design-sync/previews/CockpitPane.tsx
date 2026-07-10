import { TermFrame, CockpitPane, ReviewQueueRow, Row, Glyph } from "@kuzushi/tui-kit";

// The focused FINDINGS pane — lit rail + title accent, holding the confidence-first
// review queue. The primary variant: what the operator's active pane looks like.
export function FocusedReviewQueue() {
  return (
    <TermFrame chromeless cols={76}>
      <CockpitPane title="REVIEW QUEUE · 3" focused>
        <ReviewQueueRow
          alias="F-0012"
          severity="critical"
          proof="confirmed"
          title="sql injection via order_id"
          decision="confirmed"
          decisionTone="success"
          selected
          cols={74}
        />
        <ReviewQueueRow
          alias="F-0007"
          severity="high"
          proof="likely"
          title="path traversal in export"
          decision="needs review"
          decisionTone="warn"
          cols={74}
        />
        <ReviewQueueRow
          alias="F-0031"
          severity="medium"
          proof="unverified"
          title="open redirect on login"
          cols={74}
        />
      </CockpitPane>
    </TermFrame>
  );
}

// An unfocused SOURCE pane — subtle rail, muted title, a file-tree of Rows. This is
// how the non-active tiles read while the operator works elsewhere in the workbench.
export function UnfocusedSourceTree() {
  return (
    <TermFrame chromeless cols={64}>
      <CockpitPane title="SOURCE · 42 files">
        <Row cols={62}>{" "}<Glyph tone="muted">src/</Glyph></Row>
        <Row cols={62}>{"   "}<Glyph tone="muted">refund-bot.ts</Glyph>{"  "}<Glyph tone="warn">▸ 2</Glyph></Row>
        <Row cols={62}>{"   "}<Glyph tone="muted">files.ts</Glyph>{"       "}<Glyph tone="warn">▸ 1</Glyph></Row>
        <Row cols={62}>{"   "}<Glyph tone="subtle">auth.ts</Glyph></Row>
        <Row cols={62}>{"   "}<Glyph tone="subtle">app.ts</Glyph></Row>
      </CockpitPane>
    </TermFrame>
  );
}

// The two states side by side — focus vs unfocused, the pane's primary axis, so the
// lit rail on the active pane reads against the calm rails of the rest of the grid.
export function FocusContrast() {
  return (
    <TermFrame chromeless cols={64}>
      <CockpitPane title="FINDINGS · 3" focused>
        <ReviewQueueRow alias="F-0012" severity="critical" proof="confirmed" title="auth bypass" selected cols={62} />
        <ReviewQueueRow alias="F-0007" severity="high" proof="likely" title="ssrf in webhook" cols={62} />
      </CockpitPane>
      <Row cols={64}>{" "}</Row>
      <CockpitPane title="DETAILS">
        <Row cols={62}>{" "}<Glyph tone="subtle">select a finding to inspect</Glyph></Row>
      </CockpitPane>
    </TermFrame>
  );
}
