import { TermFrame, SectionHeader, ReviewQueueRow } from "@kuzushi/tui-kit";

// The confidence-first review queue: grouped by workflow band, one row selected.
// The primary story — a realistic FINDINGS pane.
export function Queue() {
  return (
    <TermFrame chromeless cols={92}>
      <SectionHeader label="NEEDS REVIEW · 2" cols={92} />
      <ReviewQueueRow
        alias="F-0012"
        severity="critical"
        proof="confirmed"
        title="sql injection via order_id"
        location="refund-bot.ts:127"
        decision="confirmed"
        decisionTone="success"
        selected
        cols={92}
      />
      <ReviewQueueRow
        alias="F-0007"
        severity="high"
        proof="likely"
        title="path traversal in export"
        location="files.ts:44"
        decision="needs review"
        decisionTone="warn"
        cols={92}
      />
      <SectionHeader label="TRIAGED · 2" cols={92} />
      <ReviewQueueRow
        alias="F-0031"
        severity="medium"
        proof="unverified"
        title="open redirect on login"
        location="auth.ts:88"
        cols={92}
      />
      <ReviewQueueRow
        alias="F-0044"
        severity="low"
        proof="dismissed"
        title="verbose error page"
        location="app.ts:9"
        decision="by-design"
        decisionTone="accent"
        cols={92}
      />
    </TermFrame>
  );
}

// The confidence axis swept on identical rows — how each proof band reads.
export function Confidences() {
  return (
    <TermFrame chromeless cols={64}>
      <ReviewQueueRow alias="F-0001" severity="critical" proof="confirmed" title="auth bypass" cols={64} />
      <ReviewQueueRow alias="F-0002" severity="high" proof="likely" title="ssrf in webhook" cols={64} />
      <ReviewQueueRow alias="F-0003" severity="medium" proof="unverified" title="weak jwt secret" cols={64} />
      <ReviewQueueRow alias="F-0004" severity="low" proof="dismissed" title="stack trace leak" cols={64} />
    </TermFrame>
  );
}
