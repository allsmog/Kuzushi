import { Glyph } from "./Glyph";
import { Row } from "./Row";
import { ProofBadge, type ProofState } from "./ProofBadge";
import { SeverityBadge } from "./SeverityBadge";
import type { Severity, Tone } from "./tokens";

export interface ReviewQueueRowProps {
  /** Finding alias (e.g. `F-0012`). */
  alias: string;
  /** Severity level — rendered as the compact `C/H/M/L/I/?` glyph. */
  severity: Severity;
  /** Proof confidence — the confidence-first sort key and chip. */
  proof: ProofState;
  /** Short finding title (e.g. `sql injection`). */
  title: string;
  /** Optional location (e.g. `refund-bot.ts:127`), rendered muted. */
  location?: string;
  /** Optional decision signal (e.g. `needs review`, `confirmed`, `false-pos`). */
  decision?: string;
  /** Tone for the decision signal (default `muted`). */
  decisionTone?: Tone;
  /** Highlight as the j/k cursor line (full-width `▸` selection band). */
  selected?: boolean;
  /** Fix the row to a grid width in cells. */
  cols?: number;
}

/**
 * One row of the confidence-first review queue — the FINDINGS pane of the Atlas
 * workbench. It leads with the compact severity glyph and the proof-confidence
 * chip (`✓ CONFIRMED` / `◇ LIKELY` / `? unverified` / `· dismissed`), so the
 * ledger reads confidence-first at a glance, then the alias, title, location,
 * and decision signal. `selected` paints the full-width `▸` selection band the
 * shell uses for the j/k cursor. Group runs of these under a
 * {@link SectionHeader} divider (`── NEEDS REVIEW · 3 ──`).
 *
 * @example
 * <ReviewQueueRow alias="F-0012" severity="critical" proof="confirmed"
 *   title="sql injection" location="refund-bot.ts:127"
 *   decision="confirmed" decisionTone="success" selected cols={64} />
 */
export function ReviewQueueRow({
  alias,
  severity,
  proof,
  title,
  location,
  decision,
  decisionTone = "muted",
  selected,
  cols,
}: ReviewQueueRowProps) {
  return (
    <Row cols={cols} selected={selected}>
      {selected ? "▸" : " "}{" "}
      <SeverityBadge level={severity} glyph />{" "}
      <ProofBadge state={proof} />{" "}
      <Glyph tone="accent">{alias}</Glyph>
      {"  "}
      <Glyph tone="primary">{title}</Glyph>
      {location ? <Glyph tone="muted">{`  ${location}`}</Glyph> : null}
      {decision ? <Glyph tone={decisionTone}>{`  ${decision}`}</Glyph> : null}
    </Row>
  );
}
