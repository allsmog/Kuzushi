import { Glyph } from "./Glyph";
import { Row } from "./Row";

export interface NextCalloutProps {
  /** The single recommended next move (e.g. `作 confirm · 3 findings need review`). */
  summary: string;
  /** Fix the row to a grid width in cells. */
  cols?: number;
}

/**
 * The `▸ NEXT` callout — the phase-driven single-next-action line that anchors
 * the cockpit top bar, mirroring the Rust `next_action_line`. The `▸ NEXT` lead
 * reads warn (the one thing to do now); the summary reads primary. It is derived
 * from workspace reality — the current phase and what it still needs — so it
 * always points at the real next step, never a generic prompt.
 *
 * @example
 * <NextCallout cols={72} summary="作 confirm · 3 findings need review — next to continue" />
 */
export function NextCallout({ summary, cols }: NextCalloutProps) {
  return (
    <Row cols={cols}>
      {" "}
      <Glyph tone="warn" bold>
        ▸ NEXT
      </Glyph>{" "}
      <Glyph tone="primary">{summary}</Glyph>
    </Row>
  );
}
