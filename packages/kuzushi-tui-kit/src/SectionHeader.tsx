import { Glyph } from "./Glyph";
import { Row } from "./Row";
import { DEFAULT_COLS } from "./tokens";

export interface SectionHeaderProps {
  /** The section name, rendered in the label tone (e.g. `FINDINGS`). */
  label: string;
  /** Grid width in cells the trailing rule extends to. */
  cols?: number;
}

/**
 * A `── LABEL ─────────` divider that groups console output into sections.
 * The label is rendered in the bold label tone; a subtle rule fills the rest
 * of the row to the grid width.
 *
 * @example
 * <SectionHeader label="FINDINGS · 11 triaged · 7 pending" cols={96} />
 */
export function SectionHeader({ label, cols = DEFAULT_COLS }: SectionHeaderProps) {
  const dashes = Math.max(0, cols - 1 - 4 - label.length - 1);
  return (
    <Row>
      {" "}
      <Glyph tone="label">{`── ${label} `}</Glyph>
      <Glyph tone="subtle">{"─".repeat(dashes)}</Glyph>
    </Row>
  );
}
