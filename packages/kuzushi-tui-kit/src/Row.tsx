import type { CSSProperties, ReactNode } from "react";
import { type Tone, toneClass } from "./tokens";

export interface RowProps {
  /**
   * Fix the row to a monospace grid width (in cells). When set, the row's
   * background and selection highlight extend to the full width — matching
   * how the real shell pads every line to the frame's column count.
   */
  cols?: number;
  /** Highlight the row as the j/k cursor selection (inverse accent). */
  selected?: boolean;
  /** Color the entire row with one tone (individual {@link Glyph}s override). */
  tone?: Tone;
  /** Row contents — plain text and {@link Glyph} spans. */
  children: ReactNode;
}

/**
 * One line of the terminal grid. Lines stack downward inside a {@link TermFrame}
 * to form the growing console. Compose a row from plain text and {@link Glyph}
 * spans; set `selected` for the active cursor line.
 *
 * @example
 * <Row>  <Glyph tone="accent">F-0001</Glyph>  sql injection</Row>
 * <Row selected cols={80}>  F-0001  CRITICAL  order_id concatenation</Row>
 */
export function Row({ cols, selected, tone, children }: RowProps) {
  const style: CSSProperties | undefined =
    cols != null ? { width: `${cols}ch` } : undefined;
  const className = [
    "kz-row",
    selected ? "kz-row--selected" : null,
    !selected ? toneClass(tone) : null,
  ]
    .filter(Boolean)
    .join(" ");
  return (
    <span className={className} style={style}>
      {children}
    </span>
  );
}
