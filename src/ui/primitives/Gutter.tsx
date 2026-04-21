/**
 * Fixed-width gutter box for the `⏺` / `⎿` glyph column.
 *
 * cc-repo pairs its glyphs with a `<NoSelect fromLeftEdge minWidth={2}>`
 * wrapper that (a) keeps the glyph a uniform 2-char-wide column and
 * (b) keeps glyph content out of terminal text-selection. Ink can't
 * truly disable text-select (that's a terminal behavior, not a renderer
 * one), but we can still lock the gutter width + prevent it from
 * compressing, which is the more important of the two guarantees —
 * content following a glyph will sit at the same column regardless
 * of glyph choice (`⏺`, `⠋`, `●`, space) or color.
 */

import { Box, Text } from "ink";
import type React from "react";

interface GutterProps {
  /** Glyph text rendered inside. Falls back to a single space for an empty gutter. */
  children?: React.ReactNode;
  /** Column width in character cells. Defaults to 2 (cc-repo convention). */
  minWidth?: number;
}

export function Gutter({ children, minWidth = 2 }: GutterProps): React.ReactElement {
  return (
    <Box minWidth={minWidth} flexShrink={0}>
      <Text>{children ?? " "}</Text>
    </Box>
  );
}
