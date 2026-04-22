/**
 * ShellFooterHints — canonical 1-line keybind hint bar for every ShellView.
 *
 * Every shell sub-view promised a consistent hint footer of the shape
 *   `j/k scroll · enter open · /back · /help`
 * but each one rolled its own `tokens.hint(...)` string with slightly
 * different separators, colors, and key labels. This component normalises
 * that rendering so:
 *
 *   - One visual rhythm: `<key>` in `tokens.muted` (or raw on NO_COLOR)
 *     and `<label>` in `tokens.hint`, joined by `·`.
 *   - Width-aware truncation: on narrow terminals, the rightmost hints
 *     collapse first and the bar ends with `…` rather than wrapping.
 *   - Optional leading divider — rendered via the shared `Divider`
 *     primitive so the view's content-width cap is respected.
 *
 * Usage:
 *
 *   <ShellFooterHints
 *     hints={[
 *       { key: "j/k", label: "scroll" },
 *       { key: "enter", label: "open" },
 *       { key: "/back", label: "" },
 *       { key: "/help", label: "more" },
 *     ]}
 *   />
 *
 * DO NOT add new keybinds here — agent 6 owns wiring.  This component only
 * renders truthful descriptions of behavior that is already implemented
 * in `CopilotShell.tsx`.
 */

import { Box, Text } from "ink";
import React from "react";
import { classifyTerminalWidth, useTerminalWidth } from "../hooks.js";
import { Divider } from "../primitives/Divider.js";
import { tokens } from "../tokens.js";
import { resolveContentWidth } from "./ShellHeader.js";

export interface ShellHint {
  /** The keystroke / slash-verb — renders muted.  e.g. "j/k", "1..5", "/back". */
  key: string;
  /** Short verb phrase explaining what the keystroke does. Can be empty for
   *  slash-commands whose name is self-documenting (e.g. `/back`). */
  label: string;
}

export interface ShellFooterHintsProps {
  hints: ReadonlyArray<ShellHint>;
  /** Render a dim horizontal rule above the hint line. Default true. */
  divider?: boolean;
  /** Optional explicit width cap; defaults to the shell content cap. */
  maxWidth?: number;
}

const SEP = tokens.subtle(" · ");
const ELLIPSIS = "…";

export const ShellFooterHints = React.memo(function ShellFooterHints({
  hints,
  divider = true,
  maxWidth,
}: ShellFooterHintsProps): React.ReactElement | null {
  const columns = useTerminalWidth();
  const widthClass = classifyTerminalWidth(columns);
  const width = maxWidth ?? resolveContentWidth(columns);

  if (hints.length === 0) return null;

  // Plain-width budget (what fits on one terminal line after the content
  // padding Ink assigns to most shell views). We reserve 4 cols for the
  // `paddingLeft` most views use.
  const budget = Math.max(12, width - 4);

  const { rendered, overflowed } = fitHints(hints, budget, widthClass === "tiny");

  // Most shell views render with `paddingLeft={2}`, so the effective
  // horizontal budget for the divider is `width - 2`. Subtract that here
  // so a rule never wraps into a second line on standard 80-col terms.
  const dividerWidth = Math.max(4, width - 2);

  return (
    <Box flexDirection="column" marginTop={1}>
      {divider ? <Divider width={dividerWidth} /> : null}
      <Text>
        {rendered.map((r, i) => (
          <React.Fragment key={`${r.key}-${i}`}>
            {i > 0 ? SEP : ""}
            {tokens.muted(r.key)}
            {r.label ? ` ${tokens.hint(r.label)}` : ""}
          </React.Fragment>
        ))}
        {overflowed ? `${SEP}${tokens.hint(ELLIPSIS)}` : ""}
      </Text>
    </Box>
  );
});

/**
 * Greedy-fit algorithm:  keep appending hints until the joined visible
 * length would exceed `budget`.  On `tiny` terminals the label is dropped
 * so more keys fit.
 */
export function fitHints(
  hints: ReadonlyArray<ShellHint>,
  budget: number,
  dropLabels: boolean,
): { rendered: ShellHint[]; overflowed: boolean } {
  const out: ShellHint[] = [];
  let used = 0;
  for (const h of hints) {
    const label = dropLabels ? "" : h.label;
    const piece = label ? `${h.key} ${label}` : h.key;
    const pieceLen = piece.length + (out.length === 0 ? 0 : 3 /* " · " */);
    if (used + pieceLen > budget) {
      return { rendered: out, overflowed: true };
    }
    out.push({ key: h.key, label });
    used += pieceLen;
  }
  return { rendered: out, overflowed: false };
}
