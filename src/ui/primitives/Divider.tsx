/**
 * Divider — horizontal rule primitive replacing manual `"─".repeat(n)` strings
 * scattered across the UI layer. Uses `<Box>` + `<Text>` so Ink can handle
 * layout and wrapping cleanly.
 */
import { Box, Text, useStdout } from "ink";
import type { FC } from "react";
import { resolveTerminalColumns } from "../terminal.js";
import { tokens } from "../tokens.js";

export interface DividerProps {
  /** Total divider width. Defaults to current terminal width (or 80). */
  width?: number;
  /** Fill character. Default "─". */
  char?: string;
  /** Dim the rule. Default true. */
  dim?: boolean;
  /** Optional centered title rendered inside the rule: `── Title ──`. */
  title?: string;
}

export const Divider: FC<DividerProps> = ({ width, char = "\u2500", dim = true, title }) => {
  const { stdout } = useStdout();
  const resolvedWidth = width ?? resolveTerminalColumns(stdout);
  const safeWidth = Math.max(4, resolvedWidth);
  const fill = (n: number) => char.repeat(Math.max(0, n));

  if (!title) {
    const rule = fill(safeWidth);
    return (
      <Box>
        <Text>{dim ? tokens.subtle(rule) : rule}</Text>
      </Box>
    );
  }

  const trimmed = title.trim();
  const titlePart = ` ${trimmed} `;
  const remaining = Math.max(0, safeWidth - titlePart.length);
  const leftN = Math.floor(remaining / 2);
  const rightN = remaining - leftN;
  const leftRule = fill(leftN);
  const rightRule = fill(rightN);
  const wrap = dim ? tokens.subtle : (s: string) => s;

  return (
    <Box>
      <Text>
        {wrap(leftRule)}
        {dim ? tokens.metadata(titlePart) : titlePart}
        {wrap(rightRule)}
      </Text>
    </Box>
  );
};
