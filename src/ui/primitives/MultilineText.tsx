/**
 * MultilineText — renders `\n`-delimited input as stacked `<Text>` lines inside
 * a column `<Box>`. Replaces `text.split("\n").map(...)` patterns.
 */
import { Box, Text } from "ink";
import type { ComponentProps, FC } from "react";
import { tokens } from "../tokens.js";

type ColorKey = "accent" | "muted" | "subtle" | "strong" | "hint" | "label";
type InkWrap = ComponentProps<typeof Text>["wrap"];

export interface MultilineTextProps {
  text: string;
  /** Token color applied to each non-empty line. */
  color?: ColorKey;
  /** Also dim blank lines (default false — blank lines render as-is). */
  dimEmpty?: boolean;
  /** Passed through to Ink `<Text wrap>` for soft-wrap control. */
  wrap?: InkWrap;
}

function applyToken(value: string, color: ColorKey | undefined): string {
  if (!color) return value;
  const fn = tokens[color];
  return fn ? fn(value) : value;
}

export const MultilineText: FC<MultilineTextProps> = ({
  text,
  color,
  dimEmpty = false,
  wrap,
}) => {
  const lines = text.split("\n");
  return (
    <Box flexDirection="column">
      {lines.map((line, idx) => {
        const isEmpty = line.length === 0;
        const rendered =
          isEmpty && dimEmpty ? tokens.muted(" ") : applyToken(line, color);
        return (
          <Text key={`${idx}-${line.length}`} wrap={wrap}>
            {rendered || " "}
          </Text>
        );
      })}
    </Box>
  );
};
