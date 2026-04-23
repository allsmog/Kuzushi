/**
 * Unicode progress bar Ink component.
 * Uses partial block characters for smooth sub-character progress.
 *
 * Width is terminal-aware: if no explicit `width` is passed, picks a
 * responsive value (~40% of terminal columns, clamped 10..40).
 */

import { Box, Text } from "ink";
import type React from "react";
import { useTerminalSize } from "../hooks/useTerminalSize.js";
import { SPACING, tokens } from "../tokens.js";

const FULL_BLOCK = "\u2588";
const PARTIAL_BLOCKS = ["", "\u258F", "\u258E", "\u258D", "\u258C", "\u258B", "\u258A", "\u2589"];
const EMPTY_BLOCK = "\u2591";

function buildStableBar(current: number, total: number, width: number): string {
  if (total <= 0) return EMPTY_BLOCK.repeat(width);

  const ratio = Math.max(0, Math.min(current / total, 1));
  const scaled = ratio * width;
  const full = Math.floor(scaled);
  const remainder = scaled - full;
  const partialIndex = Math.floor(remainder * 8);
  const hasPartial = partialIndex > 0 && full < width;
  const empty = width - full - (hasPartial ? 1 : 0);

  return [
    tokens.accent(FULL_BLOCK.repeat(full)),
    hasPartial ? tokens.accent(PARTIAL_BLOCKS[partialIndex] ?? "") : "",
    tokens.muted(EMPTY_BLOCK.repeat(Math.max(0, empty))),
  ].join("");
}

interface ProgressBarProps {
  current: number;
  total: number;
  width?: number;
}

export function ProgressBar({ current, total, width }: ProgressBarProps): React.ReactElement {
  const { columns } = useTerminalSize();
  const resolvedWidth = width ?? Math.max(10, Math.min(40, Math.floor(columns * 0.4)));
  const bar = buildStableBar(current, total, resolvedWidth);
  const pct = total > 0 ? Math.round((current / total) * 100) : 0;
  const totalDigits = Math.max(1, String(Math.max(total, current, 0)).length);
  const count = `${String(Math.min(current, total)).padStart(totalDigits, " ")}/${String(total).padStart(totalDigits, " ")}`;
  const pctLabel = `${String(pct).padStart(3, " ")}%`;

  return (
    <Box paddingLeft={SPACING.md}>
      <Text>
        {bar}
        {"  "}
        {tokens.muted(pctLabel)}
        {"  "}
        {tokens.muted(count)}
      </Text>
    </Box>
  );
}
