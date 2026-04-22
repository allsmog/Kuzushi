/**
 * Unicode progress bar Ink component.
 * Uses partial block characters for smooth sub-character progress.
 *
 * Width is terminal-aware: if no explicit `width` is passed, picks a
 * responsive value (~40% of terminal columns, clamped 10..40).
 */

import { Box, Text } from "ink";
import type React from "react";
import { SPACING } from "../tokens.js";
import { progressBar } from "../format.js";
import { useTerminalSize } from "../hooks/useTerminalSize.js";

interface ProgressBarProps {
  current: number;
  total: number;
  width?: number;
}

export function ProgressBar({ current, total, width }: ProgressBarProps): React.ReactElement {
  const { columns } = useTerminalSize();
  const resolvedWidth = width ?? Math.max(10, Math.min(40, Math.floor(columns * 0.4)));
  const bar = progressBar(current, total, resolvedWidth);
  const pct = total > 0 ? Math.round((current / total) * 100) : 0;

  return (
    <Box paddingLeft={SPACING.md}>
      <Text>
        {bar}
        {"  "}
        <Text dimColor>({pct}%)</Text>
      </Text>
    </Box>
  );
}
