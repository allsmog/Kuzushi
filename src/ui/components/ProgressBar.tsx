/**
 * Unicode progress bar Ink component.
 * Uses partial block characters for smooth sub-character progress.
 */
import React from "react";
import { Text } from "ink";
import { progressBar } from "../format.js";

interface ProgressBarProps {
  current: number;
  total: number;
  width?: number;
}

export function ProgressBar({ current, total, width = 20 }: ProgressBarProps): React.ReactElement {
  const bar = progressBar(current, total, width);
  const pct = total > 0 ? Math.round((current / total) * 100) : 0;

  return (
    <Text>
      {"  "}
      {bar}
      {"  "}
      <Text dimColor>({pct}%)</Text>
    </Text>
  );
}
