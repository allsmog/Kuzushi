/**
 * Persistent status footer — always visible at the bottom of the terminal.
 *
 * Shows:  claude-opus │ $0.84 │ 8/42 triaged │ 4m 12s
 *
 * Uses useTerminalSize so the divider reflows when the terminal is resized,
 * and the Divider primitive replaces the old "─".repeat hack.
 */

import { Box, Text } from "ink";
import React from "react";
import { formatCost, formatDuration } from "../format.js";
import { useTerminalSize } from "../hooks/useTerminalSize.js";
import { useElapsed } from "../hooks.js";
import { Divider } from "../primitives/Divider.js";
import type { Phase } from "../state.js";
import { tokens } from "../tokens.js";

interface StatusFooterProps {
  model: string;
  phase: Phase;
  runningCostUsd: number;
  progress: { current: number; total: number };
  startedAt?: number;
  throttle?: { concurrency: number; reason: string } | null;
}

const SEP = tokens.tertiary(" \u2502 ");

export const StatusFooter = React.memo(function StatusFooter({
  model,
  phase,
  runningCostUsd,
  progress,
  startedAt,
  throttle,
}: StatusFooterProps): React.ReactElement | null {
  const { columns } = useTerminalSize();
  const elapsed = useElapsed(startedAt);

  if (phase === "idle" || phase === "done") return null;

  const modelShort = model.replace("anthropic:", "").replace("claude-", "").replace("-latest", "");

  const phaseLabel = {
    scanning: "scanning",
    triaging: "triaging",
    verifying: "verifying",
    poc: "PoC",
    summary: "reporting",
    idle: "",
    done: "",
  }[phase];

  const progressStr =
    progress.total > 0 ? `${progress.current}/${progress.total} ${phaseLabel}` : phaseLabel;

  const costStr = runningCostUsd > 0 ? formatCost(runningCostUsd) : "$0.00";

  const elapsedStr = elapsed > 0 ? formatDuration(elapsed) : "0s";

  const throttleStr = throttle ? tokens.warn(` \u2502 \u26A0 throttled`) : "";

  return (
    <Box flexDirection="column" marginTop={1}>
      <Divider width={Math.min(columns, 80)} />
      <Text>
        {tokens.focus(modelShort)}
        {SEP}
        {costStr}
        {SEP}
        {progressStr}
        {SEP}
        {elapsedStr}
        {throttleStr}
      </Text>
    </Box>
  );
});
