/**
 * Persistent status footer — always visible at the bottom of the terminal.
 *
 * Shows:  claude-opus │ $0.84 │ 8/42 triaged │ 4m 12s
 *
 * Inspired by CC's StatusLine but adapted for Kuzushi's scan context.
 */

import chalk from "chalk";
import { Box, Text } from "ink";
import type React from "react";
import { useEffect, useState } from "react";
import { formatCost, formatDuration } from "../format.js";
import type { Phase } from "../state.js";

interface StatusFooterProps {
  model: string;
  phase: Phase;
  runningCostUsd: number;
  progress: { current: number; total: number };
  startedAt?: number;
  throttle?: { concurrency: number; reason: string } | null;
}

const SEP = chalk.dim(" │ ");

export function StatusFooter({
  model,
  phase,
  runningCostUsd,
  progress,
  startedAt,
  throttle,
}: StatusFooterProps): React.ReactElement | null {
  // Don't show footer in idle or done states
  if (phase === "idle" || phase === "done") return null;

  // Live elapsed timer
  const [elapsed, setElapsed] = useState(0);
  useEffect(() => {
    if (!startedAt) return;
    const interval = setInterval(() => {
      setElapsed(Date.now() - startedAt);
    }, 1000);
    return () => clearInterval(interval);
  }, [startedAt]);

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

  const throttleStr = throttle ? chalk.yellow(` │ ⚠ throttled`) : "";

  const termWidth = process.stdout.columns ?? 80;
  const divider = chalk.dim("─".repeat(Math.min(termWidth, 80)));

  return (
    <Box flexDirection="column" marginTop={1}>
      <Text>{divider}</Text>
      <Text>
        {chalk.redBright.bold(modelShort)}
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
}
