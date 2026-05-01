/**
 * Persistent status footer — pinned at the bottom of the terminal.
 *
 * msfconsole-style payload:
 *   ./acme-api · ctx: fresh 4m · taint-iris · $0.69 · 3 findings (1 high)
 *
 * The legacy run-progress payload (model · phase · cost / cap · elapsed)
 * remains live during a run; the new fields render whenever the analyst
 * has loaded a target / module / findings, so the footer stays visible
 * across the home screen too.
 */

import { Box, Text } from "ink";
import React from "react";
import {
  formatContextAge,
  formatCost,
  formatDuration,
  formatFindingsSummary,
  truncateMiddle,
} from "../format.js";
import { classifyTerminalWidth, useElapsed, useTerminalWidth } from "../hooks.js";
import type { Phase } from "../state.js";
import { SPACING, tokens } from "../tokens.js";

interface StatusFooterProps {
  model: string;
  phase: Phase;
  runningCostUsd: number;
  progress: { current: number; total: number };
  startedAt?: number;
  throttle?: { concurrency: number; reason: string } | null;
  /**
   * O1: optional cost cap (USD). When set, the meter renders as
   * `$X.XX / $Y.YY` and switches to a warning color once the spend
   * crosses 80% of the cap.
   */
  costCapUsd?: number;
  /** Active scan target (path / url). Renders compact-truncated. */
  target?: string | null;
  /** Currently focused module id (`use <id>`), if any. */
  focusedModule?: string | null;
  /** Context-snapshot freshness for the active target. */
  context?: { state: "fresh" | "stale" | "missing" | "building"; ageMs?: number } | null;
  /** Findings summary for the active workspace. */
  findings?: {
    total: number;
    bySeverity?: Partial<Record<"critical" | "high" | "medium" | "low" | "info", number>>;
  } | null;
}

function compactTarget(target: string | null | undefined, columns: number): string | null {
  if (!target) return null;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(target)) {
    return truncateMiddle(target, Math.min(40, Math.max(16, Math.floor(columns / 4))));
  }
  const trimmed = target.replace(/\/+$/, "");
  const parts = trimmed.split("/").filter(Boolean);
  const basename = parts[parts.length - 1] ?? target;
  return `./${basename}`;
}

function joinSegments(segments: Array<string | null | undefined>): string {
  return segments
    .filter((s): s is string => Boolean(s && s.length > 0))
    .join(tokens.tertiary(" · "));
}

export const StatusFooter = React.memo(function StatusFooter({
  model,
  phase,
  runningCostUsd,
  progress,
  startedAt,
  throttle,
  costCapUsd,
  target,
  focusedModule,
  context,
  findings,
}: StatusFooterProps): React.ReactElement | null {
  const columns = useTerminalWidth();
  const widthClass = classifyTerminalWidth(columns);
  const elapsed = useElapsed(startedAt);

  const isRunning = phase !== "idle" && phase !== "done";
  const hasContextPayload = Boolean(target || focusedModule || context || findings);

  // Quiet when there is neither a running scan nor any analyst context.
  if (!isRunning && !hasContextPayload) return null;

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

  const progressStr = isRunning
    ? progress.total > 0
      ? `${progress.current}/${progress.total} ${phaseLabel}`
      : phaseLabel
    : "";

  const baseCostStr = runningCostUsd > 0 ? formatCost(runningCostUsd) : "$0.00";
  const costStr =
    costCapUsd && costCapUsd > 0
      ? runningCostUsd > 0.8 * costCapUsd
        ? tokens.warn(`${baseCostStr} / ${formatCost(costCapUsd)}`)
        : `${baseCostStr} / ${formatCost(costCapUsd)}`
      : baseCostStr;

  const elapsedStr = isRunning && elapsed > 0 ? formatDuration(elapsed) : "";

  const throttleStr = throttle ? tokens.warn(` │ ⚠ throttled`) : "";

  // Narrow terms (<60 col): drop the model tag to avoid truncation.
  const narrow = widthClass === "tiny";

  // msfconsole-style analyst context: target · ctx: <state> <age> · <module>.
  const targetSegment = compactTarget(target, columns);
  const contextSegment = context ? formatContextAge(context.state, context.ageMs) : null;
  const moduleSegment = focusedModule ? tokens.strong(focusedModule) : null;
  const findingsSegment = findings ? formatFindingsSummary(findings) : null;

  const leftSegments = isRunning
    ? [narrow ? null : tokens.strong(modelShort), progressStr]
    : [targetSegment, contextSegment, moduleSegment];
  const rightSegments = isRunning
    ? [costStr, elapsedStr]
    : [findingsSegment, runningCostUsd > 0 ? baseCostStr : null];

  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Box width={Math.max(0, columns)} justifyContent="space-between">
        <Text>{joinSegments(leftSegments)}</Text>
        <Text>
          {joinSegments(rightSegments)}
          {throttleStr}
        </Text>
      </Box>
    </Box>
  );
});
