/**
 * Compact status block rendered beneath the conversation while a shell
 * tool is running. Progressive phase/activity lines now accumulate under
 * the `⏺` header in history + the `liveActivities` tail, so this block
 * stays intentionally thin to avoid redraw flicker: pulsing `⏺` + tool
 * name + live `mm:ss` elapsed. Phase captions and LLM heartbeat lines
 * live in `CopilotShell` where their update cadence doesn't drag the
 * whole status block into a repaint.
 *
 * We use a `PulseDot` (cc-repo ToolUseLoader-equivalent) instead of a
 * braille spinner so the live block matches the `⏺` glyph in the
 * history header — one visual vocabulary across the whole tool lifecycle.
 *
 * `useHeartbeat` drives the elapsed-stale detection + flips the pulse
 * color to `warn` + appends a `waiting…` affordance after a short silence.
 */

import { Box, Text } from "ink";
import React from "react";
import { useElapsed, useHeartbeat } from "../hooks.js";
import { Gutter } from "../primitives/Gutter.js";
import type { ShellState } from "../state.js";
import { SPACING, tokens } from "../tokens.js";
import { PulseDot } from "./PulseDot.js";

const WAITING_LABEL_WIDTH = " · waiting…".length;

interface ToolRunningStatusProps {
  tool: NonNullable<ShellState["currentTool"]>;
}

export const ToolRunningStatus = React.memo(ToolRunningStatusImpl, (prev, next) => {
  // Only re-render when fields this component actually reads change. Phase /
  // activity / elapsedSeconds bumps from `task:activity` events must NOT
  // flicker the bottom block — history owns that surface now.
  const a = prev.tool;
  const b = next.tool;
  return a.name === b.name && a.startedAt === b.startedAt && a.lastEventAt === b.lastEventAt;
});

/**
 * How long of a `task:activity` silence before the pulse flips from cyan
 * → yellow (and the operator sees "· waiting…"). cc-repo interpolates to
 * red at 3s with smooth RGB; we use a hard flip, so 5s is a calmer
 * threshold — still 3x faster than the previous 15s — without false-
 * triggering on tools whose activity cadence is naturally a few seconds
 * apart (LLM calls, remote probes).
 */
const STALE_SECONDS = 5;

function ToolRunningStatusImpl({ tool }: ToolRunningStatusProps): React.ReactElement {
  const { isStale } = useHeartbeat(
    {
      startedAt: tool.startedAt,
      lastEventAt: tool.lastEventAt,
      status: "active",
    },
    STALE_SECONDS,
  );

  // Stale (>3s silent) → use the warn status so the PulseDot renders in
  // yellow instead of cyan. Otherwise stays `running` (cyan pulse).
  const label = tool.displayName ?? tool.name;

  return (
    <Box marginTop={SPACING.sm}>
      <Gutter>
        <PulseDot status={isStale ? "warn" : "running"} />
      </Gutter>
      <Text>{isStale ? tokens.warn(label) : tokens.secondary(label)}</Text>
      <ElapsedReadout tool={tool} isStale={isStale} />
    </Box>
  );
}

/**
 * Self-ticking elapsed-time display. Owns its own 1s timer so the shell
 * subtree doesn't re-render every second when only the seconds digit
 * changed. Always formats `mm:ss` so the line width stays constant.
 */
function ElapsedReadout({
  tool,
  isStale,
}: {
  tool: ToolRunningStatusProps["tool"];
  isStale: boolean;
}): React.ReactElement | null {
  const startedAt = tool.startedAt;
  const elapsed = Math.floor(useElapsed(startedAt, 1000) / 1000);

  if (startedAt == null) {
    if (tool.elapsedSeconds && tool.elapsedSeconds > 0) {
      return <Text>{tokens.muted(` ${tool.elapsedSeconds.toFixed(0)}s`)}</Text>;
    }
    return null;
  }
  const mm = Math.floor(elapsed / 60)
    .toString()
    .padStart(2, "0");
  const ss = (elapsed % 60).toString().padStart(2, "0");
  const staleLabel = isStale ? " · waiting…" : "".padEnd(WAITING_LABEL_WIDTH, " ");
  return (
    <Text>
      {tokens.muted(`  ${mm}:${ss}`)}
      {isStale ? tokens.warn(staleLabel) : tokens.muted(staleLabel)}
    </Text>
  );
}
