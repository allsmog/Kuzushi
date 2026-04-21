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
 * color to `warn` + appends a `waiting…` affordance after 15s of silence.
 */

import { Box, Text } from "ink";
import React, { useEffect, useState } from "react";
import { useHeartbeat } from "../hooks.js";
import { Gutter } from "../primitives/Gutter.js";
import type { ShellState } from "../state.js";
import { tokens } from "../tokens.js";
import { PulseDot } from "./PulseDot.js";

interface ToolRunningStatusProps {
  tool: NonNullable<ShellState["currentTool"]>;
}

export const ToolRunningStatus = React.memo(_ToolRunningStatus, (prev, next) => {
  // Only re-render when fields this component actually reads change. Phase /
  // activity / elapsedSeconds bumps from `task:activity` events must NOT
  // flicker the bottom block — history owns that surface now.
  const a = prev.tool;
  const b = next.tool;
  return a.name === b.name && a.startedAt === b.startedAt && a.lastEventAt === b.lastEventAt;
});

function _ToolRunningStatus({ tool }: ToolRunningStatusProps): React.ReactElement {
  const { isStale } = useHeartbeat(
    {
      startedAt: tool.startedAt,
      lastEventAt: tool.lastEventAt,
      status: "active",
    },
    15,
  );

  // Stale (>15s silent) → use the warn status so the PulseDot renders in
  // yellow instead of cyan. Otherwise stays `running` (cyan pulse).
  const label = tool.displayName ?? tool.name;

  return (
    <Box marginTop={1}>
      <Gutter>
        <PulseDot status={isStale ? "warn" : "running"} />
      </Gutter>
      <Text>
        {isStale ? tokens.warn(label) : tokens.muted(label)}
      </Text>
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
  const [elapsed, setElapsed] = useState(() =>
    startedAt ? Math.floor((Date.now() - startedAt) / 1000) : 0,
  );
  useEffect(() => {
    if (startedAt == null) return;
    const timer = setInterval(() => {
      setElapsed(Math.floor((Date.now() - startedAt) / 1000));
    }, 1000);
    return () => clearInterval(timer);
  }, [startedAt]);

  if (startedAt == null) {
    if (tool.elapsedSeconds && tool.elapsedSeconds > 0) {
      return <Text>{tokens.muted(` ${tool.elapsedSeconds.toFixed(0)}s`)}</Text>;
    }
    return null;
  }
  if (elapsed <= 0 && !isStale) return null;
  const mm = Math.floor(elapsed / 60)
    .toString()
    .padStart(2, "0");
  const ss = (elapsed % 60).toString().padStart(2, "0");
  return (
    <Text>
      {tokens.muted(`  ${mm}:${ss}`)}
      {isStale ? tokens.warn(" · waiting…") : ""}
    </Text>
  );
}

