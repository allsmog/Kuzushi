/**
 * Compact spinner block rendered beneath the conversation while a shell
 * tool is running. Progressive phase/activity lines now accumulate in the
 * conversation history (cc-repo style — each step prints a new line), so
 * this component stays intentionally thin to avoid redraw flicker:
 * spinner + tool name + live `mm:ss` elapsed. Phase captions and LLM
 * heartbeat lines live in the parent `CopilotShell` (and history) where
 * their update cadence doesn't drag the whole status block into a repaint.
 *
 * `useHeartbeat` drives the elapsed-stale detection + flips the spinner
 * to `warn` + appends a `waiting…` affordance after 15s of silence.
 */

import { Box, Text } from "ink";
import React, { useEffect, useState } from "react";
import { useHeartbeat } from "../hooks.js";
import type { ShellState } from "../state.js";
import { tokens } from "../tokens.js";
import { Spinner } from "./Spinner.js";

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

  const spinnerColor = isStale ? "warn" : "accent";

  return (
    <Box marginTop={1} paddingLeft={2}>
      <Spinner color={spinnerColor} />
      <Text>
        {"  "}
        {tokens.muted(tool.name)}
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

