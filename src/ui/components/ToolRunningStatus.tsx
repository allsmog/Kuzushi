/**
 * Compact spinner block rendered beneath the conversation while a shell
 * tool is running. Progressive phase/activity lines now accumulate in the
 * conversation history (cc-repo style — each step prints a new line), so
 * this component stays small: spinner + tool name + live `mm:ss` elapsed,
 * an optional one-line phase caption, and the LLM heartbeat underneath.
 *
 * `useHeartbeat` drives the elapsed tick + flips the spinner to `warn` +
 * appends a `waiting…` affordance after 15s of silence.
 */

import { Box, Text } from "ink";
import React, { useEffect, useState } from "react";
import { useHeartbeat } from "../hooks.js";
import type { ShellState } from "../state.js";
import { tokens } from "../tokens.js";
import { Spinner } from "./Spinner.js";

interface ToolRunningStatusProps {
  tool: NonNullable<ShellState["currentTool"]>;
  heartbeat?: ShellState["llmHeartbeat"];
}

export const ToolRunningStatus = React.memo(_ToolRunningStatus);

function _ToolRunningStatus({ tool, heartbeat }: ToolRunningStatusProps): React.ReactElement {
  const { isStale } = useHeartbeat(
    {
      startedAt: tool.startedAt,
      lastEventAt: tool.lastEventAt,
      status: "active",
    },
    15,
  );

  const spinnerColor = isStale ? "warn" : "accent";
  const phaseLine = buildPhaseLine(tool);
  const caption = phaseLine ?? tool.subLabel;

  return (
    <Box flexDirection="column" marginTop={1} paddingLeft={2}>
      <Box>
        <Spinner color={spinnerColor} />
        <Text>
          {"  "}
          {tokens.muted(tool.name)}
          {caption ? tokens.muted(` · ${caption}`) : ""}
        </Text>
        <ElapsedReadout tool={tool} isStale={isStale} />
      </Box>
      {heartbeat && <LlmHeartbeatLine heartbeat={heartbeat} />}
    </Box>
  );
}

function buildPhaseLine(tool: ToolRunningStatusProps["tool"]): string | null {
  if (!tool.phase) return null;
  if (tool.step != null && tool.total != null) {
    const base = tool.phase.replace(/\s*\(\d+\s*\/\s*\d+\)\s*$/, "").trim();
    return base ? `${tool.step}/${tool.total} · ${base}` : `${tool.step}/${tool.total}`;
  }
  return tool.phase;
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

/**
 * One-line LLM heartbeat shown under the tool spinner. Mirrors the legacy
 * inline version from `CopilotShell.tsx` so the layout stays identical.
 */
function LlmHeartbeatLine({
  heartbeat,
}: {
  heartbeat: NonNullable<ShellState["llmHeartbeat"]>;
}): React.ReactElement | null {
  const { activeCalls, completedCalls, latestModel, totalCostUsd } = heartbeat;
  if (activeCalls === 0 && completedCalls === 0) return null;
  const parts: string[] = [];
  if (latestModel) parts.push(latestModel);
  const calls =
    activeCalls > 0
      ? `${activeCalls} call${activeCalls === 1 ? "" : "s"} in flight`
      : `${completedCalls} call${completedCalls === 1 ? "" : "s"}`;
  parts.push(calls);
  if (totalCostUsd > 0) parts.push(`$${totalCostUsd.toFixed(2)}`);
  return (
    <Box paddingLeft={4}>
      <Text>{tokens.muted(`· ${parts.join(" · ")}`)}</Text>
    </Box>
  );
}
