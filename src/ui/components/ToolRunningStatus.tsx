/**
 * Multi-line progress block rendered while a shell tool is running.
 *
 * Replaces the previous single-line `⠋ <tool> · <subLabel>  <elapsed>` with
 * a progressive layout that evolves as `task:phase-progress` /
 * `task:activity` events arrive:
 *
 *   ⠙  context:build · 02:14
 *      ⏵ phase 2/15 · building threat model
 *        ↳ lab · analyzing trust zones          just now
 *        ↳ lab · 3 input categories enumerated  5s ago
 *      · 4 LLM calls · sonnet-4-5 · $0.08
 *
 * When `phase` and `activities` are both empty, falls back to the original
 * single-line rendering so quick tools never flash a multi-row block.
 *
 * Re-render cadence is driven by `useHeartbeat` (5s tick), which also flags
 * `isStale` after 15s of silence. Stale → spinner flips to `warn` + a
 * `waiting…` affordance appears next to the elapsed counter.
 */

import { Box, Text } from "ink";
import React, { useEffect, useState } from "react";
import { useHeartbeat } from "../hooks.js";
import { formatRelativeAgo } from "../format.js";
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

  const activities = tool.activities ?? [];
  const hasPhase = !!tool.phase;
  const progressive = hasPhase || activities.length > 0;
  const spinnerColor = isStale ? "warn" : "accent";
  const phaseLine = buildPhaseLine(tool);

  return (
    <Box flexDirection="column" marginTop={1} paddingLeft={2}>
      <Box>
        <Spinner color={spinnerColor} />
        <Text>
          {"  "}
          {tokens.muted(tool.name)}
          {!progressive && tool.subLabel ? tokens.muted(` · ${tool.subLabel}`) : ""}
        </Text>
        <ElapsedReadout tool={tool} isStale={isStale} />
      </Box>
      {progressive && phaseLine && (
        <Box paddingLeft={3}>
          <Text>
            {tokens.accent("⏵ ")}
            {tokens.muted(phaseLine)}
          </Text>
        </Box>
      )}
      {progressive && activities.length > 0 && <ActivityTail lines={activities.slice(0, 3)} />}
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

function ActivityTail({
  lines,
}: {
  lines: NonNullable<ToolRunningStatusProps["tool"]["activities"]>;
}): React.ReactElement {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 5000);
    return () => clearInterval(id);
  }, []);
  return (
    <Box flexDirection="column" paddingLeft={5}>
      {lines.map((line, i) => (
        <Box key={`${line.ts}-${i}`}>
          <Text>
            {tokens.muted("↳ ")}
            {tokens.muted(line.text)}
            {tokens.muted(`  ${formatRelativeAgo(line.ts, now)}`)}
          </Text>
        </Box>
      ))}
    </Box>
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
