/**
 * Tree-style agent activity display.
 *
 * In the default (non-debug) view, collapses to the spinner + fingerprint
 * summary so long-running triage rows don't drown the terminal in tool
 * calls. `--debug` (via KUZUSHI_DEBUG=1) expands by default. Users can
 * always manually expand with space/enter when focus is on the row.
 */

import { Box, Text } from "ink";
import type React from "react";
import { formatCost, formatDuration } from "../format.js";
import { icons } from "../icons.js";
import { ExpandableSection } from "../primitives/ExpandableSection.js";
import type { AgentActivityLine, UIState } from "../state.js";
import { SPACING, tokens } from "../tokens.js";
import { ScreenContent } from "./ScreenContent.js";
import { Spinner } from "./Spinner.js";

const DEBUG_ON = process.env.KUZUSHI_DEBUG === "1";

interface AgentActivityProps {
  fingerprint: string;
  lines: AgentActivityLine[];
}

export function AgentActivity({
  fingerprint,
  lines,
}: AgentActivityProps): React.ReactElement | null {
  if (lines.length === 0) return null;

  const latest = lines[lines.length - 1]!;

  const summary = (
    <Box>
      <Text>
        [{latest.index}/{latest.total}]{" "}
      </Text>
      <Spinner color="warn" />
      <Text> {tokens.muted(fingerprint.slice(0, 12))}\u2026</Text>
    </Box>
  );

  return (
    <Box flexDirection="column" paddingLeft={SPACING.md}>
      <ExpandableSection
        summary={summary}
        defaultExpanded={DEBUG_ON}
        hint={`(press space for ${lines.length} activity line${lines.length === 1 ? "" : "s"})`}
      >
        {lines.map((line, i) => {
          const isLast = i === lines.length - 1;
          const connector = isLast ? icons.treeLast : icons.treeMiddle;
          const content = formatActivityLine(line);
          return (
            <Text key={`${line.index}-${line.kind}`}>
              {tokens.muted(connector)} {content}
            </Text>
          );
        })}
      </ExpandableSection>
    </Box>
  );
}

// Heartbeat strip — Phase B.1

/**
 * One-line "what's happening right now" strip rendered above StatusFooter
 * during the running phase. Computes its display entirely from existing
 * state fields (`agentActivity`, `runningCostUsd`, `pipelineStartedAt`,
 * `stages`) so no new producer wiring is required.
 *
 * When `expanded` is true, the strip adds a second line with a compact
 * per-agent list so operators can press `m` to drill in without losing
 * the primary "am I spending money?" at-a-glance read.
 */
export function HeartbeatStrip({
  state,
  expanded,
}: {
  state: UIState;
  expanded?: boolean;
}): React.ReactElement | null {
  if (state.mode !== "running") return null;

  const activeFingerprints = countActiveFingerprints(state.agentActivity);
  const elapsedMs = state.pipelineStartedAt ? Date.now() - state.pipelineStartedAt : 0;
  const elapsedStr = elapsedMs > 0 ? formatDuration(elapsedMs) : "0s";
  const costStr = state.runningCostUsd > 0 ? formatCost(state.runningCostUsd) : "$0.00";
  // During the scan phase, `agentActivity` (keyed by triage / verify
  // fingerprints) is empty by design — the live work lives in scan
  // sub-tasks. Count those instead so the strip doesn't read
  // "0 agents active" while a dozen detectors are running.
  const activeScanTasks =
    state.phase === "scanning"
      ? (state.stages
          .find((stage) => stage.id === "scan")
          ?.subTasks.filter((task) => task.status === "active").length ?? 0)
      : 0;
  const isScanCount = state.phase === "scanning" && activeFingerprints === 0;
  const visibleCount = isScanCount ? activeScanTasks : activeFingerprints;
  const agentStr = isScanCount
    ? `${visibleCount} task${visibleCount === 1 ? "" : "s"} running`
    : `${visibleCount} agent${visibleCount === 1 ? "" : "s"} active`;

  return (
    <ScreenContent>
      <Text>
        {tokens.accent(icons.active)}
        {"  "}
        {tokens.strong(agentStr)}
        {tokens.muted(`  ·  ${costStr}  ·  ${elapsedStr}`)}
        {state.throttle ? tokens.warn(`  ·  throttled (${state.throttle.concurrency})`) : ""}
        {tokens.hint(expanded ? "   (m) collapse" : "   (m) expand")}
      </Text>
      {expanded && activeFingerprints > 0 ? <HeartbeatAgentList state={state} /> : null}
    </ScreenContent>
  );
}

function HeartbeatAgentList({ state }: { state: UIState }): React.ReactElement {
  // Each active fingerprint is one "agent" from the operator's perspective —
  // show its last activity line so the expanded strip reads like a live feed
  // without duplicating the full AgentActivity tree.
  const rows: React.ReactElement[] = [];
  for (const [fingerprint, lines] of state.agentActivity) {
    if (lines.length === 0) continue;
    const latest = lines[lines.length - 1]!;
    rows.push(
      <Text key={fingerprint}>
        {"  "}
        {tokens.muted(icons.treeMiddle)} {tokens.muted(fingerprint.slice(0, 8))}
        {"  "}
        {tokens.muted(oneLineActivity(latest))}
      </Text>,
    );
    if (rows.length >= 5) break;
  }
  return <Box flexDirection="column">{rows}</Box>;
}

function countActiveFingerprints(map: Map<string, AgentActivityLine[]>): number {
  let count = 0;
  for (const lines of map.values()) {
    if (lines.length > 0) count++;
  }
  return count;
}

function oneLineActivity(line: AgentActivityLine): string {
  switch (line.kind) {
    case "tool-start":
      return `${icons.arrow} ${line.detail ?? line.toolName ?? "tool"}`;
    case "tool-progress":
      return `${icons.ellipsis} ${line.toolName ?? "tool"}`;
    case "tool-complete":
      return `${icons.success} ${line.detail ?? "done"}`;
    case "reasoning":
      return `${icons.bullet} ${(line.detail ?? "").slice(0, 60)}`;
    case "summary":
      return line.detail ?? "";
    case "finding-preview":
      return `${icons.error} ${(line.detail ?? "").slice(0, 60)}`;
  }
}

function formatActivityLine(line: AgentActivityLine): string {
  switch (line.kind) {
    case "tool-start": {
      const detail = line.detail ?? line.toolName ?? "Tool";
      return `${icons.arrow} ${detail}`;
    }
    case "tool-progress": {
      const toolName = line.toolName ?? "tool";
      const elapsed =
        line.elapsedSeconds != null ? ` (${formatDuration(line.elapsedSeconds * 1000)})` : "";
      return tokens.muted(`${icons.ellipsis} ${toolName}${elapsed}`);
    }
    case "tool-complete":
      return line.detail
        ? `${tokens.success(icons.success)} ${line.detail}`
        : tokens.success(icons.success);
    case "reasoning":
      return line.detail
        ? tokens.strong(line.detail.slice(0, 120) + (line.detail.length > 120 ? "..." : ""))
        : "";
    case "summary":
      return line.detail ? `${tokens.muted(icons.dot)} ${tokens.muted(line.detail)}` : "";
    case "finding-preview":
      return line.detail
        ? `${tokens.dangerStrong(icons.error)} ${tokens.strong(line.detail.slice(0, 120))}`
        : "";
  }
}
