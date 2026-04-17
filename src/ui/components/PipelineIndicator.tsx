/**
 * Pipeline task indicator — shows all stages with ○/●/◆ status
 * and sub-tasks branching underneath each stage (like CC's agent tree).
 *
 * Renders:
 *   ◆ Scan                                    5.1s
 *   │  ├─ ◆ semgrep                           3.2s
 *   │  └─ ◆ codeql                            5.1s
 *   │
 *   ● Triage        8/15 findings             ████████░░░░
 *   │  ├─ ◆ [1/15] ✗ TRUE POSITIVE (92%)
 *   │  ├─ ◆ [2/15] ✓ false positive (78%)
 *   │  └─ ● [3/15] analyzing...
 *   │     ├─ → Reading src/api/users.ts
 *   │     └─ ✓ Found unsanitized input
 *   │
 *   ○ Verify
 *   ○ PoC Harness
 *   ○ Report
 */

import chalk from "chalk";
import { Box, Text } from "ink";
import React from "react";
import { colorVerdict, formatCost, formatDuration, progressBar, statusBadge } from "../format.js";
import { useHeartbeat } from "../hooks.js";
import { icons } from "../icons.js";
import type { AgentActivityLine, PipelineStage, ResultLine, SubTask } from "../state.js";
import { tokens } from "../tokens.js";
import { Spinner } from "./Spinner.js";

interface PipelineIndicatorProps {
  stages: PipelineStage[];
  progress?: { current: number; total: number };
  /** Running cost total for live display. */
  runningCostUsd?: number;
  /** Rate limit throttle info — shown when active. */
  throttle?: { concurrency: number; reason: string } | null;
  /** Recent results to show as sub-task branches under the active stage. */
  results?: ResultLine[];
  /** Active agent activity to nest under the current finding. */
  agentActivity?: Map<string, AgentActivityLine[]>;
}

const MAX_VISIBLE_RESULTS = 5;
/** Seconds without a visible scan event before showing a heartbeat. */
const HEARTBEAT_STALE_SECONDS = 15;

// Column widths used by StageHeaderLine to keep detail/elapsed visually
// stable across status transitions. ANSI color codes don't count toward
// visible width, so we `padEnd` the RAW strings BEFORE coloring. When a
// field is always-absent for a given row type we skip reservation rather
// than inject blank spaces that would eat real estate.
const STAGE_DETAIL_WIDTH = 12;
const STAGE_ELAPSED_WIDTH = 8;
// Same rationale for scanner sub-task rows. Count and detail only get
// padded when at least one row in the set would ever render them — see
// `SubTaskBranches` for the per-list reservation check.
const SUBTASK_COUNT_WIDTH = 10;
const SUBTASK_DETAIL_WIDTH = 22;
const SUBTASK_ELAPSED_WIDTH = 8;

export function PipelineIndicator({
  stages,
  progress,
  runningCostUsd,
  throttle,
  results,
  agentActivity,
}: PipelineIndicatorProps): React.ReactElement | null {
  // Heartbeat timer — re-renders every 5s when scan tasks are active so
  // "still analyzing..." and elapsed time stay fresh.
  const [, setTick] = React.useState(0);
  React.useEffect(() => {
    const hasActiveScanTasks = stages.some(
      (s) => s.id === "scan" && s.subTasks.some((t) => t.status === "active"),
    );
    if (!hasActiveScanTasks) return;
    const id = setInterval(() => setTick((t) => t + 1), 5000);
    return () => clearInterval(id);
  }, [stages]);

  if (stages.length === 0) return null;

  return (
    <Box flexDirection="column" marginTop={1}>
      {stages.map((stage, stageIdx) => {
        const isLast = stageIdx === stages.length - 1;
        const hasContent =
          stage.status === "active" || (stage.status === "done" && stage.subTasks.length > 0);

        return (
          <Box key={stage.id} flexDirection="column">
            {/* Stage header line */}
            <StageHeaderLine
              stage={stage}
              progress={stage.status === "active" ? progress : undefined}
              runningCostUsd={stage.status === "active" ? runningCostUsd : undefined}
              throttle={stage.status === "active" ? throttle : undefined}
            />

            {/* Sub-task branches for scanner tasks (scan stage) */}
            {stage.subTasks.length > 0 && (
              <SubTaskBranches subTasks={stage.subTasks} hasMoreBelow={!isLast} />
            )}

            {/* Result branches for active triage/verify/poc stages */}
            {stage.status === "active" && results && results.length > 0 && (
              <ResultBranches
                results={results}
                agentActivity={agentActivity}
                hasMoreBelow={!isLast}
              />
            )}

            {/* Vertical connector to next stage */}
            {hasContent && !isLast && (
              <Text>
                {"  "}
                {chalk.dim(icons.treePipe)}
              </Text>
            )}
          </Box>
        );
      })}
    </Box>
  );
}

// --- Stage header ---

function StageHeaderLine({
  stage,
  progress,
  runningCostUsd,
  throttle,
}: {
  stage: PipelineStage;
  progress?: { current: number; total: number };
  runningCostUsd?: number;
  throttle?: { concurrency: number; reason: string } | null;
}): React.ReactElement {
  const labelWidth = 14;
  const paddedLabel = stage.label.padEnd(labelWidth);

  if (stage.status === "done") {
    // padEnd on RAW strings before coloring — ANSI escape codes don't count
    // toward visible width, so the column reserves a real cell count.
    const detailRaw = stage.detail ?? "";
    const elapsedRaw = stage.elapsedMs != null ? formatDuration(stage.elapsedMs) : "";
    const detail = chalk.dim(detailRaw.padEnd(STAGE_DETAIL_WIDTH));
    const elapsed = chalk.dim(elapsedRaw.padEnd(STAGE_ELAPSED_WIDTH));
    const { icon } = statusBadge("stage", "done");
    return (
      <Text>
        {"  "}
        {chalk.dim(`${icon} ${paddedLabel}`)} {detail} {elapsed}
      </Text>
    );
  }

  if (stage.status === "active") {
    const detailRaw = stage.detail ?? "";
    const detail = detailRaw
      ? `  ${chalk.white(detailRaw.padEnd(STAGE_DETAIL_WIDTH))}`
      : `  ${" ".repeat(STAGE_DETAIL_WIDTH)}`;
    const cost =
      runningCostUsd && runningCostUsd > 0 ? `  ${chalk.dim(formatCost(runningCostUsd))}` : "";
    const throttleLabel = throttle
      ? `  ${chalk.yellow(`${icons.warning} ${throttle.concurrency} concurrent`)}`
      : "";
    const bar =
      progress && progress.total > 0
        ? `  ${progressBar(progress.current, progress.total, 12)}`
        : "";
    const elapsedRaw = stage.startedAt ? formatDuration(Date.now() - stage.startedAt) : "";
    const elapsed = elapsedRaw ? `  ${chalk.dim(elapsedRaw.padEnd(STAGE_ELAPSED_WIDTH))}` : "";
    // Active stages use the brand accent for the spinner frame. The static
    // filled-circle glyph still carries `dangerStrong` via `statusBadge` when
    // rendered non-animated (e.g. in tests or plain-renderer).
    return (
      <Box>
        <Text>{"  "}</Text>
        <Spinner color="accent" />
        <Text>
          {" "}
          {chalk.redBright.bold(paddedLabel)}
          {detail}
          {cost}
          {throttleLabel}
          {bar}
          {elapsed}
        </Text>
      </Box>
    );
  }

  if (stage.status === "error") {
    const { icon } = statusBadge("stage", "error");
    return (
      <Text>
        {"  "}
        {tokens.danger(`${icon} ${paddedLabel}`)}
        {stage.detail ? `  ${tokens.danger(stage.detail)}` : ""}
      </Text>
    );
  }

  const { icon } = statusBadge("stage", "pending");
  return (
    <Text>
      {"  "}
      {chalk.dim(`${icon} ${paddedLabel}`)}
    </Text>
  );
}

// --- Sub-task branches (scanners under Scan stage) ---

function SubTaskBranches({
  subTasks,
  hasMoreBelow,
}: {
  subTasks: SubTask[];
  hasMoreBelow: boolean;
}): React.ReactElement {
  const pipe = hasMoreBelow ? chalk.dim(icons.treePipe) : " ";

  // Sort: primary detector tasks first, then support tasks.
  const sorted = [...subTasks].sort((a, b) => {
    const aWeight = a.role === "support" ? 1 : 0;
    const bWeight = b.role === "support" ? 1 : 0;
    return aWeight - bWeight;
  });

  // Per-list reservation decisions. Only reserve a column if at least one
  // task in the set ever renders that field — otherwise we'd inject empty
  // columns that eat horizontal real estate for lists that don't need them.
  const anyCount = sorted.some((t) => (t.findingCount ?? 0) > 0);
  const anyDetail = sorted.some((t) => !!t.detail);
  const anyElapsed = sorted.some(
    (t) => t.elapsedMs != null || (t.status === "active" && t.startedAt != null),
  );

  return (
    <Box flexDirection="column">
      {sorted.map((task, i) => (
        <SubTaskRow
          key={task.id}
          task={task}
          isLast={i === sorted.length - 1}
          pipe={pipe}
          anyCount={anyCount}
          anyDetail={anyDetail}
          anyElapsed={anyElapsed}
        />
      ))}
    </Box>
  );
}

function SubTaskRow({
  task,
  isLast,
  pipe,
  anyCount,
  anyDetail,
  anyElapsed,
}: {
  task: SubTask;
  isLast: boolean;
  pipe: string;
  anyCount: boolean;
  anyDetail: boolean;
  anyElapsed: boolean;
}): React.ReactElement {
  const connector = isLast ? icons.treeLast : icons.treeMiddle;
  const { icon: badgeIcon, color: badgeColor } = statusBadge("task", task.status);
  const statusIcon = badgeColor(badgeIcon);

  // Extracted hook owns the 5s tick + stale detection.
  const { isStale, elapsedMs: heartbeatElapsed } = useHeartbeat(task, HEARTBEAT_STALE_SECONDS);

  // Raw field values (pre-color). padEnd runs on raw strings so ANSI escapes
  // don't throw off visible width.
  const elapsedRaw =
    task.elapsedMs != null
      ? formatDuration(task.elapsedMs)
      : task.status === "active" && task.startedAt
        ? formatDuration(heartbeatElapsed)
        : "";
  const countRaw =
    task.findingCount && task.findingCount > 0
      ? `${task.findingCount} finding${task.findingCount === 1 ? "" : "s"}`
      : "";
  const detailRaw = task.detail
    ? task.detail.length > 72
      ? `${task.detail.slice(0, 69)}...`
      : task.detail
    : "";

  const count = anyCount ? `  ${chalk.white(countRaw.padEnd(SUBTASK_COUNT_WIDTH))}` : "";
  const detail = anyDetail ? `  ${chalk.dim(detailRaw.padEnd(SUBTASK_DETAIL_WIDTH))}` : "";
  const elapsed = anyElapsed ? `  ${chalk.dim(elapsedRaw.padEnd(SUBTASK_ELAPSED_WIDTH))}` : "";

  const labelColor = task.status === "active" ? chalk.white : chalk.dim;
  const roleTag = task.role === "support" ? chalk.dim(" [setup]") : "";
  const retryTag =
    task.retryCount && task.retryCount > 0 ? chalk.yellow(` (retry #${task.retryCount})`) : "";
  const hasActivity = task.activityLines && task.activityLines.length > 0;

  return (
    <Box flexDirection="column">
      {/* Task header row */}
      {task.status === "active" ? (
        <Box>
          <Text>
            {"  "}
            {pipe} {chalk.dim(connector)}{" "}
          </Text>
          <Spinner color="accent" />
          <Text>
            {" "}
            {chalk.white(task.label)}
            {roleTag}
            {count}
            {detail}
            {elapsed}
            {retryTag}
          </Text>
        </Box>
      ) : task.status === "error" ? (
        <Text>
          {"  "}
          {pipe} {chalk.dim(connector)} {statusIcon} {tokens.danger(task.label)}
          {task.lastError ? `  ${tokens.danger(task.lastError.slice(0, 72))}` : detail}
          {retryTag}
          {chalk.dim("  continuing with remaining tasks")}
        </Text>
      ) : (
        <Text>
          {"  "}
          {pipe} {chalk.dim(connector)} {statusIcon} {labelColor(task.label)}
          {roleTag}
          {count}
          {detail}
          {elapsed}
        </Text>
      )}

      {/* Activity lines nested under active scan tasks */}
      {task.status === "active" && hasActivity && (
        <Box flexDirection="column">
          {task.activityLines!.map((line, li) => {
            const toolIsLast = li === task.activityLines!.length - 1;
            const toolConnector = toolIsLast ? icons.treeLast : icons.treeMiddle;
            const branchPipe = isLast ? " " : chalk.dim(icons.treePipe);
            return (
              <Text key={li}>
                {"  "}
                {pipe} {"  "}
                {branchPipe} {chalk.dim(toolConnector)} {formatToolLine(line)}
              </Text>
            );
          })}
        </Box>
      )}

      {/* Heartbeat when quiet */}
      {task.status === "active" && !hasActivity && isStale && task.startedAt && (
        <Text>
          {"  "}
          {pipe} {"  "}
          {isLast ? " " : chalk.dim(icons.treePipe)} {chalk.dim(icons.treeLast)}{" "}
          {chalk.dim.italic(`still analyzing... ${formatDuration(heartbeatElapsed)}`)}
        </Text>
      )}
    </Box>
  );
}

// --- Result branches (findings under Triage/Verify/PoC) ---

function ResultBranches({
  results,
  agentActivity,
  hasMoreBelow,
}: {
  results: ResultLine[];
  agentActivity?: Map<string, AgentActivityLine[]>;
  hasMoreBelow: boolean;
}): React.ReactElement {
  const pipe = hasMoreBelow ? chalk.dim(icons.treePipe) : " ";
  // Show last N results + any active agent activities
  const visible = results.slice(-MAX_VISIBLE_RESULTS);
  const skipped = results.length - visible.length;
  const activeEntries = agentActivity ? [...agentActivity.entries()] : [];

  return (
    <Box flexDirection="column">
      {skipped > 0 && (
        <Text>
          {"  "}
          {pipe} {chalk.dim(`${icons.treeMiddle} ... ${skipped} more above`)}
        </Text>
      )}
      {visible.map((r, i) => {
        const isLast = i === visible.length - 1 && activeEntries.length === 0;
        const connector = isLast ? icons.treeLast : icons.treeMiddle;
        return (
          <Text key={i}>
            {"  "}
            {pipe} {chalk.dim(connector)} {formatResultBranchLine(r)}
          </Text>
        );
      })}
      {/* Active finding with nested tool calls */}
      {activeEntries.map(([fp, lines], ai) => {
        const isLast = ai === activeEntries.length - 1;
        const connector = isLast ? icons.treeLast : icons.treeMiddle;
        const latest = lines[lines.length - 1];
        const prefix = latest ? `[${latest.index}/${latest.total}]` : "";

        return (
          <Box key={fp} flexDirection="column">
            {/* Active finding header */}
            <Box>
              <Text>
                {"  "}
                {pipe} {chalk.dim(connector)}{" "}
              </Text>
              <Spinner color="warn" />
              <Text>
                {" "}
                {chalk.white(prefix)} {chalk.dim(fp.slice(0, 12))}...
              </Text>
            </Box>
            {/* Tool call sub-branches */}
            {lines.map((line, li) => {
              const toolIsLast = li === lines.length - 1;
              const toolConnector = toolIsLast ? icons.treeLast : icons.treeMiddle;
              // Continuation pipe from the active finding
              const branchPipe = isLast ? " " : chalk.dim(icons.treePipe);
              return (
                <Text key={li}>
                  {"  "}
                  {pipe} {"  "}
                  {branchPipe} {chalk.dim(toolConnector)} {formatToolLine(line)}
                </Text>
              );
            })}
          </Box>
        );
      })}
    </Box>
  );
}

function formatResultBranchLine(r: ResultLine): string {
  const prefix = `[${r.index}/${r.total}]`;

  if (r.kind === "error") {
    const stage = r.errorStage?.toUpperCase() ?? "TRIAGE";
    return `${chalk.red(`${icons.error} ${prefix} ${stage} ERROR`)}`;
  }

  if (r.kind === "triage" && r.verdict) {
    const verdict = colorVerdict(r.verdict);
    const conf = chalk.dim(`(${((r.confidence ?? 0) * 100).toFixed(0)}%)`);
    const cost = r.costUsd && r.costUsd > 0 ? ` ${chalk.dim(formatCost(r.costUsd))}` : "";
    return `${chalk.dim(icons.complete)} ${prefix} ${verdict} ${conf}${cost}`;
  }

  if (r.kind === "verify") {
    const statusIcon = r.exploitable ? chalk.red(icons.error) : chalk.green(icons.success);
    const label = r.exploitable ? "EXPLOITABLE" : "not exploitable";
    const cost = r.costUsd && r.costUsd > 0 ? ` ${chalk.dim(formatCost(r.costUsd))}` : "";
    return `${chalk.dim(icons.complete)} ${prefix} ${statusIcon} ${label}${cost}`;
  }

  if (r.kind === "poc") {
    const statusIcon = r.skipped ? chalk.yellow(icons.pending) : chalk.cyan(icons.gear);
    const label = r.skipped ? "SKIPPED" : "GENERATED";
    const parsed = r.skipped ? "" : r.parsed ? " parsed" : " parse-error";
    return `${chalk.dim(icons.complete)} ${prefix} ${statusIcon} ${label}${parsed}`;
  }

  return `${chalk.dim(prefix)}`;
}

function formatToolLine(line: AgentActivityLine): string {
  switch (line.kind) {
    case "tool-start": {
      const detail = line.detail ?? line.toolName ?? "Tool";
      return chalk.dim(`${icons.arrow} ${detail}`);
    }
    case "tool-progress": {
      const toolName = line.toolName ?? "tool";
      const elapsed =
        line.elapsedSeconds != null ? ` (${formatDuration(line.elapsedSeconds * 1000)})` : "";
      return chalk.dim(`${icons.ellipsis} ${toolName}${elapsed}`);
    }
    case "tool-complete":
      return line.detail
        ? `${chalk.green(icons.success)} ${line.detail}`
        : chalk.green(icons.success);
    case "reasoning":
      // Reasoning IS the story — show it prominently, not dimmed.
      return line.detail
        ? chalk.white(line.detail.slice(0, 120) + ((line.detail.length ?? 0) > 120 ? "..." : ""))
        : "";
    case "summary":
      return line.detail ? `${chalk.cyan(icons.dot)} ${line.detail.slice(0, 120)}` : "";
    case "finding-preview":
      return line.detail
        ? `${chalk.redBright(icons.error)} ${chalk.white(line.detail.slice(0, 120))}`
        : "";
  }
}
