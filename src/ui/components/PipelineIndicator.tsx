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
import React from "react";
import { Box, Text } from "ink";
import chalk from "chalk";
import { icons } from "../icons.js";
import { progressBar, formatDuration, colorVerdict, formatCost } from "../format.js";
import { Spinner } from "./Spinner.js";
import type { PipelineStage, SubTask, ResultLine, AgentActivityLine } from "../state.js";

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
        const hasContent = stage.status === "active" || (stage.status === "done" && stage.subTasks.length > 0);

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
              <SubTaskBranches
                subTasks={stage.subTasks}
                hasMoreBelow={!isLast}
              />
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
              <Text>{"  "}{chalk.dim(icons.treePipe)}</Text>
            )}
          </Box>
        );
      })}
    </Box>
  );
}

// --- Stage header ---

function StageHeaderLine({ stage, progress, runningCostUsd, throttle }: {
  stage: PipelineStage;
  progress?: { current: number; total: number };
  runningCostUsd?: number;
  throttle?: { concurrency: number; reason: string } | null;
}): React.ReactElement {
  const labelWidth = 14;
  const paddedLabel = stage.label.padEnd(labelWidth);

  if (stage.status === "done") {
    const elapsed = stage.elapsedMs != null ? chalk.dim(formatDuration(stage.elapsedMs)) : "";
    const detail = stage.detail ? chalk.dim(stage.detail) : "";
    return (
      <Text>
        {"  "}{chalk.dim(`${icons.complete} ${paddedLabel}`)}
        {detail ? `  ${detail}` : ""}
        {elapsed ? `  ${elapsed}` : ""}
      </Text>
    );
  }

  if (stage.status === "active") {
    const detail = stage.detail ?? "";
    const cost = runningCostUsd && runningCostUsd > 0
      ? `  ${chalk.dim(formatCost(runningCostUsd))}`
      : "";
    const throttleLabel = throttle
      ? `  ${chalk.yellow(`${icons.warning} ${throttle.concurrency} concurrent`)}`
      : "";
    const bar = progress && progress.total > 0
      ? `  ${progressBar(progress.current, progress.total, 12)}`
      : "";
    const elapsed = stage.startedAt
      ? `  ${chalk.dim(formatDuration(Date.now() - stage.startedAt))}`
      : "";
    return (
      <Box>
        <Text>{"  "}</Text>
        <Spinner color="red" />
        <Text>
          {" "}{chalk.redBright.bold(paddedLabel)}
          {detail ? `  ${chalk.white(detail)}` : ""}
          {cost}{throttleLabel}{bar}{elapsed}
        </Text>
      </Box>
    );
  }

  if (stage.status === "error") {
    return (
      <Text>
        {"  "}{chalk.red(`${icons.error} ${paddedLabel}`)}
        {stage.detail ? `  ${chalk.red(stage.detail)}` : ""}
      </Text>
    );
  }

  return (
    <Text>{"  "}{chalk.dim(`${icons.pending} ${paddedLabel}`)}</Text>
  );
}

// --- Sub-task branches (scanners under Scan stage) ---

function SubTaskBranches({ subTasks, hasMoreBelow }: {
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

  return (
    <Box flexDirection="column">
      {sorted.map((task, i) => {
        const isLast = i === sorted.length - 1;
        const connector = isLast ? icons.treeLast : icons.treeMiddle;
        const statusIcon = task.status === "done"
          ? chalk.dim(icons.complete)
          : task.status === "error"
            ? chalk.red(icons.error)
            : task.status === "active"
              ? chalk.redBright(icons.active)
              : chalk.dim(icons.pending);
        const elapsed = task.elapsedMs != null
          ? `  ${chalk.dim(formatDuration(task.elapsedMs))}`
          : task.status === "active" && task.startedAt
            ? `  ${chalk.dim(formatDuration(Date.now() - task.startedAt))}`
            : "";
        const count = task.findingCount && task.findingCount > 0
          ? `  ${chalk.white(`${task.findingCount} finding${task.findingCount === 1 ? "" : "s"}`)}`
          : "";
        const detail = task.detail
          ? `  ${chalk.dim(task.detail.length > 72 ? `${task.detail.slice(0, 69)}...` : task.detail)}`
          : "";
        const labelColor = task.status === "active" ? chalk.white : chalk.dim;
        const roleTag = task.role === "support" ? chalk.dim(" [setup]") : "";
        const retryTag = task.retryCount && task.retryCount > 0
          ? chalk.yellow(` (retry #${task.retryCount})`)
          : "";

        const hasActivity = task.activityLines && task.activityLines.length > 0;
        // Heartbeat: show "still analyzing..." when active but quiet for > 15s
        const now = Date.now();
        const isStale = task.status === "active"
          && task.startedAt
          && (!task.lastEventAt || (now - task.lastEventAt) > HEARTBEAT_STALE_SECONDS * 1000);

        return (
          <Box key={task.id} flexDirection="column">
            {/* Task header row */}
            {task.status === "active" ? (
              <Box>
                <Text>{"  "}{pipe}  {chalk.dim(connector)} </Text>
                <Spinner color="red" />
                <Text> {chalk.white(task.label)}{roleTag}{count}{detail}{elapsed}{retryTag}</Text>
              </Box>
            ) : task.status === "error" ? (
              <Text>
                {"  "}{pipe}  {chalk.dim(connector)} {statusIcon} {chalk.red(task.label)}
                {task.lastError ? `  ${chalk.red(task.lastError.slice(0, 72))}` : detail}
                {retryTag}
                {chalk.dim("  continuing with remaining tasks")}
              </Text>
            ) : (
              <Text>
                {"  "}{pipe}  {chalk.dim(connector)} {statusIcon} {labelColor(task.label)}{roleTag}{count}{detail}{elapsed}
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
                      {"  "}{pipe}  {"  "}{branchPipe}  {chalk.dim(toolConnector)} {formatToolLine(line)}
                    </Text>
                  );
                })}
              </Box>
            )}

            {/* Heartbeat when quiet */}
            {task.status === "active" && !hasActivity && isStale && (
              <Text>
                {"  "}{pipe}  {"  "}{isLast ? " " : chalk.dim(icons.treePipe)}  {chalk.dim(icons.treeLast)} {chalk.dim.italic(`still analyzing... ${formatDuration(now - task.startedAt!)}`)}
              </Text>
            )}
          </Box>
        );
      })}
    </Box>
  );
}

// --- Result branches (findings under Triage/Verify/PoC) ---

function ResultBranches({ results, agentActivity, hasMoreBelow }: {
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
        <Text>{"  "}{pipe}  {chalk.dim(`${icons.treeMiddle} ... ${skipped} more above`)}</Text>
      )}
      {visible.map((r, i) => {
        const isLast = i === visible.length - 1 && activeEntries.length === 0;
        const connector = isLast ? icons.treeLast : icons.treeMiddle;
        return (
          <Text key={i}>
            {"  "}{pipe}  {chalk.dim(connector)} {formatResultBranchLine(r)}
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
              <Text>{"  "}{pipe}  {chalk.dim(connector)} </Text>
              <Spinner color="yellow" />
              <Text> {chalk.white(prefix)} {chalk.dim(fp.slice(0, 12))}...</Text>
            </Box>
            {/* Tool call sub-branches */}
            {lines.map((line, li) => {
              const toolIsLast = li === lines.length - 1;
              const toolConnector = toolIsLast ? icons.treeLast : icons.treeMiddle;
              // Continuation pipe from the active finding
              const branchPipe = isLast ? " " : chalk.dim(icons.treePipe);
              return (
                <Text key={li}>
                  {"  "}{pipe}  {"  "}{branchPipe}  {chalk.dim(toolConnector)} {formatToolLine(line)}
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
      const elapsed = line.elapsedSeconds != null ? ` (${formatDuration(line.elapsedSeconds * 1000)})` : "";
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
      return line.detail
        ? `${chalk.cyan(icons.dot)} ${line.detail.slice(0, 120)}`
        : "";
    case "finding-preview":
      return line.detail
        ? `${chalk.redBright(icons.error)} ${chalk.white(line.detail.slice(0, 120))}`
        : "";
  }
}
