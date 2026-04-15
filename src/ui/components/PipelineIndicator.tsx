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

export function PipelineIndicator({
  stages,
  progress,
  runningCostUsd,
  throttle,
  results,
  agentActivity,
}: PipelineIndicatorProps): React.ReactElement | null {
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
    return (
      <Box>
        <Text>{"  "}</Text>
        <Spinner color="red" />
        <Text>
          {" "}{chalk.redBright.bold(paddedLabel)}
          {detail ? `  ${chalk.white(detail)}` : ""}
          {cost}{throttleLabel}{bar}
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

  return (
    <Box flexDirection="column">
      {subTasks.map((task, i) => {
        const isLast = i === subTasks.length - 1;
        const connector = isLast ? icons.treeLast : icons.treeMiddle;
        const statusIcon = task.status === "done"
          ? chalk.dim(icons.complete)
          : task.status === "error"
            ? chalk.red(icons.error)
            : task.status === "active"
              ? chalk.redBright(icons.active)
              : chalk.dim(icons.pending);
        const elapsed = task.elapsedMs != null ? `  ${chalk.dim(formatDuration(task.elapsedMs))}` : "";
        const detail = task.detail ? `  ${chalk.dim(task.detail)}` : "";
        const labelColor = task.status === "active" ? chalk.white : chalk.dim;

        return (
          <Box key={task.id}>
            {task.status === "active" ? (
              <Box>
                <Text>{"  "}{pipe}  {chalk.dim(connector)} </Text>
                <Spinner color="red" />
                <Text> {chalk.white(task.label)}{detail}{elapsed}</Text>
              </Box>
            ) : (
              <Text>
                {"  "}{pipe}  {chalk.dim(connector)} {statusIcon} {labelColor(task.label)}{detail}{elapsed}
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
      return `${icons.arrow} ${detail}`;
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
      return line.detail
        ? `${chalk.italic.dim(line.detail.slice(0, 80))}${(line.detail.length ?? 0) > 80 ? "..." : ""}`
        : "";
    case "summary":
      return line.detail
        ? `${chalk.dim(icons.dot)} ${chalk.dim(line.detail)}`
        : "";
  }
}
