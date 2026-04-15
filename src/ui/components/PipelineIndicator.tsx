/**
 * Pipeline task indicator — shows all stages with ○/●/◆ status.
 *
 * Renders:
 *   ◆ Scan          semgrep, codeql         3.2s
 *   ● Triage        12/42 findings          ████████░░░░
 *   ○ Verify
 *   ○ PoC Harness
 *   ○ Report
 */
import React from "react";
import { Box, Text } from "ink";
import chalk from "chalk";
import { icons } from "../icons.js";
import { progressBar, formatDuration } from "../format.js";
import { Spinner } from "./Spinner.js";
import type { PipelineStage } from "../state.js";

interface PipelineIndicatorProps {
  stages: PipelineStage[];
  progress?: { current: number; total: number };
}

export function PipelineIndicator({ stages, progress }: PipelineIndicatorProps): React.ReactElement | null {
  if (stages.length === 0) return null;

  return (
    <Box flexDirection="column" marginTop={1}>
      {stages.map((stage) => (
        <PipelineStageLine
          key={stage.id}
          stage={stage}
          progress={stage.status === "active" ? progress : undefined}
        />
      ))}
      <Text>{""}</Text>
    </Box>
  );
}

function PipelineStageLine({ stage, progress }: {
  stage: PipelineStage;
  progress?: { current: number; total: number };
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
          {bar}
        </Text>
      </Box>
    );
  }

  if (stage.status === "error") {
    const detail = stage.detail ?? "";
    return (
      <Text>
        {"  "}{chalk.red(`${icons.error} ${paddedLabel}`)}
        {detail ? `  ${chalk.red(detail)}` : ""}
      </Text>
    );
  }

  // Pending
  return (
    <Text>{"  "}{chalk.dim(`${icons.pending} ${paddedLabel}`)}</Text>
  );
}
