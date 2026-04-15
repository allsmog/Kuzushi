/**
 * Resume diff display — shows what changed since the last run.
 *
 * Rendered once via <Static> when resuming a scan.
 *
 *   ┌─ Resume ────────────────────────────────────────────┐
 *   │  Previous run: 2024-04-14 (42 findings, 38 triaged) │
 *   │                                                      │
 *   │  New findings:       3                               │
 *   │  Previously triaged: 38 (skipped)                    │
 *   │  Pending re-triage:  4                               │
 *   └────────────────────────────────────────────────────┘
 */
import React from "react";
import { Box, Text } from "ink";
import chalk from "chalk";
import { icons } from "../icons.js";
import { boxHeader, boxFooter } from "../format.js";

export interface ResumeDiffData {
  previousRunDate?: string;
  previousFindingCount: number;
  previousTriagedCount: number;
  newFindings: number;
  skipped: number;
  pendingRetriage: number;
  verdictChanges: Array<{
    fingerprint: string;
    fromVerdict: string;
    toVerdict: string;
    reason?: string;
  }>;
}

interface ResumeDiffProps {
  data: ResumeDiffData;
}

export function ResumeDiff({ data }: ResumeDiffProps): React.ReactElement {
  const prevDate = data.previousRunDate
    ? new Date(data.previousRunDate).toLocaleDateString()
    : "unknown";

  return (
    <Box flexDirection="column">
      <Text>{boxHeader("Resume", 58)}</Text>
      <Text>
        {"  "}{chalk.dim("Previous run:")} {prevDate} ({data.previousFindingCount} findings, {data.previousTriagedCount} triaged)
      </Text>
      <Text>{""}</Text>

      {data.newFindings > 0 && (
        <Text>{"  "}{chalk.redBright(`${icons.active} New findings:`)}       {data.newFindings}</Text>
      )}
      <Text>{"  "}{chalk.dim(`${icons.complete} Previously triaged:`)} {data.skipped} {chalk.dim("(skipped)")}</Text>
      {data.pendingRetriage > 0 && (
        <Text>{"  "}{chalk.yellow(`${icons.warning} Pending re-triage:`)}  {data.pendingRetriage}</Text>
      )}

      {data.verdictChanges.length > 0 && (
        <>
          <Text>{""}</Text>
          <Text>{"  "}{chalk.yellow(`${icons.warning} Verdict changes:`)}   {data.verdictChanges.length}</Text>
          {data.verdictChanges.slice(0, 5).map((change, i) => {
            const isLast = i === Math.min(data.verdictChanges.length, 5) - 1;
            const connector = isLast ? icons.treeLast : icons.treeMiddle;
            return (
              <Text key={i}>
                {"    "}{chalk.dim(connector)} {chalk.dim(change.fingerprint.slice(0, 12))} {chalk.red(change.fromVerdict)} {icons.arrow} {chalk.green(change.toVerdict)}
                {change.reason ? chalk.dim(` (${change.reason})`) : ""}
              </Text>
            );
          })}
          {data.verdictChanges.length > 5 && (
            <Text>{"    "}{chalk.dim(`... and ${data.verdictChanges.length - 5} more`)}</Text>
          )}
        </>
      )}

      <Text>{boxFooter(58)}</Text>
    </Box>
  );
}
