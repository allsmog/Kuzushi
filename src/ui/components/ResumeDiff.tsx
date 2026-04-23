/**
 * Resume diff display — shows what changed since the last run.
 * Rendered once via <Static> when resuming a scan.
 */

import { Box, Text } from "ink";
import type React from "react";
import { boxFooter, boxHeader } from "../format.js";
import { useTerminalCardWidth } from "../hooks.js";
import { icons } from "../icons.js";
import { SPACING, tokens } from "../tokens.js";

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
  const width = useTerminalCardWidth();

  return (
    <Box flexDirection="column">
      <Text>{boxHeader("Resume", width)}</Text>
      <Box paddingLeft={SPACING.md} flexDirection="column">
        <Text>
          {tokens.muted("Previous run:")} {prevDate} ({data.previousFindingCount} findings,{" "}
          {data.previousTriagedCount} triaged)
        </Text>
        <Text>{""}</Text>

        {data.newFindings > 0 && (
          <Text>
            {tokens.dangerStrong(`${icons.active} New findings:`)} {data.newFindings}
          </Text>
        )}
        <Text>
          {tokens.muted(`${icons.complete} Previously triaged:`)} {data.skipped}{" "}
          {tokens.muted("(skipped)")}
        </Text>
        {data.pendingRetriage > 0 && (
          <Text>
            {tokens.warn(`${icons.warning} Pending re-triage:`)} {data.pendingRetriage}
          </Text>
        )}

        {data.verdictChanges.length > 0 && (
          <>
            <Text>{""}</Text>
            <Text>
              {tokens.warn(`${icons.warning} Verdict changes:`)} {data.verdictChanges.length}
            </Text>
            <Box flexDirection="column" paddingLeft={SPACING.md}>
              {data.verdictChanges.slice(0, 5).map((change, i) => {
                const isLast = i === Math.min(data.verdictChanges.length, 5) - 1;
                const connector = isLast ? icons.treeLast : icons.treeMiddle;
                return (
                  <Text key={change.fingerprint}>
                    {tokens.muted(connector)} {tokens.muted(change.fingerprint.slice(0, 12))}{" "}
                    {tokens.danger(change.fromVerdict)} {icons.arrow}{" "}
                    {tokens.success(change.toVerdict)}
                    {change.reason ? tokens.muted(` (${change.reason})`) : ""}
                  </Text>
                );
              })}
              {data.verdictChanges.length > 5 && (
                <Text>{tokens.muted(`... and ${data.verdictChanges.length - 5} more`)}</Text>
              )}
            </Box>
          </>
        )}
      </Box>
      <Text>{boxFooter(width)}</Text>
    </Box>
  );
}
