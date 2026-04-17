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
import { formatDuration } from "../format.js";
import { icons } from "../icons.js";
import { ExpandableSection } from "../primitives/ExpandableSection.js";
import type { AgentActivityLine } from "../state.js";
import { tokens } from "../tokens.js";
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
      <Text>[{latest.index}/{latest.total}] </Text>
      <Spinner color="warn" />
      <Text> {tokens.muted(fingerprint.slice(0, 12))}\u2026</Text>
    </Box>
  );

  return (
    <Box flexDirection="column" paddingLeft={2}>
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
            <Text key={i}>
              {tokens.muted(connector)} {content}
            </Text>
          );
        })}
      </ExpandableSection>
    </Box>
  );
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
