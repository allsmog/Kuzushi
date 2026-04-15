/**
 * Tree-style agent activity display.
 *
 * Renders:
 *   [3/142] ⠹ Analyzing finding...
 *   ├─ → Reading src/api/users.ts
 *   ├─ ⋯ Grep "sanitize" (2.1s)
 *   └─ ✓ Found unsanitized user input flows to query
 */
import React from "react";
import { Box, Text } from "ink";
import chalk from "chalk";
import { icons } from "../icons.js";
import { formatDuration } from "../format.js";
import { Spinner } from "./Spinner.js";
import type { AgentActivityLine } from "../state.js";

interface AgentActivityProps {
  fingerprint: string;
  lines: AgentActivityLine[];
}

export function AgentActivity({ fingerprint, lines }: AgentActivityProps): React.ReactElement | null {
  if (lines.length === 0) return null;

  const latest = lines[lines.length - 1]!;
  const prefix = `  [${latest.index}/${latest.total}]`;

  return (
    <Box flexDirection="column">
      <Box>
        <Text>{prefix} </Text>
        <Spinner color="yellow" />
        <Text> {chalk.dim(fingerprint.slice(0, 12))}...</Text>
      </Box>
      {lines.map((line, i) => {
        const isLast = i === lines.length - 1;
        const connector = isLast ? icons.treeLast : icons.treeMiddle;
        const content = formatActivityLine(line);
        return (
          <Text key={i}>
            {"    "}{chalk.dim(connector)} {content}
          </Text>
        );
      })}
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
      const elapsed = line.elapsedSeconds != null ? ` (${formatDuration(line.elapsedSeconds * 1000)})` : "";
      return chalk.dim(`${icons.ellipsis} ${toolName}${elapsed}`);
    }
    case "tool-complete":
      return line.detail
        ? `${chalk.green(icons.success)} ${line.detail}`
        : chalk.green(icons.success);
    case "reasoning":
      return line.detail
        ? chalk.italic.dim(line.detail.slice(0, 80) + (line.detail.length > 80 ? "..." : ""))
        : "";
    case "summary":
      return line.detail
        ? `${chalk.dim(icons.dot)} ${chalk.dim(line.detail)}`
        : "";
  }
}
