/**
 * Structured diff display for patch previews.
 *
 * Renders unified diff format with colored additions/removals:
 *   ├─ Patch for sql-injection (src/api/users.ts)
 *   │    42  - db.query(`SELECT * WHERE name = '${name}'`);
 *   │    42  + db.query(`SELECT * WHERE name = ?`, [name]);
 */

import chalk from "chalk";
import { Box, Text } from "ink";
import type React from "react";
import { icons } from "../icons.js";

interface DiffViewProps {
  /** The unified diff string (output of git diff or similar). */
  diff: string;
  /** Optional title shown above the diff. */
  title?: string;
  /** Max lines to show (default 20). */
  maxLines?: number;
}

interface DiffLine {
  type: "add" | "remove" | "context" | "hunk-header" | "meta";
  content: string;
  lineNumber?: number;
}

export function DiffView({ diff, title, maxLines = 20 }: DiffViewProps): React.ReactElement {
  const lines = parseDiff(diff);
  const visible = lines.slice(0, maxLines);
  const truncated = lines.length > maxLines;

  return (
    <Box flexDirection="column">
      {title && (
        <Text>
          {"  "}
          {chalk.bold(title)}
        </Text>
      )}
      {visible.map((line, i) => (
        <DiffLine key={i} line={line} />
      ))}
      {truncated && (
        <Text>
          {"    "}
          {chalk.dim(`... ${lines.length - maxLines} more lines`)}
        </Text>
      )}
    </Box>
  );
}

function DiffLine({ line }: { line: DiffLine }): React.ReactElement {
  const lineNum = line.lineNumber != null ? chalk.dim(String(line.lineNumber).padStart(4)) : "    ";

  switch (line.type) {
    case "add":
      return (
        <Text>
          {"    "}
          {lineNum} {chalk.green(`+ ${line.content}`)}
        </Text>
      );
    case "remove":
      return (
        <Text>
          {"    "}
          {lineNum} {chalk.red(`- ${line.content}`)}
        </Text>
      );
    case "context":
      return (
        <Text>
          {"    "}
          {lineNum} {chalk.dim(`  ${line.content}`)}
        </Text>
      );
    case "hunk-header":
      return (
        <Text>
          {"    "}
          {chalk.dim(icons.ellipsis)}
        </Text>
      );
    case "meta":
      return (
        <Text>
          {"    "}
          {chalk.dim(line.content)}
        </Text>
      );
  }
}

function parseDiff(diff: string): DiffLine[] {
  const rawLines = diff.split("\n");
  const result: DiffLine[] = [];
  let currentLineOld = 0;
  let currentLineNew = 0;

  for (const raw of rawLines) {
    if (raw.startsWith("@@")) {
      // Parse hunk header: @@ -oldStart,oldCount +newStart,newCount @@
      const match = raw.match(/@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
      if (match) {
        currentLineOld = parseInt(match[1]!, 10);
        currentLineNew = parseInt(match[2]!, 10);
      }
      result.push({ type: "hunk-header", content: raw });
      continue;
    }

    if (
      raw.startsWith("---") ||
      raw.startsWith("+++") ||
      raw.startsWith("diff ") ||
      raw.startsWith("index ")
    ) {
      result.push({ type: "meta", content: raw });
      continue;
    }

    if (raw.startsWith("-")) {
      result.push({ type: "remove", content: raw.slice(1), lineNumber: currentLineOld });
      currentLineOld++;
      continue;
    }

    if (raw.startsWith("+")) {
      result.push({ type: "add", content: raw.slice(1), lineNumber: currentLineNew });
      currentLineNew++;
      continue;
    }

    if (raw.startsWith(" ")) {
      result.push({ type: "context", content: raw.slice(1), lineNumber: currentLineNew });
      currentLineOld++;
      currentLineNew++;
    }
  }

  return result;
}
