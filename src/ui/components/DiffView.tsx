/**
 * Structured diff display for patch previews.
 *
 * Uses paddingLeft for indentation and tokens for color. Parse logic
 * preserved from the earlier implementation.
 */

import { Box, Text } from "ink";
import type React from "react";
import { icons } from "../icons.js";
import { SPACING, tokens } from "../tokens.js";

interface DiffViewProps {
  diff: string;
  title?: string;
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
        <Box paddingLeft={SPACING.md}>
          <Text>{tokens.label(title)}</Text>
        </Box>
      )}
      <Box flexDirection="column" paddingLeft={SPACING.xl}>
        {visible.map((line, i) => (
          <DiffLineRow key={i} line={line} />
        ))}
        {truncated && <Text>{tokens.muted(`... ${lines.length - maxLines} more lines`)}</Text>}
      </Box>
    </Box>
  );
}

function DiffLineRow({ line }: { line: DiffLine }): React.ReactElement {
  const lineNum =
    line.lineNumber != null ? tokens.muted(String(line.lineNumber).padStart(4)) : "    ";

  switch (line.type) {
    case "add":
      return (
        <Text>
          {lineNum} {tokens.success(`+ ${line.content}`)}
        </Text>
      );
    case "remove":
      return (
        <Text>
          {lineNum} {tokens.danger(`- ${line.content}`)}
        </Text>
      );
    case "context":
      return (
        <Text>
          {lineNum} {tokens.muted(`  ${line.content}`)}
        </Text>
      );
    case "hunk-header":
      return <Text>{tokens.muted(icons.ellipsis)}</Text>;
    case "meta":
      return <Text>{tokens.muted(line.content)}</Text>;
  }
}

function parseDiff(diff: string): DiffLine[] {
  const rawLines = diff.split("\n");
  const result: DiffLine[] = [];
  let currentLineOld = 0;
  let currentLineNew = 0;

  for (const raw of rawLines) {
    if (raw.startsWith("@@")) {
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
