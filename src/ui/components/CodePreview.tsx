/**
 * Inline code preview — reads the actual source file and displays
 * context around the vulnerable line.
 *
 * Renders:
 *     │  40 │  const name = req.body.name;
 *     │  41 │  const query = `SELECT * FROM users
 *     │▸ 42 │    WHERE name = '${name}'`;
 *     │  43 │  const result = await db.query(query);
 */
import React from "react";
import { Box, Text } from "ink";
import chalk from "chalk";

interface CodePreviewProps {
  /** Absolute or relative file path. */
  filePath: string;
  /** The flagged line (1-indexed). */
  line: number;
  /** Lines of context above/below (default 2). */
  context?: number;
  /** Repo root for resolving relative paths. */
  repoRoot?: string;
}

export function CodePreview({
  filePath,
  line,
  context = 2,
  repoRoot,
}: CodePreviewProps): React.ReactElement | null {
  const lines = readSourceLines(filePath, line, context, repoRoot);
  if (!lines || lines.length === 0) return null;

  return (
    <Box flexDirection="column">
      {lines.map(({ lineNumber, text, isTarget }) => {
        const num = String(lineNumber).padStart(4);
        const marker = isTarget ? chalk.redBright("▸") : " ";
        const lineContent = isTarget
          ? chalk.white(text)
          : chalk.dim(text);
        const lineNum = isTarget
          ? chalk.redBright(num)
          : chalk.dim(num);

        return (
          <Text key={lineNumber}>
            {"      "}{chalk.dim("│")}{marker}{lineNum} {chalk.dim("│")} {lineContent}
          </Text>
        );
      })}
    </Box>
  );
}

interface SourceLine {
  lineNumber: number;
  text: string;
  isTarget: boolean;
}

function readSourceLines(
  filePath: string,
  targetLine: number,
  context: number,
  repoRoot?: string,
): SourceLine[] | null {
  try {
    const path = require("node:path") as typeof import("node:path");
    const fs = require("node:fs") as typeof import("node:fs");

    const absolute = path.isAbsolute(filePath)
      ? filePath
      : repoRoot
        ? path.resolve(repoRoot, filePath)
        : path.resolve(filePath);

    if (!fs.existsSync(absolute)) return null;

    const content = fs.readFileSync(absolute, "utf-8");
    const allLines = content.split("\n");

    const start = Math.max(0, targetLine - 1 - context);
    const end = Math.min(allLines.length, targetLine + context);

    const result: SourceLine[] = [];
    for (let i = start; i < end; i++) {
      result.push({
        lineNumber: i + 1,
        text: allLines[i]!,
        isTarget: i + 1 === targetLine,
      });
    }

    return result;
  } catch {
    return null;
  }
}
