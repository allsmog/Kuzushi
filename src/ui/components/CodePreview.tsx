/**
 * Inline code preview — reads the actual source file and displays context
 * around the vulnerable line.
 *
 * Uses strict Flexbox (`paddingLeft`) for indentation rather than leading
 * whitespace literals, and tokens for coloring.
 */

import { Box, Text } from "ink";
import { existsSync, readFileSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";
import type React from "react";
import { tokens } from "../tokens.js";

interface CodePreviewProps {
  filePath: string;
  line: number;
  context?: number;
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
    <Box flexDirection="column" paddingLeft={6}>
      {lines.map(({ lineNumber, text, isTarget }) => {
        const num = String(lineNumber).padStart(4);
        const marker = isTarget ? tokens.dangerStrong("\u25B8") : " ";
        const lineContent = isTarget ? tokens.strong(text) : tokens.muted(text);
        const lineNum = isTarget ? tokens.dangerStrong(num) : tokens.muted(num);

        return (
          <Text key={lineNumber}>
            {tokens.muted("\u2502")}
            {marker}
            {lineNum} {tokens.muted("\u2502")} {lineContent}
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
    const absolute = isAbsolute(filePath)
      ? filePath
      : repoRoot
        ? resolve(repoRoot, filePath)
        : resolve(filePath);

    if (!existsSync(absolute)) return null;

    const content = readFileSync(absolute, "utf-8");
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
