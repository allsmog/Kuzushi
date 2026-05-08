import type { FileIndex } from "../../types.js";
import type { PreReadResult } from "./pre-read.js";

const MAX_TREE_LINES = 200;

export function formatFileTreeForPrompt(
  fileIndex: FileIndex | undefined,
  hasPatternMatches?: boolean,
): string {
  if (!fileIndex || fileIndex.tree.length === 0) return "";

  if (hasPatternMatches) {
    return [
      `## Repository: ${fileIndex.totalFiles} source files${fileIndex.truncated ? " (truncated)" : ""}`,
      "Use Glob if you need files beyond those listed in the pattern matches and pre-loaded files above.",
      "",
    ].join("\n");
  }

  const entries = fileIndex.tree.slice(0, MAX_TREE_LINES);
  const lines = [
    "## Repository file tree",
    `${fileIndex.totalFiles} source files${fileIndex.truncated ? " (truncated)" : ""}:`,
    "```",
    ...entries.map((e) => e.path),
    "```",
    "",
    "Use this listing instead of Glob for initial file discovery. Only use Glob if you need files not shown above.",
    "",
  ];
  return lines.join("\n");
}

export function formatPreReadForPrompt(preRead: PreReadResult): string {
  if (preRead.files.length === 0) return "";

  const lines = [
    "## Pre-loaded files",
    "The following files have been pre-read for you. Analyze them directly instead of using Read.",
    "Only use Read for files not included below.",
    "",
  ];

  for (const file of preRead.files) {
    lines.push(`### ${file.path}`);
    lines.push("```");
    lines.push(file.content);
    lines.push("```");
    lines.push("");
  }

  return lines.join("\n");
}

export function formatPatternMatchesForPrompt(
  fileIndex: FileIndex | undefined,
  domains: string[],
): string {
  if (!fileIndex) return "";

  const matchLines: string[] = [];

  for (const domain of domains) {
    const matches = fileIndex.patternMatches[domain];
    if (!matches || matches.length === 0) continue;

    // Group by file
    const byFile = new Map<string, Array<{ lineNumber: number; lineContent: string }>>();
    for (const m of matches) {
      let arr = byFile.get(m.filePath);
      if (!arr) {
        arr = [];
        byFile.set(m.filePath, arr);
      }
      arr.push({ lineNumber: m.lineNumber, lineContent: m.lineContent });
    }

    for (const [filePath, fileMatches] of byFile) {
      for (const fm of fileMatches) {
        matchLines.push(
          `- **${filePath}** L${fm.lineNumber}: ${fm.lineContent.trim().slice(0, 120)}`,
        );
      }
    }
  }

  if (matchLines.length === 0) return "";

  return [
    "## Security pattern matches",
    "Prioritize investigating these files — they contain patterns relevant to your analysis:",
    "",
    ...matchLines,
    "",
  ].join("\n");
}
