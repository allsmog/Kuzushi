import { readFile } from "node:fs/promises";

/**
 * Read source code around a finding for LLM context.
 * Returns ~(radius*2) lines centered on the target line.
 */
export async function readFileContext(
  filePath: string,
  line: number,
  radius: number = 30,
): Promise<string> {
  if (!filePath || filePath === ".") {
    return "// Architectural finding: no specific source file location.";
  }

  try {
    const content = await readFile(filePath, "utf-8");
    const lines = content.split("\n");

    const start = Math.max(0, line - radius - 1);
    const end = Math.min(lines.length, line + radius);

    const numbered = lines
      .slice(start, end)
      .map((l, i) => {
        const lineNum = start + i + 1;
        const marker = lineNum === line ? " >>>" : "    ";
        return `${marker} ${String(lineNum).padStart(4)} | ${l}`;
      })
      .join("\n");

    return `// File: ${filePath}\n${numbered}`;
  } catch {
    return `// Could not read file: ${filePath}`;
  }
}
