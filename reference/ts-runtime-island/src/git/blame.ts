import { execFileSync } from "node:child_process";
import path from "node:path";

export interface BlameInfo {
  sha: string;
  author: string;
  date: string;
  summary: string;
}

/**
 * Get git blame info for a specific line in a file.
 * Returns null if the file is not tracked by git or blame fails.
 */
export function getBlameForLine(
  repoRoot: string,
  filePath: string,
  line: number,
): BlameInfo | null {
  try {
    const resolvedPath = path.isAbsolute(filePath) ? filePath : path.join(repoRoot, filePath);
    const relativePath = path.relative(repoRoot, resolvedPath);
    const output = execFileSync(
      "git",
      ["blame", "-L", `${line},${line}`, "--porcelain", "--", relativePath],
      { cwd: repoRoot, encoding: "utf-8", timeout: 10000 },
    );
    return parsePorcelainBlame(output);
  } catch {
    return null;
  }
}

function parsePorcelainBlame(output: string): BlameInfo | null {
  const lines = output.split("\n");
  if (lines.length === 0) return null;

  // First line: <sha> <orig-line> <final-line> [<num-lines>]
  const headerMatch = lines[0]?.match(/^([0-9a-f]{40})/);
  if (!headerMatch) return null;
  const sha = headerMatch[1];

  // Skip uncommitted changes (all zeros)
  if (sha === "0".repeat(40)) return null;

  let author = "";
  let date = "";
  let summary = "";

  for (const line of lines) {
    if (line.startsWith("author ")) {
      author = line.slice("author ".length);
    } else if (line.startsWith("author-time ")) {
      const timestamp = parseInt(line.slice("author-time ".length), 10);
      date = new Date(timestamp * 1000).toISOString().split("T")[0];
    } else if (line.startsWith("summary ")) {
      summary = line.slice("summary ".length);
    }
  }

  if (!sha || !author) return null;
  return { sha: sha.slice(0, 8), author, date, summary };
}
