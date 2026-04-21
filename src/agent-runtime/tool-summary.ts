import path from "node:path";

const HINT_MAX = 40;

/**
 * Render a ≤40-char summary of a tool input for "⏺ tool(<hint>)" headers
 * and activity-tail displays. Returns undefined when no sensible primary
 * field exists — callers fall back to bare tool name.
 */
export function summarizeInput(input: unknown): string | undefined {
  if (input == null) return undefined;
  if (typeof input === "string") return clampHint(input);
  if (typeof input === "number" || typeof input === "boolean") return String(input);
  if (Array.isArray(input)) {
    if (input.length === 0) return undefined;
    const first = input[0];
    if (typeof first === "string") return clampHint(first);
    return clampHint(JSON.stringify(input));
  }
  if (typeof input === "object") {
    const record = input as Record<string, unknown>;
    const primary =
      record["target"] ??
      record["path"] ??
      record["file"] ??
      record["file_path"] ??
      record["filePath"] ??
      record["query"] ??
      record["pattern"] ??
      record["command"] ??
      record["name"] ??
      record["url"] ??
      record["module"];
    if (typeof primary === "string" && primary.length > 0) return clampHint(primary);
    if (typeof primary === "number" || typeof primary === "boolean") return String(primary);
    try {
      const json = JSON.stringify(record);
      if (json && json.length > 2) return clampHint(json);
    } catch {
      // ignore
    }
    return undefined;
  }
  return undefined;
}

export function clampHint(s: string): string {
  const trimmed = s.trim();
  if (trimmed.length <= HINT_MAX) return trimmed;
  return `${trimmed.slice(0, HINT_MAX - 1)}…`;
}

export interface ToolCompletionOptions {
  elapsedSeconds?: number;
}

/**
 * Format a completed tool call as a single human-readable line.
 *
 * Preferred shapes per tool:
 *   Read  src/foo.ts (2868 lines)
 *   Grep  "override" in src/ (14 matches)
 *   Glob  "**\/*.ts" (142 files)
 *   Bash  "pnpm test" (exit 0, 18s)
 *   Write src/new-helper.ts (83 lines)
 *
 * Unknown / module tools fall back to
 *   <name>(<inputHint>) → <first-line-of-result clamped>
 */
export function summarizeToolCompletion(
  toolName: string,
  input: Record<string, unknown> | undefined,
  result: string,
  isError: boolean,
  opts: ToolCompletionOptions = {},
): string {
  if (isError) {
    return formatError(toolName, input, result);
  }

  const safeInput = input && typeof input === "object" ? input : undefined;

  switch (toolName) {
    case "Read":
      return formatRead(safeInput, result);
    case "Write":
      return formatWrite(safeInput, result);
    case "Edit":
      return formatEdit(safeInput, result);
    case "Grep":
      return formatGrep(safeInput, result);
    case "Glob":
      return formatGlob(safeInput, result);
    case "Bash":
      return formatBash(safeInput, result, opts.elapsedSeconds);
    default:
      return formatFallback(toolName, safeInput, result);
  }
}

function formatError(
  toolName: string,
  input: Record<string, unknown> | undefined,
  result: string,
): string {
  const hint = summarizeInput(input);
  const label = hint ? `${toolName} ${hint}` : toolName;

  // Special case: pi-ai / AJV "Validation failed for tool \"X\":\n  - path: detail"
  // formats the tool name on line 1 and the real cause on line 2. The default
  // first-line-only path truncates away the useful bit and the operator sees
  // `Write failed: Validation failed for to…` — unactionable. Capture the first
  // detail line and surface it alongside the tool name.
  //
  // AJV emits two forms:
  //   - `- : must have required property 'file_path'`   (root-level error)
  //   - `- old_string: must be string`                  (named-path error)
  // We strip the leading `:` on the root form (no path name) so the rendered
  // output reads naturally; we keep `old_string:` on the named form.
  const validationMatch = result.match(/Validation failed for tool "([^"]+)":\s*\n\s*-\s*([^\n]+)/);
  if (validationMatch) {
    const [, failedTool, detail] = validationMatch;
    const cleaned = (detail ?? "").trim().replace(/^:\s*/, "");
    return `${toolName} validation failed (${failedTool}): ${clamp(cleaned, 100)}`;
  }

  const firstLine = firstNonEmptyLine(result);
  return firstLine ? `${label} failed: ${clamp(firstLine, 80)}` : `${label} failed`;
}

function formatRead(input: Record<string, unknown> | undefined, result: string): string {
  const pathArg = getStringField(input, ["path", "file_path", "filePath"]);
  const label = pathArg ? `Read ${shortenPath(pathArg)}` : "Read";
  const lines = countLines(result);
  return lines > 0 ? `${label} (${lines} ${plural(lines, "line", "lines")})` : label;
}

function formatWrite(input: Record<string, unknown> | undefined, result: string): string {
  const pathArg = getStringField(input, ["path", "file_path", "filePath"]);
  const content = getStringField(input, ["content", "text"]);
  const label = pathArg ? `Write ${shortenPath(pathArg)}` : "Write";
  if (content) {
    const lines = countLines(content);
    return `${label} (${lines} ${plural(lines, "line", "lines")})`;
  }
  const firstLine = firstNonEmptyLine(result);
  return firstLine ? `${label}: ${clamp(firstLine, 60)}` : label;
}

function formatEdit(input: Record<string, unknown> | undefined, result: string): string {
  const pathArg = getStringField(input, ["path", "file_path", "filePath"]);
  const label = pathArg ? `Edit ${shortenPath(pathArg)}` : "Edit";
  const firstLine = firstNonEmptyLine(result);
  if (firstLine && /\d+\s+replacement/i.test(firstLine)) {
    return `${label} (${firstLine.trim()})`;
  }
  return label;
}

function formatGrep(input: Record<string, unknown> | undefined, result: string): string {
  const pattern = getStringField(input, ["pattern", "query"]);
  const searchPath = getStringField(input, ["path", "target"]);
  const patternPart = pattern ? `"${clamp(pattern, 40)}"` : "";
  const pathPart = searchPath ? ` in ${shortenPath(searchPath)}` : "";
  const label = `Grep${patternPart ? ` ${patternPart}` : ""}${pathPart}`;
  const matches = countMatches(result);
  if (matches == null) return label;
  return `${label} (${matches} ${plural(matches, "match", "matches")})`;
}

function formatGlob(input: Record<string, unknown> | undefined, result: string): string {
  const pattern = getStringField(input, ["pattern", "query"]);
  const label = pattern ? `Glob "${clamp(pattern, 40)}"` : "Glob";
  const files = countNonEmptyLines(result);
  if (files === 0) return `${label} (no files)`;
  return `${label} (${files} ${plural(files, "file", "files")})`;
}

function formatBash(
  input: Record<string, unknown> | undefined,
  result: string,
  elapsedSeconds: number | undefined,
): string {
  const command = getStringField(input, ["command", "cmd"]);
  const label = command ? `Bash "${clamp(command, 50)}"` : "Bash";
  const exitCode = extractExitCode(result);
  const parts: string[] = [];
  if (exitCode != null) parts.push(`exit ${exitCode}`);
  if (typeof elapsedSeconds === "number" && elapsedSeconds >= 0) {
    parts.push(formatElapsed(elapsedSeconds));
  }
  return parts.length > 0 ? `${label} (${parts.join(", ")})` : label;
}

function formatFallback(
  toolName: string,
  input: Record<string, unknown> | undefined,
  result: string,
): string {
  const hint = summarizeInput(input);
  const label = hint ? `${toolName}(${hint})` : toolName;
  const firstLine = firstNonEmptyLine(result);
  if (!firstLine) return label;
  return `${label} → ${clamp(firstLine, 60)}`;
}

function getStringField(
  input: Record<string, unknown> | undefined,
  keys: string[],
): string | undefined {
  if (!input) return undefined;
  for (const key of keys) {
    const value = input[key];
    if (typeof value === "string" && value.trim().length > 0) {
      return value.trim();
    }
  }
  return undefined;
}

function shortenPath(p: string): string {
  // Prefer basename when the path is long; keep full when short.
  if (p.length <= 50) return p;
  const base = path.basename(p);
  const dir = path.dirname(p);
  if (dir === "." || dir === "") return clamp(p, 50);
  const shortDir = dir.length > 20 ? `…/${path.basename(dir)}` : dir;
  return `${shortDir}/${base}`;
}

function firstNonEmptyLine(text: string): string | undefined {
  if (!text) return undefined;
  for (const raw of text.split(/\r?\n/)) {
    const trimmed = raw.trim();
    if (trimmed.length > 0) return trimmed;
  }
  return undefined;
}

function countLines(text: string): number {
  if (!text) return 0;
  // Count all newline-separated segments, including the last (no trailing newline).
  const lines = text.split(/\r?\n/);
  // Read output uses cat-style "    N |  content" — count those specifically when present.
  let catLines = 0;
  for (const line of lines) {
    if (/^\s*\d+[│|]/.test(line)) catLines++;
  }
  if (catLines > 0) return catLines;
  // Otherwise fall back to non-empty line count.
  return lines.filter((l) => l.length > 0).length;
}

function countNonEmptyLines(text: string): number {
  if (!text) return 0;
  return text.split(/\r?\n/).filter((l) => l.trim().length > 0).length;
}

function countMatches(text: string): number | undefined {
  if (!text) return 0;
  // Ripgrep/grep outputs can include a trailing "N matches" summary or
  // one "file:line:content" per match. Count non-empty lines minus any
  // header/footer boilerplate.
  const lines = text.split(/\r?\n/).filter((l) => l.trim().length > 0);
  if (lines.length === 0) return 0;
  // Heuristic: if a line ends with "matches" or "matched", trust the number in it.
  for (const line of lines) {
    const m = line.match(/^(\d+)\s+match(?:es)?\b/i);
    if (m) return Number(m[1]);
  }
  return lines.length;
}

function extractExitCode(result: string): number | undefined {
  if (!result) return undefined;
  const lines = result.split(/\r?\n/);
  for (let i = lines.length - 1; i >= 0; i--) {
    const m = lines[i]?.match(/exit(?:ed)?\s*(?:code)?\s*[:=]?\s*(-?\d+)/i);
    if (m) return Number(m[1]);
  }
  return undefined;
}

function formatElapsed(seconds: number): string {
  if (seconds < 1) return `${Math.round(seconds * 1000)}ms`;
  if (seconds < 60) return `${seconds.toFixed(seconds < 10 ? 1 : 0)}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds - m * 60);
  return `${m}m${s.toString().padStart(2, "0")}s`;
}

function plural(n: number, singular: string, plural: string): string {
  return n === 1 ? singular : plural;
}

function clamp(s: string, max: number): string {
  const trimmed = s.trim();
  if (trimmed.length <= max) return trimmed;
  return `${trimmed.slice(0, max - 1)}…`;
}
