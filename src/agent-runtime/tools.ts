import { globSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { Type, type Tool } from "@mariozechner/pi-ai";
import { toErrorMessage } from "../utils.js";

const DEFAULT_READ_LIMIT = 200;
const DEFAULT_GLOB_LIMIT = 200;
const DEFAULT_GREP_LIMIT = 200;

const ReadParameters = Type.Object(
  {
    path: Type.Optional(Type.String({ description: "File path to read" })),
    file_path: Type.Optional(Type.String({ description: "File path to read" })),
    filePath: Type.Optional(Type.String({ description: "File path to read" })),
    offset: Type.Optional(Type.Integer({ minimum: 0, description: "0-based line offset" })),
    start_line: Type.Optional(Type.Integer({ minimum: 1, description: "1-based starting line" })),
    startLine: Type.Optional(Type.Integer({ minimum: 1, description: "1-based starting line" })),
    limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 2000, description: "Lines to return" })),
    lines: Type.Optional(Type.Integer({ minimum: 1, maximum: 2000, description: "Lines to return" })),
    end_line: Type.Optional(Type.Integer({ minimum: 1, description: "1-based ending line (inclusive)" })),
  },
  { additionalProperties: true },
);

const GlobParameters = Type.Object(
  {
    pattern: Type.String({ description: "Glob pattern (e.g. src/**/*.ts)" }),
    path: Type.Optional(Type.String({ description: "Directory to search from" })),
    exclude: Type.Optional(Type.Array(Type.String(), { maxItems: 200 })),
    limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 5000 })),
  },
  { additionalProperties: true },
);

const GrepParameters = Type.Object(
  {
    pattern: Type.String({ description: "Regex pattern (or literal when literal=true)" }),
    path: Type.Optional(Type.String({ description: "Directory to search from" })),
    glob: Type.Optional(Type.String({ description: "File glob filter", default: "**/*" })),
    case_sensitive: Type.Optional(Type.Boolean()),
    caseSensitive: Type.Optional(Type.Boolean()),
    literal: Type.Optional(Type.Boolean()),
    max_matches: Type.Optional(Type.Integer({ minimum: 1, maximum: 10000 })),
    maxMatches: Type.Optional(Type.Integer({ minimum: 1, maximum: 10000 })),
  },
  { additionalProperties: true },
);

export const PI_AI_TOOL_DEFINITIONS: Tool[] = [
  {
    name: "Read",
    description: "Read a file with line numbers. Supports optional offset/start_line and limit.",
    parameters: ReadParameters,
  },
  {
    name: "Glob",
    description: "Find files by glob pattern.",
    parameters: GlobParameters,
  },
  {
    name: "Grep",
    description: "Search file contents by regex across matching files.",
    parameters: GrepParameters,
  },
];

export async function executeTool(
  name: string,
  args: Record<string, unknown>,
  cwd: string,
): Promise<string> {
  if (name === "Read") {
    return executeRead(args, cwd);
  }

  if (name === "Glob") {
    return executeGlob(args, cwd);
  }

  if (name === "Grep") {
    return executeGrep(args, cwd);
  }

  throw new Error(`Unsupported tool: ${name}`);
}

function executeRead(args: Record<string, unknown>, cwd: string): string {
  const inputPath = getString(args, ["path", "file_path", "filePath"]);
  if (!inputPath) {
    throw new Error("Read requires a file path");
  }

  const absolutePath = resolvePath(cwd, inputPath);
  const fileStats = statSync(absolutePath, { throwIfNoEntry: false });
  if (!fileStats || !fileStats.isFile()) {
    throw new Error(`Read path is not a file: ${inputPath}`);
  }

  const fileContent = readFileSync(absolutePath, "utf8");
  const lines = fileContent.split(/\r?\n/);
  const totalLines = lines.length;

  const explicitOffset = toNonNegativeInt(args["offset"]);
  const explicitStartLine = toPositiveInt(args["start_line"] ?? args["startLine"]);
  const explicitEndLine = toPositiveInt(args["end_line"]);

  let startOffset = explicitOffset ?? 0;
  if (explicitOffset == null && explicitStartLine != null) {
    startOffset = Math.max(0, explicitStartLine - 1);
  }

  let lineLimit = toPositiveInt(args["limit"] ?? args["lines"]) ?? DEFAULT_READ_LIMIT;
  if (explicitEndLine != null) {
    lineLimit = Math.max(1, explicitEndLine - startOffset);
  }

  if (startOffset >= totalLines) {
    return `No lines available at offset ${startOffset} in ${normalizeForDisplay(path.relative(cwd, absolutePath) || inputPath)}.`;
  }

  const selected = lines.slice(startOffset, startOffset + lineLimit);
  const maxLineNumber = startOffset + selected.length;
  const width = Math.max(1, String(maxLineNumber).length);

  const numbered = selected.map((line, index) => {
    const lineNumber = String(startOffset + index + 1).padStart(width, " ");
    return `${lineNumber} | ${line}`;
  });

  if (startOffset + selected.length < totalLines) {
    const remaining = totalLines - (startOffset + selected.length);
    numbered.push(`... (${remaining} more lines)`);
  }

  return numbered.join("\n");
}

function executeGlob(args: Record<string, unknown>, cwd: string): string {
  const pattern = getString(args, ["pattern"]);
  if (!pattern) {
    throw new Error("Glob requires a pattern");
  }

  const searchRootInput = getString(args, ["path"]) ?? ".";
  const searchRoot = resolvePath(cwd, searchRootInput);
  const searchRootStats = statSync(searchRoot, { throwIfNoEntry: false });
  if (!searchRootStats || !searchRootStats.isDirectory()) {
    throw new Error(`Glob path is not a directory: ${searchRootInput}`);
  }

  const exclude = normalizeStringArray(args["exclude"]);
  const limit = toPositiveInt(args["limit"]) ?? DEFAULT_GLOB_LIMIT;
  const rawMatches = globSync(pattern, {
    cwd: searchRoot,
    ...(exclude.length > 0 ? { exclude } : {}),
  });

  const sorted = rawMatches
    .map((match) => normalizeForDisplay(path.relative(cwd, path.resolve(searchRoot, match))))
    .sort((a, b) => a.localeCompare(b))
    .slice(0, limit);

  if (sorted.length === 0) {
    return "No files matched.";
  }

  return sorted.join("\n");
}

function executeGrep(args: Record<string, unknown>, cwd: string): string {
  const pattern = getString(args, ["pattern"]);
  if (!pattern) {
    throw new Error("Grep requires a pattern");
  }

  const searchRootInput = getString(args, ["path"]) ?? ".";
  const searchRoot = resolvePath(cwd, searchRootInput);
  const searchRootStats = statSync(searchRoot, { throwIfNoEntry: false });
  if (!searchRootStats || !searchRootStats.isDirectory()) {
    throw new Error(`Grep path is not a directory: ${searchRootInput}`);
  }

  const filePattern = getString(args, ["glob"]) ?? "**/*";
  const caseSensitive = toBoolean(args["case_sensitive"] ?? args["caseSensitive"]) ?? false;
  const literal = toBoolean(args["literal"]) ?? false;
  const limit = toPositiveInt(args["max_matches"] ?? args["maxMatches"]) ?? DEFAULT_GREP_LIMIT;

  const regexFlags = caseSensitive ? "g" : "gi";
  let matcher: RegExp;
  try {
    const source = literal ? escapeRegex(pattern) : pattern;
    matcher = new RegExp(source, regexFlags);
  } catch (error) {
    throw new Error(`Invalid grep pattern: ${toErrorMessage(error)}`);
  }

  const files = globSync(filePattern, {
    cwd: searchRoot,
    exclude: ["**/.git/**", "**/node_modules/**"],
  });

  const output: string[] = [];
  let reachedLimit = false;

  for (const file of files) {
    const absolutePath = path.resolve(searchRoot, file);
    const fileStats = statSync(absolutePath, { throwIfNoEntry: false });
    if (!fileStats || !fileStats.isFile()) {
      continue;
    }

    let fileContent: string;
    try {
      fileContent = readFileSync(absolutePath, "utf8");
    } catch {
      continue;
    }

    const lines = fileContent.split(/\r?\n/);
    for (let index = 0; index < lines.length; index++) {
      matcher.lastIndex = 0;
      if (!matcher.test(lines[index])) {
        continue;
      }

      const displayPath = normalizeForDisplay(path.relative(cwd, absolutePath));
      output.push(`${displayPath}:${index + 1}:${lines[index]}`);
      if (output.length >= limit) {
        reachedLimit = true;
        break;
      }
    }

    if (reachedLimit) {
      break;
    }
  }

  if (output.length === 0) {
    return "No matches found.";
  }

  if (reachedLimit) {
    output.push(`... (truncated to ${limit} matches)`);
  }

  return output.join("\n");
}

function resolvePath(cwd: string, targetPath: string): string {
  const root = path.resolve(cwd);
  const resolved = path.isAbsolute(targetPath)
    ? path.normalize(targetPath)
    : path.resolve(root, targetPath);
  const relative = path.relative(root, resolved);

  const isInsideRoot = relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
  if (!isInsideRoot) {
    throw new Error(`Path escapes repository root: ${targetPath}`);
  }

  return resolved;
}

function normalizeForDisplay(filePath: string): string {
  return filePath.split(path.sep).join("/");
}

function normalizeStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value
    .map((item) => (typeof item === "string" ? item.trim() : ""))
    .filter(Boolean);
}

function getString(obj: Record<string, unknown>, keys: string[]): string | undefined {
  for (const key of keys) {
    const value = obj[key];
    if (typeof value !== "string") {
      continue;
    }

    const trimmed = value.trim();
    if (trimmed) {
      return trimmed;
    }
  }

  return undefined;
}

function toPositiveInt(value: unknown): number | undefined {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 1) {
    return undefined;
  }

  return Math.floor(parsed);
}

function toNonNegativeInt(value: unknown): number | undefined {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) {
    return undefined;
  }

  return Math.floor(parsed);
}

function toBoolean(value: unknown): boolean | undefined {
  if (typeof value === "boolean") {
    return value;
  }

  return undefined;
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
