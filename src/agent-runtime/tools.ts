import { execFile, spawn } from "node:child_process";
import { globSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { promisify } from "node:util";
import { Type, type Tool } from "@mariozechner/pi-ai";
import { isRecord, toErrorMessage } from "../utils.js";

const execFileAsync = promisify(execFile);
const require = createRequire(import.meta.url);
const TSSERVER_PATH = require.resolve("typescript/lib/tsserver.js");

const DEFAULT_BASH_TIMEOUT = 120_000;
const MAX_BASH_TIMEOUT = 300_000;
const BASH_MAX_BUFFER = 64 * 1024 * 1024;

const DEFAULT_READ_LIMIT = 200;
const DEFAULT_GLOB_LIMIT = 200;
const DEFAULT_GREP_LIMIT = 200;
const DEFAULT_FIND_REFERENCES_LIMIT = 50;
const MAX_FIND_REFERENCES_LIMIT = 200;
const TSSERVER_TIMEOUT_MS = 10_000;
const TSSERVER_HEADER_SEPARATOR = Buffer.from("\r\n\r\n", "utf8");
const SUPPORTED_SEMANTIC_EXTENSIONS = new Set([".ts", ".tsx", ".js", ".jsx", ".mts", ".cts"]);

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

const BashParameters = Type.Object(
  {
    command: Type.String({ description: "Shell command to execute" }),
    timeout: Type.Optional(
      Type.Integer({
        minimum: 1000,
        maximum: 300000,
        description: "Timeout in ms (default 120000)",
      }),
    ),
  },
  { additionalProperties: true },
);

const WriteParameters = Type.Object(
  {
    file_path: Type.String({ description: "Absolute path to write to" }),
    content: Type.String({ description: "File content to write" }),
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

const GetFunctionBodyParameters = Type.Object(
  {
    name: Type.String({ description: "Function or method name to find" }),
    file_path: Type.Optional(Type.String({ description: "File to search in (searches repo if omitted)" })),
    language: Type.Optional(Type.String({ description: "Language hint (js, ts, py, go, java, rust, rb, php, cs)" })),
  },
  { additionalProperties: true },
);

const GetCallersParameters = Type.Object(
  {
    name: Type.String({ description: "Function or method name to find callers of" }),
    path: Type.Optional(Type.String({ description: "Directory to scope the search" })),
    max_results: Type.Optional(Type.Integer({ minimum: 1, maximum: 100, description: "Max results (default 20)" })),
  },
  { additionalProperties: true },
);

const GetCalleesParameters = Type.Object(
  {
    name: Type.String({ description: "Function or method name to analyze" }),
    file_path: Type.String({ description: "File containing the function" }),
  },
  { additionalProperties: true },
);

const SemanticPositionParameters = Type.Object(
  {
    file_path: Type.String({ description: "TypeScript/JavaScript file path" }),
    line: Type.Integer({ minimum: 1, description: "1-based line number" }),
    column: Type.Integer({ minimum: 1, description: "1-based column number" }),
  },
  { additionalProperties: true },
);

const FindReferencesParameters = Type.Object(
  {
    file_path: Type.String({ description: "TypeScript/JavaScript file path" }),
    line: Type.Integer({ minimum: 1, description: "1-based line number" }),
    column: Type.Integer({ minimum: 1, description: "1-based column number" }),
    max_results: Type.Optional(
      Type.Integer({
        minimum: 1,
        maximum: MAX_FIND_REFERENCES_LIMIT,
        description: `Max results to return (default ${DEFAULT_FIND_REFERENCES_LIMIT})`,
      }),
    ),
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
  {
    name: "Bash",
    description: "Execute a shell command and return its stdout+stderr.",
    parameters: BashParameters,
  },
  {
    name: "Write",
    description: "Write content to a file (creates parent directories as needed).",
    parameters: WriteParameters,
  },
  {
    name: "GetFunctionBody",
    description: "Find a function/method definition by name and return its body with surrounding context (~50 lines before and after).",
    parameters: GetFunctionBodyParameters,
  },
  {
    name: "GetCallers",
    description: "Find all call sites of a function/method across the codebase. Returns file:line:content for each call site.",
    parameters: GetCallersParameters,
  },
  {
    name: "GetCallees",
    description: "Given a function, list all functions/methods it calls. Returns deduplicated list of callee names.",
    parameters: GetCalleesParameters,
  },
  {
    name: "GoToDefinition",
    description: "Resolve the definition location for the symbol at a TypeScript/JavaScript position.",
    parameters: SemanticPositionParameters,
  },
  {
    name: "FindReferences",
    description: "Find symbol references at a TypeScript/JavaScript position using semantic analysis.",
    parameters: FindReferencesParameters,
  },
  {
    name: "TypeAtPosition",
    description: "Return the inferred or declared type for the symbol at a TypeScript/JavaScript position.",
    parameters: SemanticPositionParameters,
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

  if (name === "Bash") {
    return executeBash(args, cwd);
  }

  if (name === "Write") {
    return executeWrite(args, cwd);
  }

  if (name === "GetFunctionBody") {
    return executeGetFunctionBody(args, cwd);
  }

  if (name === "GetCallers") {
    return executeGetCallers(args, cwd);
  }

  if (name === "GetCallees") {
    return executeGetCallees(args, cwd);
  }

  if (name === "GoToDefinition") {
    return executeGoToDefinition(args, cwd);
  }

  if (name === "FindReferences") {
    return executeFindReferences(args, cwd);
  }

  if (name === "TypeAtPosition") {
    return executeTypeAtPosition(args, cwd);
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

async function executeBash(args: Record<string, unknown>, cwd: string): Promise<string> {
  const command = getString(args, ["command"]);
  if (!command) {
    throw new Error("Bash requires a command");
  }

  const timeout = Math.min(
    toPositiveInt(args["timeout"]) ?? DEFAULT_BASH_TIMEOUT,
    MAX_BASH_TIMEOUT,
  );

  try {
    const { stdout, stderr } = await execFileAsync("bash", ["-c", command], {
      cwd,
      encoding: "utf-8",
      timeout,
      maxBuffer: BASH_MAX_BUFFER,
    });

    const combined = [stdout, stderr].filter(Boolean).join("\n");
    return combined || "(no output)";
  } catch (error) {
    const err = error as Error & { stdout?: string; stderr?: string; code?: number | string };
    const combined = [err.stdout, err.stderr].filter(Boolean).join("\n");
    if (combined) {
      return combined;
    }
    throw error;
  }
}

function executeWrite(args: Record<string, unknown>, cwd: string): string {
  const filePath = getString(args, ["file_path", "filePath", "path"]);
  if (!filePath) {
    throw new Error("Write requires a file_path");
  }

  const content = args["content"];
  if (typeof content !== "string") {
    throw new Error("Write requires string content");
  }

  const absolutePath = resolvePath(cwd, filePath);
  mkdirSync(path.dirname(absolutePath), { recursive: true });
  writeFileSync(absolutePath, content, "utf-8");

  return `Wrote ${content.length} bytes to ${filePath}`;
}

interface TsServerLocation {
  file: string;
  start: { line: number; offset: number };
  end: { line: number; offset: number };
  lineText?: string;
}

interface TsServerReference extends TsServerLocation {
  isWriteAccess?: boolean;
}

interface TsServerQuickInfoBody {
  kind?: string;
  kindModifiers?: string;
  start?: { line: number; offset: number };
  end?: { line: number; offset: number };
  displayString?: string;
  documentation?: string;
}

interface TsServerResponse {
  type: "response";
  command?: string;
  request_seq?: number;
  success: boolean;
  message?: string;
  body?: unknown;
}

class TsServerSession {
  private readonly child;

  private readonly pending = new Map<number, {
    resolve: (response: TsServerResponse) => void;
    reject: (error: Error) => void;
    timeout: ReturnType<typeof setTimeout>;
  }>();

  private stdoutBuffer = Buffer.alloc(0);
  private stderrText = "";
  private nextSeq = 1;
  private closed = false;

  constructor(private readonly cwd: string) {
    this.child = spawn(process.execPath, [TSSERVER_PATH], {
      cwd,
      stdio: ["pipe", "pipe", "pipe"],
    });

    this.child.stdout?.on("data", (chunk: Buffer) => {
      this.stdoutBuffer = Buffer.concat([this.stdoutBuffer, chunk]);
      this.processStdoutBuffer();
    });

    this.child.stderr?.on("data", (chunk: Buffer) => {
      this.stderrText += chunk.toString("utf8");
    });

    this.child.on("error", (error) => {
      this.rejectAll(new Error(`tsserver process error: ${toErrorMessage(error)}`));
    });

    this.child.on("exit", (code, signal) => {
      if (this.pending.size === 0) {
        this.closed = true;
        return;
      }

      const reason = signal
        ? `tsserver exited from signal ${signal}`
        : `tsserver exited with code ${code ?? "unknown"}`;
      const stderr = this.stderrText.trim();
      this.rejectAll(new Error(stderr ? `${reason}: ${stderr}` : reason));
      this.closed = true;
    });
  }

  async close(): Promise<void> {
    if (this.closed) {
      return;
    }

    this.closed = true;
    this.child.kill();
    await new Promise<void>((resolve) => {
      this.child.once("exit", () => resolve());
      setTimeout(resolve, 200);
    });
  }

  async request<TBody = unknown>(
    command: string,
    args: Record<string, unknown>,
  ): Promise<{ success: boolean; body?: TBody; message?: string }> {
    if (this.closed) {
      throw new Error("tsserver session is closed");
    }

    const seq = this.nextSeq++;
    const payload = JSON.stringify({
      seq,
      type: "request",
      command,
      arguments: args,
    });

    const response = await new Promise<TsServerResponse>((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pending.delete(seq);
        reject(new Error(`tsserver ${command} timed out after ${TSSERVER_TIMEOUT_MS}ms`));
      }, TSSERVER_TIMEOUT_MS);

      this.pending.set(seq, { resolve, reject, timeout });
      if (!this.child.stdin) {
        clearTimeout(timeout);
        this.pending.delete(seq);
        reject(new Error(`tsserver ${command} write failed: stdin unavailable`));
        return;
      }

      this.child.stdin.write(`${payload}\n`, "utf8", (error) => {
        if (!error) {
          return;
        }

        const pending = this.pending.get(seq);
        if (!pending) {
          return;
        }

        clearTimeout(pending.timeout);
        this.pending.delete(seq);
        reject(new Error(`tsserver ${command} write failed: ${toErrorMessage(error)}`));
      });
    });

    return {
      success: response.success,
      body: response.body as TBody | undefined,
      message: response.message,
    };
  }

  private processStdoutBuffer(): void {
    while (true) {
      const headerEnd = this.stdoutBuffer.indexOf(TSSERVER_HEADER_SEPARATOR);
      if (headerEnd === -1) {
        return;
      }

      const header = this.stdoutBuffer.subarray(0, headerEnd).toString("utf8");
      const lengthMatch = header.match(/Content-Length:\s*(\d+)/i);
      if (!lengthMatch) {
        this.stdoutBuffer = this.stdoutBuffer.subarray(headerEnd + TSSERVER_HEADER_SEPARATOR.length);
        continue;
      }

      const bodyStart = headerEnd + TSSERVER_HEADER_SEPARATOR.length;
      const bodyLength = Number(lengthMatch[1]);
      const frameLength = bodyStart + bodyLength;
      if (this.stdoutBuffer.length < frameLength) {
        return;
      }

      const bodyText = this.stdoutBuffer.subarray(bodyStart, frameLength).toString("utf8");
      this.stdoutBuffer = this.stdoutBuffer.subarray(frameLength);

      let message: unknown;
      try {
        message = JSON.parse(bodyText);
      } catch {
        continue;
      }

      if (!isTsServerResponse(message) || typeof message.request_seq !== "number") {
        continue;
      }

      const pending = this.pending.get(message.request_seq);
      if (!pending) {
        continue;
      }

      clearTimeout(pending.timeout);
      this.pending.delete(message.request_seq);
      pending.resolve(message);
    }
  }

  private rejectAll(error: Error): void {
    for (const [seq, pending] of this.pending) {
      clearTimeout(pending.timeout);
      pending.reject(error);
      this.pending.delete(seq);
    }
  }
}

async function executeGoToDefinition(args: Record<string, unknown>, cwd: string): Promise<string> {
  const position = resolveSemanticPosition(args, cwd, "GoToDefinition");
  if (!isSupportedSemanticPath(position.absolutePath)) {
    return formatSemanticFailure("GoToDefinition", position, undefined);
  }
  const session = new TsServerSession(cwd);

  try {
    const openResult = await session.request("open", { file: position.absolutePath });
    if (!openResult.success) {
      return formatSemanticFailure("GoToDefinition", position, openResult.message);
    }

    const [quickInfo, definition] = await Promise.all([
      session.request<TsServerQuickInfoBody>("quickinfo", {
        file: position.absolutePath,
        line: position.line,
        offset: position.column,
      }),
      session.request<{ definitions?: TsServerLocation[] }>("definitionAndBoundSpan", {
        file: position.absolutePath,
        line: position.line,
        offset: position.column,
      }),
    ]);

    if (!definition.success) {
      return formatSemanticFailure("GoToDefinition", position, definition.message);
    }

    const definitions = Array.isArray(definition.body?.definitions)
      ? definition.body.definitions
      : [];
    if (definitions.length === 0) {
      return `No definition found at ${position.displayPath}:${position.line}:${position.column}.`;
    }

    const quickInfoBody = quickInfo.success ? quickInfo.body : undefined;
    const header = formatSemanticHeader(position, quickInfoBody);
    const lines = definitions.map((location) => formatTsServerLocation(cwd, location));
    return [...header, ...lines].join("\n");
  } finally {
    await session.close();
  }
}

async function executeFindReferences(args: Record<string, unknown>, cwd: string): Promise<string> {
  const position = resolveSemanticPosition(args, cwd, "FindReferences");
  if (!isSupportedSemanticPath(position.absolutePath)) {
    return formatSemanticFailure("FindReferences", position, undefined);
  }
  const maxResults = Math.min(
    toPositiveInt(args["max_results"] ?? args["maxResults"]) ?? DEFAULT_FIND_REFERENCES_LIMIT,
    MAX_FIND_REFERENCES_LIMIT,
  );
  const session = new TsServerSession(cwd);

  try {
    const openResult = await session.request("open", { file: position.absolutePath });
    if (!openResult.success) {
      return formatSemanticFailure("FindReferences", position, openResult.message);
    }

    const [quickInfo, definition, references] = await Promise.all([
      session.request<TsServerQuickInfoBody>("quickinfo", {
        file: position.absolutePath,
        line: position.line,
        offset: position.column,
      }),
      session.request<{ definitions?: TsServerLocation[] }>("definitionAndBoundSpan", {
        file: position.absolutePath,
        line: position.line,
        offset: position.column,
      }),
      session.request<{ refs?: TsServerReference[]; symbolName?: string }>("references", {
        file: position.absolutePath,
        line: position.line,
        offset: position.column,
      }),
    ]);

    if (!references.success) {
      return formatSemanticFailure("FindReferences", position, references.message);
    }

    const definitions = Array.isArray(definition.body?.definitions)
      ? definition.body.definitions
      : [];
    const refs = Array.isArray(references.body?.refs)
      ? references.body.refs
      : [];

    const filtered = refs.filter((reference) =>
      !definitions.some((definitionLocation) => isSameSemanticLocation(definitionLocation, reference)),
    );

    if (filtered.length === 0) {
      const symbolName = references.body?.symbolName
        ?? extractSymbolName(quickInfo.success ? quickInfo.body : undefined, position);
      return `No references found for "${symbolName}" in ${position.displayPath}:${position.line}:${position.column}.`;
    }

    const lines = filtered
      .slice(0, maxResults)
      .map((reference) => formatTsServerLocation(cwd, reference));

    if (filtered.length > maxResults) {
      lines.push(`... (truncated to ${maxResults} references)`);
    }

    return lines.join("\n");
  } finally {
    await session.close();
  }
}

async function executeTypeAtPosition(args: Record<string, unknown>, cwd: string): Promise<string> {
  const position = resolveSemanticPosition(args, cwd, "TypeAtPosition");
  if (!isSupportedSemanticPath(position.absolutePath)) {
    return formatSemanticFailure("TypeAtPosition", position, undefined);
  }
  const session = new TsServerSession(cwd);

  try {
    const openResult = await session.request("open", { file: position.absolutePath });
    if (!openResult.success) {
      return formatSemanticFailure("TypeAtPosition", position, openResult.message);
    }

    const quickInfo = await session.request<TsServerQuickInfoBody>("quickinfo", {
      file: position.absolutePath,
      line: position.line,
      offset: position.column,
    });

    if (!quickInfo.success) {
      return formatSemanticFailure("TypeAtPosition", position, quickInfo.message);
    }

    if (!quickInfo.body) {
      return `No symbol found at ${position.displayPath}:${position.line}:${position.column}.`;
    }

    const symbolName = extractSymbolName(quickInfo.body, position);
    const kind = quickInfo.body.kind ?? "unknown";
    const typeDisplay = normalizeTypeDisplay(quickInfo.body.displayString);

    return [
      `Symbol: ${symbolName}`,
      `Kind: ${kind}`,
      `Type: ${typeDisplay}`,
      `Location: ${position.displayPath}:${position.line}:${position.column}`,
    ].join("\n");
  } finally {
    await session.close();
  }
}

const FUNCTION_DEF_CONTEXT_LINES = 50;
const DEFAULT_GET_CALLERS_LIMIT = 20;

const TEXT_FILE_EXTENSIONS = new Set([
  "ts", "tsx", "js", "jsx", "mjs", "cjs", "mts", "cts",
  "py", "pyi", "pyw",
  "go",
  "java", "kt", "kts", "scala",
  "cs", "fs", "vb",
  "rs",
  "rb", "erb",
  "php",
  "c", "h", "cpp", "hpp", "cc", "cxx", "hxx",
  "swift", "m", "mm",
  "lua", "pl", "pm", "r", "R", "jl",
  "sh", "bash", "zsh", "fish",
  "sql", "graphql", "gql",
  "html", "htm", "xml", "xsl", "xslt", "svg",
  "css", "scss", "sass", "less",
  "json", "yaml", "yml", "toml", "ini", "cfg", "conf",
  "md", "txt", "rst", "adoc",
  "vue", "svelte", "astro",
  "tf", "hcl",
  "proto", "thrift", "avsc",
  "ex", "exs", "erl", "hrl",
  "hs", "lhs", "ml", "mli", "clj", "cljs", "cljc", "el", "lisp", "scm",
  "dart", "nim", "zig", "v",
]);

function extToLangHint(ext: string): string | undefined {
  switch (ext) {
    case "ts": case "tsx": case "mts": case "cts": return "ts";
    case "js": case "jsx": case "mjs": case "cjs": return "js";
    case "py": case "pyi": case "pyw": return "py";
    case "go": return "go";
    case "java": return "java";
    case "kt": case "kts": return "kotlin";
    case "cs": return "cs";
    case "rs": return "rust";
    case "rb": case "erb": return "rb";
    case "php": return "php";
    default: return undefined;
  }
}

// Generic patterns that match any function definition (used for body-end detection)
const GENERIC_FUNCTION_DEF_PATTERNS: RegExp[] = [
  /\bfunction\s+[\w$]+\s*\(/,
  /\b(?:const|let|var)\s+[\w$]+\s*=\s*(?:async\s+)?(?:\([^)]*\)|[\w$]+)\s*=>/,
  /^\s*(?:export\s+)?(?:async\s+)?function\s+[\w$]+/,
  /^\s*(?:async\s+)?def\s+[\w$]+\s*\(/,
  /^\s*class\s+[\w$]+\s*[:(]/,
  /^\s*func\s+[\w$]*\s*\(/,
  /^\s*func\s+\([^)]+\)\s+[\w$]+\s*\(/,
  /^\s*(?:pub\s+)?(?:async\s+)?fn\s+[\w$]+\s*[<(]/,
  /^\s*def\s+(?:self\.)?[\w$]+/,
  /^\s*(?:public|private|protected|static)?\s*function\s+[\w$]+\s*\(/,
];

const LANGUAGE_KEYWORDS = new Set([
  "if", "else", "for", "while", "do", "switch", "case", "catch", "throw",
  "return", "new", "delete", "typeof", "instanceof", "void", "in", "of",
  "try", "finally", "break", "continue", "default", "with", "yield", "await",
  "import", "export", "from", "as", "class", "extends", "super", "this",
  "const", "let", "var", "static", "async", "function",
  "print", "assert", "raise", "pass", "lambda", "elif", "except", "not", "and", "or", "is",
  "range", "len", "type", "list", "dict", "set", "tuple", "str", "int", "float", "bool",
  "fmt", "make", "append", "panic", "recover", "defer", "go", "select", "chan",
  "match", "enum", "impl", "trait", "pub", "mod", "use", "crate", "self", "Self",
  "require", "require_once", "include", "include_once", "echo", "isset", "unset", "empty",
  "puts", "attr_accessor", "attr_reader", "attr_writer",
  "System", "String", "Integer", "Boolean", "Object", "Array", "Map", "Set",
  "console", "Math", "JSON", "Promise", "Error", "RegExp", "Date", "Number",
]);

function buildFunctionDefPatterns(name: string, language?: string): RegExp[] {
  const escapedName = escapeRegex(name);
  const patterns: RegExp[] = [];

  const lang = (language ?? "").toLowerCase();

  // JS/TS patterns
  if (!lang || lang === "js" || lang === "ts" || lang === "javascript" || lang === "typescript") {
    patterns.push(
      new RegExp(`\\bfunction\\s+${escapedName}\\s*\\(`),
      new RegExp(`\\b(?:const|let|var)\\s+${escapedName}\\s*=`),
      new RegExp(`^\\s*(?:export\\s+)?(?:async\\s+)?function\\s+${escapedName}\\b`),
    );
  }

  // Python patterns
  if (!lang || lang === "py" || lang === "python") {
    patterns.push(
      new RegExp(`^\\s*(?:async\\s+)?def\\s+${escapedName}\\s*\\(`),
      new RegExp(`^\\s*class\\s+${escapedName}\\s*[:(]`),
    );
  }

  // Go patterns
  if (!lang || lang === "go" || lang === "golang") {
    patterns.push(
      new RegExp(`^\\s*func\\s+${escapedName}\\s*\\(`),
      new RegExp(`^\\s*func\\s+\\([^)]+\\)\\s+${escapedName}\\s*\\(`),
    );
  }

  // Java/Kotlin/C# patterns
  if (!lang || lang === "java" || lang === "kotlin" || lang === "kt" || lang === "cs" || lang === "csharp") {
    patterns.push(
      new RegExp(`(?:public|private|protected|internal|static|final|abstract|override|suspend|synchronized)\\s+.*\\b${escapedName}\\s*\\(`),
      new RegExp(`^\\s*(?:fun|void|int|long|double|float|boolean|char|byte|short|string|var|val|dynamic|object|Task|async)\\s+${escapedName}\\s*[<(]`),
    );
  }

  // Rust patterns
  if (!lang || lang === "rust" || lang === "rs") {
    patterns.push(
      new RegExp(`^\\s*(?:pub\\s+)?(?:async\\s+)?fn\\s+${escapedName}\\s*[<(]`),
    );
  }

  // Ruby patterns
  if (!lang || lang === "ruby" || lang === "rb") {
    patterns.push(
      new RegExp(`^\\s*def\\s+(?:self\\.)?${escapedName}\\b`),
    );
  }

  // PHP patterns
  if (!lang || lang === "php") {
    patterns.push(
      new RegExp(`^\\s*(?:public|private|protected|static)?\\s*function\\s+${escapedName}\\s*\\(`),
    );
  }

  return patterns;
}

function executeGetFunctionBody(args: Record<string, unknown>, cwd: string): string {
  const name = getString(args, ["name"]);
  if (!name) {
    throw new Error("GetFunctionBody requires a function name");
  }

  const filePath = getString(args, ["file_path", "filePath"]);
  const language = getString(args, ["language"]);
  const patterns = buildFunctionDefPatterns(name, language);

  const filesToSearch: string[] = [];

  if (filePath) {
    const absolutePath = resolvePath(cwd, filePath);
    const fileStats = statSync(absolutePath, { throwIfNoEntry: false });
    if (!fileStats || !fileStats.isFile()) {
      throw new Error(`GetFunctionBody file not found: ${filePath}`);
    }
    filesToSearch.push(absolutePath);
  } else {
    const allFiles = globSync("**/*", {
      cwd,
      exclude: ["**/.git/**", "**/node_modules/**", "**/dist/**", "**/build/**"],
    });
    for (const file of allFiles) {
      const ext = path.extname(file).slice(1).toLowerCase();
      if (!TEXT_FILE_EXTENSIONS.has(ext)) {
        continue;
      }
      const absolutePath = path.resolve(cwd, file);
      const fileStats = statSync(absolutePath, { throwIfNoEntry: false });
      if (fileStats && fileStats.isFile()) {
        filesToSearch.push(absolutePath);
      }
    }
  }

  for (const absolutePath of filesToSearch) {
    let fileContent: string;
    try {
      fileContent = readFileSync(absolutePath, "utf8");
    } catch {
      continue;
    }

    const lines = fileContent.split(/\r?\n/);
    for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
      const line = lines[lineIndex];
      const matched = patterns.some((pattern) => pattern.test(line));

      if (!matched) {
        continue;
      }

      const startOffset = Math.max(0, lineIndex - FUNCTION_DEF_CONTEXT_LINES);
      const endOffset = Math.min(lines.length, lineIndex + FUNCTION_DEF_CONTEXT_LINES + 1);
      const selected = lines.slice(startOffset, endOffset);

      const displayPath = normalizeForDisplay(path.relative(cwd, absolutePath));
      const maxLineNumber = startOffset + selected.length;
      const width = Math.max(1, String(maxLineNumber).length);

      const numbered = selected.map((l, idx) => {
        const lineNumber = String(startOffset + idx + 1).padStart(width, " ");
        return `${lineNumber} | ${l}`;
      });

      const header = `${displayPath}:${lineIndex + 1}`;
      return `${header}\n${numbered.join("\n")}`;
    }
  }

  return `Function "${name}" not found.`;
}

function executeGetCallers(args: Record<string, unknown>, cwd: string): string {
  const name = getString(args, ["name"]);
  if (!name) {
    throw new Error("GetCallers requires a function name");
  }

  const searchPath = getString(args, ["path"]) ?? ".";
  const searchRoot = resolvePath(cwd, searchPath);
  const searchRootStats = statSync(searchRoot, { throwIfNoEntry: false });
  if (!searchRootStats || !searchRootStats.isDirectory()) {
    throw new Error(`GetCallers path is not a directory: ${searchPath}`);
  }

  const maxResults = toPositiveInt(args["max_results"] ?? args["maxResults"]) ?? DEFAULT_GET_CALLERS_LIMIT;

  const callPattern = new RegExp(`(?<![\\w$])${escapeRegex(name)}\\s*\\(`, "g");

  const files = globSync("**/*", {
    cwd: searchRoot,
    exclude: ["**/.git/**", "**/node_modules/**", "**/dist/**", "**/build/**"],
  });

  const output: string[] = [];

  for (const file of files) {
    const absolutePath = path.resolve(searchRoot, file);
    const ext = path.extname(absolutePath).slice(1).toLowerCase();
    if (!TEXT_FILE_EXTENSIONS.has(ext)) {
      continue;
    }
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

    const langHint = extToLangHint(ext);
    const defPatterns = buildFunctionDefPatterns(name, langHint);

    const lines = fileContent.split(/\r?\n/);
    for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
      const line = lines[lineIndex];

      callPattern.lastIndex = 0;
      if (!callPattern.test(line)) {
        continue;
      }

      // Filter out definition lines
      const isDefinition = defPatterns.some((pattern) => pattern.test(line));
      if (isDefinition) {
        continue;
      }

      const displayPath = normalizeForDisplay(path.relative(cwd, absolutePath));
      output.push(`${displayPath}:${lineIndex + 1}:${line}`);

      if (output.length >= maxResults) {
        output.push(`... (truncated to ${maxResults} results)`);
        return output.join("\n");
      }
    }
  }

  if (output.length === 0) {
    return `No callers found for "${name}".`;
  }

  return output.join("\n");
}

function executeGetCallees(args: Record<string, unknown>, cwd: string): string {
  const name = getString(args, ["name"]);
  if (!name) {
    throw new Error("GetCallees requires a function name");
  }

  const filePath = getString(args, ["file_path", "filePath"]);
  if (!filePath) {
    throw new Error("GetCallees requires a file_path");
  }

  const absolutePath = resolvePath(cwd, filePath);
  const fileStats = statSync(absolutePath, { throwIfNoEntry: false });
  if (!fileStats || !fileStats.isFile()) {
    throw new Error(`GetCallees file not found: ${filePath}`);
  }

  let fileContent: string;
  try {
    fileContent = readFileSync(absolutePath, "utf8");
  } catch {
    throw new Error(`GetCallees could not read file: ${filePath}`);
  }

  // Find the function body — derive language from file extension for accuracy
  const fileExt = path.extname(absolutePath).slice(1).toLowerCase();
  const patterns = buildFunctionDefPatterns(name, extToLangHint(fileExt));
  const lines = fileContent.split(/\r?\n/);
  let functionStartLine = -1;

  for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
    const line = lines[lineIndex];
    const matched = patterns.some((pattern) => pattern.test(line));
    if (matched) {
      functionStartLine = lineIndex;
      break;
    }
  }

  if (functionStartLine === -1) {
    return `Function "${name}" not found in ${filePath}.`;
  }

  // Extract function body heuristically: from definition to the next function definition or 100 lines
  let bodyEnd = Math.min(lines.length, functionStartLine + 100);
  for (let i = functionStartLine + 1; i < bodyEnd; i++) {
    const isNextDef = GENERIC_FUNCTION_DEF_PATTERNS.some((p) => p.test(lines[i]));
    if (isNextDef) {
      bodyEnd = i;
      break;
    }
  }
  const bodyLines = lines.slice(functionStartLine, bodyEnd);
  const bodyText = bodyLines.join("\n");

  // Extract function calls
  const functionCallPattern = /\b([a-zA-Z_$][\w$]*)\s*\(/g;
  const methodCallPattern = /\.([a-zA-Z_$][\w$]*)\s*\(/g;

  const callees = new Set<string>();
  let fnMatch: RegExpExecArray | null;

  // biome-ignore lint/suspicious/noAssignInExpressions: regex exec loop
  while ((fnMatch = functionCallPattern.exec(bodyText)) !== null) {
    const calleeName = fnMatch[1];
    if (!LANGUAGE_KEYWORDS.has(calleeName) && calleeName !== name) {
      callees.add(calleeName);
    }
  }

  // biome-ignore lint/suspicious/noAssignInExpressions: regex exec loop
  while ((fnMatch = methodCallPattern.exec(bodyText)) !== null) {
    const calleeName = fnMatch[1];
    if (!LANGUAGE_KEYWORDS.has(calleeName)) {
      callees.add(calleeName);
    }
  }

  if (callees.size === 0) {
    return `No callees found in function "${name}".`;
  }

  const sorted = [...callees].sort((a, b) => a.localeCompare(b));
  return sorted.join("\n");
}

function resolveSemanticPosition(
  args: Record<string, unknown>,
  cwd: string,
  toolName: string,
): {
  absolutePath: string;
  displayPath: string;
  line: number;
  column: number;
} {
  const filePath = getString(args, ["file_path", "filePath", "path"]);
  if (!filePath) {
    throw new Error(`${toolName} requires a file_path`);
  }

  const absolutePath = resolvePath(cwd, filePath);
  const fileStats = statSync(absolutePath, { throwIfNoEntry: false });
  if (!fileStats || !fileStats.isFile()) {
    throw new Error(`${toolName} file not found: ${filePath}`);
  }

  const line = toPositiveInt(args["line"]);
  const column = toPositiveInt(args["column"]);
  if (line == null || column == null) {
    throw new Error(`${toolName} requires 1-based line and column`);
  }

  return {
    absolutePath,
    displayPath: normalizeForDisplay(path.relative(cwd, absolutePath)),
    line,
    column,
  };
}

function formatSemanticFailure(
  toolName: "GoToDefinition" | "FindReferences" | "TypeAtPosition",
  position: { absolutePath: string; displayPath: string; line: number; column: number },
  message: string | undefined,
): string {
  const extension = path.extname(position.absolutePath).toLowerCase();
  if (!SUPPORTED_SEMANTIC_EXTENSIONS.has(extension)) {
    return [
      `Semantic navigation is only supported for TypeScript/JavaScript files (.ts, .tsx, .js, .jsx, .mts, .cts).`,
      `File: ${position.displayPath}`,
    ].join("\n");
  }

  const normalizedMessage = (message ?? "").trim();
  if (!normalizedMessage) {
    return `No symbol found at ${position.displayPath}:${position.line}:${position.column}.`;
  }

  if (/no project/i.test(normalizedMessage)) {
    return `Semantic navigation could not resolve a TypeScript/JavaScript project for ${position.displayPath}.`;
  }

  if (/no content available|no references available|not found/i.test(normalizedMessage)) {
    return `No symbol found at ${position.displayPath}:${position.line}:${position.column}.`;
  }

  return `${toolName} failed at ${position.displayPath}:${position.line}:${position.column}: ${normalizedMessage}`;
}

function formatSemanticHeader(
  position: { absolutePath: string; displayPath: string; line: number; column: number },
  quickInfo: TsServerQuickInfoBody | undefined,
): string[] {
  const symbolName = extractSymbolName(quickInfo, {
    absolutePath: position.absolutePath,
    displayPath: position.displayPath,
    line: position.line,
    column: position.column,
  });
  const kind = quickInfo?.kind ?? "unknown";
  return [
    `Symbol: ${symbolName}`,
    `Kind: ${kind}`,
  ];
}

function extractSymbolName(
  quickInfo: TsServerQuickInfoBody | undefined,
  position: { absolutePath?: string; displayPath: string; line: number; column: number },
): string {
  const textFromSpan = quickInfo?.start && quickInfo?.end && position.absolutePath
    ? readSpanText(position.absolutePath, quickInfo.start, quickInfo.end)
    : undefined;
  if (textFromSpan) {
    return textFromSpan;
  }

  const display = quickInfo?.displayString?.split("\n")[0]?.trim();
  if (display) {
    const strippedPrefix = display.replace(/^\([^)]*\)\s*/, "");
    const match = strippedPrefix.match(/[A-Za-z_$][\w$]*/);
    if (match) {
      return match[0];
    }
  }

  return `${position.displayPath}:${position.line}:${position.column}`;
}

function normalizeTypeDisplay(displayString: string | undefined): string {
  const normalized = displayString?.split("\n").map((line) => line.trim()).filter(Boolean).join(" | ");
  return normalized && normalized.length > 0 ? normalized : "unknown";
}

function formatTsServerLocation(cwd: string, location: TsServerLocation): string {
  const displayPath = normalizeForDisplay(path.relative(cwd, location.file));
  const snippet = normalizeLocationSnippet(location.file, location.start.line, location.lineText);
  return `${displayPath}:${location.start.line}:${location.start.offset}:${snippet}`;
}

function normalizeLocationSnippet(
  absolutePath: string,
  lineNumber: number,
  fallback: string | undefined,
): string {
  const rawLine = fallback ?? readLineSnippet(absolutePath, lineNumber);
  return rawLine.replace(/\s+/g, " ").trim().slice(0, 200);
}

function readLineSnippet(absolutePath: string, lineNumber: number): string {
  try {
    const fileContent = readFileSync(absolutePath, "utf8");
    const lines = fileContent.split(/\r?\n/);
    return lines[lineNumber - 1] ?? "";
  } catch {
    return "";
  }
}

function readSpanText(
  absolutePath: string,
  start: { line: number; offset: number },
  end: { line: number; offset: number },
): string | undefined {
  try {
    const fileContent = readFileSync(absolutePath, "utf8");
    const lines = fileContent.split(/\r?\n/);
    if (start.line !== end.line) {
      return lines[start.line - 1]?.trim();
    }
    const line = lines[start.line - 1];
    if (line == null) {
      return undefined;
    }
    return line.slice(Math.max(0, start.offset - 1), Math.max(0, end.offset - 1)).trim() || undefined;
  } catch {
    return undefined;
  }
}

function isSameSemanticLocation(left: TsServerLocation, right: TsServerLocation): boolean {
  return path.normalize(left.file) === path.normalize(right.file)
    && left.start.line === right.start.line
    && left.start.offset === right.start.offset
    && left.end.line === right.end.line
    && left.end.offset === right.end.offset;
}

function isTsServerResponse(value: unknown): value is TsServerResponse {
  return isRecord(value)
    && value["type"] === "response"
    && typeof value["success"] === "boolean";
}

function isSupportedSemanticPath(absolutePath: string): boolean {
  return SUPPORTED_SEMANTIC_EXTENSIONS.has(path.extname(absolutePath).toLowerCase());
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
