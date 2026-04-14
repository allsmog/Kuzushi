import { execFile } from "node:child_process";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { executeTool } from "../agent-runtime/tools.js";
import { createSimpleTextIndexProvider } from "./simple-index.js";
import type {
  CodeIntelligenceProvider,
  ImportGraphEdge,
  IndexedTextMatch,
  SemanticLocation,
  SemanticPosition,
  SymbolLookupMatch,
  SymbolLookupQuery,
} from "./types.js";

const execFileAsync = promisify(execFile);
const IMPORT_SCAN_EXTENSIONS = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".mts",
  ".cts",
  ".py",
  ".go",
]);
const IMPORT_SKIP_DIRS = new Set([
  ".git",
  ".kuzushi",
  "node_modules",
  "dist",
  "build",
  "coverage",
  "vendor",
  "target",
  ".next",
]);

const providerCache = new Map<string, Promise<CodeIntelligenceProvider>>();

export async function getCodeIntelligenceProvider(repoRoot: string): Promise<CodeIntelligenceProvider> {
  const scopeKey = await resolveRepoScopeKey(repoRoot);
  const cacheKey = `${repoRoot}\x00${scopeKey}`;
  const existing = providerCache.get(cacheKey);
  if (existing) {
    return existing;
  }

  const created = createProvider(repoRoot, scopeKey);
  providerCache.set(cacheKey, created);
  return created;
}

async function createProvider(repoRoot: string, scopeKey: string): Promise<CodeIntelligenceProvider> {
  const fallback = await createSimpleTextIndexProvider(repoRoot);
  return new CachedCodeIntelligenceProvider(repoRoot, scopeKey, fallback);
}

async function resolveRepoScopeKey(repoRoot: string): Promise<string> {
  try {
    const [{ stdout: headStdout }, dirtyResult] = await Promise.all([
      execFileAsync("git", ["rev-parse", "HEAD"], { cwd: repoRoot }),
      execFileAsync("git", ["status", "--porcelain"], { cwd: repoRoot }).catch(() => ({ stdout: "" })),
    ]);
    const head = headStdout.trim() || "unknown";
    const dirty = dirtyResult.stdout.trim().length > 0 ? ":dirty" : "";
    return `${head}${dirty}`;
  } catch {
    return `workspace:${repoRoot}`;
  }
}

class CachedCodeIntelligenceProvider implements CodeIntelligenceProvider {
  readonly kind = "cached-code-intelligence";

  private readonly definitionCache = new Map<string, Promise<SemanticLocation[]>>();
  private readonly referenceCache = new Map<string, Promise<SemanticLocation[]>>();
  private readonly typeCache = new Map<string, Promise<SemanticLocation | undefined>>();
  private readonly importGraphCache = new Map<string, Promise<ImportGraphEdge[]>>();
  private readonly callersCache = new Map<string, Promise<string[]>>();
  private readonly calleesCache = new Map<string, Promise<string[]>>();

  constructor(
    private readonly repoRoot: string,
    readonly scopeKey: string,
    private readonly fallback: Awaited<ReturnType<typeof createSimpleTextIndexProvider>>,
  ) {}

  async searchText(query: string, options?: { maxResults?: number }): Promise<IndexedTextMatch[]> {
    return this.fallback.searchText(query, options);
  }

  async getSnippet(filePath: string, line: number): Promise<string | undefined> {
    return this.fallback.getSnippet(filePath, line);
  }

  async findSymbol(query: SymbolLookupQuery): Promise<SymbolLookupMatch[]> {
    return this.fallback.findSymbol(query);
  }

  async getDiffSlice(base: string): Promise<{ base: string; changedFiles: string[] }> {
    return this.fallback.getDiffSlice(base);
  }

  async getDefinitions(position: SemanticPosition): Promise<SemanticLocation[]> {
    const key = `${position.filePath}:${position.line}:${position.column}`;
    const cached = this.definitionCache.get(key);
    if (cached) {
      return cached;
    }
    const created = this.resolveDefinitions(position);
    this.definitionCache.set(key, created);
    return created;
  }

  async getReferences(
    position: SemanticPosition,
    options: { maxResults?: number } = {},
  ): Promise<SemanticLocation[]> {
    const key = `${position.filePath}:${position.line}:${position.column}:${options.maxResults ?? 50}`;
    const cached = this.referenceCache.get(key);
    if (cached) {
      return cached;
    }
    const created = this.resolveReferences(position, options.maxResults);
    this.referenceCache.set(key, created);
    return created;
  }

  async getTypeAtPosition(position: SemanticPosition): Promise<SemanticLocation | undefined> {
    const key = `${position.filePath}:${position.line}:${position.column}`;
    const cached = this.typeCache.get(key);
    if (cached) {
      return cached;
    }
    const created = this.resolveTypeAtPosition(position);
    this.typeCache.set(key, created);
    return created;
  }

  async getImportGraph(): Promise<ImportGraphEdge[]> {
    const cacheKey = "imports";
    const cached = this.importGraphCache.get(cacheKey);
    if (cached) {
      return cached;
    }
    const created = collectImportGraph(this.repoRoot);
    this.importGraphCache.set(cacheKey, created);
    return created;
  }

  async getCallers(args: {
    functionName: string;
    searchPath?: string;
    maxResults?: number;
  }): Promise<string[]> {
    const key = `${args.functionName}:${args.searchPath ?? "."}:${args.maxResults ?? 20}`;
    const cached = this.callersCache.get(key);
    if (cached) {
      return cached;
    }
    const created = this.resolveNameList("GetCallers", {
      name: args.functionName,
      path: args.searchPath ?? ".",
      max_results: args.maxResults ?? 20,
    });
    this.callersCache.set(key, created);
    return created;
  }

  async getCallees(args: {
    functionName: string;
    filePath: string;
  }): Promise<string[]> {
    const key = `${args.functionName}:${args.filePath}`;
    const cached = this.calleesCache.get(key);
    if (cached) {
      return cached;
    }
    const created = this.resolveNameList("GetCallees", {
      name: args.functionName,
      file_path: args.filePath,
    });
    this.calleesCache.set(key, created);
    return created;
  }

  private async resolveDefinitions(position: SemanticPosition): Promise<SemanticLocation[]> {
    const output = await executeTool("GoToDefinition", normalizeSemanticArgs(position), this.repoRoot);
    return parseSemanticLocations(output);
  }

  private async resolveReferences(
    position: SemanticPosition,
    maxResults?: number,
  ): Promise<SemanticLocation[]> {
    const output = await executeTool("FindReferences", {
      ...normalizeSemanticArgs(position),
      ...(maxResults ? { max_results: maxResults } : {}),
    }, this.repoRoot);
    return parseSemanticLocations(output);
  }

  private async resolveTypeAtPosition(position: SemanticPosition): Promise<SemanticLocation | undefined> {
    const output = await executeTool("TypeAtPosition", normalizeSemanticArgs(position), this.repoRoot);
    return parseTypeAtPosition(output);
  }

  private async resolveNameList(toolName: "GetCallers" | "GetCallees", args: Record<string, unknown>): Promise<string[]> {
    const output = await executeTool(toolName, args, this.repoRoot);
    return output
      .split(/\r?\n/u)
      .map((line) => line.trim())
      .filter((line) => line.length > 0 && !line.startsWith("No "));
  }
}

function normalizeSemanticArgs(position: SemanticPosition): Record<string, unknown> {
  return {
    file_path: position.filePath,
    line: position.line,
    column: position.column,
  };
}

function parseSemanticLocations(output: string): SemanticLocation[] {
  const locations: SemanticLocation[] = [];
  for (const line of output.split(/\r?\n/u)) {
    const match = line.match(/^(.+):(\d+):(\d+):(.*)$/u);
    if (!match) {
      continue;
    }
    locations.push({
      filePath: match[1],
      line: Number(match[2]),
      column: Number(match[3]),
      snippet: match[4]?.trim() || undefined,
    });
  }
  return locations;
}

function parseTypeAtPosition(output: string): SemanticLocation | undefined {
  const fileMatch = output.match(/^Location:\s+(.+):(\d+):(\d+)$/m);
  if (!fileMatch) {
    return undefined;
  }

  const symbol = output.match(/^Symbol:\s+(.+)$/m)?.[1]?.trim();
  const kind = output.match(/^Kind:\s+(.+)$/m)?.[1]?.trim();
  const type = output.match(/^Type:\s+(.+)$/m)?.[1]?.trim();

  return {
    filePath: fileMatch[1],
    line: Number(fileMatch[2]),
    column: Number(fileMatch[3]),
    symbol,
    kind,
    type,
  };
}

async function collectImportGraph(repoRoot: string): Promise<ImportGraphEdge[]> {
  const files: string[] = [];
  await walkImportFiles(repoRoot, repoRoot, files);

  const edges: ImportGraphEdge[] = [];
  for (const relativePath of files) {
    const absolutePath = path.join(repoRoot, relativePath);
    let content = "";
    try {
      content = await readFile(absolutePath, "utf-8");
    } catch {
      continue;
    }

    for (const importedPath of extractImportTargets(relativePath, content)) {
      edges.push({
        fromFilePath: relativePath,
        toPath: importedPath,
      });
    }
  }

  return edges;
}

async function walkImportFiles(
  repoRoot: string,
  currentDir: string,
  files: string[],
): Promise<void> {
  const entries = await readdir(currentDir, { withFileTypes: true });
  for (const entry of entries) {
    const absolutePath = path.join(currentDir, entry.name);
    if (entry.isDirectory()) {
      if (IMPORT_SKIP_DIRS.has(entry.name)) {
        continue;
      }
      await walkImportFiles(repoRoot, absolutePath, files);
      continue;
    }

    if (!entry.isFile()) {
      continue;
    }

    if (!IMPORT_SCAN_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
      continue;
    }

    files.push(path.relative(repoRoot, absolutePath).replace(/\\/g, "/"));
  }
}

function extractImportTargets(filePath: string, content: string): string[] {
  const extension = path.extname(filePath).toLowerCase();
  const targets = new Set<string>();
  const patterns = extension === ".py"
    ? [
        /^\s*import\s+([A-Za-z0-9_.,\s]+)/gmu,
        /^\s*from\s+([A-Za-z0-9_./]+)\s+import\s+/gmu,
      ]
    : extension === ".go"
      ? [
          /^\s*import\s+"([^"]+)"/gmu,
          /^\s*"([^"]+)"\s*$/gmu,
        ]
      : [
          /import\s+(?:[^'"]+\s+from\s+)?['"]([^'"]+)['"]/gmu,
          /require\(\s*['"]([^'"]+)['"]\s*\)/gmu,
        ];

  for (const pattern of patterns) {
    for (const match of content.matchAll(pattern)) {
      const rawTarget = match[1]?.trim();
      if (!rawTarget) {
        continue;
      }

      if (extension === ".py" && pattern.source.startsWith("^\\s*import")) {
        for (const part of rawTarget.split(",")) {
          const normalized = part.trim().split(/\s+/u)[0];
          if (normalized) {
            targets.add(normalized);
          }
        }
        continue;
      }

      targets.add(rawTarget);
    }
  }

  return [...targets];
}

export const __codeIntelligenceInternals = {
  parseSemanticLocations,
  parseTypeAtPosition,
  resolveRepoScopeKey,
  extractImportTargets,
};
