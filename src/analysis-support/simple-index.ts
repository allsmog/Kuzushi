import { execFile } from "node:child_process";
import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import type {
  DiffSlice,
  DiffSlicer,
  IndexedTextMatch,
  IndexProvider,
  SymbolLookup,
  SymbolLookupMatch,
  SymbolLookupQuery,
} from "./types.js";

const execFileAsync = promisify(execFile);
const SOURCE_EXTENSIONS = new Set([
  ".c",
  ".cc",
  ".cpp",
  ".cs",
  ".go",
  ".h",
  ".hpp",
  ".java",
  ".js",
  ".jsx",
  ".mjs",
  ".py",
  ".rb",
  ".rs",
  ".sql",
  ".swift",
  ".ts",
  ".tsx",
]);
const SKIP_DIRS = new Set([
  ".git",
  ".kuzushi",
  ".next",
  ".turbo",
  "build",
  "coverage",
  "dist",
  "node_modules",
  "out",
  "target",
  "vendor",
]);
const MAX_FILE_SIZE_BYTES = 1_000_000;
const MAX_INDEXED_FILES = 2_500;

interface IndexedFile {
  filePath: string;
  content: string;
  lines: string[];
}

export class SimpleTextIndexProvider implements IndexProvider, SymbolLookup, DiffSlicer {
  readonly kind = "simple-text-index";

  private constructor(
    private readonly repoRoot: string,
    private readonly files: IndexedFile[],
  ) {}

  static async create(repoRoot: string): Promise<SimpleTextIndexProvider> {
    const files = await collectIndexedFiles(repoRoot);
    return new SimpleTextIndexProvider(repoRoot, files);
  }

  async searchText(
    query: string,
    options: { maxResults?: number } = {},
  ): Promise<IndexedTextMatch[]> {
    const needle = query.trim();
    if (!needle) {
      return [];
    }

    const loweredNeedle = needle.toLowerCase();
    const matches: IndexedTextMatch[] = [];
    for (const file of this.files) {
      for (let index = 0; index < file.lines.length; index += 1) {
        const line = file.lines[index];
        if (!line.toLowerCase().includes(loweredNeedle)) {
          continue;
        }
        matches.push({
          filePath: file.filePath,
          line: index + 1,
          snippet: line.trim(),
        });
        if (matches.length >= (options.maxResults ?? 20)) {
          return matches;
        }
      }
    }

    return matches;
  }

  async getSnippet(filePath: string, line: number): Promise<string | undefined> {
    const normalized = normalizeRelativePath(filePath);
    const file = this.files.find((entry) => entry.filePath === normalized);
    if (!file) {
      return undefined;
    }
    if (!Number.isFinite(line) || line < 1 || line > file.lines.length) {
      return undefined;
    }
    return file.lines[line - 1]?.trim() || undefined;
  }

  async findSymbol(query: SymbolLookupQuery): Promise<SymbolLookupMatch[]> {
    const rawSymbol = query.symbol.trim();
    if (!rawSymbol) {
      return [];
    }

    const baseSymbol = normalizeSymbolBaseName(rawSymbol);
    const symbolPattern = buildSymbolPattern(baseSymbol);
    const receiverTokens = splitReceiverTokens(query.receiverHint);
    const matches: SymbolLookupMatch[] = [];

    for (const file of this.files) {
      const fileReceiverMatched =
        receiverTokens.length > 0 && receiverTokens.some((token) => file.content.includes(token));

      for (let index = 0; index < file.lines.length; index += 1) {
        const line = file.lines[index];
        if (!symbolPattern.test(line)) {
          continue;
        }

        const receiverMatched =
          fileReceiverMatched || receiverTokens.some((token) => line.includes(token));
        const arityHint = estimateArityHint(line, baseSymbol);
        const confidence = estimateMatchConfidence(line, baseSymbol, receiverMatched);
        matches.push({
          filePath: file.filePath,
          line: index + 1,
          snippet: line.trim(),
          symbol: baseSymbol,
          confidence,
          receiverMatched,
          arityHint,
        });
        if (matches.length >= (query.maxResults ?? 20)) {
          return matches.sort((a, b) => b.confidence - a.confidence);
        }
      }
    }

    return matches.sort((a, b) => b.confidence - a.confidence);
  }

  async getDiffSlice(base: string): Promise<DiffSlice> {
    const trimmedBase = base.trim();
    if (!trimmedBase) {
      return { base: "", changedFiles: [] };
    }

    try {
      const changedFiles = new Set<string>();
      for (const output of await Promise.all([
        runGitNameOnly(this.repoRoot, ["diff", "--name-only", `${trimmedBase}...HEAD`]),
        runGitNameOnly(this.repoRoot, ["diff", "--name-only", trimmedBase]),
        runGitNameOnly(this.repoRoot, ["ls-files", "--others", "--exclude-standard"]),
      ])) {
        for (const filePath of output) {
          changedFiles.add(filePath);
        }
      }

      return {
        base: trimmedBase,
        changedFiles: [...changedFiles].sort((a, b) => a.localeCompare(b)),
      };
    } catch {
      return {
        base: trimmedBase,
        changedFiles: [],
      };
    }
  }
}

function normalizeRelativePath(filePath: string): string {
  return filePath.replace(/\\/g, "/").replace(/^\/+/, "");
}

function normalizeSymbolBaseName(symbol: string): string {
  const normalized = symbol.trim().replace(/[`"'()]/g, "");
  const split = normalized.split(/[./:\\]/u).filter(Boolean);
  return split[split.length - 1] ?? normalized;
}

function buildSymbolPattern(symbol: string): RegExp {
  const escaped = symbol.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(^|[^A-Za-z0-9_])${escaped}([^A-Za-z0-9_]|$)`);
}

function splitReceiverTokens(receiverHint: string | null | undefined): string[] {
  if (!receiverHint) {
    return [];
  }

  return receiverHint
    .split(/[./:\\]/u)
    .map((token) => token.trim())
    .filter((token) => token.length >= 2);
}

function estimateMatchConfidence(
  line: string,
  baseSymbol: string,
  receiverMatched: boolean,
): number {
  let score = 0.45;
  if (line.includes(`${baseSymbol}(`) || line.includes(`.${baseSymbol}(`)) {
    score += 0.3;
  }
  if (
    line.includes(`function ${baseSymbol}`) ||
    line.includes(`def ${baseSymbol}`) ||
    line.includes(`func ${baseSymbol}`)
  ) {
    score += 0.15;
  }
  if (receiverMatched) {
    score += 0.1;
  }
  return Math.min(1, score);
}

function estimateArityHint(line: string, baseSymbol: string): number | undefined {
  const escaped = baseSymbol.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const callLike = new RegExp(`${escaped}\\s*\\(([^)]*)\\)`);
  const match = line.match(callLike);
  if (!match) {
    return undefined;
  }

  const body = match[1]?.trim() ?? "";
  if (!body) {
    return 0;
  }

  const parts = body
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
  return parts.length;
}

async function collectIndexedFiles(repoRoot: string): Promise<IndexedFile[]> {
  const files: IndexedFile[] = [];
  await walkDirectory(repoRoot, repoRoot, files);
  return files;
}

async function walkDirectory(
  repoRoot: string,
  currentDir: string,
  files: IndexedFile[],
): Promise<void> {
  if (files.length >= MAX_INDEXED_FILES) {
    return;
  }

  const entries = await readdir(currentDir, { withFileTypes: true });
  for (const entry of entries) {
    if (files.length >= MAX_INDEXED_FILES) {
      return;
    }

    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) {
        continue;
      }
      await walkDirectory(repoRoot, path.join(currentDir, entry.name), files);
      continue;
    }

    if (!entry.isFile()) {
      continue;
    }

    const extension = path.extname(entry.name).toLowerCase();
    if (!SOURCE_EXTENSIONS.has(extension)) {
      continue;
    }

    const absolutePath = path.join(currentDir, entry.name);
    const metadata = await stat(absolutePath);
    if (metadata.size > MAX_FILE_SIZE_BYTES) {
      continue;
    }

    const content = await readFile(absolutePath, "utf-8");
    files.push({
      filePath: normalizeRelativePath(path.relative(repoRoot, absolutePath)),
      content,
      lines: content.split(/\r?\n/u),
    });
  }
}

export async function createSimpleTextIndexProvider(
  repoRoot: string,
): Promise<SimpleTextIndexProvider> {
  return SimpleTextIndexProvider.create(repoRoot);
}

async function runGitNameOnly(repoRoot: string, args: string[]): Promise<string[]> {
  try {
    const { stdout } = await execFileAsync("git", args, { cwd: repoRoot });
    return stdout
      .split(/\r?\n/u)
      .map((line) => normalizeRelativePath(line))
      .filter(Boolean);
  } catch {
    return [];
  }
}
