import { spawn } from "node:child_process";
import {
  type Dirent,
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { resolveCodeQLBinary } from "../../scanners/resolve-codeql.js";
import { runCodeQL, selectFindings } from "../../scanners/run-codeql.js";
import type { Finding } from "../../scanners/types.js";
import { isRecord, toErrorMessage } from "../../utils.js";
import type { ExecutionContext } from "../types.js";
import type { TaintIrisNextCweCatalogEntry } from "./cwe-reference.js";
import type {
  TaintIrisNextEvidence,
  TaintIrisNextEvidenceConfidence,
  TaintIrisNextEvidenceResult,
  TaintIrisNextPlan,
} from "./types.js";

const RG_IGNORE_GLOBS = [
  "!.git/**",
  "!.kuzushi/**",
  "!node_modules/**",
  "!vendor/**",
  "!dist/**",
  "!build/**",
  "!coverage/**",
  "!.next/**",
  "!.turbo/**",
  "!target/**",
  "!__pycache__/**",
];

const LANGUAGE_BY_EXTENSION = new Map<string, string>([
  [".c", "c"],
  [".cc", "cpp"],
  [".cpp", "cpp"],
  [".cs", "csharp"],
  [".go", "go"],
  [".h", "c"],
  [".hpp", "cpp"],
  [".java", "java"],
  [".js", "javascript"],
  [".jsx", "javascript"],
  [".php", "php"],
  [".py", "python"],
  [".rb", "ruby"],
  [".rs", "rust"],
  [".ts", "typescript"],
  [".tsx", "typescript"],
]);

const FALLBACK_IGNORED_DIRECTORIES = new Set([
  ".git",
  ".kuzushi",
  "node_modules",
  "vendor",
  "dist",
  "build",
  "coverage",
  ".next",
  ".turbo",
  "target",
  "__pycache__",
]);

type StructuralSearchResult = {
  code: number | null;
  stdout: string;
  stderr: string;
  error?: string;
  warnings?: string[];
};

export async function extractTaintIrisNextEvidence(
  plan: TaintIrisNextPlan,
  ctx: ExecutionContext,
): Promise<TaintIrisNextEvidenceResult> {
  const structural = await runStructuralExtractor(plan, ctx);
  if (plan.backend.selected !== "codeql") return structural;

  const codeql = await runCodeqlEvidenceExtractor(plan, ctx);
  return {
    backend: "codeql",
    tool: codeql.evidence.length > 0 ? "codeql" : structural.tool,
    evidence: mergeEvidence(structural.evidence, codeql.evidence, plan.caps.maxEvidencePerCwe),
    queryCount: structural.queryCount + codeql.queryCount,
    warnings: [...structural.warnings, ...codeql.warnings],
  };
}

export async function runStructuralExtractor(
  plan: TaintIrisNextPlan,
  ctx: ExecutionContext,
): Promise<TaintIrisNextEvidenceResult> {
  const evidence: TaintIrisNextEvidence[] = [];
  const warnings = [...plan.backend.warnings];
  const seen = new Set<string>();
  const perCweCount = new Map<string, number>();

  for (const query of plan.structuralQueries) {
    if ((perCweCount.get(query.cwe) ?? 0) >= plan.caps.maxEvidencePerCwe) continue;
    if (ctx.signal?.aborted) break;

    const result = await runStructuralSearch(
      query.pattern,
      plan.scanRoot,
      plan.repoRoot,
      ctx.signal,
    );
    if (result.warnings) warnings.push(...result.warnings);
    if (result.error) {
      warnings.push(result.error);
      continue;
    }
    if (result.code !== 0 && result.code !== 1) {
      warnings.push(`rg exited ${result.code} for ${query.cwe} ${query.role}:${query.pattern}`);
      continue;
    }

    const matchedFiles = new Set<string>();
    for (const line of result.stdout.split(/\r?\n/u)) {
      if (!line.trim()) continue;
      if ((perCweCount.get(query.cwe) ?? 0) >= plan.caps.maxEvidencePerCwe) break;
      const parsed = parseRgLine(line, plan.repoRoot);
      if (!parsed) continue;
      if (!matchedFiles.has(parsed.filePath) && matchedFiles.size >= plan.caps.maxFilesPerQuery) {
        continue;
      }
      matchedFiles.add(parsed.filePath);

      const key = `${query.cwe}:${query.role}:${parsed.filePath}:${parsed.line}:${query.pattern}`;
      if (seen.has(key)) continue;
      seen.add(key);
      perCweCount.set(query.cwe, (perCweCount.get(query.cwe) ?? 0) + 1);

      evidence.push({
        cwe: query.cwe,
        taintClass: query.taintClass,
        role: query.role,
        pattern: query.pattern,
        filePath: parsed.filePath,
        line: parsed.line,
        snippet: parsed.snippet,
        language: languageForPath(parsed.filePath),
        confidence: confidenceForRole(query.role),
        catalogSignal: `${query.role}: ${query.pattern}`,
      });
    }
  }

  return {
    backend: "structural",
    tool: plan.backend.structuralTool,
    evidence,
    queryCount: plan.structuralQueries.length,
    warnings,
  };
}

export async function runCodeqlEvidenceExtractor(
  plan: TaintIrisNextPlan,
  ctx: ExecutionContext,
): Promise<TaintIrisNextEvidenceResult> {
  const warnings: string[] = [];
  const dbPath = plan.backend.codeqlDbPath;
  if (!dbPath) {
    return {
      backend: "codeql",
      tool: "codeql",
      evidence: [],
      queryCount: 0,
      warnings: ["backend=codeql selected, but no existing CodeQL DB path was resolved"],
    };
  }
  if (!existsSync(dbPath)) {
    return {
      backend: "codeql",
      tool: "codeql",
      evidence: [],
      queryCount: 0,
      warnings: [`CodeQL DB path does not exist: ${dbPath}`],
    };
  }

  let codeqlBin: string;
  try {
    codeqlBin = resolveConfiguredCodeqlBinary(ctx) ?? (await resolveCodeQLBinary());
  } catch (error) {
    return {
      backend: "codeql",
      tool: "codeql",
      evidence: [],
      queryCount: 0,
      warnings: [
        `CodeQL DB found at ${dbPath}, but CodeQL CLI is unavailable; using structural evidence only. ${toErrorMessage(error)}`,
      ],
    };
  }

  const language = detectCodeqlDatabaseLanguage(dbPath, plan.languages);
  const query = buildCodeqlCatalogQuery(plan, language);
  if (!query) {
    return {
      backend: "codeql",
      tool: "codeql",
      evidence: [],
      queryCount: 0,
      warnings: [
        `CodeQL DB found for ${language}, but the bounded IRIS Next CodeQL adapter currently supports javascript only; using structural evidence only.`,
      ],
    };
  }

  const tmpDir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-iris-next-codeql-"));
  const queryPath = path.join(tmpDir, "iris-next-candidates.ql");
  try {
    writeFileSync(
      path.join(tmpDir, "qlpack.yml"),
      [
        "name: kuzushi/taint-iris-next-generated",
        "version: 0.0.0",
        "libraryPathDependencies:",
        "  - codeql/javascript-all",
        "",
      ].join("\n"),
      "utf8",
    );
    writeFileSync(queryPath, query, "utf8");
    const sarif = await runCodeQL(dbPath, codeqlBin, queryPath, {
      threads: 1,
      searchPath: resolveCodeqlPackSearchPath(),
      additionalPacks: resolveCodeqlInstalledPackPaths(),
    });
    const findings = selectFindings(sarif, path.basename(plan.repoRoot), "HEAD");
    const evidence = codeqlFindingsToEvidence(findings, plan);
    return {
      backend: "codeql",
      tool: "codeql",
      evidence,
      queryCount: 1,
      warnings,
    };
  } catch (error) {
    return {
      backend: "codeql",
      tool: "codeql",
      evidence: [],
      queryCount: 1,
      warnings: [
        `CodeQL read-only analysis failed for ${language}; using structural evidence only. ${toErrorMessage(error)}`,
      ],
    };
  } finally {
    rmSync(tmpDir, { recursive: true, force: true });
  }
}

export function buildCodeqlCatalogQuery(plan: TaintIrisNextPlan, language: string): string | null {
  if (language !== "javascript") return null;
  const clauses = buildCodeqlCandidateClauses(plan);
  if (clauses.length === 0) return null;
  return [
    "/**",
    " * @name Taint IRIS Next bounded catalog candidates",
    " * @description Bounded source/sink call candidates generated from the ranked Taint IRIS Next CWE catalog.",
    " * @kind problem",
    " * @problem.severity recommendation",
    " * @precision low",
    " * @id js/taint-iris-next/catalog-candidate",
    " */",
    "import javascript",
    "",
    "from CallExpr call, string callee, string cwe, string signal",
    "where",
    "  callee = call.getCallee().toString() and",
    "  (",
    clauses.map((clause) => `    ${clause}`).join("\n    or\n"),
    "  )",
    'select call, "Taint IRIS Next " + cwe + " catalog signal " + signal + " at call " + callee',
    "",
  ].join("\n");
}

export function codeqlFindingsToEvidence(
  findings: readonly Finding[],
  plan: TaintIrisNextPlan,
): TaintIrisNextEvidence[] {
  const evidence: TaintIrisNextEvidence[] = [];
  const seen = new Set<string>();
  const perCweCount = new Map<string, number>();

  for (const finding of findings) {
    const catalogEntries = matchFindingCatalogEntries(finding, plan.catalog);
    for (const entry of catalogEntries) {
      if ((perCweCount.get(entry.cwe) ?? 0) >= plan.caps.maxEvidencePerCwe) continue;

      const steps =
        finding.taintPath && finding.taintPath.length > 0
          ? finding.taintPath
          : [
              {
                filePath: finding.filePath,
                line: finding.startLine,
                message: finding.message,
                snippet: finding.evidence ?? undefined,
              },
            ];

      for (const [index, step] of steps.entries()) {
        if ((perCweCount.get(entry.cwe) ?? 0) >= plan.caps.maxEvidencePerCwe) break;
        const role = roleForCodeqlStep(index, steps.length);
        const key = `${entry.cwe}:${role}:${step.filePath}:${step.line}:${finding.ruleId}`;
        if (seen.has(key)) continue;
        seen.add(key);
        perCweCount.set(entry.cwe, (perCweCount.get(entry.cwe) ?? 0) + 1);
        evidence.push({
          cwe: entry.cwe,
          taintClass: entry.taintClass,
          role,
          pattern: finding.ruleId,
          filePath: normalizePath(plan.repoRoot, step.filePath),
          line: Math.max(1, step.line),
          snippet: step.snippet ?? step.message ?? finding.message,
          language: languageForPath(step.filePath),
          confidence: confidenceForCodeqlFinding(finding),
          catalogSignal: `codeql: ${finding.ruleId}`,
        });
      }
    }
  }

  return evidence;
}

function runRg(
  pattern: string,
  scanRoot: string,
  repoRoot: string,
  signal: AbortSignal | undefined,
): Promise<StructuralSearchResult> {
  const searchPath = relativeSearchPath(repoRoot, scanRoot);
  const args = [
    "--line-number",
    "--no-heading",
    "--color",
    "never",
    "--fixed-strings",
    ...RG_IGNORE_GLOBS.flatMap((glob) => ["--glob", glob]),
    "--",
    pattern,
    searchPath,
  ];

  return new Promise((resolve) => {
    const child = spawn("rg", args, { cwd: repoRoot, signal });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    child.on("error", (error) => {
      resolve({
        code: null,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
        error: `rg unavailable for structural extraction: ${error.message}`,
      });
    });
    child.on("close", (code) => {
      resolve({
        code,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      });
    });
  });
}

async function runStructuralSearch(
  pattern: string,
  scanRoot: string,
  repoRoot: string,
  signal: AbortSignal | undefined,
): Promise<StructuralSearchResult> {
  const rgResult = await runRg(pattern, scanRoot, repoRoot, signal);
  if (!rgResult.error) return rgResult;
  const fallbackResult = runFilesystemSearch(pattern, scanRoot, repoRoot);
  return { ...fallbackResult, warnings: [rgResult.error] };
}

function runFilesystemSearch(
  pattern: string,
  scanRoot: string,
  repoRoot: string,
): StructuralSearchResult {
  const root = resolveSearchRoot(scanRoot, repoRoot);
  const stdout = collectSearchFiles(root)
    .flatMap((filePath) => searchTextFile(pattern, filePath, repoRoot))
    .join("\n");
  return { code: stdout ? 0 : 1, stdout, stderr: "" };
}

function resolveSearchRoot(scanRoot: string, repoRoot: string): string {
  return path.isAbsolute(scanRoot) ? scanRoot : path.resolve(repoRoot, scanRoot);
}

function collectSearchFiles(root: string): string[] {
  const files: string[] = [];
  visitSearchDirectory(root, files);
  return files;
}

function visitSearchDirectory(directory: string, files: string[]): void {
  let entries: Dirent[];
  try {
    entries = readdirSync(directory, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory() && shouldSearchDirectory(entry.name)) {
      visitSearchDirectory(entryPath, files);
    } else if (entry.isFile()) {
      files.push(entryPath);
    }
  }
}

function shouldSearchDirectory(name: string): boolean {
  return !FALLBACK_IGNORED_DIRECTORIES.has(name);
}

function searchTextFile(pattern: string, filePath: string, repoRoot: string): string[] {
  let body: string;
  try {
    body = readFileSync(filePath, "utf8");
  } catch {
    return [];
  }
  if (body.includes("\u0000")) return [];
  const relativePath = normalizePath(repoRoot, filePath);
  return body
    .split(/\r?\n/u)
    .flatMap((line, index) =>
      line.includes(pattern) ? [`${relativePath}:${index + 1}:${line}`] : [],
    );
}

function mergeEvidence(
  structural: readonly TaintIrisNextEvidence[],
  codeql: readonly TaintIrisNextEvidence[],
  maxEvidencePerCwe: number,
): TaintIrisNextEvidence[] {
  const merged: TaintIrisNextEvidence[] = [];
  const seen = new Set<string>();
  const perCweCount = new Map<string, number>();

  for (const item of [...codeql, ...structural]) {
    if ((perCweCount.get(item.cwe) ?? 0) >= maxEvidencePerCwe) continue;
    const key = `${item.cwe}:${item.role}:${item.filePath}:${item.line}:${item.pattern}`;
    if (seen.has(key)) continue;
    seen.add(key);
    perCweCount.set(item.cwe, (perCweCount.get(item.cwe) ?? 0) + 1);
    merged.push(item);
  }

  return merged;
}

function resolveConfiguredCodeqlBinary(ctx: ExecutionContext): string | undefined {
  const codeqlConfig = ctx.config.taskConfig?.["codeql"];
  if (!isRecord(codeqlConfig)) return undefined;
  const binary = codeqlConfig["binary"];
  return typeof binary === "string" && binary.trim() ? binary.trim() : undefined;
}

function resolveCodeqlPackSearchPath(): string | undefined {
  const packagesPath = path.join(os.homedir(), ".codeql", "packages");
  return existsSync(packagesPath) ? packagesPath : undefined;
}

function resolveCodeqlInstalledPackPaths(): string | undefined {
  const root = path.join(os.homedir(), ".codeql", "packages", "codeql");
  if (!existsSync(root)) return undefined;
  const latestByPack: string[] = [];
  for (const packName of readdirSync(root)) {
    const packRoot = path.join(root, packName);
    if (!existsSync(packRoot)) continue;
    const versions = readdirSync(packRoot)
      .filter((entry) => existsSync(path.join(packRoot, entry, "qlpack.yml")))
      .sort(compareVersionDesc);
    const latest = versions[0];
    if (latest) latestByPack.push(path.join(packRoot, latest));
  }
  return latestByPack.length > 0 ? latestByPack.join(path.delimiter) : undefined;
}

function compareVersionDesc(left: string, right: string): number {
  const leftParts = left.split(".").map((part) => Number.parseInt(part, 10) || 0);
  const rightParts = right.split(".").map((part) => Number.parseInt(part, 10) || 0);
  for (let index = 0; index < Math.max(leftParts.length, rightParts.length); index += 1) {
    const delta = (rightParts[index] ?? 0) - (leftParts[index] ?? 0);
    if (delta !== 0) return delta;
  }
  return right.localeCompare(left);
}

function detectCodeqlDatabaseLanguage(dbPath: string, languageHints: readonly string[]): string {
  const metadataPath = path.join(dbPath, "codeql-database.yml");
  if (existsSync(metadataPath)) {
    const metadata = readFileSync(metadataPath, "utf8");
    const match = metadata.match(/^\s*primaryLanguage:\s*([^\s#]+)/imu);
    if (match?.[1]) return normalizeCodeqlLanguage(match[1]);
  }

  for (const language of languageHints) {
    const normalized = normalizeCodeqlLanguage(language);
    if (normalized !== "unknown") return normalized;
  }

  return "javascript";
}

function normalizeCodeqlLanguage(language: string): string {
  const normalized = language.trim().toLowerCase();
  if (normalized === "javascript" || normalized === "typescript" || normalized === "js") {
    return "javascript";
  }
  if (normalized === "python" || normalized === "py") return "python";
  if (normalized === "ruby" || normalized === "rb") return "ruby";
  if (normalized === "java") return "java";
  if (normalized === "go" || normalized === "golang") return "go";
  if (normalized === "csharp" || normalized === "c#") return "csharp";
  if (normalized === "cpp" || normalized === "c++" || normalized === "c") return "cpp";
  if (normalized === "rust" || normalized === "rs") return "rust";
  if (normalized === "swift") return "swift";
  return "unknown";
}

function buildCodeqlCandidateClauses(plan: TaintIrisNextPlan): string[] {
  const clauses: string[] = [];
  const seen = new Set<string>();
  for (const query of plan.structuralQueries) {
    if (query.role !== "sink" && query.role !== "structural") continue;
    const token = normalizeCodeqlPatternToken(query.pattern);
    if (!token) continue;
    const key = `${query.cwe}:${token.toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);
    clauses.push(
      `(cwe = ${qlString(query.cwe)} and signal = ${qlString(query.pattern)} and (callee.matches(${qlString(`%${token}%`)}) or call.toString().matches(${qlString(`%${token}%`)})))`,
    );
    if (clauses.length >= 80) break;
  }
  return clauses;
}

function normalizeCodeqlPatternToken(pattern: string): string | null {
  const trimmed = pattern.trim();
  if (trimmed.length < 3) return null;
  const cleaned = trimmed
    .replace(/[()[\]{}'"`]/gu, "")
    .replace(/^\.+/u, "")
    .replace(/\.+$/u, "");
  if (cleaned.length < 3 || /\s/u.test(cleaned)) return null;
  if (!/^[\w$./:-]+$/u.test(cleaned)) return null;
  return cleaned;
}

function qlString(value: string): string {
  return `"${value.replace(/\\/gu, "\\\\").replace(/"/gu, '\\"')}"`;
}

function matchFindingCatalogEntries(
  finding: Finding,
  catalog: readonly TaintIrisNextCweCatalogEntry[],
): TaintIrisNextCweCatalogEntry[] {
  const cwes = new Set(finding.cwe.map((cwe) => cwe.toUpperCase()));
  const direct = catalog.filter((entry) => cwes.has(entry.cwe));
  if (direct.length > 0) return direct;

  const haystack = [
    finding.ruleId,
    finding.message,
    finding.evidence ?? "",
    ...(finding.taintPath ?? []).map((step) => `${step.message ?? ""} ${step.snippet ?? ""}`),
  ]
    .join(" ")
    .toLowerCase();

  return catalog.filter((entry) => {
    if (haystack.includes(entry.cwe.toLowerCase())) return true;
    if (haystack.includes(entry.taintClass.toLowerCase())) return true;
    if (haystack.includes(entry.name.toLowerCase())) return true;
    return [...entry.sinkSignals, ...entry.sourceSignals].some((signal) => {
      const normalized = signal.toLowerCase();
      return normalized.length >= 4 && haystack.includes(normalized);
    });
  });
}

function roleForCodeqlStep(index: number, total: number): TaintIrisNextEvidence["role"] {
  if (total <= 1) return "sink";
  if (index === 0) return "source";
  if (index === total - 1) return "sink";
  return "structural";
}

function confidenceForCodeqlFinding(finding: Finding): TaintIrisNextEvidenceConfidence {
  if (finding.scannerConfidence === "HIGH") return "high";
  if (finding.scannerConfidence === "MEDIUM") return "medium";
  return "low";
}

function relativeSearchPath(repoRoot: string, scanRoot: string): string {
  if (!path.isAbsolute(scanRoot)) return scanRoot;
  const rel = path.relative(repoRoot, scanRoot);
  if (!rel) return ".";
  return rel.startsWith("..") ? scanRoot : rel;
}

function parseRgLine(
  line: string,
  repoRoot: string,
): { filePath: string; line: number; snippet: string } | undefined {
  const first = line.indexOf(":");
  if (first < 0) return undefined;
  const second = line.indexOf(":", first + 1);
  if (second < 0) return undefined;
  const rawPath = line.slice(0, first);
  const lineNumber = Number.parseInt(line.slice(first + 1, second), 10);
  const snippet = line.slice(second + 1).trim();
  if (!rawPath || !Number.isFinite(lineNumber)) return undefined;

  return {
    filePath: normalizePath(repoRoot, rawPath),
    line: Math.max(1, lineNumber),
    snippet,
  };
}

function normalizePath(repoRoot: string, filePath: string): string {
  if (filePath.startsWith(`.${path.sep}`)) return filePath.slice(2);
  if (!path.isAbsolute(filePath)) return filePath;
  const rel = path.relative(repoRoot, filePath);
  return rel.startsWith("..") ? filePath : rel || filePath;
}

function languageForPath(filePath: string): string {
  return LANGUAGE_BY_EXTENSION.get(path.extname(filePath).toLowerCase()) ?? "unknown";
}

function confidenceForRole(role: string): TaintIrisNextEvidenceConfidence {
  if (role === "sink") return "medium";
  if (role === "source") return "medium";
  return "low";
}
