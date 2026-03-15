import { execFile, type ExecFileException } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { access, mkdir, readdir } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { isRecord, toErrorMessage } from "../utils.js";
import { scoreFindingMetadata, detectParameterRiskBoost } from "./scoring.js";
import type { Finding } from "./types.js";

/**
 * In-process lock map to prevent concurrent `ensureDatabase` calls from racing
 * on the same dbPath. The first caller creates the database; subsequent callers
 * wait for the promise to resolve and reuse the result.
 */
const dbCreationLocks = new Map<string, Promise<EnsureCodeQLDatabaseResult>>();

/**
 * Per-database operation mutex. CodeQL holds a JVM file lock on the DB cache
 * directory, so concurrent operations (analyze, query run) on the same DB will
 * fail with OverlappingFileLockException. This serializes all CodeQL operations
 * that target the same database path.
 */
const dbOperationQueues = new Map<string, Promise<unknown>>();

function enqueueDbOperation<T>(dbPath: string, fn: () => Promise<T>): Promise<T> {
  const previous = dbOperationQueues.get(dbPath) ?? Promise.resolve();
  const next = previous.then(fn, fn);
  dbOperationQueues.set(dbPath, next);
  return next;
}

const execFileAsync = promisify(execFile);
const COMPILED_LANGUAGES = new Set(["go", "java", "cpp", "csharp", "swift", "rust"]);

export interface EnsureCodeQLDatabaseOptions {
  dbPath?: string;
  language?: string;
}

export interface EnsureCodeQLDatabaseResult {
  dbPath: string;
  language: string;
}

export interface RunCodeQLOptions {
  threads?: number;
  ram?: number;
}

interface CodeQLSarifDriver {
  rules?: CodeQLSarifRule[];
}

interface CodeQLSarifTool {
  driver?: CodeQLSarifDriver;
}

interface CodeQLSarifRun {
  tool?: CodeQLSarifTool;
  results?: CodeQLSarifResult[];
}

interface CodeQLSarifResult {
  ruleId?: string;
  level?: string;
  message?: {
    text?: string;
  };
  codeFlows?: CodeQLSarifCodeFlow[];
  locations?: Array<{
    physicalLocation?: {
      artifactLocation?: {
        uri?: string;
      };
      region?: {
        startLine?: number;
      };
    };
  }>;
}

interface CodeQLSarifCodeFlow {
  threadFlows?: CodeQLSarifThreadFlow[];
}

interface CodeQLSarifThreadFlow {
  locations?: CodeQLSarifThreadFlowLocation[];
}

interface CodeQLSarifThreadFlowLocation {
  message?: {
    text?: string;
  };
  location?: {
    message?: {
      text?: string;
    };
    physicalLocation?: {
      artifactLocation?: {
        uri?: string;
      };
      region?: {
        startLine?: number;
      };
    };
  };
}

interface CodeQLSarifRule {
  id?: string;
  shortDescription?: {
    text?: string;
  };
  properties?: {
    precision?: string;
    tags?: string[];
    problem?: {
      severity?: string;
    };
    "security-severity"?: string | number;
  };
}

export interface CodeQLSarifOutput {
  runs: CodeQLSarifRun[];
}

/** Ensure a CodeQL database exists; reuse configured dbPath when valid. */
export async function ensureDatabase(
  repoRoot: string,
  codeqlBin: string,
  config: EnsureCodeQLDatabaseOptions = {},
): Promise<EnsureCodeQLDatabaseResult> {
  const configuredDbPath = asOptionalString(config.dbPath);
  if (configuredDbPath) {
    const resolvedDbPath = resolveRepoPath(repoRoot, configuredDbPath);
    if (!(await isCodeQLDatabaseDir(resolvedDbPath))) {
      throw new Error(`Configured CodeQL database path is not valid: ${resolvedDbPath}`);
    }

    const resolvedLanguage = normalizeLanguage(config.language)
      ?? (await detectLanguageFromDatabase(codeqlBin, resolvedDbPath))
      ?? (await detectCodeQLLanguageFromHeuristics(repoRoot))
      ?? "javascript";

    return {
      dbPath: resolvedDbPath,
      language: resolvedLanguage,
    };
  }

  const language = normalizeLanguage(config.language) ?? await detectCodeQLLanguage(repoRoot, codeqlBin);
  const dbPath = path.join(repoRoot, ".kuzushi", "codeql-db");

  // If another caller is already creating this database, wait for it.
  const existing = dbCreationLocks.get(dbPath);
  if (existing) {
    return existing;
  }

  // If a valid database already exists on disk, reuse it.
  if (await isCodeQLDatabaseDir(dbPath)) {
    return { dbPath, language };
  }

  // Serialize creation through the same operation queue used by runCodeQL
  // to prevent creation from overlapping with analysis operations.
  const creationPromise = enqueueDbOperation(
    dbPath,
    () => createCodeQLDatabase(repoRoot, codeqlBin, dbPath, language),
  );
  dbCreationLocks.set(dbPath, creationPromise);

  try {
    return await creationPromise;
  } finally {
    dbCreationLocks.delete(dbPath);
  }
}

async function createCodeQLDatabase(
  repoRoot: string,
  codeqlBin: string,
  dbPath: string,
  language: string,
): Promise<EnsureCodeQLDatabaseResult> {
  await mkdir(path.dirname(dbPath), { recursive: true });

  // Clean up any partial/corrupted database left from a previous failed run.
  if (existsSync(dbPath) && !(await isCodeQLDatabaseDir(dbPath))) {
    rmSync(dbPath, { recursive: true, force: true });
  }

  if (language === "go") {
    await resolveGoDependencies(repoRoot);
  }

  const createArgs = [
    "database",
    "create",
    dbPath,
    `--language=${language}`,
    "--overwrite",
    `--source-root=${repoRoot}`,
  ];

  if (COMPILED_LANGUAGES.has(language)) {
    try {
      await execCodeQL(codeqlBin, [...createArgs, "--build-mode=autobuild"], repoRoot);
    } catch {
      await execCodeQL(codeqlBin, createArgs, repoRoot);
    }
  } else {
    await execCodeQL(codeqlBin, createArgs, repoRoot);
  }

  return {
    dbPath,
    language,
  };
}

/**
 * Serialize an arbitrary CodeQL operation on a given database path.
 * Use this to wrap any `codeql query run` or similar command that accesses
 * a database, preventing OverlappingFileLockException from concurrent access.
 */
export function withCodeQLDatabase<T>(dbPath: string, fn: () => Promise<T>): Promise<T> {
  return enqueueDbOperation(dbPath, fn);
}

/** Run CodeQL analysis against a prepared database and parse SARIF output. */
export async function runCodeQL(
  dbPath: string,
  codeqlBin: string,
  suite: string,
  opts: RunCodeQLOptions = {},
): Promise<CodeQLSarifOutput> {
  return enqueueDbOperation(dbPath, () => runCodeQLImpl(dbPath, codeqlBin, suite, opts));
}

async function runCodeQLImpl(
  dbPath: string,
  codeqlBin: string,
  suite: string,
  opts: RunCodeQLOptions = {},
): Promise<CodeQLSarifOutput> {
  const normalizedSuite = suite.trim();
  if (!normalizedSuite) {
    throw new Error("CodeQL suite must be a non-empty string");
  }

  const tmpDir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-codeql-"));
  const outputPath = path.join(tmpDir, "results.sarif");

  try {
    const args = [
      "database",
      "analyze",
      dbPath,
      normalizedSuite,
      "--format=sarif-latest",
      `--output=${outputPath}`,
    ];

    const threads = asPositiveInt(opts.threads);
    if (threads != null) {
      args.push(`--threads=${threads}`);
    }

    const ram = asPositiveInt(opts.ram);
    if (ram != null) {
      args.push(`--ram=${ram}`);
    }

    await execCodeQL(codeqlBin, args);

    const parsed = JSON.parse(readFileSync(outputPath, "utf-8"));
    if (!isRecord(parsed) || !Array.isArray(parsed["runs"])) {
      throw new Error("CodeQL SARIF output is missing runs[]");
    }

    return {
      runs: parsed["runs"] as CodeQLSarifOutput["runs"],
    };
  } finally {
    rmSync(tmpDir, { recursive: true, force: true });
  }
}

/** Parse CodeQL SARIF into ranked Kuzushi findings. */
export function selectFindings(
  sarifOutput: CodeQLSarifOutput,
  repoName: string,
  ref: string,
  maxFindings?: number,
): Finding[] {
  if (!Array.isArray(sarifOutput.runs) || sarifOutput.runs.length === 0) {
    return [];
  }

  const deduped = new Map<string, Finding>();

  for (const run of sarifOutput.runs) {
    const rulesById = buildRuleIndex(run.tool?.driver?.rules ?? []);

    for (const result of run.results ?? []) {
      const ruleId = asOptionalString(result.ruleId) || "codeql.unknown";
      const rule = rulesById.get(ruleId);
      const { filePath, startLine } = extractLocation(result);
      if (!filePath) {
        continue;
      }
      const evidence = extractCodeFlowEvidence(result);

      const message = (
        asOptionalString(result.message?.text)
        || asOptionalString(rule?.shortDescription?.text)
        || ruleId
      );

      const tags = normalizeTags(rule?.properties?.tags);
      const severity = mapSeverity(rule?.properties?.problem?.severity, result.level);
      const scannerConfidence = mapPrecision(rule?.properties?.precision);
      const likelihood = confidenceToLikelihood(scannerConfidence);
      const impact = mapImpact(rule?.properties?.["security-severity"]);
      const subcategory = hasSecuritySignal(tags) ? ["vuln"] : ["audit"];
      const cwe = extractCwe(tags);
      const score = scoreFindingMetadata({
        severity,
        likelihood,
        impact,
        subcategory,
        cwe,
        parameterRiskBoost: detectParameterRiskBoost(message),
      });

      const fingerprint = computeCodeQLFingerprint(repoName, ref, {
        ruleId,
        filePath,
        startLine,
        message,
      });

      const finding: Finding = {
        scanner: "codeql",
        fingerprint,
        ruleId,
        filePath,
        startLine,
        severity,
        message,
        evidence,
        scannerConfidence,
        subcategory,
        likelihood,
        impact,
        cwe,
        score,
      };

      const existing = deduped.get(fingerprint);
      if (!existing || finding.score > existing.score) {
        deduped.set(fingerprint, finding);
      }
    }
  }

  return [...deduped.values()]
    .sort((a, b) => b.score - a.score)
    .slice(0, maxFindings);
}

/** Stable fingerprint for CodeQL findings. */
export function computeCodeQLFingerprint(
  repoName: string,
  ref: string,
  input: { ruleId: string; filePath: string; startLine: number; message: string },
): string {
  const source = [
    repoName,
    ref,
    input.ruleId,
    input.filePath,
    String(input.startLine),
    input.message,
  ].join("|");

  return createHash("sha256").update(source).digest("hex");
}

/** Detect all CodeQL languages present in a polyglot repo. */
export async function detectAllCodeQLLanguages(repoRoot: string, codeqlBin: string): Promise<string[]> {
  const languages: string[] = [];

  const markers: Array<{ check: () => Promise<boolean>; lang: string }> = [
    { check: () => pathExists(path.join(repoRoot, "package.json")), lang: "javascript" },
    { check: () => pathExists(path.join(repoRoot, "go.mod")), lang: "go" },
    { check: async () =>
      await pathExists(path.join(repoRoot, "pom.xml"))
      || await pathExists(path.join(repoRoot, "build.gradle"))
      || await pathExists(path.join(repoRoot, "build.gradle.kts")),
      lang: "java",
    },
    { check: async () =>
      await pathExists(path.join(repoRoot, "requirements.txt"))
      || await pathExists(path.join(repoRoot, "pyproject.toml"))
      || await pathExists(path.join(repoRoot, "setup.py")),
      lang: "python",
    },
    { check: () => pathExists(path.join(repoRoot, "Cargo.toml")), lang: "rust" },
    { check: () => pathExists(path.join(repoRoot, "Gemfile")), lang: "ruby" },
  ];

  for (const marker of markers) {
    if (await marker.check()) {
      languages.push(marker.lang);
    }
  }

  // Check top-level files for additional signals
  const topLevel = await safeReadDir(repoRoot);
  if (topLevel.some((n) => n.endsWith(".sln") || n.endsWith(".csproj")) && !languages.includes("csharp")) {
    languages.push("csharp");
  }

  // Fallback: if no markers found, try single language detection
  if (languages.length === 0) {
    const single = await detectCodeQLLanguage(repoRoot, codeqlBin);
    return [single];
  }

  return languages;
}

/** Detect CodeQL language from repo markers, with resolve-language fallback. */
export async function detectCodeQLLanguage(repoRoot: string, codeqlBin: string): Promise<string> {
  const heuristic = await detectCodeQLLanguageFromHeuristics(repoRoot);
  if (heuristic) {
    return heuristic;
  }

  const installed = await resolveInstalledLanguages(codeqlBin);
  if (installed.length > 0) {
    return installed[0];
  }

  throw new Error(
    "Unable to determine CodeQL language automatically. Set scannerConfig.codeql.language.",
  );
}

/** Lightweight marker-based language detection for local repositories. */
export async function detectCodeQLLanguageFromHeuristics(
  repoRoot: string,
): Promise<string | undefined> {
  if (await pathExists(path.join(repoRoot, "package.json"))) {
    return "javascript";
  }

  if (await pathExists(path.join(repoRoot, "go.mod"))) {
    return "go";
  }

  if (
    await pathExists(path.join(repoRoot, "pom.xml"))
    || await pathExists(path.join(repoRoot, "build.gradle"))
    || await pathExists(path.join(repoRoot, "build.gradle.kts"))
    || await pathExists(path.join(repoRoot, "gradlew"))
    || await pathExists(path.join(repoRoot, "mvnw"))
  ) {
    return "java";
  }

  if (
    await pathExists(path.join(repoRoot, "requirements.txt"))
    || await pathExists(path.join(repoRoot, "pyproject.toml"))
    || await pathExists(path.join(repoRoot, "setup.py"))
  ) {
    return "python";
  }

  if (await pathExists(path.join(repoRoot, "Cargo.toml"))) {
    return "rust";
  }

  if (await pathExists(path.join(repoRoot, "Gemfile"))) {
    return "ruby";
  }

  const topLevel = await safeReadDir(repoRoot);
  if (topLevel.some((name) => name.endsWith(".sln") || name.endsWith(".csproj"))) {
    return "csharp";
  }

  if (topLevel.some((name) => name.endsWith(".go"))) {
    return "go";
  }

  if (topLevel.some((name) => name.endsWith(".py"))) {
    return "python";
  }

  return undefined;
}

async function detectLanguageFromDatabase(
  codeqlBin: string,
  dbPath: string,
): Promise<string | undefined> {
  try {
    const { stdout } = await execCodeQL(codeqlBin, [
      "database",
      "resolve",
      "languages",
      dbPath,
      "--format=json",
    ]);

    const languages = parseLanguageList(stdout);
    return languages[0];
  } catch {
    return undefined;
  }
}

async function resolveInstalledLanguages(codeqlBin: string): Promise<string[]> {
  try {
    const { stdout } = await execCodeQL(codeqlBin, ["resolve", "languages", "--format=json"]);
    return parseLanguageList(stdout);
  } catch {
    try {
      const { stdout } = await execCodeQL(codeqlBin, ["resolve", "languages"]);
      return parseLanguageList(stdout);
    } catch {
      return [];
    }
  }
}

function parseLanguageList(raw: string): string[] {
  const trimmed = raw.trim();
  if (!trimmed) {
    return [];
  }

  try {
    const parsed = JSON.parse(trimmed);
    if (Array.isArray(parsed)) {
      const fromArray = parsed
        .map((item) => {
          if (typeof item === "string") {
            return normalizeLanguage(item);
          }
          if (isRecord(item) && typeof item["name"] === "string") {
            return normalizeLanguage(item["name"]);
          }
          return undefined;
        })
        .filter((value): value is string => Boolean(value));

      return uniqueValues(fromArray);
    }

    if (isRecord(parsed) && Array.isArray(parsed["languages"])) {
      return uniqueValues(
        parsed["languages"]
          .map((item) => normalizeLanguage(item))
          .filter((value): value is string => Boolean(value)),
      );
    }

    // codeql resolve languages --format=json returns { "go": "/path/...", "java": "/path/..." }
    if (isRecord(parsed)) {
      const fromKeys = Object.keys(parsed)
        .map((key) => normalizeLanguage(key))
        .filter((value): value is string => Boolean(value));
      if (fromKeys.length > 0) {
        return uniqueValues(fromKeys);
      }
    }
  } catch {
    // Fall back to line-oriented parsing.
  }

  return uniqueValues(
    trimmed
      .split(/\r?\n/)
      .map((line) => normalizeLanguage(line))
      .filter((value): value is string => Boolean(value)),
  );
}

function buildRuleIndex(rules: CodeQLSarifRule[]): Map<string, CodeQLSarifRule> {
  const map = new Map<string, CodeQLSarifRule>();
  for (const rule of rules) {
    const id = asOptionalString(rule.id);
    if (!id) {
      continue;
    }

    map.set(id, rule);
  }

  return map;
}

function extractLocation(result: CodeQLSarifResult): { filePath: string; startLine: number } {
  for (const location of result.locations ?? []) {
    const uri = asOptionalString(location.physicalLocation?.artifactLocation?.uri);
    if (!uri) {
      continue;
    }

    const filePath = normalizeArtifactUri(uri);
    const startLine = asPositiveInt(location.physicalLocation?.region?.startLine) ?? 1;
    return { filePath, startLine };
  }

  return { filePath: "", startLine: 1 };
}

function extractCodeFlowEvidence(result: CodeQLSarifResult): string | null {
  const segments: string[] = [];

  for (const codeFlow of result.codeFlows ?? []) {
    for (const threadFlow of codeFlow.threadFlows ?? []) {
      for (const location of threadFlow.locations ?? []) {
        const uri = asOptionalString(location.location?.physicalLocation?.artifactLocation?.uri);
        if (!uri) {
          continue;
        }

        const filePath = normalizeArtifactUri(uri);
        const startLine = asPositiveInt(location.location?.physicalLocation?.region?.startLine) ?? 1;
        const message = asOptionalString(location.location?.message?.text)
          ?? asOptionalString(location.message?.text);
        const segment = message
          ? `${filePath}:${startLine} (${message})`
          : `${filePath}:${startLine}`;

        segments.push(segment);
        if (segments.length >= 16) {
          return `Code flow: ${segments.join(" -> ")}`;
        }
      }
    }
  }

  if (segments.length === 0) {
    return null;
  }

  return `Code flow: ${segments.join(" -> ")}`;
}

function normalizeArtifactUri(uri: string): string {
  let normalized = uri;

  if (uri.startsWith("file://")) {
    try {
      const fileUrl = new URL(uri);
      normalized = decodeURIComponent(fileUrl.pathname);
    } catch {
      normalized = uri.replace(/^file:\/\//, "");
    }
  }

  return normalized
    .replace(/\\/g, "/")
    .replace(/^\/+/, "")
    .replace(/^[A-Za-z]:\//, "");
}

function mapSeverity(problemSeverity: string | undefined, resultLevel: string | undefined): string {
  const normalizedProblem = asOptionalString(problemSeverity)?.toLowerCase();
  if (normalizedProblem === "error") {
    return "ERROR";
  }
  if (normalizedProblem === "warning") {
    return "WARNING";
  }
  if (normalizedProblem === "recommendation") {
    return "INFO";
  }

  const normalizedLevel = asOptionalString(resultLevel)?.toLowerCase();
  if (normalizedLevel === "error") {
    return "ERROR";
  }
  if (normalizedLevel === "warning") {
    return "WARNING";
  }

  return "INFO";
}

function mapImpact(securitySeverity: unknown): string {
  const numeric = asNumeric(securitySeverity);
  if (numeric == null) {
    return "LOW";
  }

  if (numeric >= 7) {
    return "HIGH";
  }

  if (numeric >= 4) {
    return "MEDIUM";
  }

  return "LOW";
}

function mapPrecision(value: string | undefined): string {
  const normalized = asOptionalString(value)?.toLowerCase();
  if (normalized === "very-high" || normalized === "high") {
    return "HIGH";
  }

  if (normalized === "medium") {
    return "MEDIUM";
  }

  return "LOW";
}

function confidenceToLikelihood(confidence: string): string {
  if (confidence === "HIGH") {
    return "HIGH";
  }

  if (confidence === "MEDIUM") {
    return "MEDIUM";
  }

  return "LOW";
}

function normalizeTags(tags: string[] | undefined): string[] {
  if (!Array.isArray(tags)) {
    return [];
  }

  return tags
    .map((tag) => String(tag).trim())
    .filter(Boolean);
}

function extractCwe(tags: string[]): string[] {
  const cwe = new Set<string>();

  for (const tag of tags) {
    const match = tag.toLowerCase().match(/^external\/cwe\/cwe-(\d+)$/);
    if (!match) {
      continue;
    }

    cwe.add(`CWE-${Number.parseInt(match[1], 10)}`);
  }

  return [...cwe];
}

function hasSecuritySignal(tags: string[]): boolean {
  return tags.some((tag) => {
    const normalized = tag.toLowerCase();
    return normalized.includes("security") || normalized.startsWith("external/cwe/cwe-");
  });
}

async function isCodeQLDatabaseDir(dbPath: string): Promise<boolean> {
  if (!existsSync(dbPath)) {
    return false;
  }

  try {
    if (!statSync(dbPath).isDirectory()) {
      return false;
    }
  } catch {
    return false;
  }

  if (existsSync(path.join(dbPath, "codeql-database.yml"))) {
    return true;
  }

  const children = await safeReadDir(dbPath);
  return children.some((child) => existsSync(path.join(dbPath, child, "codeql-database.yml")));
}

async function findGoMod(startDir: string): Promise<string | null> {
  let dir = path.resolve(startDir);
  for (let i = 0; i < 4; i++) {
    const candidate = path.join(dir, "go.mod");
    if (existsSync(candidate)) return candidate;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

async function resolveGoDependencies(repoRoot: string): Promise<void> {
  const goModPath = await findGoMod(repoRoot);
  if (!goModPath) return;

  const goModDir = path.dirname(goModPath);
  try {
    await execFileAsync("go", ["mod", "download"], {
      cwd: goModDir,
      encoding: "utf-8",
      timeout: 120_000,
      maxBuffer: 16 * 1024 * 1024,
    });
    process.stderr.write(`[codeql] Pre-fetched Go modules from ${goModDir}\n`);
  } catch (error) {
    process.stderr.write(
      `[codeql] go mod download failed (non-fatal): ${toErrorMessage(error)}\n`,
    );
  }
}

async function execCodeQL(
  codeqlBin: string,
  args: string[],
  cwd?: string,
): Promise<{ stdout: string; stderr: string }> {
  try {
    const result = await execFileAsync(codeqlBin, args, {
      cwd,
      encoding: "utf-8",
      maxBuffer: 64 * 1024 * 1024,
    });

    return {
      stdout: result.stdout,
      stderr: result.stderr,
    };
  } catch (error) {
    const err = error as ExecFileException & { stderr?: string };
    const details = err.stderr?.trim() || toErrorMessage(error);
    throw new Error(`CodeQL command failed: ${codeqlBin} ${args.join(" ")}\n${details}`);
  }
}

function normalizeLanguage(value: unknown): string | undefined {
  const raw = asOptionalString(value);
  if (!raw) {
    return undefined;
  }

  const normalized = raw.toLowerCase();
  if (normalized.includes("javascript") || normalized.includes("typescript")) {
    return "javascript";
  }
  if (normalized.includes("python")) {
    return "python";
  }
  if (normalized === "c#" || normalized.includes("csharp")) {
    return "csharp";
  }
  if (normalized.includes("java")) {
    return "java";
  }
  if (normalized.includes("go")) {
    return "go";
  }
  if (normalized.includes("cpp") || normalized === "c++" || normalized.includes("c-cpp")) {
    return "cpp";
  }
  if (normalized.includes("swift")) {
    return "swift";
  }
  if (normalized.includes("ruby")) {
    return "ruby";
  }
  if (normalized.includes("rust")) {
    return "rust";
  }

  // Reject unknown languages rather than passing unsanitized values to CodeQL CLI
  return undefined;
}

function resolveRepoPath(repoRoot: string, candidate: string): string {
  return path.resolve(repoRoot, candidate);
}

function asOptionalString(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }

  const trimmed = value.trim();
  return trimmed || undefined;
}

function asPositiveInt(value: unknown): number | null {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric < 1) {
    return null;
  }

  return Math.floor(numeric);
}

function asNumeric(value: unknown): number | null {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return null;
  }

  return numeric;
}

async function pathExists(filePath: string): Promise<boolean> {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function safeReadDir(dirPath: string): Promise<string[]> {
  try {
    return await readdir(dirPath);
  } catch {
    return [];
  }
}

function uniqueValues(values: string[]): string[] {
  return [...new Set(values)];
}
