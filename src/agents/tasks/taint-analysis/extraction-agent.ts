import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import type {
  AgentResultErrorMessage,
  AgentResultSuccessMessage,
  AgentRuntime,
  AgentToolDecision,
} from "../../../agent-runtime/types.js";
import { getLogger } from "../../../logger.js";
import { toErrorMessage } from "../../../utils.js";
import type { TaintAnalysisLanguage } from "./types.js";

const SOURCE_BODY_PLACEHOLDERS = ["{{SOURCE_HANDLER_PREDICATE}}"];
const SINK_BODY_PLACEHOLDERS = ["{{SINK_CALL_PREDICATE}}"];
const CACHE_PREFIX = "// cache:";
const QUERY_FENCE_REGEX = /```([a-zA-Z0-9_-]+)?[ \t]*\n([\s\S]*?)```/g;
const log = getLogger("taint-analysis-extraction-agent");

export interface ExtractionAgentOptions {
  language: TaintAnalysisLanguage;
  kind: "source" | "sink";
  template: string;
  referenceFiles: string[];
  taintAnalysisPath: string;
  model: string;
  repoRoot: string;
  workspaceDir: string;
  codeqlBinary: string;
  dbPath: string;
  codeqlApiProfileId: string;
  dataFlowImport: string;
  taintTrackingImport: string;
  runtime: AgentRuntime;
  disableCacheRead?: boolean;
}

export interface ExtractionQueryResult {
  query: string | null;
  costUsd: number;
}

/**
 * Returns true when the template contains unresolved body placeholders
 * that prevent deterministic rendering (i.e. the agent path is needed).
 */
export function hasBodyPlaceholders(template: string, kind: "source" | "sink"): boolean {
  const placeholders = kind === "source" ? SOURCE_BODY_PLACEHOLDERS : SINK_BODY_PLACEHOLDERS;
  return placeholders.some((p) => template.includes(p));
}

/**
 * Uses the AgentRuntime to generate a CodeQL extraction query by having an LLM
 * inspect the actual codebase and fill in the stub template placeholders.
 *
 * Returns the generated query text on success, or null on failure (caller falls back to `where false`).
 */
export async function generateExtractionQuery(
  options: ExtractionAgentOptions,
): Promise<ExtractionQueryResult> {
  const {
    language,
    kind,
    template,
    referenceFiles,
    taintAnalysisPath,
    model,
    repoRoot,
    workspaceDir,
    codeqlBinary,
    dbPath,
    codeqlApiProfileId,
    dataFlowImport,
    taintTrackingImport,
    runtime,
    disableCacheRead = false,
  } = options;

  const cacheDir = path.join(workspaceDir, "extraction");
  const cachePath = path.join(cacheDir, `.cache-${language}-${kind}.ql`);
  const queryPath = path.join(cacheDir, `${kind}s.ql`);
  const canUseTool = createExtractionToolGuard({
    repoRoot,
    codeqlBinary,
    workspaceDir,
    queryPath,
  });

  // --- Cache check ---
  const referenceContent = await loadReferenceContent(referenceFiles);
  const cacheHash = computeCacheHash(template, referenceContent);

  if (!disableCacheRead) {
    const cached = await readCacheIfValid(cachePath, cacheHash);
    if (cached !== null) {
      return {
        query: cached,
        costUsd: 0,
      };
    }
  }

  // --- Build system prompt ---
  const systemPrompt = await buildExtractionPrompt({
    language,
    kind,
    template,
    referenceContent,
    taintAnalysisPath,
    queryPath,
    codeqlBinary,
    workspaceDir,
    dbPath,
    codeqlApiProfileId,
    dataFlowImport,
    taintTrackingImport,
  });

  // --- Call LLM (with retry for transient API errors) ---
  const MAX_RETRIES = 2;
  let resultText: string | null = null;
  let costUsd = 0;

  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    resultText = null;
    let lastErrorSubtype: string | null = null;

    try {
      log.info(
        {
          language,
          kind,
          model,
          attempt,
          maxRetries: MAX_RETRIES,
        },
        `Starting LLM call for ${language}/${kind}${attempt > 0 ? ` (retry ${attempt}/${MAX_RETRIES})` : ""}`,
      );
      for await (const message of runtime.query({
        prompt: systemPrompt,
        options: {
          cwd: repoRoot,
          model,
          allowedTools: ["Read", "Glob", "Grep", "Bash", "Write"],
          permissionMode: "acceptEdits",
          canUseTool,
        },
      })) {
        if (
          message.type === "result" &&
          typeof message.totalCostUsd === "number" &&
          Number.isFinite(message.totalCostUsd)
        ) {
          costUsd = message.totalCostUsd;
        }
        if (message.type === "result" && message.subtype === "success") {
          resultText = (message as AgentResultSuccessMessage).result;
        } else if (message.type === "result") {
          lastErrorSubtype = message.subtype;
          const errMsg = (message as AgentResultErrorMessage).errors.join("; ") || message.subtype;
          log.warn(
            { language, kind, subtype: message.subtype, error: errMsg },
            `Non-success result for ${language}/${kind}`,
          );
        }
      }
    } catch (error) {
      log.warn(
        { language, kind, error: toErrorMessage(error) },
        `LLM call failed for ${language}/${kind}`,
      );
      if (attempt < MAX_RETRIES) {
        continue;
      }
      return {
        query: null,
        costUsd,
      };
    }

    if (resultText) {
      break;
    }

    // Retry on transient runtime errors; don't retry on non-transient failures like max_turns
    const isTransient =
      lastErrorSubtype === "error_runtime" || lastErrorSubtype === "error_aborted";
    if (!isTransient || attempt >= MAX_RETRIES) {
      break;
    }

    log.info({ language, kind, attempt }, `Transient error for ${language}/${kind}, retrying`);
  }

  if (!resultText) {
    log.warn({ language, kind }, `No result text from LLM for ${language}/${kind}`);
    return {
      query: null,
      costUsd,
    };
  }

  log.info(
    { language, kind, resultLength: resultText.length },
    `Got result text for ${language}/${kind}`,
  );

  // --- Extract query from result ---
  let queryText = extractQueryFromResult(resultText);

  // If the agent wrote the file directly, read it back
  if (!queryText && existsSync(queryPath)) {
    try {
      queryText = await readFile(queryPath, "utf-8");
    } catch {
      // ignore
    }
  }

  if (!queryText) {
    return {
      query: null,
      costUsd,
    };
  }

  // --- Cache the result ---
  try {
    await mkdir(cacheDir, { recursive: true });
    const cacheContent = `${CACHE_PREFIX}${cacheHash}\n${queryText}`;
    await writeFile(cachePath, cacheContent, "utf-8");
  } catch {
    // Cache write failure is non-fatal
  }

  return {
    query: queryText,
    costUsd,
  };
}

// ── Internals ──────────────────────────────────────────────

interface PromptBuildOptions {
  language: TaintAnalysisLanguage;
  kind: "source" | "sink";
  template: string;
  referenceContent: string;
  taintAnalysisPath: string;
  queryPath: string;
  codeqlBinary: string;
  workspaceDir: string;
  dbPath: string;
  codeqlApiProfileId: string;
  dataFlowImport: string;
  taintTrackingImport: string;
}

async function buildExtractionPrompt(opts: PromptBuildOptions): Promise<string> {
  const {
    language,
    kind,
    template,
    referenceContent,
    taintAnalysisPath,
    queryPath,
    codeqlBinary,
    workspaceDir,
    dbPath,
    codeqlApiProfileId,
    dataFlowImport,
    taintTrackingImport,
  } = opts;

  const workflowSection = await loadWorkflowStep2(taintAnalysisPath);
  const pythonExample = await loadPythonExample(taintAnalysisPath, kind);

  const candidateKind = kind === "source" ? "source_candidate" : "sink_candidate";

  const lines = [
    `You are a CodeQL extraction query expert working on a ${language} codebase.`,
    "",
    "## Your task",
    `Generate a CodeQL extraction query that identifies ${kind} candidates.`,
    `The query must produce exactly 8 select columns matching this order:`,
    `  node, "${candidateKind}", callable, flow_kind, receiver_hint, module_hint, arg_index, line.`,
    "",
    "## Workflow context (from WORKFLOW.md Step 2)",
    workflowSection,
    "",
    "## Stub template to implement",
    "Replace ALL {{PLACEHOLDER}} markers with concrete CodeQL predicates.",
    "```ql",
    template,
    "```",
    "",
    "## CodeQL compatibility profile (required)",
    `Use this CodeQL profile: ${codeqlApiProfileId}`,
    `Required imports: ${dataFlowImport}, ${taintTrackingImport}`,
    "Do not switch to alternate import variants unless these exact imports compile.",
    "",
  ];

  if (kind === "sink") {
    lines.push(
      "## Sink prioritization guidance (Balanced mode)",
      "- Prioritize terminal security-sensitive actions: command execution, database query execution, outbound network requests, filesystem writes, template/code execution, LDAP/filter construction, and HTTP redirect/header setters.",
      "- Include ORM/raw-query entrypoints where attacker-controlled text becomes executable query text (for example raw SQL APIs or query-builder raw fragment APIs).",
      "- For SQL-focused sink coverage, ensure first-argument query text entrypoints are represented when applicable (for example `Raw(query, ...)` and `From(query)`).",
      "- Do not prioritize pure string formatting or logging helpers as sinks; those are labeling false-positive traps.",
      "",
    );
  }

  if (pythonExample) {
    lines.push(
      `## Working Python ${kind} example (for reference)`,
      "This Python template is fully functional. Use it as a structural guide for how to write predicates,",
      "but adapt the language-specific APIs for " + language + ".",
      "```ql",
      pythonExample,
      "```",
      "",
    );
  }

  if (referenceContent) {
    lines.push("## Reference documentation", referenceContent, "");
  }

  lines.push(
    "## Instructions",
    `1. Use Read/Glob/Grep to explore the codebase and identify which frameworks and APIs are in use.`,
    `2. Write a complete CodeQL query for codeql/${language}-all replacing ALL {{PLACEHOLDER}} markers.`,
    `3. The query metadata header (@name, @kind, @id, @problem.severity) must be present.`,
    `4. Write the query to: ${queryPath}`,
    `5. Validate with: ${codeqlBinary} query compile ${queryPath} --search-path ${workspaceDir}`,
    `6. If compilation fails, read the error, fix the query, and retry (up to 2 retries).`,
    `7. After a successful compile, output the final working query text in your response.`,
    "",
    "## Important constraints",
    `- Use only APIs available in codeql/${language}-all.`,
    "- The select clause must output exactly 8 columns in the order specified above.",
    "- Do not use deprecated CodeQL APIs.",
    `- Database path for reference (do NOT run queries against it): ${dbPath}`,
    "",
  );

  return lines.join("\n");
}

async function loadWorkflowStep2(taintAnalysisPath: string): Promise<string> {
  const workflowPath = path.join(taintAnalysisPath, "WORKFLOW.md");
  try {
    const content = await readFile(workflowPath, "utf-8");
    const step2Match = content.match(
      /## 4\.3 Step 2 - Extract candidates[\s\S]*?(?=## 4\.4 Step 3|$)/,
    );
    return step2Match ? step2Match[0].trim() : "(WORKFLOW.md Step 2 section not found)";
  } catch {
    return "(WORKFLOW.md not found)";
  }
}

async function loadPythonExample(
  taintAnalysisPath: string,
  kind: "source" | "sink",
): Promise<string | null> {
  const referencePath = path.join(
    taintAnalysisPath,
    "assets",
    "extraction",
    `python_${kind}s_reference.ql`,
  );
  try {
    return await readFile(referencePath, "utf-8");
  } catch {
    return null;
  }
}

async function loadReferenceContent(referenceFiles: string[]): Promise<string> {
  const sorted = [...referenceFiles].sort();
  const parts: string[] = [];

  for (const filePath of sorted) {
    try {
      const content = await readFile(filePath, "utf-8");
      const fileName = path.basename(filePath);
      parts.push(`### ${fileName}\n${content}`);
    } catch {
      // skip unreadable files
    }
  }

  return parts.join("\n\n");
}

interface ExtractionToolGuardOptions {
  repoRoot: string;
  codeqlBinary: string;
  workspaceDir: string;
  queryPath: string;
}

function createExtractionToolGuard(options: ExtractionToolGuardOptions) {
  const repoRoot = path.resolve(options.repoRoot);
  const queryPath = path.resolve(options.queryPath);
  const workspaceDir = path.resolve(options.workspaceDir);
  const codeqlBinary = path.resolve(options.codeqlBinary);

  return (toolName: string, args: Record<string, unknown>): AgentToolDecision => {
    if (toolName === "Read" || toolName === "Glob" || toolName === "Grep") {
      const inputPath = getPathArg(args);
      if (!inputPath) {
        return { behavior: "allow" };
      }

      const resolvedPath = resolveInputPath(repoRoot, inputPath);
      if (!isPathWithinRoot(repoRoot, resolvedPath)) {
        return {
          behavior: "deny",
          message: `Tool "${toolName}" path must stay inside repository root`,
        };
      }

      return { behavior: "allow" };
    }

    if (toolName === "Write") {
      const filePath = getPathArg(args);
      if (!filePath) {
        return { behavior: "deny", message: "Write requires file_path" };
      }

      const resolvedPath = resolveInputPath(repoRoot, filePath);
      if (!isSamePath(resolvedPath, queryPath)) {
        return {
          behavior: "deny",
          message: `Write may only target ${queryPath}`,
        };
      }

      return { behavior: "allow" };
    }

    if (toolName === "Bash") {
      const command = typeof args["command"] === "string" ? args["command"] : "";
      if (
        !isAllowedCodeqlCompileCommand(command, {
          repoRoot,
          codeqlBinary,
          queryPath,
          workspaceDir,
        })
      ) {
        return {
          behavior: "deny",
          message: "Bash is restricted to a single CodeQL query compile command",
        };
      }

      return { behavior: "allow" };
    }

    return {
      behavior: "deny",
      message: `Tool "${toolName}" is not allowed in extraction generation`,
    };
  };
}

interface CompileCommandOptions {
  repoRoot: string;
  codeqlBinary: string;
  queryPath: string;
  workspaceDir: string;
}

function isAllowedCodeqlCompileCommand(command: string, options: CompileCommandOptions): boolean {
  const words = splitShellWords(command);
  if (!words || words.length < 5) {
    return false;
  }

  const resolvedBinary = resolveInputPath(options.repoRoot, words[0]);
  if (!isSamePath(resolvedBinary, options.codeqlBinary)) {
    return false;
  }

  if (words[1] !== "query" || words[2] !== "compile") {
    return false;
  }

  const resolvedQueryPath = resolveInputPath(options.repoRoot, words[3]);
  if (!isSamePath(resolvedQueryPath, options.queryPath)) {
    return false;
  }

  if (words.length === 6 && words[4] === "--search-path") {
    const resolvedSearchPath = resolveInputPath(options.repoRoot, words[5]);
    return isSamePath(resolvedSearchPath, options.workspaceDir);
  }

  if (words.length === 5 && words[4].startsWith("--search-path=")) {
    const value = words[4].slice("--search-path=".length).trim();
    if (!value) {
      return false;
    }
    const resolvedSearchPath = resolveInputPath(options.repoRoot, value);
    return isSamePath(resolvedSearchPath, options.workspaceDir);
  }

  return false;
}

function splitShellWords(command: string): string[] | null {
  const words: string[] = [];
  let current = "";
  let quote: '"' | "'" | null = null;
  let escaping = false;

  for (const char of command.trim()) {
    // In single-quoted shell strings, backslashes are literal characters.
    if (quote === "'") {
      if (char === "'") {
        quote = null;
      } else {
        current += char;
      }
      continue;
    }

    if (escaping) {
      current += char;
      escaping = false;
      continue;
    }

    if (quote === '"') {
      if (char === '"') {
        quote = null;
        continue;
      }

      if (char === "\\") {
        escaping = true;
        continue;
      }

      current += char;
      continue;
    }

    if (char === "\\") {
      escaping = true;
      continue;
    }

    if (char === '"' || char === "'") {
      quote = char;
      continue;
    }

    if (
      char === "$" ||
      char === ";" ||
      char === "|" ||
      char === "&" ||
      char === ">" ||
      char === "<" ||
      char === "`"
    ) {
      return null;
    }

    if (/\s/.test(char)) {
      if (current) {
        words.push(current);
        current = "";
      }
      continue;
    }

    current += char;
  }

  if (escaping || quote) {
    return null;
  }

  if (current) {
    words.push(current);
  }

  return words;
}

function getPathArg(args: Record<string, unknown>): string | null {
  const candidates = ["path", "file_path", "filePath"];
  for (const key of candidates) {
    const value = args[key];
    if (typeof value === "string" && value.trim()) {
      return value.trim();
    }
  }

  return null;
}

function resolveInputPath(repoRoot: string, candidatePath: string): string {
  return path.isAbsolute(candidatePath)
    ? path.normalize(candidatePath)
    : path.resolve(repoRoot, candidatePath);
}

function isPathWithinRoot(rootPath: string, candidatePath: string): boolean {
  const relative = path.relative(path.resolve(rootPath), path.resolve(candidatePath));
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function isSamePath(left: string, right: string): boolean {
  const a = path.resolve(left);
  const b = path.resolve(right);
  return process.platform === "win32" ? a.toLowerCase() === b.toLowerCase() : a === b;
}

function extractQueryFromResult(text: string): string | null {
  const candidates: Array<{ query: string; score: number }> = [];

  // Prefer fenced blocks and score each candidate instead of taking the first regex hit.
  for (const block of extractFencedBlocks(text)) {
    const query = block.content.trim();
    if (!isLikelyCodeqlQuery(query)) {
      continue;
    }
    candidates.push({
      query,
      score: scoreCodeqlCandidate(query, block.language),
    });
  }

  // Fallback to raw text parsing for agents that return plain text without fences.
  const rawCandidates = extractRawQueryCandidates(text);
  for (const query of rawCandidates) {
    if (!isLikelyCodeqlQuery(query)) {
      continue;
    }
    candidates.push({
      query,
      score: scoreCodeqlCandidate(query),
    });
  }

  if (candidates.length === 0) {
    return null;
  }

  candidates.sort((a, b) => b.score - a.score);
  return candidates[0].query;
}

function extractFencedBlocks(
  text: string,
): Array<{ language: string | undefined; content: string }> {
  const out: Array<{ language: string | undefined; content: string }> = [];
  const matches = text.matchAll(QUERY_FENCE_REGEX);
  for (const match of matches) {
    out.push({
      language: match[1]?.trim().toLowerCase(),
      content: match[2] ?? "",
    });
  }
  return out;
}

function extractRawQueryCandidates(text: string): string[] {
  const trimmed = text.trim();
  if (!trimmed) {
    return [];
  }

  const candidates = new Set<string>();
  const metadataStart = trimmed.indexOf("/**");
  if (metadataStart !== -1) {
    const fromMetadata = trimmed.slice(metadataStart).trim();
    candidates.add(trimTrailingNonQueryLines(fromMetadata));
  }

  const importMatch = /\bimport\s+[A-Za-z_][A-Za-z0-9_]*\b/.exec(trimmed);
  if (importMatch && importMatch.index >= 0) {
    const fromImport = trimmed.slice(importMatch.index).trim();
    candidates.add(trimTrailingNonQueryLines(fromImport));
  }

  if (isLikelyCodeqlQuery(trimmed)) {
    candidates.add(trimTrailingNonQueryLines(trimmed));
  }

  return [...candidates].filter(Boolean);
}

function trimTrailingNonQueryLines(queryText: string): string {
  const lines = queryText.split(/\r?\n/);
  let lastSelectIndex = -1;
  for (let i = 0; i < lines.length; i++) {
    if (/^\s*select\b/.test(lines[i] ?? "")) {
      lastSelectIndex = i;
    }
  }

  if (lastSelectIndex !== -1) {
    for (let i = lastSelectIndex + 1; i < lines.length; i++) {
      if ((lines[i] ?? "").trim() === "") {
        return lines.slice(0, i).join("\n").trim();
      }
    }
  }

  let lastCodeLine = lines.length - 1;

  while (lastCodeLine >= 0) {
    const line = lines[lastCodeLine]?.trim();
    if (!line) {
      lastCodeLine -= 1;
      continue;
    }

    if (looksLikeCodeqlLine(line)) {
      break;
    }

    lastCodeLine -= 1;
  }

  if (lastCodeLine < 0) {
    return queryText.trim();
  }

  return lines
    .slice(0, lastCodeLine + 1)
    .join("\n")
    .trim();
}

function looksLikeCodeqlLine(line: string): boolean {
  if (
    line.startsWith("//") ||
    line.startsWith("/*") ||
    line.startsWith("*") ||
    line.startsWith("*/")
  ) {
    return true;
  }

  return /^(?:@|import\b|private\b|module\b|class\b|predicate\b|from\b|where\b|select\b|exists\b|if\b|then\b|else\b|and\b|or\b|not\b|[A-Za-z_][A-Za-z0-9_:.<>()[\], ]*[,{)]?|"(?:[^"\\]|\\.)*"\s*,?|'(?:[^'\\]|\\.)*'\s*,?|-?\d+(?:\.\d+)?\s*,?)$/.test(
    line,
  );
}

function isLikelyCodeqlQuery(candidate: string): boolean {
  return /\bimport\b/.test(candidate) && /\bselect\b/.test(candidate);
}

function scoreCodeqlCandidate(candidate: string, language: string | undefined = undefined): number {
  let score = 0;
  if (language === "ql" || language === "codeql") {
    score += 3;
  }
  if (/\bimport\b/.test(candidate)) {
    score += 3;
  }
  if (/\bselect\b/.test(candidate)) {
    score += 3;
  }
  if (/\bfrom\b/.test(candidate)) {
    score += 1;
  }
  if (/@kind\b/.test(candidate)) {
    score += 1;
  }
  if (/@id\b/.test(candidate)) {
    score += 1;
  }
  return score;
}

export function computeCacheHash(template: string, referenceContent: string): string {
  return createHash("sha256")
    .update(template)
    .update("\x00")
    .update(referenceContent)
    .digest("hex")
    .slice(0, 16);
}

export async function readCacheIfValid(
  cachePath: string,
  expectedHash: string,
): Promise<string | null> {
  try {
    const content = await readFile(cachePath, "utf-8");
    const firstNewline = content.indexOf("\n");
    if (firstNewline === -1) {
      return null;
    }

    const firstLine = content.slice(0, firstNewline);
    if (!firstLine.startsWith(CACHE_PREFIX)) {
      return null;
    }

    const storedHash = firstLine.slice(CACHE_PREFIX.length);
    if (storedHash !== expectedHash) {
      return null;
    }

    return content.slice(firstNewline + 1);
  } catch {
    return null;
  }
}

export const __taintAnalysisExtractionAgentInternals = {
  extractQueryFromResult,
  isAllowedCodeqlCompileCommand,
  splitShellWords,
};
