import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { getAgentRuntime } from "../../agent-runtime/index.js";
import type {
  AgentResultSuccessMessage,
  AgentToolDecision,
} from "../../agent-runtime/types.js";
import { toErrorMessage } from "../../utils.js";
import type { AugurLanguage } from "./augur-types.js";

const SOURCE_BODY_PLACEHOLDERS = ["{{SOURCE_HANDLER_PREDICATE}}"];
const SINK_BODY_PLACEHOLDERS = ["{{SINK_CALL_PREDICATE}}"];
const CACHE_PREFIX = "// cache:";
const QUERY_FENCE_REGEX = /```([a-zA-Z0-9_-]+)?[ \t]*\n([\s\S]*?)```/g;

export interface ExtractionAgentOptions {
  language: AugurLanguage;
  kind: "source" | "sink";
  template: string;
  referenceFiles: string[];
  augurPath: string;
  model: string;
  repoRoot: string;
  workspaceDir: string;
  codeqlBinary: string;
  dbPath: string;
}

/**
 * Returns true when the template contains unresolved body placeholders
 * that prevent deterministic rendering (i.e. the agent path is needed).
 *
 * Python templates have fully hardcoded predicates, so this returns false for them.
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
): Promise<string | null> {
  const {
    language,
    kind,
    template,
    referenceFiles,
    augurPath,
    model,
    repoRoot,
    workspaceDir,
    codeqlBinary,
    dbPath,
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

  const cached = await readCacheIfValid(cachePath, cacheHash);
  if (cached !== null) {
    return cached;
  }

  // --- Build system prompt ---
  const systemPrompt = await buildExtractionPrompt({
    language,
    kind,
    template,
    referenceContent,
    augurPath,
    queryPath,
    codeqlBinary,
    workspaceDir,
    dbPath,
  });

  // --- Call LLM ---
  const runtime = getAgentRuntime();
  let resultText: string | null = null;

  try {
    for await (const message of runtime.query({
      prompt: systemPrompt,
      options: {
        cwd: repoRoot,
        model,
        maxTurns: 15,
        allowedTools: ["Read", "Glob", "Grep", "Bash", "Write"],
        permissionMode: "acceptEdits",
        canUseTool,
      },
    })) {
      if (message.type === "result" && message.subtype === "success") {
        resultText = (message as AgentResultSuccessMessage).result;
      }
    }
  } catch (error) {
    process.stderr.write(
      `[augur-extraction-agent] LLM call failed for ${language}/${kind}: ${toErrorMessage(error)}\n`,
    );
    return null;
  }

  if (!resultText) {
    return null;
  }

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
    return null;
  }

  // --- Cache the result ---
  try {
    await mkdir(cacheDir, { recursive: true });
    const cacheContent = `${CACHE_PREFIX}${cacheHash}\n${queryText}`;
    await writeFile(cachePath, cacheContent, "utf-8");
  } catch {
    // Cache write failure is non-fatal
  }

  return queryText;
}

// ── Internals ──────────────────────────────────────────────

interface PromptBuildOptions {
  language: AugurLanguage;
  kind: "source" | "sink";
  template: string;
  referenceContent: string;
  augurPath: string;
  queryPath: string;
  codeqlBinary: string;
  workspaceDir: string;
  dbPath: string;
}

async function buildExtractionPrompt(opts: PromptBuildOptions): Promise<string> {
  const {
    language,
    kind,
    template,
    referenceContent,
    augurPath,
    queryPath,
    codeqlBinary,
    workspaceDir,
    dbPath,
  } = opts;

  const workflowSection = await loadWorkflowStep2(augurPath);
  const pythonExample = await loadPythonExample(augurPath, kind);

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
  ];

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
    lines.push(
      "## Reference documentation",
      referenceContent,
      "",
    );
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

async function loadWorkflowStep2(augurPath: string): Promise<string> {
  const workflowPath = path.join(augurPath, "WORKFLOW.md");
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

async function loadPythonExample(augurPath: string, kind: "source" | "sink"): Promise<string | null> {
  const templatePath = path.join(augurPath, "assets", "extraction", `python_${kind}s.ql.tmpl`);
  try {
    return await readFile(templatePath, "utf-8");
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
      if (!isAllowedCodeqlCompileCommand(command, {
        repoRoot,
        codeqlBinary,
        queryPath,
        workspaceDir,
      })) {
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

function isAllowedCodeqlCompileCommand(
  command: string,
  options: CompileCommandOptions,
): boolean {
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
  let quote: "\"" | "'" | null = null;
  let escaping = false;

  for (const char of command.trim()) {
    if (escaping) {
      current += char;
      escaping = false;
      continue;
    }

    if (char === "\\") {
      escaping = true;
      continue;
    }

    if (quote) {
      if (char === quote) {
        quote = null;
        continue;
      }
      current += char;
      continue;
    }

    if (char === "\"" || char === "'") {
      quote = char;
      continue;
    }

    if (char === "$" || char === ";" || char === "|" || char === "&" || char === ">" || char === "<" || char === "`") {
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
  return process.platform === "win32"
    ? a.toLowerCase() === b.toLowerCase()
    : a === b;
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

function extractFencedBlocks(text: string): Array<{ language: string | undefined; content: string }> {
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

  return lines.slice(0, lastCodeLine + 1).join("\n").trim();
}

function looksLikeCodeqlLine(line: string): boolean {
  if (line.startsWith("//") || line.startsWith("/*") || line.startsWith("*") || line.startsWith("*/")) {
    return true;
  }

  return /^(?:@|import\b|private\b|module\b|class\b|predicate\b|from\b|where\b|select\b|exists\b|if\b|then\b|else\b|and\b|or\b|not\b|[A-Za-z_][A-Za-z0-9_:.<>()\[\], ]*[,{)]?)$/.test(line);
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

export const __augurExtractionAgentInternals = {
  extractQueryFromResult,
  isAllowedCodeqlCompileCommand,
  splitShellWords,
};
