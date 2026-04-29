/**
 * taint-iris — IRIS-style taint analysis: LLM writes all CodeQL queries dynamically.
 *
 * For each CWE from taint-cwe-select, runs a full IRIS loop in a single Claude session:
 *   Step A: Write & run CodeQL extraction queries for CWE-relevant sources/sinks
 *   Step B: Label candidates (source/sink/sanitizer/none)
 *   Step C: Generate TaintTracking configuration, compile, run (iterate on failure)
 *   Step D: Interpret SARIF results, triage
 *
 * Language-agnostic: the LLM writes CodeQL for whatever language the database contains.
 * Framework-agnostic: the LLM knows gRPC, protobuf, GORM, Django, Express, etc.
 */
import { createHash } from "node:crypto";
import { existsSync, mkdirSync } from "node:fs";
import path from "node:path";
import type { AgentToolDecision } from "../../../agent-runtime/types.js";
import { createLogger } from "../../../logger.js";
import { coerceRepoContext } from "../../../repo-context.js";
import { scoreFindingMetadata } from "../../../scanners/scoring.js";
import type { Finding, TaintPathStep } from "../../../scanners/types.js";
import { attachTaskOutputMeta } from "../../../task-output-meta.js";
import type { ScanOpts } from "../../../types.js";
import { isPathWithinRoot, isRecord, toErrorMessage } from "../../../utils.js";
import type { DagNodeImpl, DagRunContext } from "../../types.js";
import {
  resolveTaskAllowedTools,
  resolveTaskModel,
  resolveTaskRuntime,
} from "../runtime-overrides.js";
import type { CweSelection, CweSelectOutput } from "./cwe-select.js";

const log = createLogger({ stage: "taint-iris" });

const IRIS_FINDING_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["findings"],
  properties: {
    findings: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: [
          "title",
          "cwe",
          "severity",
          "filePath",
          "startLine",
          "message",
          "sourceSinkTrace",
        ],
        properties: {
          title: { type: "string" },
          cwe: { type: "string" },
          severity: { type: "string", enum: ["critical", "high", "medium", "low"] },
          filePath: { type: "string" },
          startLine: { type: "integer" },
          message: { type: "string" },
          sourceSinkTrace: { type: "string" },
          taintPath: {
            type: "array",
            items: {
              type: "object",
              additionalProperties: false,
              required: ["filePath", "line"],
              properties: {
                filePath: { type: "string" },
                line: { type: "integer" },
                message: { type: "string" },
                snippet: { type: "string" },
              },
            },
          },
          confidence: { type: "string", enum: ["high", "medium", "low"] },
          exploitPreconditions: { type: "string" },
        },
      },
    },
  },
} as const;

function resolveCodeqlDbPath(context: DagRunContext): string | null {
  // Check common locations for a pre-built CodeQL database
  for (const root of resolveCodeqlSearchRoots(context)) {
    const candidates = [path.join(root, ".kuzushi", "codeql-db"), path.join(root, ".codeql", "db")];
    for (const p of candidates) {
      if (existsSync(p)) return p;
    }
  }
  return null;
}

function resolveCodeqlSearchRoots(context: DagRunContext): string[] {
  const roots = [
    context.scanPath,
    context.workRoot,
    context.projectRoot,
    context.repoRoot,
    context.gitRoot,
  ].filter((item): item is string => typeof item === "string" && item.trim().length > 0);
  const out: string[] = [];
  const seen = new Set<string>();
  for (const root of roots) {
    const resolved = path.resolve(root);
    if (seen.has(resolved)) continue;
    seen.add(resolved);
    out.push(resolved);
  }
  return out;
}

function resolveScanRoot(context: DagRunContext): string {
  return path.resolve(context.scanPath ?? context.workRoot ?? context.repoRoot);
}

function resolveIrisWorkspace(context: DagRunContext): string {
  const artifactRoot = path.resolve(
    context.gitRoot ?? context.projectRoot ?? context.repoRoot,
    ".kuzushi",
    "runs",
    sanitizePathSegment(context.runId || "adhoc"),
    "taint-iris",
  );
  mkdirSync(artifactRoot, { recursive: true });
  return artifactRoot;
}

function buildIrisPrompt(
  cwes: CweSelection[],
  codeqlDbPath: string | null,
  repoContext: ReturnType<typeof coerceRepoContext>,
  options: {
    promptOverride?: string;
    cweLimitNotice?: string;
    scanRoot: string;
    repoRoot: string;
    workspaceDir: string;
  },
): string {
  const cweList = cwes.map((c) => `- ${c.id}: ${c.name} (${c.reason})`).join("\n");
  const repoInfo = repoContext
    ? [
        `Languages: ${repoContext.languages.join(", ")}`,
        `Frameworks: ${repoContext.frameworks.join(", ")}`,
        `DB/ORM: ${repoContext.ormOrDb.join(", ")}`,
        `Entry points: ${repoContext.entryPoints.join(", ")}`,
      ].join("\n")
    : "No context available.";

  const codeqlSection = codeqlDbPath
    ? [
        `## CodeQL Database`,
        `A CodeQL database is available at: ${codeqlDbPath}`,
        `Generated query workspace: ${options.workspaceDir}`,
        `Write generated .ql/.qll/.qls files only under that workspace.`,
        `Validate queries with: codeql query compile ${path.join(options.workspaceDir, "query.ql")}`,
        `You can run queries with: codeql query run -d ${codeqlDbPath} ${path.join(options.workspaceDir, "query.ql")}`,
        `You can analyze with: codeql database analyze ${codeqlDbPath} ${path.join(options.workspaceDir, "query.ql")} --format=sarif-latest --output=${path.join(options.workspaceDir, "results.sarif")}`,
        "",
      ].join("\n")
    : [
        "No CodeQL database available. Use grep-based manual tracing inside the scan scope only.",
        `Generated notes/workspace path: ${options.workspaceDir}`,
      ].join("\n");

  const prompt = [
    "You are an IRIS-style security analyst performing taint analysis on a codebase.",
    "Your goal: find exploitable data flow vulnerabilities by combining LLM reasoning with CodeQL.",
    "",
    "## Hard Scope",
    `Scan root: ${options.scanRoot}`,
    `Repository root for metadata/CodeQL DB resolution: ${options.repoRoot}`,
    `Generated query workspace: ${options.workspaceDir}`,
    "Do not inspect paths outside the scan root, except for generated CodeQL files in the workspace and the resolved CodeQL database path.",
    "Do not run broad filesystem discovery commands such as find /, find /Users, or searches from $HOME.",
    "All shell commands are guarded. Only CodeQL compile/run/analyze commands against the resolved DB and workspace are allowed.",
    "",
    "## Project",
    repoInfo,
    "",
    codeqlSection,
    "",
    "## CWE Classes to Analyze",
    cweList,
    "",
    "## Method (IRIS loop — repeat for each CWE)",
    "",
    "For EACH CWE class above, perform these steps:",
    "",
    "### Step A: Extract sink and source candidates",
    "Write a CodeQL query that extracts API calls relevant to this CWE from the project's dependencies.",
    "For example, for CWE-89 (SQL Injection), query for calls to database query/exec methods.",
    "For sources, query for entry points (HTTP handlers, gRPC handlers, CLI arg reads, etc.).",
    "Run the query. If it fails to compile, read the error and fix the query. Iterate until it works.",
    "",
    "### Step B: Label candidates",
    "Review the extraction results. For each candidate, classify as:",
    "- **source**: untrusted user input enters here",
    "- **sink**: dangerous operation — vulnerability occurs if tainted data reaches here",
    "- **sanitizer**: blocks taint flow (escaping, validation, parameterization)",
    "- **none**: not security-relevant for this CWE",
    "",
    "### Step C: Generate and run taint tracking query",
    "Write a CodeQL TaintTracking::Configuration (or DataFlow::Configuration) that:",
    "- Defines isSource() using your labeled sources",
    "- Defines isSink() using your labeled sinks",
    "- Optionally adds isAdditionalFlowStep() for framework-specific propagation",
    "  (e.g., protobuf field access, gRPC metadata flow, ORM query builders)",
    "- Optionally adds isSanitizer() for identified sanitizers",
    "",
    "Compile and run. If compilation fails, read the error and fix. If it runs but finds 0 results,",
    "investigate: are you missing propagation steps? Is the source granularity wrong?",
    "Add AdditionalFlowStep predicates and re-run. Try up to 3 iterations per CWE.",
    "",
    "### Step D: Interpret results",
    "Read the SARIF output (or query results). For each data flow path found:",
    "- Read the actual source code at each step",
    "- Determine if the path is exploitable (check for sanitizers, type constraints, dead code)",
    "- If true positive: record as a finding with source→sink trace",
    "- If false positive: explain why and skip",
    "",
    "## Output",
    "After analyzing ALL CWE classes, return your findings as structured JSON.",
    "Each finding needs: title, CWE, severity, file path, line number, description, source→sink trace,",
    "and a structured taintPath array with each step's filePath, line, message (role like 'source', 'step', 'sink'), and code snippet.",
  ];
  if (options.cweLimitNotice) {
    prompt.splice(2, 0, "", options.cweLimitNotice);
  }
  if (options.promptOverride?.trim()) {
    prompt.push("", "## Operator Prompt Override", options.promptOverride.trim());
  }
  return prompt.join("\n");
}

export const taintIrisTask: DagNodeImpl<ScanOpts, Finding[]> = {
  id: "taint-iris",
  displayName: "IRIS Taint Analysis",
  outputKind: "findings",
  dependsOn: ["taint-cwe-select", "context-gatherer"],

  condition(upstreamOutputs) {
    const cweOutput = upstreamOutputs.get("taint-cwe-select") as CweSelectOutput | undefined;
    return !!cweOutput?.cwes?.length;
  },

  async run(input, context): Promise<Finding[]> {
    const runtime = resolveTaskRuntime(context);
    const model = resolveTaskModel(context, "taint-iris");
    const params = (input ?? {}) as unknown as Record<string, unknown>;
    const taskConfig = {
      ...(context.config.taskConfig["taint-iris"] ?? {}),
      ...(context.config.taskConfig["taint-iris:hunt"] ?? {}),
    };
    const repoContext = coerceRepoContext(context.upstreamOutputs.get("context-gatherer"));
    const cweOutput = context.upstreamOutputs.get("taint-cwe-select") as
      | CweSelectOutput
      | undefined;
    const cwes = cweOutput?.cwes ?? [];

    if (cwes.length === 0) {
      log.info("No CWE classes selected — skipping IRIS taint analysis");
      return attachTaskOutputMeta([], { costUsd: 0 });
    }

    const maxCwes = readPositiveInteger(params["maxCwes"] ?? taskConfig["maxCwes"]);
    const selectedCwes = maxCwes ? cwes.slice(0, maxCwes) : cwes;
    const cweLimitNotice =
      maxCwes && cwes.length > selectedCwes.length
        ? `Analyzing first ${selectedCwes.length} of ${cwes.length} selected CWE classes.`
        : undefined;
    const promptOverride = readString(
      params["TAINT_IRIS_PROMPT"] ?? taskConfig["TAINT_IRIS_PROMPT"],
    );
    const maxBudgetUsd = readPositiveNumber(params["maxBudgetUsd"] ?? taskConfig["maxBudgetUsd"]);
    const scanRoot = resolveScanRoot(context);
    const workspaceDir = resolveIrisWorkspace(context);
    const guardDenied: string[] = [];
    const abortController = context.signal ? new AbortController() : undefined;
    if (context.signal && abortController) {
      if (context.signal.aborted) abortController.abort();
      else context.signal.addEventListener("abort", () => abortController.abort(), { once: true });
    }

    const codeqlDbPath = resolveCodeqlDbPath(context);
    const canUseTool = createIrisToolGuard({
      scanRoot,
      workspaceDir,
      ...(codeqlDbPath ? { codeqlDbPath } : {}),
      denied: guardDenied,
    });
    const prompt = buildIrisPrompt(selectedCwes, codeqlDbPath, repoContext, {
      ...(promptOverride ? { promptOverride } : {}),
      ...(cweLimitNotice ? { cweLimitNotice } : {}),
      scanRoot,
      repoRoot: context.repoRoot,
      workspaceDir,
    });

    log.info(
      `Starting IRIS taint analysis for ${selectedCwes.length} CWE classes (model=${model}, codeql=${!!codeqlDbPath})`,
    );

    let structuredOutput: unknown;
    let resultText = "";
    let costUsd = 0;

    try {
      for await (const message of runtime.query({
        prompt,
        options: {
          cwd: scanRoot,
          model,
          allowedTools: [...resolveTaskAllowedTools(context), "Bash", "Write"],
          permissionMode: "dontAsk",
          canUseTool,
          taskId: "taint-iris:hunt",
          fingerprint: "taint-iris:classic-agent",
          phase: "scan",
          ...(maxBudgetUsd ? { maxBudgetUsd } : {}),
          ...(abortController ? { abortController } : {}),
          outputFormat: {
            type: "json_schema",
            schema: IRIS_FINDING_SCHEMA,
            strict: true,
            retryInvalidStructuredOutput: 2,
          },
        },
      })) {
        if (message.type !== "result") continue;
        if (typeof message.totalCostUsd === "number") costUsd = message.totalCostUsd;
        if ("result" in message) {
          resultText = message.result;
          structuredOutput = message.structuredOutput;
        }
      }
    } catch (error) {
      throw new Error(`[taint-iris] Agent error: ${toErrorMessage(error)}`);
    }

    const findings = parseFindings(
      structuredOutput ?? tryParseJson(resultText),
      context.repoRoot,
      context.repoName,
    );

    log.info(`IRIS analysis complete: ${findings.length} findings, $${costUsd.toFixed(2)}`);

    const degradation =
      guardDenied.length > 0
        ? {
            type: "guarded-tools",
            reason: "denied-out-of-scope-agent-tool-use",
            message: `Denied ${new Set(guardDenied).size} out-of-scope IRIS agent tool request(s).`,
            denied: [...new Set(guardDenied)],
          }
        : undefined;
    return attachTaskOutputMeta(findings, { costUsd, ...(degradation ? { degradation } : {}) });
  },
};

interface IrisToolGuardOptions {
  scanRoot: string;
  workspaceDir: string;
  codeqlDbPath?: string;
  denied: string[];
}

function createIrisToolGuard(options: IrisToolGuardOptions) {
  const scanRoot = path.resolve(options.scanRoot);
  const workspaceDir = path.resolve(options.workspaceDir);
  const codeqlDbPath = options.codeqlDbPath ? path.resolve(options.codeqlDbPath) : undefined;

  return (toolName: string, args: Record<string, unknown>): AgentToolDecision => {
    if (toolName === "Read" || toolName === "Grep" || toolName === "Glob") {
      const inputPath = getPathArg(args);
      if (!inputPath) return { behavior: "allow" };
      const resolvedPath = resolveInputPath(scanRoot, inputPath);
      if (isPathWithinAnyRoot(resolvedPath, [scanRoot, workspaceDir])) return { behavior: "allow" };
      const message = `${toolName} path must stay inside scan root or IRIS workspace`;
      options.denied.push(`${toolName}: ${inputPath}`);
      return { behavior: "deny", message };
    }

    if (toolName === "Write") {
      const filePath = getPathArg(args);
      if (!filePath) {
        options.denied.push("Write: missing path");
        return { behavior: "deny", message: "Write requires a file path" };
      }
      const resolvedPath = resolveInputPath(scanRoot, filePath);
      if (isAllowedGeneratedCodeqlPath(resolvedPath, workspaceDir)) return { behavior: "allow" };
      options.denied.push(`Write: ${filePath}`);
      return {
        behavior: "deny",
        message: "Write is restricted to generated CodeQL files inside the IRIS workspace",
      };
    }

    if (toolName === "Bash") {
      const command = typeof args["command"] === "string" ? args["command"] : "";
      if (isAllowedCodeqlCommand(command, { scanRoot, workspaceDir, codeqlDbPath })) {
        return { behavior: "allow" };
      }
      options.denied.push(`Bash: ${command.slice(0, 160)}`);
      return {
        behavior: "deny",
        message:
          "Bash is restricted to CodeQL query compile/run/database analyze commands for this scan",
      };
    }

    return { behavior: "allow" };
  };
}

interface CodeqlCommandGuardOptions {
  scanRoot: string;
  workspaceDir: string;
  codeqlDbPath?: string;
}

function isAllowedCodeqlCommand(command: string, options: CodeqlCommandGuardOptions): boolean {
  const words = splitShellWords(command);
  if (!words || words.length < 3) return false;
  if (!isCodeqlBinaryWord(words[0])) return false;

  if (words[1] === "query" && words[2] === "compile") {
    return isAllowedQueryCompile(words.slice(3), options);
  }
  if (words[1] === "query" && words[2] === "run") {
    return isAllowedQueryRun(words.slice(3), options);
  }
  if (words[1] === "database" && words[2] === "analyze") {
    return isAllowedDatabaseAnalyze(words.slice(3), options);
  }

  return false;
}

function isAllowedQueryCompile(args: string[], options: CodeqlCommandGuardOptions): boolean {
  if (args.length < 1) return false;
  const queryPath = resolveInputPath(options.scanRoot, args[0]);
  if (!isAllowedGeneratedCodeqlPath(queryPath, options.workspaceDir)) return false;
  return areAllowedCodeqlOptions(args.slice(1), options);
}

function isAllowedQueryRun(args: string[], options: CodeqlCommandGuardOptions): boolean {
  if (!options.codeqlDbPath) return false;
  const queryPaths: string[] = [];
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if ((arg === "-d" || arg === "--database") && args[index + 1]) {
      const dbPath = resolveInputPath(options.scanRoot, args[index + 1]);
      if (!isSamePath(dbPath, options.codeqlDbPath)) return false;
      index += 1;
      continue;
    }
    if (arg.startsWith("--database=")) {
      const dbPath = resolveInputPath(options.scanRoot, arg.slice("--database=".length));
      if (!isSamePath(dbPath, options.codeqlDbPath)) return false;
      continue;
    }
    if (arg.startsWith("-")) {
      return areAllowedCodeqlOptions(args.slice(index), options);
    }
    const queryPath = resolveInputPath(options.scanRoot, arg);
    if (!isAllowedGeneratedCodeqlPath(queryPath, options.workspaceDir)) return false;
    queryPaths.push(queryPath);
  }
  return queryPaths.length === 1;
}

function isAllowedDatabaseAnalyze(args: string[], options: CodeqlCommandGuardOptions): boolean {
  if (!options.codeqlDbPath || args.length < 2) return false;
  const dbPath = resolveInputPath(options.scanRoot, args[0]);
  const queryPath = resolveInputPath(options.scanRoot, args[1]);
  if (!isSamePath(dbPath, options.codeqlDbPath)) return false;
  if (!isAllowedGeneratedCodeqlPath(queryPath, options.workspaceDir)) return false;
  return areAllowedCodeqlOptions(args.slice(2), options);
}

function areAllowedCodeqlOptions(args: string[], options: CodeqlCommandGuardOptions): boolean {
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--search-path" || arg === "--additional-packs" || arg === "--output") {
      const value = args[index + 1];
      if (!value || !isAllowedCodeqlOptionValue(arg, value, options)) return false;
      index += 1;
      continue;
    }
    if (!isAllowedCodeqlOption(arg, options)) return false;
  }
  return true;
}

function isAllowedCodeqlOption(arg: string, options: CodeqlCommandGuardOptions): boolean {
  if (arg === "--format=sarif-latest" || arg === "--format=csv" || arg === "--format=json") {
    return true;
  }
  if (/^--(threads|ram)=\d+$/u.test(arg)) return true;
  if (arg.startsWith("--output=")) {
    const outputPath = resolveInputPath(options.scanRoot, arg.slice("--output=".length));
    return isPathWithinRoot(options.workspaceDir, outputPath);
  }
  if (arg.startsWith("--search-path=") || arg.startsWith("--additional-packs=")) {
    return true;
  }
  return false;
}

function isAllowedCodeqlOptionValue(
  option: string,
  value: string,
  options: CodeqlCommandGuardOptions,
): boolean {
  if (option === "--output") {
    const outputPath = resolveInputPath(options.scanRoot, value);
    return isPathWithinRoot(options.workspaceDir, outputPath);
  }
  return option === "--search-path" || option === "--additional-packs";
}

function isCodeqlBinaryWord(word: string): boolean {
  return path.basename(word) === "codeql";
}

function isAllowedGeneratedCodeqlPath(filePath: string, workspaceDir: string): boolean {
  if (!isPathWithinRoot(workspaceDir, filePath)) return false;
  return [".ql", ".qll", ".qls", ".yml", ".yaml"].includes(path.extname(filePath));
}

function isPathWithinAnyRoot(filePath: string, roots: readonly string[]): boolean {
  return roots.some((root) => isPathWithinRoot(root, filePath));
}

function getPathArg(args: Record<string, unknown>): string | null {
  for (const key of ["path", "file_path", "filePath"]) {
    const value = args[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return null;
}

function resolveInputPath(baseRoot: string, candidatePath: string): string {
  return path.isAbsolute(candidatePath)
    ? path.normalize(candidatePath)
    : path.resolve(baseRoot, candidatePath);
}

function isSamePath(left: string, right: string): boolean {
  const a = path.resolve(left);
  const b = path.resolve(right);
  return process.platform === "win32" ? a.toLowerCase() === b.toLowerCase() : a === b;
}

function splitShellWords(command: string): string[] | null {
  const words: string[] = [];
  let current = "";
  let quote: '"' | "'" | null = null;
  let escaping = false;

  for (const char of command.trim()) {
    if (quote === "'") {
      if (char === "'") quote = null;
      else current += char;
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

    if (/\s/u.test(char)) {
      if (current) {
        words.push(current);
        current = "";
      }
      continue;
    }

    current += char;
  }

  if (escaping || quote) return null;
  if (current) words.push(current);
  return words;
}

function sanitizePathSegment(value: string): string {
  return value.replace(/[^a-zA-Z0-9._-]/gu, "_").slice(0, 80) || "adhoc";
}

function parseFindings(raw: unknown, repoRoot: string, repoName: string): Finding[] {
  if (!isRecord(raw)) return [];
  const items = Array.isArray(raw["findings"]) ? raw["findings"] : [];
  const out: Finding[] = [];

  for (const item of items) {
    if (!isRecord(item)) continue;
    const title = str(item["title"]);
    const cwe = str(item["cwe"]);
    const filePath = str(item["filePath"]);
    const startLine = Math.max(1, Math.floor(Number(item["startLine"]) || 1));
    const message = str(item["message"]);
    const trace = str(item["sourceSinkTrace"]);
    const confidence = str(item["confidence"]) || "medium";

    if (!title || !filePath || !message) continue;

    const rawPath = Array.isArray(item["taintPath"]) ? item["taintPath"] : [];
    const taintPath: TaintPathStep[] = [];
    for (const step of rawPath) {
      if (!isRecord(step)) continue;
      const fp = str(step["filePath"]);
      const ln = Math.max(1, Math.floor(Number(step["line"]) || 1));
      if (!fp) continue;
      taintPath.push({
        filePath: normalizePath(repoRoot, fp),
        line: ln,
        message: str(step["message"]) || undefined,
        snippet: str(step["snippet"]) || undefined,
      });
    }

    const severity = mapSeverity(str(item["severity"]));
    const fingerprint = createHash("sha256")
      .update([repoName, "taint-iris", cwe, filePath, String(startLine), title].join("|"))
      .digest("hex");

    out.push({
      taskId: "taint-iris",
      fingerprint,
      ruleId: `taint-iris/${cwe || "unknown"}`,
      filePath: normalizePath(repoRoot, filePath),
      startLine,
      severity,
      message: `[${cwe}] ${title}: ${message}`,
      evidence: trace || null,
      scannerConfidence: confidence.toUpperCase() as "HIGH" | "MEDIUM" | "LOW",
      subcategory: ["vuln"],
      likelihood: confidence.toUpperCase(),
      impact: severity === "ERROR" ? "HIGH" : "MEDIUM",
      cwe: cwe ? [cwe] : [],
      score: scoreFindingMetadata({
        severity,
        likelihood: confidence.toUpperCase(),
        impact: severity === "ERROR" ? "HIGH" : "MEDIUM",
        subcategory: ["vuln"],
      }),
      taintPath: taintPath.length > 0 ? taintPath : undefined,
      proofState: "symbolic_only",
      engineProvenance: [{ kind: "taint-analysis", detail: "IRIS CodeQL-backed taint analysis" }],
    });
  }

  return out;
}

function mapSeverity(s: string): string {
  switch (s.toLowerCase()) {
    case "critical":
    case "high":
      return "ERROR";
    case "medium":
      return "WARNING";
    default:
      return "INFO";
  }
}

function normalizePath(repoRoot: string, filePath: string): string {
  if (!path.isAbsolute(filePath)) return filePath;
  const rel = path.relative(repoRoot, filePath);
  return rel.startsWith("..") ? filePath : rel || filePath;
}

function str(v: unknown): string {
  return typeof v === "string" ? v.trim() : "";
}

function tryParseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function readString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value : undefined;
}

function readPositiveInteger(value: unknown): number | undefined {
  const parsed = typeof value === "number" ? value : typeof value === "string" ? Number(value) : 0;
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : undefined;
}

function readPositiveNumber(value: unknown): number | undefined {
  const parsed = typeof value === "number" ? value : typeof value === "string" ? Number(value) : 0;
  return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined;
}

export const __taintIrisInternals = {
  createIrisToolGuard,
  isAllowedCodeqlCommand,
  resolveCodeqlDbPath,
  resolveScanRoot,
};
