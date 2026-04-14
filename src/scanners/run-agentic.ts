import type { AgentRuntime } from "../agent-runtime/types.js";
import { getLogger } from "../logger.js";
import type { RepoContext, ScanOpts } from "../types.js";
import { languageTuningModule } from "../prompts/language-tuning.js";
import type { Finding } from "./types.js";
import {
  FINDING_SCHEMA,
  parseFindingOutput,
  selectFindings,
  computeFingerprint,
  type FindingOutput,
  type NormalizedFinding,
} from "./normalize-findings.js";

const log = getLogger("agentic-scan");

// Re-export under old names for backward compatibility
export { FINDING_SCHEMA as AGENTIC_SCHEMA };
export type AgenticFinding = NormalizedFinding;
export type AgenticOutput = FindingOutput;

export interface AgenticRuntimeOptions {
  runtime?: AgentRuntime;
  abortController?: AbortController;
  maxBudgetUsd?: number;
}

/** Run the agentic scanner and return structured findings. */
export async function runAgentic(
  repoRoot: string,
  opts: ScanOpts,
  model: string,
  defaultMaxFindings: number,
  runtimeOptions: AgenticRuntimeOptions = {},
  repoContext?: RepoContext,
): Promise<AgenticOutput> {
  const requestedMax = Math.max(1, opts.maxFindings ?? defaultMaxFindings);
  const prompt = buildPrompt(opts, requestedMax, repoContext);
  const runtime = runtimeOptions.runtime;
  if (!runtime) {
    throw new Error("Agentic scanner requires an explicit runtime.");
  }
  let resultText = "";
  let structuredOutput: unknown = undefined;
  let executionError: string | null = null;
  let costUsd = 0;

  const tag = "[agentic]";
  log.info(`${tag} Starting scan (model=${model}, cwd=${repoRoot})`);

  for await (const message of runtime.query({
    prompt,
    options: {
      cwd: repoRoot,
      model,
      allowedTools: ["Read", "Glob", "Grep"],
      permissionMode: "dontAsk",
      maxBudgetUsd: runtimeOptions.maxBudgetUsd,
      abortController: runtimeOptions.abortController,
      outputFormat: {
        type: "json_schema",
        schema: FINDING_SCHEMA,
        strict: true,
        retryInvalidStructuredOutput: 2,
      },
    },
  })) {
    // Prompt/message logging handled by LoggingAgentRuntime wrapper
    if (message.type === "tool-progress" || message.type === "tool-summary" || message.type === "assistant") {
      continue;
    }

    if (message.type !== "result") continue;
    if (typeof message.totalCostUsd === "number" && Number.isFinite(message.totalCostUsd)) {
      costUsd = message.totalCostUsd;
    }
    if ("result" in message) {
      resultText = message.result;
      structuredOutput = message.structuredOutput;
      const durationSec = message.durationMs ? (message.durationMs / 1000).toFixed(1) : "?";
      log.info(`${tag} Complete in ${durationSec}s — ${message.numTurns} turns, $${message.totalCostUsd?.toFixed(4) ?? "?"}`);
      break;
    }

    executionError = (Array.isArray(message.errors) ? message.errors.join("; ") : "") || message.subtype || "unknown error";
  }

  if (executionError) {
    throw new Error(`agentic scanner failed: ${executionError}`);
  }

  const parsed = parseFindingOutput(structuredOutput ?? resultText);
  return { findings: parsed.findings, costUsd };
}

/** Rank and map agentic findings into Finding records. */
export function selectAgenticFindings(
  output: AgenticOutput,
  repoRoot: string,
  repoName: string,
  ref: string,
  maxFindings?: number,
): Finding[] {
  return selectFindings(output, repoRoot, repoName, ref, "agentic", maxFindings);
}

/** Parse and normalize structured output from the agentic scanner. */
export const parseAgenticOutput = parseFindingOutput;

/** Stable fingerprint for agentic findings. */
export function computeAgenticFingerprint(
  repoName: string,
  ref: string,
  finding: AgenticFinding,
): string {
  return computeFingerprint(repoName, ref, "agentic", finding);
}

function buildPrompt(opts: ScanOpts, maxFindings: number, repoContext?: RepoContext): string {
  const reviewContext = opts.agenticReviewContext
    ? [
        "",
        opts.agenticReviewContext,
        "",
        "Your task in this second pass: validate the above findings and discover vulnerability",
        "classes that were MISSED in the first pass. Do NOT simply re-report the same findings.",
        "",
      ]
    : [];

  const scanPathsContext = opts.scanPaths && opts.scanPaths.length > 1
    ? [
        "",
        "## Scan scope (multi-path module)",
        "This module spans multiple package directories. Examine files across ALL of these paths:",
        ...opts.scanPaths.map((p) => `- ${p}`),
        "Trace data flows ACROSS these directories — they form one deployment unit.",
        "",
      ]
    : [];

  return [
    "You are a senior application security researcher with deep expertise in vulnerability discovery.",
    "You think like an attacker: you map attack surfaces, trace data flows, and verify exploitability",
    "before reporting. You know that most static analysis findings are false positives.",
    "",
    ...scanPathsContext,
    ...reviewContext,
    ...(repoContext?.languages.length
      ? [
          `## Detected stack: ${repoContext.languages.join(", ")}${repoContext.frameworks.length ? ` (${repoContext.frameworks.join(", ")})` : ""}`,
          languageTuningModule({ taskId: "agentic", repoContext, frameworks: repoContext.frameworks }),
          "",
        ]
      : []),
    `Severity filter: ${opts.severity.join(", ") || "ERROR, WARNING, INFO"}`,
    `Max findings: ${maxFindings}`,
    `Exclude paths/globs: ${opts.excludePatterns.join(", ") || "(none)"}`,
    "",
    "## Phase 1: Context research",
    "Map the application's attack surface:",
    "1. Identify candidate surfaces: request handlers, auth middleware, deserializers, template/rendering code, filesystem access, process execution, DB/query code, redirects, and outbound HTTP.",
    "2. Understand the auth/middleware stack and framework protections in place.",
    "3. Identify sanitization libraries, validation layers, and security utilities.",
    "",
    "## Phase 2: Comparative analysis",
    "For each candidate surface from Phase 1:",
    "1. Confirm a concrete sink and the attacker-controlled input that reaches it.",
    "2. Check for sanitization, validation, allowlists, authz, feature flags, and router-level middleware.",
    "3. If the issue depends on the absence of a guard, inspect the exact handler/router/middleware chain rather than inferring from one file.",
    "",
    "## Phase 3: Vulnerability assessment",
    "For each confirmed issue from Phase 2:",
    "1. Verify exploitability — can an attacker actually trigger this?",
    "2. Assign confidence: only report HIGH or MEDIUM confidence findings.",
    "3. Document evidence: name the source, sink, and missing guard.",
    "",
    "## Evidence requirements for every reported finding",
    "- Include a precise file and start line for the vulnerable code path.",
    "- The evidence field must name the source/sink/guard fact that justifies the finding.",
    "- Omit the finding entirely if you cannot verify the path in code.",
    "",
    "For each finding return:",
    "- ruleId (string)",
    "- filePath (relative path preferred)",
    "- startLine (1-based integer)",
    "- severity (ERROR|WARNING|INFO)",
    "- message (short finding summary)",
    "- confidence (HIGH|MEDIUM|LOW)",
    "- subcategory (vuln or audit; default to audit when unsure)",
    "- likelihood (HIGH|MEDIUM|LOW)",
    "- impact (HIGH|MEDIUM|LOW)",
    "- cwe (array of CWE strings, optional)",
    "- evidence (short evidence snippet)",
    "",
    "## Few-shot examples",
    "",
    "### Example 1: True positive (SQL injection)",
    "```json",
    '{"ruleId": "sql-injection", "filePath": "src/api/users.ts", "startLine": 42,',
    ' "severity": "ERROR", "message": "User-supplied id parameter concatenated into SQL query without parameterization",',
    ' "confidence": "HIGH", "subcategory": ["vuln"], "likelihood": "HIGH", "impact": "HIGH",',
    ' "cwe": ["CWE-89"], "evidence": "Source: req.params.id (line 38) -> Sink: db.query(template literal with id) (line 42). No parameterization or sanitization."}',
    "```",
    "",
    "### Example 2: Correctly rejected false positive",
    "A shell command call was found, but the command string is fully hardcoded with no user input.",
    "Example: running `git rev-parse HEAD` with a static string — no user input reaches the shell. Do NOT report this.",
    "",
    "### Example 3: Nuanced finding (partial validation)",
    "```json",
    '{"ruleId": "path-traversal", "filePath": "src/files/download.ts", "startLine": 15,',
    ' "severity": "WARNING", "message": "User-controlled filename passed to fs.readFile with path.join but no startsWith check against base directory",',
    ' "confidence": "MEDIUM", "subcategory": ["vuln"], "likelihood": "MEDIUM", "impact": "HIGH",',
    ' "cwe": ["CWE-22"], "evidence": "Source: req.query.file (line 10) -> path.join(uploadDir, file) (line 15) -> fs.readFile (line 16). path.join normalizes but does not prevent traversal without a startsWith guard."}',
    "```",
    "",
    "## Anti-hallucination constraints",
    "- Do not propose remediations. Do not include non-security style issues.",
    "- Do not return placeholders or hypothetical findings.",
    "- Only report what you can verify exists in actual code.",
    "- If unsure, do NOT report — false negatives are better than false positives.",
  ].join("\n");
}

