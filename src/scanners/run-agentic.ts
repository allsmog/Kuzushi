import { createHash } from "node:crypto";
import path from "node:path";
import type { AgentRuntime } from "../agent-runtime/types.js";
import { getLogger } from "../logger.js";
import type { ScanOpts } from "../types.js";
import { isRecord, toErrorMessage } from "../utils.js";
import type { Finding } from "./types.js";
import { scoreFindingMetadata, detectParameterRiskBoost } from "./scoring.js";

const log = getLogger("agentic-scan");

const SEVERITY_LEVELS = new Set(["ERROR", "WARNING", "INFO"]);
const CONFIDENCE_LEVELS = new Set(["HIGH", "MEDIUM", "LOW"]);
const SUBCATEGORIES = new Set(["vuln", "audit"]);

const AGENTIC_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["findings"],
  properties: {
    findings: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["ruleId", "filePath", "startLine", "severity", "message"],
        properties: {
          ruleId: { type: "string" },
          filePath: { type: "string" },
          startLine: { type: "integer", minimum: 1 },
          severity: { type: "string", enum: ["ERROR", "WARNING", "INFO"] },
          message: { type: "string" },
          confidence: { type: "string", enum: ["HIGH", "MEDIUM", "LOW"] },
          subcategory: {
            type: "array",
            items: { type: "string", enum: ["vuln", "audit"] },
          },
          likelihood: { type: "string", enum: ["HIGH", "MEDIUM", "LOW"] },
          impact: { type: "string", enum: ["HIGH", "MEDIUM", "LOW"] },
          cwe: {
            type: "array",
            items: { type: "string" },
          },
          evidence: { type: "string" },
        },
      },
    },
  },
} as const;

interface AgenticFinding {
  ruleId: string;
  filePath: string;
  startLine: number;
  severity: string;
  message: string;
  confidence: string;
  subcategory: string[];
  likelihood: string;
  impact: string;
  cwe: string[];
  evidence: string;
}

export interface AgenticOutput {
  findings: AgenticFinding[];
  costUsd?: number;
}

export interface AgenticRuntimeOptions {
  runtime?: AgentRuntime;
  abortController?: AbortController;
  maxBudgetUsd?: number;
  maxTurns?: number;
}

/** Run the agentic scanner and return structured findings. */
export async function runAgentic(
  repoRoot: string,
  opts: ScanOpts,
  model: string,
  defaultMaxFindings: number,
  runtimeOptions: AgenticRuntimeOptions = {},
): Promise<AgenticOutput> {
  const requestedMax = Math.max(1, opts.maxFindings ?? defaultMaxFindings);
  const prompt = buildPrompt(opts, requestedMax);
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
      maxTurns: runtimeOptions.maxTurns ?? undefined,
      maxBudgetUsd: runtimeOptions.maxBudgetUsd,
      abortController: runtimeOptions.abortController,
      outputFormat: {
        type: "json_schema",
        schema: AGENTIC_SCHEMA,
        strict: true,
        retryInvalidStructuredOutput: 2,
      },
    },
  })) {
    if (message.type === "tool-progress") {
      log.debug(`${tag} [${Math.round(message.elapsedSeconds)}s] Tool: ${message.toolName}`);
      continue;
    }

    if (message.type === "tool-summary") {
      log.debug(`${tag} ${message.summary}`);
      continue;
    }

    if (message.type === "assistant") {
      const toolUses = message.content
        .filter((b: Record<string, unknown>) => b["type"] === "tool_use")
        .map((b: Record<string, unknown>) => b["name"]);
      if (toolUses.length > 0) {
        log.debug(`${tag} Using tools: ${toolUses.join(", ")}`);
      } else {
        const textBlocks = message.content
          .filter((b: Record<string, unknown>) => b["type"] === "text")
          .map((b: Record<string, unknown>) => String(b["text"] ?? "").slice(0, 120));
        if (textBlocks.length > 0) {
          log.debug(`${tag} ${textBlocks[0]}${textBlocks[0].length >= 120 ? "..." : ""}`);
        }
      }
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

  const parsed = parseAgenticOutput(structuredOutput ?? resultText);
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
  const deduped = new Map<string, Finding>();

  for (const finding of output.findings) {
    const filePath = normalizeFilePath(repoRoot, finding.filePath);
    const fingerprint = computeAgenticFingerprint(repoName, ref, {
      ...finding,
      filePath,
    });
    const score = scoreFindingMetadata({
      severity: finding.severity,
      likelihood: finding.likelihood,
      impact: finding.impact,
      subcategory: finding.subcategory,
      cwe: finding.cwe,
      parameterRiskBoost: detectParameterRiskBoost(finding.message),
    });

    const normalized: Finding = {
      scanner: "agentic",
      fingerprint,
      ruleId: finding.ruleId,
      filePath,
      startLine: finding.startLine,
      severity: finding.severity,
      message: finding.message,
      evidence: finding.evidence || null,
      scannerConfidence: finding.confidence,
      subcategory: finding.subcategory,
      likelihood: finding.likelihood,
      impact: finding.impact,
      cwe: finding.cwe,
      score,
    };

    const existing = deduped.get(fingerprint);
    if (!existing || normalized.score > existing.score) {
      deduped.set(fingerprint, normalized);
    }
  }

  return [...deduped.values()]
    .sort((a, b) => b.score - a.score)
    .slice(0, maxFindings);
}

/** Parse and normalize structured output from the agentic scanner. */
export function parseAgenticOutput(raw: unknown): AgenticOutput {
  const data = parseRawOutput(raw);
  if (!isRecord(data) || !Array.isArray(data["findings"])) {
    throw new Error("agentic scanner returned invalid output shape");
  }

  const findings: AgenticFinding[] = [];
  for (const item of data["findings"]) {
    if (!isRecord(item)) continue;

    const ruleId = asString(item["ruleId"], "agentic.security.finding");
    const filePath = asString(item["filePath"], "").trim();
    if (!filePath) continue;

    const startLine = asPositiveInt(item["startLine"], 1);
    const severity = normalizeSeverity(item["severity"], "WARNING");
    const message = asString(item["message"], "Potential security issue");
    const confidence = normalizeConfidence(item["confidence"], "MEDIUM");
    const subcategory = normalizeSubcategory(item["subcategory"]);
    const likelihood = normalizeConfidence(item["likelihood"], "MEDIUM");
    const impact = normalizeConfidence(item["impact"], "MEDIUM");
    const cwe = normalizeStringArray(item["cwe"]);
    const evidence = asString(item["evidence"], "");

    findings.push({
      ruleId,
      filePath,
      startLine,
      severity,
      message,
      confidence,
      subcategory,
      likelihood,
      impact,
      cwe,
      evidence,
    });
  }

  return { findings };
}

/** Stable fingerprint for agentic findings. */
export function computeAgenticFingerprint(
  repoName: string,
  ref: string,
  finding: AgenticFinding,
): string {
  const source = [
    repoName,
    ref,
    "agentic",
    finding.ruleId,
    finding.filePath,
    String(finding.startLine),
  ].join("|");
  return createHash("sha256").update(source).digest("hex");
}

function buildPrompt(opts: ScanOpts, maxFindings: number): string {
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

  return [
    "You are a senior application security researcher with deep expertise in vulnerability discovery.",
    "You think like an attacker: you map attack surfaces, trace data flows, and verify exploitability",
    "before reporting. You know that most static analysis findings are false positives.",
    "",
    ...reviewContext,
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

function parseRawOutput(raw: unknown): unknown {
  if (typeof raw !== "string") return raw;
  const text = raw.trim();
  if (!text) {
    throw new Error("agentic scanner returned empty output");
  }

  try {
    return JSON.parse(text);
  } catch {
    try {
      const extracted = extractJsonObject(text);
      return JSON.parse(extracted);
    } catch (error) {
      throw new Error(`agentic scanner returned invalid JSON output: ${toErrorMessage(error)}`);
    }
  }
}

function extractJsonObject(text: string): string {
  const fenceMatch = text.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
  if (fenceMatch) return fenceMatch[1].trim();

  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start !== -1 && end > start) {
    return text.slice(start, end + 1);
  }

  return text;
}

function normalizeFilePath(repoRoot: string, filePath: string): string {
  if (!path.isAbsolute(filePath)) return filePath;
  const relative = path.relative(repoRoot, filePath);
  if (relative.startsWith("..")) return filePath;
  return relative || filePath;
}

function normalizeSeverity(value: unknown, fallback: string): string {
  const normalized = asString(value, fallback).toUpperCase();
  return SEVERITY_LEVELS.has(normalized) ? normalized : fallback;
}

function normalizeConfidence(value: unknown, fallback: string): string {
  const normalized = asString(value, fallback).toUpperCase();
  return CONFIDENCE_LEVELS.has(normalized) ? normalized : fallback;
}

function normalizeSubcategory(value: unknown): string[] {
  const items = normalizeStringArray(value).map((v) => v.toLowerCase());
  const valid = items.filter((v) => SUBCATEGORIES.has(v));
  return valid.length > 0 ? valid : ["audit"];
}

function normalizeStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.map((v) => String(v).trim()).filter(Boolean);
}

function asPositiveInt(value: unknown, fallback: number): number {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric < 1) return fallback;
  return Math.floor(numeric);
}

function asString(value: unknown, fallback: string): string {
  if (typeof value === "string") return value;
  if (value == null) return fallback;
  return String(value);
}
