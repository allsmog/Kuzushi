import { createHash } from "node:crypto";
import path from "node:path";
import { getAgentRuntime, type AgentRuntime } from "../agent-runtime/index.js";
import type { ScanOpts } from "../types.js";
import { isRecord } from "../utils.js";
import type { Finding } from "./types.js";
import { scoreFindingMetadata } from "./scoring.js";

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
}

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
): Promise<AgenticOutput> {
  const requestedMax = Math.max(1, opts.maxFindings ?? defaultMaxFindings);
  const prompt = buildPrompt(opts, requestedMax);
  const runtime = runtimeOptions.runtime ?? getAgentRuntime();
  let resultText = "";
  let structuredOutput: unknown = undefined;
  let executionError: string | null = null;

  const tag = "[agentic]";
  console.error(`${tag} Starting scan (model=${model}, cwd=${repoRoot})`);

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
        schema: AGENTIC_SCHEMA,
      },
    },
  })) {
    if (message.type === "tool-progress") {
      console.error(`${tag} [${Math.round(message.elapsedSeconds)}s] Tool: ${message.toolName}`);
      continue;
    }

    if (message.type === "tool-summary") {
      console.error(`${tag} ${message.summary}`);
      continue;
    }

    if (message.type === "assistant") {
      const toolUses = message.content
        .filter((b: Record<string, unknown>) => b["type"] === "tool_use")
        .map((b: Record<string, unknown>) => b["name"]);
      if (toolUses.length > 0) {
        console.error(`${tag} Using tools: ${toolUses.join(", ")}`);
      } else {
        const textBlocks = message.content
          .filter((b: Record<string, unknown>) => b["type"] === "text")
          .map((b: Record<string, unknown>) => String(b["text"] ?? "").slice(0, 120));
        if (textBlocks.length > 0) {
          console.error(`${tag} ${textBlocks[0]}${textBlocks[0].length >= 120 ? "..." : ""}`);
        }
      }
      continue;
    }

    if (message.type !== "result") continue;
    if ("result" in message) {
      resultText = message.result;
      structuredOutput = message.structuredOutput;
      const durationSec = message.durationMs ? (message.durationMs / 1000).toFixed(1) : "?";
      console.error(`${tag} Complete in ${durationSec}s — ${message.numTurns} turns, $${message.totalCostUsd?.toFixed(4) ?? "?"}`);
      continue;
    }

    executionError = message.errors.join("; ") || message.subtype;
  }

  if (executionError) {
    throw new Error(`agentic scanner failed: ${executionError}`);
  }

  const parsed = parseAgenticOutput(structuredOutput ?? resultText);
  return {
    findings: parsed.findings.slice(0, requestedMax),
  };
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
    finding.message,
    finding.evidence,
  ].join("|");
  return createHash("sha256").update(source).digest("hex");
}

function buildPrompt(opts: ScanOpts, maxFindings: number): string {
  return [
    "You are a static analysis security scanner.",
    "Analyze the repository for concrete application security issues.",
    "Return only findings with enough evidence in code.",
    "",
    `Severity filter: ${opts.severity.join(", ") || "ERROR, WARNING, INFO"}`,
    `Max findings: ${maxFindings}`,
    `Exclude paths/globs: ${opts.excludePatterns.join(", ") || "(none)"}`,
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
    "Do not propose remediations. Do not include non-security style issues.",
  ].join("\n");
}

function parseRawOutput(raw: unknown): unknown {
  if (typeof raw !== "string") return raw;
  const text = raw.trim();
  if (!text) return { findings: [] };

  try {
    return JSON.parse(text);
  } catch {
    const extracted = extractJsonObject(text);
    return JSON.parse(extracted);
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
