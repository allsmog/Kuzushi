/**
 * Shared finding normalization — schema, parsing, and selection logic
 * used by both the agentic scanner and threat-hunt task.
 */
import { createHash } from "node:crypto";
import path from "node:path";
import { isRecord } from "../utils.js";
import type { Finding } from "./types.js";
import { scoreFindingMetadata, detectParameterRiskBoost } from "./scoring.js";

const SEVERITY_LEVELS = new Set(["ERROR", "WARNING", "INFO"]);
const CONFIDENCE_LEVELS = new Set(["HIGH", "MEDIUM", "LOW"]);
const SUBCATEGORIES = new Set(["vuln", "audit"]);

export const FINDING_SCHEMA = {
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

export interface NormalizedFinding {
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

export interface FindingOutput {
  findings: NormalizedFinding[];
  costUsd?: number;
}

/** Parse and normalize structured output into typed findings. */
export function parseFindingOutput(raw: unknown): FindingOutput {
  const data = parseRawOutput(raw);
  if (!isRecord(data) || !Array.isArray(data["findings"])) {
    throw new Error("Scanner returned invalid output shape");
  }

  const findings: NormalizedFinding[] = [];
  for (const item of data["findings"]) {
    if (!isRecord(item)) continue;

    const ruleId = asString(item["ruleId"], "security.finding");
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

/** Rank, dedup, and map findings into Finding records. */
export function selectFindings(
  output: FindingOutput,
  repoRoot: string,
  repoName: string,
  ref: string,
  scanner: string,
  maxFindings?: number,
): Finding[] {
  const deduped = new Map<string, Finding>();

  for (const finding of output.findings) {
    const filePath = normalizeFilePath(repoRoot, finding.filePath);

    // Hard scope filter: drop findings with paths that resolve outside the scan root.
    // Agents can traverse the filesystem freely; this is the post-hoc guarantee.
    if (isOutOfScope(repoRoot, filePath)) continue;

    const fingerprint = computeFingerprint(repoName, ref, scanner, {
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
      scanner,
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

/** Stable fingerprint for findings. */
export function computeFingerprint(
  repoName: string,
  ref: string,
  scanner: string,
  finding: NormalizedFinding,
): string {
  const source = [
    repoName,
    ref,
    scanner,
    finding.ruleId,
    finding.filePath,
    String(finding.startLine),
  ].join("|");
  return createHash("sha256").update(source).digest("hex");
}

// ── Internal helpers ──

function parseRawOutput(raw: unknown): unknown {
  if (typeof raw !== "string") return raw;
  const text = raw.trim();
  if (!text) {
    throw new Error("Scanner returned empty output");
  }

  try {
    return JSON.parse(text);
  } catch {
    try {
      const extracted = extractJsonObject(text);
      return JSON.parse(extracted);
    } catch {
      throw new Error("Scanner returned invalid JSON output");
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

/**
 * Returns true if filePath resolves outside the given scope root.
 * Handles both relative and absolute paths.
 */
function isOutOfScope(scopeRoot: string, filePath: string): boolean {
  const resolved = path.isAbsolute(filePath)
    ? filePath
    : path.resolve(scopeRoot, filePath);
  const relative = path.relative(scopeRoot, resolved);
  return relative.startsWith("..");
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
