import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { coerceRepoContext } from "../../repo-context.js";
import { scoreFindingMetadata } from "../../scanners/scoring.js";
import type { Finding, TriageAgentConfig } from "../../scanners/types.js";
import { getFixedFindingsForFiles } from "../../store.js";
import { attachTaskOutputMeta } from "../../task-output-meta.js";
import type { RepoContext, ScanOpts } from "../../types.js";
import { isRecord, toErrorMessage } from "../../utils.js";
import { createLogger } from "../../logger.js";
import { getProfilesForTask, formatProfilesForPrompt } from "../../security-profiles.js";
import type { AgentTask, TaskContext } from "../types.js";
import { resolveTaskAllowedTools } from "./runtime-overrides.js";

const log = createLogger({ stage: "diff-review" });

const DIFF_REVIEW_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["findings"],
  properties: {
    findings: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["ruleId", "filePath", "startLine", "severity", "message", "confidence", "rationale"],
        properties: {
          ruleId: { type: "string" },
          filePath: { type: "string" },
          startLine: { type: "integer", minimum: 1 },
          severity: { type: "string", enum: ["ERROR", "WARNING", "INFO"] },
          message: { type: "string" },
          confidence: { type: "number", minimum: 0, maximum: 1 },
          rationale: { type: "string" },
          cwe: { type: "array", items: { type: "string" } },
          evidence: { type: "string" },
        },
      },
    },
  },
} as const;

interface DiffReviewFinding {
  ruleId: string;
  filePath: string;
  startLine: number;
  severity: string;
  message: string;
  confidence: number;
  rationale: string;
  cwe?: string[];
  evidence?: string;
}

const REGRESSION_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["regressions"],
  properties: {
    regressions: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["originalFingerprint", "ruleId", "filePath", "startLine", "message", "confidence"],
        properties: {
          originalFingerprint: { type: "string" },
          ruleId: { type: "string" },
          filePath: { type: "string" },
          startLine: { type: "integer", minimum: 1 },
          message: { type: "string" },
          confidence: { type: "number", minimum: 0, maximum: 1 },
        },
      },
    },
  },
} as const;

interface RegressionEntry {
  originalFingerprint: string;
  ruleId: string;
  filePath: string;
  startLine: number;
  message: string;
  confidence: number;
}

interface DiffReviewConfig {
  model: string;
  maxFindings: number;
  diffBase: string;
}

function resolveConfig(ctx: TaskContext): DiffReviewConfig {
  const raw = ctx.config.scannerConfig["diff-review"];
  const model = (isRecord(raw) && typeof raw["model"] === "string" && raw["model"].trim())
    ? raw["model"].trim()
    : ctx.config.model;
  const maxFindings = (isRecord(raw) && typeof raw["maxFindings"] === "number" && raw["maxFindings"] >= 1)
    ? Math.floor(raw["maxFindings"])
    : 30;
  const diffBase = ctx.config.diffBase || "main";
  return { model, maxFindings, diffBase };
}

function getDiffContent(repoRoot: string, diffBase: string): { changedFiles: string[]; diff: string } {
  try {
    const diffRef = `${diffBase}...HEAD`;
    const filesRaw = execFileSync("git", ["diff", "--name-only", diffRef], {
      cwd: repoRoot,
      encoding: "utf-8",
      timeout: 30_000,
    });
    const changedFiles = filesRaw.trim().split("\n").filter(Boolean);

    const diff = execFileSync("git", ["diff", diffRef], {
      cwd: repoRoot,
      encoding: "utf-8",
      timeout: 60_000,
      maxBuffer: 10 * 1024 * 1024,
    });

    return { changedFiles, diff };
  } catch (error) {
    throw new Error(`Failed to get git diff: ${toErrorMessage(error)}`);
  }
}

function buildPrompt(
  repoContext: RepoContext | undefined,
  changedFiles: string[],
  diff: string,
  diffBase: string,
  maxFindings: number,
  profileLines: string[] = [],
): string {
  const contextLines = repoContext
    ? [
        "## Repository context",
        `- Languages: ${repoContext.languages.join(", ") || "unknown"}`,
        `- Frameworks: ${repoContext.frameworks.join(", ") || "unknown"}`,
        `- Auth patterns: ${repoContext.authPatterns.join(", ") || "unknown"}`,
        `- Sanitization libs: ${repoContext.sanitizationLibs.join(", ") || "unknown"}`,
        "",
      ]
    : [];

  // Truncate diff if very large
  const maxDiffLength = 100_000;
  const truncatedDiff = diff.length > maxDiffLength
    ? diff.slice(0, maxDiffLength) + "\n... [diff truncated]"
    : diff;

  return [
    "You are a senior security engineer reviewing a code diff for security vulnerabilities.",
    "Focus ONLY on the changed code. Do not report issues in unchanged code.",
    "",
    ...contextLines,
    ...(profileLines.length > 0 ? [...profileLines, ""] : []),
    `## Diff base: ${diffBase}...HEAD`,
    `## Changed files (${changedFiles.length}):`,
    ...changedFiles.map((f) => `- ${f}`),
    "",
    "## Three-phase methodology",
    "",
    "### Phase 1: Context research",
    "Read the changed files to understand what the diff does. Use Glob and Grep to understand",
    "the surrounding code context — auth middleware, validation, sanitization in place.",
    "",
    "### Phase 2: Comparative analysis",
    "For each changed file, compare the old and new code paths:",
    "- Are new inputs being accepted without validation?",
    "- Are new API calls being made without proper error handling?",
    "- Are new data flows introduced that bypass existing guards?",
    "- Are security controls being weakened or removed?",
    "",
    "### Phase 3: Vulnerability assessment",
    "For each potential issue found in phases 1-2:",
    "- Verify the vulnerability exists in the actual changed code.",
    "- Confirm the input source is attacker-controlled.",
    "- Check for mitigating controls that prevent exploitation.",
    "- Assign confidence (0.0-1.0). Only report findings with confidence > 0.7.",
    "",
    "## Diff content",
    "```diff",
    truncatedDiff,
    "```",
    "",
    "## Constraints",
    "- ONLY report findings in changed code (files listed above, within changed line ranges).",
    "- confidence must be > 0.7 — do not report speculative issues.",
    "- Every finding must reference a specific file and line number from the diff.",
    "- Do not report style issues, documentation issues, or non-security concerns.",
    `- Return at most ${maxFindings} findings.`,
  ].join("\n");
}

function normalizeFindings(
  raw: unknown,
  repoRoot: string,
  repoName: string,
  diffBase: string,
  maxFindings: number,
): Finding[] {
  if (!isRecord(raw) || !Array.isArray(raw["findings"])) return [];

  const deduped = new Map<string, Finding>();
  for (const item of raw["findings"] as unknown[]) {
    if (!isRecord(item)) continue;
    const f = item as unknown as DiffReviewFinding;
    if (!f.filePath?.trim()) continue;

    // Filter out low confidence
    if (typeof f.confidence === "number" && f.confidence < 0.7) continue;

    const filePath = normalizeFilePath(repoRoot, f.filePath);
    const cweList = f.cwe ?? [];
    const fingerprint = computeFingerprint(repoName, diffBase, filePath, f);

    const finding: Finding = {
      scanner: "diff-review",
      fingerprint,
      ruleId: f.ruleId || "diff-review/security-issue",
      filePath,
      startLine: Math.max(1, Math.floor(Number(f.startLine) || 1)),
      severity: f.severity || "WARNING",
      message: f.message || "Security issue in changed code",
      evidence: f.rationale || f.evidence || null,
      scannerConfidence: confidenceToLevel(f.confidence),
      subcategory: ["vuln"],
      likelihood: confidenceToLevel(f.confidence),
      impact: f.severity === "ERROR" ? "HIGH" : f.severity === "INFO" ? "LOW" : "MEDIUM",
      cwe: cweList,
      score: scoreFindingMetadata({
        severity: f.severity || "WARNING",
        likelihood: confidenceToLevel(f.confidence),
        impact: f.severity === "ERROR" ? "HIGH" : f.severity === "INFO" ? "LOW" : "MEDIUM",
        subcategory: ["vuln"],
      }),
    };

    const existing = deduped.get(fingerprint);
    if (!existing || finding.score > existing.score) {
      deduped.set(fingerprint, finding);
    }
  }

  return [...deduped.values()]
    .sort((a, b) => b.score - a.score)
    .slice(0, maxFindings);
}

function confidenceToLevel(confidence: number): string {
  if (confidence >= 0.85) return "HIGH";
  if (confidence >= 0.7) return "MEDIUM";
  return "LOW";
}

function computeFingerprint(
  repoName: string,
  diffBase: string,
  filePath: string,
  f: DiffReviewFinding,
): string {
  const source = [repoName, "diff-review", diffBase, f.ruleId, filePath, String(f.startLine)].join("|");
  return createHash("sha256").update(source).digest("hex");
}

function normalizeFilePath(repoRoot: string, filePath: string): string {
  if (!path.isAbsolute(filePath)) return filePath;
  const relative = path.relative(repoRoot, filePath);
  if (relative.startsWith("..")) return filePath;
  return relative || filePath;
}

function buildRegressionPrompt(
  diff: string,
  previousFindings: Array<{ fingerprint: string; ruleId: string; filePath: string; startLine: number; message: string }>,
): string {
  const findingsList = previousFindings
    .map((f, i) => `${i + 1}. [${f.ruleId}] ${f.filePath}:${f.startLine} — ${f.message}`)
    .join("\n");

  return [
    "You are checking whether a code diff re-introduces previously-fixed security vulnerabilities.",
    "",
    "## Previously confirmed vulnerabilities in these files:",
    findingsList,
    "",
    "## Current diff:",
    "```diff",
    diff.length > 50_000 ? diff.slice(0, 50_000) + "\n... [truncated]" : diff,
    "```",
    "",
    "## Task",
    "For each previously-confirmed vulnerability above, check if this diff REVERTS the fix",
    "or RE-INTRODUCES the same vulnerability pattern. Only report regressions you can confirm",
    "by comparing the diff against the known vulnerability.",
    "",
    "Return a JSON object with a 'regressions' array. Each entry should have:",
    "- originalFingerprint: the fingerprint of the original finding",
    "- ruleId: the rule ID",
    "- filePath: the file where the regression occurs",
    "- startLine: approximate line number in the new code",
    "- message: description of how the fix was reverted",
    "- confidence: 0.0-1.0",
    "",
    "If no regressions are found, return { regressions: [] }",
  ].join("\n");
}

async function detectRegressions(
  context: TaskContext,
  previousFindings: Array<{ fingerprint: string; ruleId: string; filePath: string; startLine: number; message: string }>,
  diff: string,
  model: string,
): Promise<Finding[]> {
  const prompt = buildRegressionPrompt(diff, previousFindings);
  const runtime = context.runtime;

  let structuredOutput: unknown;
  let resultText = "";

  for await (const message of runtime.query({
    prompt,
    options: {
      cwd: context.repoRoot,
      model,
      maxTurns: context.config.taskMaxTurns ?? 15,
      allowedTools: resolveTaskAllowedTools(context),
      permissionMode: "dontAsk",
      outputFormat: {
        type: "json_schema",
        schema: REGRESSION_SCHEMA,
        strict: true,
        retryInvalidStructuredOutput: 2,
      },
    },
  })) {
    if (message.type !== "result") continue;
    if ("result" in message) {
      resultText = message.result;
      structuredOutput = message.structuredOutput;
    }
  }

  const parsed = structuredOutput ?? (() => {
    try { return JSON.parse(resultText); } catch { return { regressions: [] }; }
  })();

  if (!isRecord(parsed) || !Array.isArray(parsed["regressions"])) return [];

  const findings: Finding[] = [];
  for (const entry of parsed["regressions"] as unknown[]) {
    if (!isRecord(entry)) continue;
    const r = entry as unknown as RegressionEntry;
    if (!r.filePath?.trim() || typeof r.confidence !== "number" || r.confidence < 0.5) continue;

    const filePath = normalizeFilePath(context.repoRoot, r.filePath);
    const fingerprint = createHash("sha256")
      .update([context.repoName, "regression", r.originalFingerprint, filePath, String(r.startLine)].join("|"))
      .digest("hex");

    findings.push({
      scanner: "diff-review",
      fingerprint,
      ruleId: `regression/${r.ruleId}`,
      filePath,
      startLine: Math.max(1, Math.floor(Number(r.startLine) || 1)),
      severity: "ERROR",
      message: `[REGRESSION] ${r.message}`,
      evidence: `Re-introduction of previously-fixed vulnerability (original: ${r.originalFingerprint})`,
      scannerConfidence: confidenceToLevel(r.confidence),
      subcategory: ["vuln", "regression"],
      likelihood: confidenceToLevel(r.confidence),
      impact: "HIGH",
      cwe: [],
      score: scoreFindingMetadata({
        severity: "ERROR",
        likelihood: confidenceToLevel(r.confidence),
        impact: "HIGH",
        subcategory: ["vuln", "regression"],
      }),
    });
  }

  return findings;
}

export const diffReviewTask: AgentTask<ScanOpts, Finding[]> = {
  id: "diff-review",
  displayName: "Differential Review",
  outputKind: "findings",
  dependsOn: ["context-gatherer"],

  async run(_input, context): Promise<Finding[]> {
    const { model, maxFindings, diffBase } = resolveConfig(context);
    const repoContext = coerceRepoContext(context.upstreamOutputs.get("context-gatherer"));
    const profiles = context.securityProfiles
      ? getProfilesForTask(context.securityProfiles, "diff-review")
      : [];
    const profileLines = formatProfilesForPrompt(profiles);

    const tag = "[diff-review]";
    log.info(`Getting diff ${diffBase}...HEAD`);

    let changedFiles: string[];
    let diff: string;
    try {
      ({ changedFiles, diff } = getDiffContent(context.repoRoot, diffBase));
    } catch (error) {
      log.error(toErrorMessage(error));
      return [];
    }

    if (changedFiles.length === 0) {
      log.info(`No changed files, skipping`);
      return [];
    }

    log.info(`${changedFiles.length} changed files, starting review (model=${model})`);

    const prompt = buildPrompt(repoContext, changedFiles, diff, diffBase, maxFindings, profileLines);
    const runtime = context.runtime;

    let structuredOutput: unknown;
    let resultText = "";
    let costUsd = 0;

    try {
      for await (const message of runtime.query({
        prompt,
        options: {
          cwd: context.repoRoot,
          model,
          maxTurns: context.config.taskMaxTurns ?? 15,
          allowedTools: resolveTaskAllowedTools(context),
          permissionMode: "dontAsk",
          outputFormat: {
            type: "json_schema",
            schema: DIFF_REVIEW_SCHEMA,
            strict: true,
            retryInvalidStructuredOutput: 2,
          },
        },
      })) {
        if (message.type !== "result") continue;
        if (typeof message.totalCostUsd === "number" && Number.isFinite(message.totalCostUsd)) {
          costUsd = message.totalCostUsd;
        }
        if ("result" in message) {
          resultText = message.result;
          structuredOutput = message.structuredOutput;
        }
      }
    } catch (error) {
      throw new Error(`${tag} Agent error: ${toErrorMessage(error)}`);
    }

    const findings = normalizeFindings(
      structuredOutput ?? parseJson(resultText, tag),
      context.repoRoot,
      context.repoName,
      diffBase,
      maxFindings,
    );

    // Regression detection — check if diff reverts previously-fixed vulnerabilities
    if (context.db && changedFiles.length > 0) {
      try {
        const previousFindings = getFixedFindingsForFiles(context.db, changedFiles);
        if (previousFindings.length > 0) {
          log.info(`Checking ${previousFindings.length} previous TP findings for regressions`);
          const regressions = await detectRegressions(context, previousFindings, diff, model);
          findings.push(...regressions);
        }
      } catch (error) {
        log.error(`Regression detection failed: ${toErrorMessage(error)}`);
      }
    }

    return attachTaskOutputMeta(findings, { costUsd });
  },

  triageAgentConfig(finding: Finding, repoName: string): TriageAgentConfig {
    return {
      prompt: [
        `You are triaging a diff-review finding in "${repoName}".`,
        "",
        `Rule: ${finding.ruleId}`,
        `File: ${finding.filePath}:${finding.startLine}`,
        `Message: ${finding.message}`,
        finding.evidence ? `Rationale: ${finding.evidence}` : "",
        "",
        "This finding was detected in recently changed code.",
        "Verify the vulnerability exists in the current code and is exploitable.",
      ].filter(Boolean).join("\n"),
    };
  },
};

function parseJson(text: string, tag: string): unknown {
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new Error(`${tag} Invalid JSON output: ${toErrorMessage(error)}`);
  }
}

export const __diffReviewInternals = {
  resolveConfig,
  buildPrompt,
  buildRegressionPrompt,
  normalizeFindings,
  computeFingerprint,
  getDiffContent,
  detectRegressions,
};
