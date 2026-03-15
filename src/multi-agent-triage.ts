/**
 * Multi-agent triage: replaces single-agent triage with a manager + specialist
 * panel that investigates findings from multiple angles in parallel.
 *
 * Inspired by MAVUL (2025) multi-agent vulnerability detection.
 */

import { randomUUID } from "node:crypto";
import {
  DEFAULT_READ_ONLY_TOOLS,
  runStructuredAgentQuery,
  type AgentRuntimeOptions,
} from "./agent-runtime/execution.js";
import type { Finding, AllowedTriageTool } from "./scanners/types.js";
import type { RepoContext, TriageResult } from "./types.js";
import {
  TRIAGE_RESULT_SCHEMA,
  parseAgentOutput,
  TriageExecutionError,
  triageFindingWithAgent,
  type TriageConfigProvider,
  type TriageOutput,
  type TriageRuntimeOptions,
} from "./triage.js";
import {
  confidenceEscalationModule,
  falseDismissalModule,
} from "./prompts/modules.js";
import { toErrorMessage } from "./utils.js";

/** Specialist roles for multi-agent triage. */
export type SpecialistRole = "source-tracer" | "sink-analyzer" | "sanitization-checker" | "config-reviewer";

/** Result from a single specialist agent. */
export interface SpecialistReport {
  role: SpecialistRole;
  findings: string;
  isFalsePositive: boolean;
  evidence: string;
  confidence: number;
  costUsd: number;
  error?: string;
}

const SPECIALIST_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["role", "findings", "is_false_positive", "evidence", "confidence"],
  properties: {
    role: { type: "string" },
    findings: { type: "string" },
    is_false_positive: { type: "boolean" },
    evidence: { type: "string" },
    confidence: { type: "number", minimum: 0, maximum: 1 },
  },
} as const;

const SPECIALIST_PROMPTS: Record<SpecialistRole, (finding: Finding, repoName: string) => string> = {
  "source-tracer": (finding, repoName) => [
    `You are a source-tracing specialist investigating a security finding in ${repoName}.`,
    "Your ONLY job: determine who controls the input that reaches the flagged code location.",
    "",
    "Trace ALL paths from user-controlled input (HTTP params, headers, cookies, file uploads,",
    "environment variables, database records) to the flagged location. Report whether the input",
    "is truly attacker-controllable and through what path it flows.",
    "",
    formatFindingContext(finding),
    "",
    "Use Read, Grep, GetCallers to trace input sources. Return your assessment as JSON.",
  ].join("\n"),

  "sink-analyzer": (finding, repoName) => [
    `You are a sink-analysis specialist investigating a security finding in ${repoName}.`,
    "Your ONLY job: analyze what dangerous operation the flagged sink performs.",
    "",
    "Determine: What does this code actually do with the data? Is it executing a command,",
    "writing to a database, rendering to HTML, accessing the filesystem, or making a network",
    "request? How dangerous is this specific sink in context?",
    "",
    formatFindingContext(finding),
    "",
    "Use Read, GetFunctionBody, GetCallees to understand the sink. Return your assessment as JSON.",
  ].join("\n"),

  "sanitization-checker": (finding, repoName) => [
    `You are a sanitization-checking specialist investigating a security finding in ${repoName}.`,
    "Your ONLY job: search for sanitization, validation, encoding, and guards between",
    "the source and the sink.",
    "",
    "Check for: input validation middleware, sanitization functions, encoding helpers,",
    "parameterized queries, CSP headers, CSRF tokens, rate limiters, WAF rules,",
    "and any other defensive measures that might prevent exploitation.",
    "",
    formatFindingContext(finding),
    "",
    "Use Grep, Glob, Read to find defenses. Return your assessment as JSON.",
  ].join("\n"),

  "config-reviewer": (finding, repoName) => [
    `You are a configuration-review specialist investigating a security finding in ${repoName}.`,
    "Your ONLY job: check framework security settings, middleware configuration,",
    "and deployment settings that might affect this finding.",
    "",
    "Check for: framework security defaults, helmet/cors middleware, ORM configuration,",
    "template engine auto-escaping settings, security headers, content-type enforcement,",
    "and any security-relevant configuration that could prevent or enable exploitation.",
    "",
    formatFindingContext(finding),
    "",
    "Use Grep, Glob, Read to check configs. Return your assessment as JSON.",
  ].join("\n"),
};

function formatFindingContext(finding: Finding): string {
  return [
    "## Finding",
    `Rule: ${finding.ruleId}`,
    `File: ${finding.filePath}:${finding.startLine}`,
    `Severity: ${finding.severity}`,
    `CWE: ${finding.cwe.join(", ") || "none"}`,
    `Message: ${finding.message}`,
    `Evidence: ${finding.evidence || "none"}`,
  ].join("\n");
}

/**
 * Run a single specialist agent and return its report.
 */
async function runSpecialist(
  role: SpecialistRole,
  finding: Finding,
  repoRoot: string,
  repoName: string,
  model: string,
  maxTurns: number | null,
  runtimeOptions?: AgentRuntimeOptions,
): Promise<SpecialistReport> {
  const prompt = SPECIALIST_PROMPTS[role](finding, repoName);

  try {
    const { structuredOutput, resultText, executionError, costUsd } =
      await runStructuredAgentQuery({
        prompt,
        cwd: repoRoot,
        model,
        maxTurns,
        allowedTools: [...DEFAULT_READ_ONLY_TOOLS] as unknown as string[],
        runtimeOptions,
        schema: SPECIALIST_SCHEMA,
      });

    if (executionError) {
      return {
        role,
        findings: "",
        isFalsePositive: false,
        evidence: `Specialist error: ${executionError}`,
        confidence: 0,
        costUsd,
        error: executionError,
      };
    }

    const output = (structuredOutput ?? resultText) as Record<string, unknown>;
    return {
      role,
      findings: String(output?.["findings"] ?? ""),
      isFalsePositive: output?.["is_false_positive"] === true,
      evidence: String(output?.["evidence"] ?? ""),
      confidence: clampConfidence(output?.["confidence"]),
      costUsd,
    };
  } catch (error) {
    return {
      role,
      findings: "",
      isFalsePositive: false,
      evidence: `Specialist exception: ${toErrorMessage(error)}`,
      confidence: 0,
      costUsd: 0,
      error: toErrorMessage(error),
    };
  }
}

/**
 * Build manager synthesis prompt from specialist reports.
 */
function buildManagerPrompt(
  finding: Finding,
  repoName: string,
  reports: SpecialistReport[],
): string {
  const reportSections = reports
    .filter((r) => !r.error)
    .map((r) => [
      `### ${formatRoleName(r.role)} (confidence: ${r.confidence}${r.isFalsePositive ? ", says FP" : ""})`,
      `Evidence: ${r.evidence}`,
      r.findings ? `Findings: ${r.findings}` : "",
    ].filter(Boolean).join("\n"));

  const errorReports = reports.filter((r) => r.error);
  const errorSection = errorReports.length > 0
    ? [
        "### Failed Specialists",
        ...errorReports.map((r) => `- ${formatRoleName(r.role)}: ${r.error}`),
      ].join("\n")
    : "";

  return [
    "You are a senior security engineer synthesizing specialist reports for a triage decision.",
    "Multiple specialists have independently investigated this finding from different angles.",
    "Your job: synthesize their findings into a single, definitive verdict.",
    "",
    `Repo: ${repoName}`,
    "",
    formatFindingContext(finding),
    `Fingerprint: ${finding.fingerprint}`,
    "",
    "## Specialist Reports",
    ...reportSections,
    errorSection,
    "",
    "## Your Task",
    "Synthesize these reports into a single verdict. Resolve disagreements by evidence quality.",
    "If specialists disagree, weight concrete code evidence over speculation.",
    "If most specialists found no guards/sanitization, lean toward TP.",
    "",
    confidenceEscalationModule("triage"),
    "",
    falseDismissalModule(),
    "",
    "## Output requirements",
    "Return ONLY a JSON object with:",
    "fingerprint, verdict(tp|fp|needs_review), confidence(0..1), rationale, verification_steps(array), fix_patch(string|null),",
    "source, sink, evidence_trail",
  ].join("\n");
}

function formatRoleName(role: SpecialistRole): string {
  return role.split("-").map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join(" ");
}

function clampConfidence(value: unknown): number {
  const n = Number(value);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(1, n));
}

/**
 * Multi-agent triage: dispatches specialists in parallel, then synthesizes
 * via a manager agent. Falls back to single-agent triage if all specialists fail.
 */
export async function triageFindingMultiAgent(
  registry: TriageConfigProvider,
  finding: Finding,
  repoRoot: string,
  repoName: string,
  managerModel: string,
  specialistModel: string,
  managerMaxTurns: number | null,
  specialistMaxTurns: number | null,
  repoContext?: RepoContext,
  runtimeOptions?: TriageRuntimeOptions,
): Promise<TriageOutput> {
  const roles: SpecialistRole[] = [
    "source-tracer",
    "sink-analyzer",
    "sanitization-checker",
    "config-reviewer",
  ];

  // Run all specialists in parallel
  const specialistResults = await Promise.allSettled(
    roles.map((role) =>
      runSpecialist(
        role,
        finding,
        repoRoot,
        repoName,
        specialistModel,
        specialistMaxTurns,
        runtimeOptions,
      ),
    ),
  );

  const reports: SpecialistReport[] = specialistResults.map((result, idx) => {
    if (result.status === "fulfilled") {
      return result.value;
    }
    return {
      role: roles[idx],
      findings: "",
      isFalsePositive: false,
      evidence: `Specialist crashed: ${toErrorMessage(result.reason)}`,
      confidence: 0,
      costUsd: 0,
      error: toErrorMessage(result.reason),
    };
  });

  const specialistCost = reports.reduce((sum, r) => sum + r.costUsd, 0);
  const successfulReports = reports.filter((r) => !r.error);

  // If all specialists failed, fall back to single-agent triage
  if (successfulReports.length === 0) {
    const fallback = await triageFindingWithAgent(
      registry,
      finding,
      repoRoot,
      repoName,
      managerModel,
      managerMaxTurns,
      repoContext,
      runtimeOptions ?? {},
    );
    return {
      result: fallback.result,
      costUsd: specialistCost + fallback.costUsd,
    };
  }

  // Run manager synthesis
  const managerPrompt = buildManagerPrompt(finding, repoName, reports);

  const { structuredOutput, resultText, executionError, costUsd: managerCost } =
    await runStructuredAgentQuery({
      prompt: managerPrompt,
      cwd: repoRoot,
      model: managerModel,
      maxTurns: managerMaxTurns,
      allowedTools: [...DEFAULT_READ_ONLY_TOOLS] as unknown as string[],
      runtimeOptions,
      schema: TRIAGE_RESULT_SCHEMA,
    });

  const totalCost = specialistCost + managerCost;

  if (executionError) {
    throw new TriageExecutionError(
      `multi-agent manager failed: ${executionError}`,
      totalCost,
    );
  }

  let result: TriageResult;
  try {
    result = parseAgentOutput(structuredOutput ?? resultText, finding.fingerprint);
  } catch (error) {
    throw new TriageExecutionError(
      `multi-agent manager output parse failed: ${toErrorMessage(error)}`,
      totalCost,
    );
  }

  return {
    result,
    costUsd: totalCost,
  };
}
