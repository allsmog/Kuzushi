/**
 * Multi-agent triage: replaces single-agent triage with a manager + specialist
 * panel that investigates findings from multiple angles in parallel.
 *
 * Inspired by MAVUL (2025) multi-agent vulnerability detection.
 */

import { randomUUID } from "node:crypto";
import {
  resolveDefaultReadOnlyTools,
  runStructuredAgentQuery,
  runStructuredSessionQuery,
  type AgentRuntimeOptions,
} from "./agent-runtime/execution.js";
import { writeBatchFile, cleanupBatchFiles } from "./agent-runtime/batch-files.js";
import type { AgentSession } from "./agent-runtime/types.js";
import type { Finding, AllowedTriageTool } from "./scanners/types.js";
import type { RepoContext, TriageResult } from "./types.js";
import {
  TRIAGE_RESULT_SCHEMA,
  parseAgentOutput,
  TriageExecutionError,
  triageFindingWithAgent,
  triageSystemPromptPrefix,
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
 * Run a single specialist agent via session (subprocess reuse) and return its report.
 */
async function runSpecialistViaSession(
  session: AgentSession,
  role: SpecialistRole,
  finding: Finding,
  repoRoot: string,
  repoName: string,
  runId: string,
  batchIdx: number,
): Promise<SpecialistReport> {
  const batchFile = writeBatchFile(repoRoot, runId, `specialist-${role}`, batchIdx, {
    role,
    finding: {
      ruleId: finding.ruleId,
      filePath: finding.filePath,
      startLine: finding.startLine,
      severity: finding.severity,
      cwe: finding.cwe,
      message: finding.message,
      evidence: finding.evidence,
    },
  });

  const prompt = [
    SPECIALIST_PROMPTS[role](finding, repoName),
    "",
    `Finding context has been written to ${batchFile} — use Read to load it if needed.`,
  ].join("\n");

  try {
    const { structuredOutput, resultText, executionError, costUsd } =
      await runStructuredSessionQuery(session, prompt);

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
 * Run a single specialist agent and return its report.
 */
async function runSpecialist(
  role: SpecialistRole,
  finding: Finding,
  repoRoot: string,
  repoName: string,
  model: string,
  repoContext?: RepoContext,
  runtimeOptions?: AgentRuntimeOptions,
): Promise<SpecialistReport> {
  const prompt = SPECIALIST_PROMPTS[role](finding, repoName);

  try {
    const { structuredOutput, resultText, executionError, costUsd } =
        await runStructuredAgentQuery({
        prompt,
        cwd: repoRoot,
        model,
        allowedTools: resolveDefaultReadOnlyTools(runtimeOptions?.runtime),
        runtimeOptions,
        systemPromptPrefix: triageSystemPromptPrefix(
          repoContext,
          (runtimeOptions as TriageRuntimeOptions | undefined)?.enrichedContext,
        ),
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
  extraPromptContext?: string,
  specialistAccuracies?: Map<string, number>,
): string {
  const reportSections = reports
    .filter((r) => !r.error)
    .map((r) => {
      const accuracyNote = specialistAccuracies?.get(r.role) != null
        ? `, historical accuracy: ${(specialistAccuracies.get(r.role)! * 100).toFixed(0)}%`
        : "";
      return [
        `### ${formatRoleName(r.role)} (confidence: ${r.confidence}${r.isFalsePositive ? ", says FP" : ""}${accuracyNote})`,
        `Evidence: ${r.evidence}`,
        r.findings ? `Findings: ${r.findings}` : "",
      ].filter(Boolean).join("\n");
    });

  const errorReports = reports.filter((r) => r.error);
  const errorSection = errorReports.length > 0
    ? [
        "### Failed Specialists",
        ...errorReports.map((r) => `- ${formatRoleName(r.role)}: ${r.error}`),
      ].join("\n")
    : "";

  // Detect specialist disagreements
  const successfulReports = reports.filter((r) => !r.error);
  const confidences = successfulReports.map((r) => r.confidence);
  const maxConf = Math.max(...confidences, 0);
  const minConf = Math.min(...confidences, 0);
  const confidenceSpread = maxConf - minConf;
  const hasFpDisagreement = successfulReports.some((r) => r.isFalsePositive)
    && successfulReports.some((r) => !r.isFalsePositive);
  const hasDisagreement = confidenceSpread > 0.3 || hasFpDisagreement;

  let conflictSection = "";
  if (hasDisagreement) {
    conflictSection = [
      "## CONFLICT DETECTED — Specialists DISAGREE",
      "For each conflict, you MUST resolve it explicitly:",
      "1. Which specialist cited specific file:line evidence?",
      "2. Which specialist's claim is falsifiable by reading code?",
      "3. Does the evidence chain connect end-to-end from source to sink?",
      "4. If one specialist found guards/sanitization and another didn't, verify the guards actually protect this specific path.",
      "",
      "Include a 'conflict_resolution' field in your JSON output explaining how each disagreement was resolved.",
    ].join("\n");
  }

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
    conflictSection,
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
    "source, sink, evidence_trail, conflict_resolution(string, explain how disagreements were resolved)",
    ...(extraPromptContext ? ["", extraPromptContext] : []),
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
 *
 * When `createSession` is available on the runtime, creates 5 long-lived sessions
 * (4 specialist + 1 manager) instead of spawning 5 subprocesses per finding.
 * Each specialist session handles ALL findings for that role sequentially, and
 * the manager session synthesizes results after specialists complete.
 */
export async function triageFindingMultiAgent(
  registry: TriageConfigProvider,
  finding: Finding,
  repoRoot: string,
  repoName: string,
  managerModel: string,
  specialistModel: string,
  repoContext?: RepoContext,
  runtimeOptions?: TriageRuntimeOptions,
  extraPromptContext?: string,
  specialistAccuracies?: Map<string, number>,
): Promise<TriageOutput> {
  const runtime = runtimeOptions?.runtime;
  const canUseSession = runtime?.createSession != null;

  const roles: SpecialistRole[] = [
    "source-tracer",
    "sink-analyzer",
    "sanitization-checker",
    "config-reviewer",
  ];

  // ── Session-based path: reuse subprocesses across findings ──
  if (canUseSession) {
    const runId = randomUUID();
    const systemPrefix = triageSystemPromptPrefix(
      repoContext,
      runtimeOptions?.enrichedContext,
    );

    // Create one session per specialist role (4 total)
    const specialistSessions = new Map<SpecialistRole, AgentSession>();
    for (const role of roles) {
      specialistSessions.set(
        role,
        runtime.createSession!({
          cwd: repoRoot,
          model: specialistModel,
          allowedTools: resolveDefaultReadOnlyTools(runtime),
          permissionMode: "dontAsk",
          systemPromptPrefix: systemPrefix,
          outputFormat: {
            type: "json_schema",
            schema: SPECIALIST_SCHEMA,
          },
        }),
      );
    }

    try {
      // Run all 4 specialist sessions in parallel, each handling this finding
      const specialistResults = await Promise.allSettled(
        roles.map((role) =>
          runSpecialistViaSession(
            specialistSessions.get(role)!,
            role,
            finding,
            repoRoot,
            repoName,
            runId,
            0,
          ),
        ),
      );

      const reports: SpecialistReport[] = specialistResults.map((result, idx) => {
        if (result.status === "fulfilled") return result.value;
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
          registry, finding, repoRoot, repoName, managerModel, repoContext, runtimeOptions ?? {},
        );
        return { result: fallback.result, costUsd: specialistCost + fallback.costUsd };
      }

      // Create manager session and synthesize
      const managerSession = runtime.createSession!({
        cwd: repoRoot,
        model: managerModel,
        allowedTools: resolveDefaultReadOnlyTools(runtime),
        permissionMode: "dontAsk",
        systemPromptPrefix: systemPrefix,
        outputFormat: {
          type: "json_schema",
          schema: TRIAGE_RESULT_SCHEMA,
        },
      });

      try {
        const managerPrompt = buildManagerPrompt(finding, repoName, reports, extraPromptContext, specialistAccuracies);
        const { structuredOutput, resultText, executionError, costUsd: managerCost } =
          await runStructuredSessionQuery(managerSession, managerPrompt);

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

        return { result, costUsd: totalCost };
      } finally {
        await managerSession.close();
      }
    } finally {
      // Close all specialist sessions
      await Promise.allSettled(
        [...specialistSessions.values()].map((s) => s.close()),
      );
      cleanupBatchFiles(repoRoot, runId);
    }
  }

  // ── Fallback: original subprocess-per-call path ──

  // Run all specialists in parallel
  const specialistResults = await Promise.allSettled(
    roles.map((role) =>
      runSpecialist(
        role,
        finding,
        repoRoot,
        repoName,
        specialistModel,
        repoContext,
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
      repoContext,
      runtimeOptions ?? {},
    );
    return {
      result: fallback.result,
      costUsd: specialistCost + fallback.costUsd,
    };
  }

  // Run manager synthesis
  const managerPrompt = buildManagerPrompt(finding, repoName, reports, extraPromptContext, specialistAccuracies);

  const { structuredOutput, resultText, executionError, costUsd: managerCost } =
    await runStructuredAgentQuery({
      prompt: managerPrompt,
      cwd: repoRoot,
      model: managerModel,
      allowedTools: resolveDefaultReadOnlyTools(runtimeOptions?.runtime),
      runtimeOptions,
      systemPromptPrefix: triageSystemPromptPrefix(
        repoContext,
        runtimeOptions?.enrichedContext,
      ),
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
