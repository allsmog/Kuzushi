import type { AgentRuntime } from "../../agent-runtime/types.js";
import type { Finding } from "../../scanners/types.js";
import { attachTaskOutputMeta } from "../../task-output-meta.js";
import { normalizeCostUsd } from "../../utils.js";
import type { AgentTask, TaskContext } from "../types.js";
import { resolveTaskRuntime } from "./runtime-overrides.js";

export type QuickClassifierLabel = "LIKELY_REAL" | "LIKELY_FALSE_POSITIVE";

export interface QuickClassifierDecision {
  fingerprint: string;
  label: QuickClassifierLabel;
  confidence: number;
  model: string;
}

export interface QuickClassifierOutput {
  findings: Finding[];
  decisions: QuickClassifierDecision[];
}

const QUICK_CLASSIFIER_PROMPT_PREFIX = [
  "Given this potential vulnerability finding, classify it as LIKELY_REAL or LIKELY_FALSE_POSITIVE.",
  "Respond with exactly one word.",
].join("\n");

export const quickClassifierTask: AgentTask<Finding[], QuickClassifierOutput> = {
  id: "quick-classifier",
  displayName: "Quick Classifier",
  outputKind: "custom",
  dependsOn: [],

  async run(input, context): Promise<QuickClassifierOutput> {
    const findings = Array.isArray(input) ? input : [];
    const model = resolveClassifierModel(context);
    const threshold = normalizeThreshold(context.config.classifierThreshold);
    const concurrency = Math.max(1, context.config.triageConcurrency ?? 5);
    const runtime = resolveTaskRuntime(context);

    const decisionsByFingerprint = new Map<string, QuickClassifierDecision>();
    const keptFingerprints = new Set<string>();
    let totalCostUsd = 0;
    let cursor = 0;

    const worker = async (): Promise<void> => {
      while (cursor < findings.length) {
        const index = cursor;
        cursor += 1;
        const finding = findings[index];
        if (!finding) {
          continue;
        }

        const { decision, costUsd } = await classifyFinding(runtime, context, finding, model);
        totalCostUsd += costUsd;
        decisionsByFingerprint.set(finding.fingerprint, decision);
        if (decision.label === "LIKELY_REAL" && decision.confidence >= threshold) {
          keptFingerprints.add(finding.fingerprint);
        }
      }
    };

    await Promise.all(Array.from({ length: Math.min(concurrency, findings.length || 1) }, () => worker()));

    return attachTaskOutputMeta(
      {
        findings: findings.filter((finding) => keptFingerprints.has(finding.fingerprint)),
        decisions: findings
          .map((finding) => decisionsByFingerprint.get(finding.fingerprint))
          .filter((decision): decision is QuickClassifierDecision => Boolean(decision)),
      },
      { costUsd: totalCostUsd },
    );
  },
};

async function classifyFinding(
  runtime: AgentRuntime,
  context: TaskContext,
  finding: Finding,
  model: string,
): Promise<{ decision: QuickClassifierDecision; costUsd: number }> {
  const prompt = buildPrompt(finding);
  const workingRoot = context.scanPath ?? context.repoRoot;
  let resultText = "";
  let costUsd = 0;

  try {
    for await (const message of runtime.query({
      prompt,
      options: {
        cwd: workingRoot,
        model,
        maxTurns: 1,
        temperature: 0,
        maxOutputTokens: 1,
        allowedTools: [],
        permissionMode: "dontAsk",
      },
    })) {
      if (message.type !== "result") {
        continue;
      }
      if (typeof message.totalCostUsd === "number" && Number.isFinite(message.totalCostUsd)) {
        costUsd = message.totalCostUsd;
      }
      if ("result" in message && typeof message.result === "string") {
        resultText = message.result;
      }
    }
  } catch (error) {
    return {
      decision: {
        fingerprint: finding.fingerprint,
        label: "LIKELY_REAL",
        confidence: 1,
        model,
      },
      costUsd: normalizeCostUsd(costUsd),
    };
  }

  const label = normalizeClassifierLabel(resultText);
  if (!label) {
    return {
      decision: {
        fingerprint: finding.fingerprint,
        label: "LIKELY_REAL",
        confidence: 1,
        model,
      },
      costUsd: normalizeCostUsd(costUsd),
    };
  }

  return {
    decision: {
      fingerprint: finding.fingerprint,
      label,
      confidence: label === "LIKELY_REAL" ? 1 : 0,
      model,
    },
    costUsd: normalizeCostUsd(costUsd),
  };
}

function buildPrompt(finding: Finding): string {
  return [
    QUICK_CLASSIFIER_PROMPT_PREFIX,
    "",
    "Finding:",
    `${finding.ruleId} in ${finding.filePath}:${finding.startLine}`,
    "Message:",
    finding.message,
    `Severity: ${finding.severity}`,
    `CWE: ${finding.cwe.join(", ") || "none"}`,
  ].join("\n");
}

function resolveClassifierModel(context: TaskContext): string {
  return context.config.classifierModel
    ?? context.config.triageBatchModel
    ?? context.config.contextEnrichmentModel
    ?? context.config.model;
}

function normalizeThreshold(value: unknown): number {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric < 0 || numeric > 1) {
    return 0.5;
  }
  return numeric;
}

function normalizeClassifierLabel(raw: string): QuickClassifierLabel | undefined {
  const normalized = raw.trim().toUpperCase();
  if (normalized === "LIKELY_REAL") {
    return normalized;
  }
  if (normalized === "LIKELY_FALSE_POSITIVE") {
    return normalized;
  }
  return undefined;
}

export const __quickClassifierInternals = {
  buildPrompt,
  normalizeClassifierLabel,
  resolveClassifierModel,
};
