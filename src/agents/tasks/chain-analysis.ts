import {
  resolveDefaultReadOnlyTools,
  runStructuredAgentQuery,
} from "../../agent-runtime/execution.js";
import { getLogger } from "../../logger.js";
import type { Finding } from "../../scanners/types.js";
import { attachTaskOutputMeta } from "../../task-output-meta.js";
import type { TriageResult } from "../../types.js";
import { isRecord, toErrorMessage } from "../../utils.js";
import type { AgentTask } from "../types.js";

const log = getLogger("chain-analysis");

export interface ChainInput {
  confirmedFindings: Array<{ finding: Finding; triageResult: TriageResult }>;
}

export interface ExploitChain {
  id: string;
  name: string;
  steps: Array<{
    findingFingerprint: string;
    role: string;
    description: string;
  }>;
  overallSeverity: "CRITICAL" | "HIGH" | "MEDIUM";
  preconditions: string[];
  impactDescription: string;
}

export interface ChainAnalysisOutput {
  chains: ExploitChain[];
  analysisNotes: string;
}

const CHAIN_ANALYSIS_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["chains", "analysis_notes"],
  properties: {
    chains: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: [
          "id",
          "name",
          "steps",
          "overall_severity",
          "preconditions",
          "impact_description",
        ],
        properties: {
          id: { type: "string" },
          name: { type: "string" },
          steps: {
            type: "array",
            items: {
              type: "object",
              additionalProperties: false,
              required: ["finding_fingerprint", "role", "description"],
              properties: {
                finding_fingerprint: { type: "string" },
                role: { type: "string" },
                description: { type: "string" },
              },
            },
            minItems: 2,
          },
          overall_severity: {
            type: "string",
            enum: ["CRITICAL", "HIGH", "MEDIUM"],
          },
          preconditions: { type: "array", items: { type: "string" } },
          impact_description: { type: "string" },
        },
      },
    },
    analysis_notes: { type: "string" },
  },
} as const;

function buildPrompt(
  confirmedFindings: Array<{ finding: Finding; triageResult: TriageResult }>,
  repoName: string,
): string {
  const findingSections = confirmedFindings.map((item, idx) => {
    const f = item.finding;
    const t = item.triageResult;
    return [
      `### Finding ${idx + 1}`,
      `Fingerprint: ${f.fingerprint}`,
      `Scanner: ${f.taskId}`,
      `Rule: ${f.ruleId}`,
      `File: ${f.filePath}:${f.startLine}`,
      `Severity: ${f.severity}`,
      `CWE: ${f.cwe.join(", ") || "none"}`,
      `Message: ${f.message}`,
      `Triage verdict: ${t.verdict} (confidence: ${t.confidence})`,
      `Triage rationale: ${t.rationale}`,
    ].join("\n");
  });

  return [
    "You are a senior red team operator who specializes in chaining low-severity vulnerabilities",
    "into critical attack paths. You have extensive experience with real-world penetration testing",
    "and know that individual findings often combine into far more severe attack chains.",
    "",
    `Analyze the following ${confirmedFindings.length} confirmed true-positive findings from "${repoName}"`,
    "and identify exploitation chains where multiple vulnerabilities can be combined for greater impact.",
    "",
    "## Confirmed Findings",
    "",
    ...findingSections.flatMap((s) => [s, ""]),
    "## Chain Detection Patterns",
    "Look for these common chaining patterns from real-world penetration tests:",
    "- Information disclosure → source code / config access → credential extraction → system compromise",
    "- SSRF → internal service access → data exfiltration",
    "- Auth weakness → privilege escalation → admin functionality",
    "- File upload → code execution → lateral movement",
    "- XSS → session hijacking → account takeover",
    "- SQL injection → data extraction → credential reuse → system access",
    "- Path traversal → config file read → credential extraction → further compromise",
    "",
    "## Requirements",
    "- Each chain must involve at least 2 different findings (single-finding issues don't chain).",
    "- Use the finding fingerprints to reference specific findings in each chain step.",
    "- Assign a role to each finding in the chain (e.g., 'initial access', 'privilege escalation', 'data exfiltration').",
    "- Rate overall chain severity: CRITICAL (full compromise), HIGH (significant data/access), MEDIUM (limited impact escalation).",
    "- List concrete preconditions needed for the chain to succeed.",
    "- Use Read, Glob, Grep to verify chain feasibility in the actual code.",
    "- If no valid chains exist, return an empty chains array with a note explaining why.",
    "",
    "## Anti-hallucination constraints",
    "- Only report chains you can verify are feasible in the codebase.",
    "- Each step must reference an actual confirmed finding by its fingerprint.",
    "- Do not invent findings or steps that don't correspond to the listed findings.",
  ].join("\n");
}

function parseOutput(raw: unknown): ChainAnalysisOutput {
  if (!isRecord(raw)) {
    return { chains: [], analysisNotes: "Failed to parse chain analysis output" };
  }

  const analysisNotes = typeof raw["analysis_notes"] === "string" ? raw["analysis_notes"] : "";

  if (!Array.isArray(raw["chains"])) {
    return { chains: [], analysisNotes };
  }

  const chains: ExploitChain[] = [];
  for (const item of raw["chains"]) {
    if (!isRecord(item)) continue;

    const steps: ExploitChain["steps"] = [];
    if (Array.isArray(item["steps"])) {
      for (const step of item["steps"]) {
        if (!isRecord(step)) continue;
        steps.push({
          findingFingerprint: String(step["finding_fingerprint"] ?? ""),
          role: String(step["role"] ?? ""),
          description: String(step["description"] ?? ""),
        });
      }
    }

    if (steps.length < 2) continue;

    const severity = String(item["overall_severity"] ?? "MEDIUM").toUpperCase();
    const validSeverity =
      severity === "CRITICAL" || severity === "HIGH" || severity === "MEDIUM" ? severity : "MEDIUM";

    chains.push({
      id: String(item["id"] ?? `chain-${chains.length + 1}`),
      name: String(item["name"] ?? "Unnamed chain"),
      steps,
      overallSeverity: validSeverity as ExploitChain["overallSeverity"],
      preconditions: Array.isArray(item["preconditions"])
        ? item["preconditions"].map((p: unknown) => String(p))
        : [],
      impactDescription: String(item["impact_description"] ?? ""),
    });
  }

  return { chains, analysisNotes };
}

export const chainAnalysisTask: AgentTask<ChainInput, ChainAnalysisOutput> = {
  id: "chain-analysis",
  displayName: "Exploitation Chain Analyzer",
  outputKind: "custom",
  dependsOn: [],

  async run(input, context): Promise<ChainAnalysisOutput> {
    if (!input.confirmedFindings || input.confirmedFindings.length < 2) {
      return {
        chains: [],
        analysisNotes: "Fewer than 2 confirmed findings — chain analysis requires at least 2.",
      };
    }

    const model =
      (isRecord(context.config.taskConfig["chain-analysis"]) &&
      typeof context.config.taskConfig["chain-analysis"]["model"] === "string"
        ? context.config.taskConfig["chain-analysis"]["model"]
        : undefined) ?? context.config.model;

    const prompt = buildPrompt(input.confirmedFindings, context.repoName);
    log.info(
      { count: input.confirmedFindings.length },
      "Analyzing confirmed findings for exploitation chains",
    );

    try {
      const { structuredOutput, resultText, executionError, costUsd } =
        await runStructuredAgentQuery({
          prompt,
          cwd: context.repoRoot,
          model,

          allowedTools: resolveDefaultReadOnlyTools(context.runtime),
          runtimeOptions: { runtime: context.runtime },
          schema: CHAIN_ANALYSIS_SCHEMA,
        });

      if (executionError) {
        log.warn({ executionError }, "Agent error during chain analysis");
        return attachTaskOutputMeta(
          { chains: [], analysisNotes: `Agent error: ${executionError}` },
          { costUsd },
        );
      }

      const output = parseOutput(structuredOutput ?? resultText);
      log.info({ chains: output.chains.length, costUsd }, "Chain analysis complete");
      return attachTaskOutputMeta(output, { costUsd });
    } catch (error) {
      log.error({ error: toErrorMessage(error) }, "Chain analysis failed");
      return { chains: [], analysisNotes: `Error: ${toErrorMessage(error)}` };
    }
  },
};

export const __chainAnalysisInternals = {
  buildPrompt,
  parseOutput,
};
