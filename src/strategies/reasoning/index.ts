import { resolveTaskModel, resolveTaskRuntime } from "../../agents/tasks/runtime-overrides.js";
import { createLogger } from "../../logger.js";
import type { Finding } from "../../scanners/types.js";
import type { RepoContext } from "../../types.js";
import { toErrorMessage } from "../../utils.js";
import type {
  AnalysisStrategy,
  StrategyEvidence,
  StrategyInput,
  StrategyResult,
} from "../types.js";

const log = createLogger({ stage: "strategy-reasoning" });

// Reasoning strategy applies to ALL CWEs — it reasons from first principles
const SUPPORTED_CWES = new Set([
  "CWE-89",
  "CWE-79",
  "CWE-918",
  "CWE-78",
  "CWE-94",
  "CWE-22",
  "CWE-502",
  "CWE-862",
  "CWE-863",
  "CWE-95",
  "CWE-943",
  "CWE-1336",
  "CWE-1321",
  "CWE-362",
  "CWE-367",
  "CWE-798",
  "CWE-327",
  "CWE-326",
  "CWE-829",
  "CWE-200",
  "CWE-400",
  "CWE-611",
  "CWE-776",
]);

const REASONING_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["assessment"],
  properties: {
    assessment: {
      type: "object",
      additionalProperties: false,
      required: ["vulnerable", "confidence", "reasoning"],
      properties: {
        vulnerable: { type: "boolean" },
        confidence: { type: "number" },
        reasoning: { type: "string" },
        trustBoundaries: { type: "array", items: { type: "string" } },
        mitigations: { type: "array", items: { type: "string" } },
        missingGuards: { type: "array", items: { type: "string" } },
      },
    },
  },
} as const;

/** Create a reasoning strategy for a specific CWE class. */
export function createReasoningStrategy(strategyId: string, cweIds: string[]): AnalysisStrategy {
  return {
    id: strategyId,
    kind: "reasoning",
    displayName: `First-Principles Reasoning (${cweIds.join(", ")})`,
    costTier: 6,

    appliesTo(targetCweIds: string[]): boolean {
      return targetCweIds.some((cwe) => SUPPORTED_CWES.has(cwe));
    },

    async run(input: StrategyInput): Promise<StrategyResult> {
      const startTime = Date.now();
      const evidence: StrategyEvidence[] = [];
      let costUsd = 0;

      const runtime = resolveTaskRuntime(input.context);
      const model = resolveTaskModel(input.context, "multi-strategy");
      const cwd = input.context.scanPath ?? input.context.repoRoot;

      // Use KnowledgeModule for bypass techniques and safe patterns
      const knowledgeRegistry = input.context.knowledgeRegistry;
      let knowledgeContext = "";
      if (knowledgeRegistry) {
        const modules = knowledgeRegistry.query({ cwes: cweIds });
        for (const mod of modules) {
          if (mod.safePatterns.length > 0) {
            knowledgeContext += `\nKnown safe patterns: ${mod.safePatterns.map((p) => p.pattern).join(", ")}`;
          }
          if (mod.bypassTechniques.length > 0) {
            knowledgeContext += `\nKnown bypass techniques: ${mod.bypassTechniques.join(", ")}`;
          }
        }
      }

      const prompt = buildReasoningPrompt(cweIds, input.finding, knowledgeContext);

      try {
        let structuredOutput: unknown;

        for await (const message of runtime.query({
          prompt,
          options: {
            cwd,
            model,
            allowedTools: ["Read", "Glob", "Grep"],
            permissionMode: "dontAsk",
            outputFormat: {
              type: "json_schema",
              schema: REASONING_SCHEMA,
              strict: true,
              retryInvalidStructuredOutput: 1,
            },
          },
        })) {
          if (message.type === "result" && "result" in message) {
            structuredOutput = message.structuredOutput;
            costUsd = ((message as unknown as Record<string, unknown>).totalCostUsd as number) ?? 0;
          }
        }

        const assessment = parseAssessment(structuredOutput);
        if (assessment) {
          evidence.push({
            kind: "reasoning-chain",
            description: assessment.reasoning,
          });

          if (assessment.missingGuards.length > 0) {
            evidence.push({
              kind: "reasoning-chain",
              description: `Missing guards: ${assessment.missingGuards.join(", ")}`,
            });
          }
        }
      } catch (error) {
        log.warn(`Reasoning strategy failed: ${toErrorMessage(error)}`);
      }

      const confidence = evidence.length > 0 ? Math.min(0.85, 0.4 + evidence.length * 0.15) : 0;

      return {
        strategyKind: "reasoning",
        strategyId,
        findings: [],
        confidence,
        costUsd,
        durationMs: Date.now() - startTime,
        evidence,
      };
    },
  };
}

function buildReasoningPrompt(
  cweIds: string[],
  finding?: Finding,
  knowledgeContext?: string,
): string {
  const findingContext = finding
    ? `\n## Known Finding\nFile: ${finding.filePath}:${finding.startLine}\nRule: ${finding.ruleId}\nMessage: ${finding.message}\n`
    : "";

  return [
    `You are a security architect performing first-principles analysis for ${cweIds.join(", ")}.`,
    "Do NOT look for specific patterns. Instead, reason about the application's architecture:",
    findingContext,
    "## Analysis Steps",
    "1. **Trust boundaries**: Where does trusted data end and untrusted data begin?",
    "2. **Authentication model**: How does the app verify identity? Are there gaps?",
    "3. **Authorization model**: How are permissions checked? Are there missing checks?",
    "4. **Framework defaults**: What security does the framework provide by default? What must be explicitly configured?",
    "5. **Configuration**: Are security features enabled? Check config files, env vars, middleware setup.",
    "6. **Missing guards**: What protections SHOULD exist but don't?",
    "",
    "Use Read and Grep to examine config files, middleware setup, auth logic, and route handlers.",
    knowledgeContext ?? "",
    "",
    "## Output",
    "Assess whether the application is vulnerable to the target CWE class.",
    "Focus on architectural gaps, not individual code patterns.",
  ].join("\n");
}

interface ReasoningAssessment {
  vulnerable: boolean;
  confidence: number;
  reasoning: string;
  trustBoundaries: string[];
  mitigations: string[];
  missingGuards: string[];
}

function parseAssessment(raw: unknown): ReasoningAssessment | null {
  if (!raw || typeof raw !== "object") return null;
  const obj = raw as Record<string, unknown>;
  const assessment = obj["assessment"] as Record<string, unknown> | undefined;
  if (!assessment) return null;

  return {
    vulnerable: assessment["vulnerable"] === true,
    confidence: typeof assessment["confidence"] === "number" ? assessment["confidence"] : 0.5,
    reasoning: String(assessment["reasoning"] ?? ""),
    trustBoundaries: Array.isArray(assessment["trustBoundaries"])
      ? assessment["trustBoundaries"].map(String)
      : [],
    mitigations: Array.isArray(assessment["mitigations"])
      ? assessment["mitigations"].map(String)
      : [],
    missingGuards: Array.isArray(assessment["missingGuards"])
      ? assessment["missingGuards"].map(String)
      : [],
  };
}
