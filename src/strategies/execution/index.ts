import type { Finding } from "../../scanners/types.js";
import type { RepoContext } from "../../types.js";
import { createLogger } from "../../logger.js";
import { toErrorMessage } from "../../utils.js";
import type { AnalysisStrategy, StrategyInput, StrategyResult, StrategyEvidence } from "../types.js";
import { resolveTaskModel, resolveTaskRuntime } from "../../agents/tasks/runtime-overrides.js";

const log = createLogger({ stage: "strategy-execution" });

const SUPPORTED_CWES = new Set([
  "CWE-89", "CWE-918", "CWE-78", "CWE-94", "CWE-22",
]);

const EXECUTION_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["testCase"],
  properties: {
    testCase: {
      type: "object",
      additionalProperties: false,
      required: ["input", "expectedBehavior", "exploitDescription", "confidence"],
      properties: {
        input: { type: "string" },
        expectedBehavior: { type: "string" },
        exploitDescription: { type: "string" },
        confidence: { type: "number" },
        preconditions: { type: "array", items: { type: "string" } },
        attackVector: { type: "string" },
      },
    },
  },
} as const;

/** Create an execution strategy for a specific CWE class. */
export function createExecutionStrategy(strategyId: string, cweIds: string[]): AnalysisStrategy {
  return {
    id: strategyId,
    kind: "execution",
    displayName: `Execution-Based Proof (${cweIds.join(", ")})`,
    costTier: 9,

    appliesTo(targetCweIds: string[]): boolean {
      return targetCweIds.some((cwe) => SUPPORTED_CWES.has(cwe));
    },

    async run(input: StrategyInput): Promise<StrategyResult> {
      const startTime = Date.now();
      const evidence: StrategyEvidence[] = [];
      let costUsd = 0;

      if (!input.finding) {
        // Execution strategy requires an existing finding to validate
        return {
          strategyKind: "execution", strategyId,
          findings: [], confidence: 0, costUsd: 0,
          durationMs: Date.now() - startTime, evidence: [],
        };
      }

      const runtime = resolveTaskRuntime(input.context);
      const model = resolveTaskModel(input.context, "multi-strategy");
      const cwd = input.context.scanPath ?? input.context.repoRoot;

      const prompt = buildExecutionPrompt(cweIds, input.finding);

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
              schema: EXECUTION_SCHEMA,
              strict: true,
              retryInvalidStructuredOutput: 1,
            },
          },
        })) {
          if (message.type === "result" && "result" in message) {
            structuredOutput = message.structuredOutput;
            costUsd = (message as unknown as Record<string, unknown>).totalCostUsd as number ?? 0;
          }
        }

        const testCase = parseTestCase(structuredOutput);
        if (testCase && testCase.confidence > 0.5) {
          evidence.push({
            kind: "execution-result",
            description: `PoC: ${testCase.exploitDescription}. Input: ${testCase.input}. Attack vector: ${testCase.attackVector ?? "N/A"}`,
          });
        }
      } catch (error) {
        log.warn(`Execution strategy failed: ${toErrorMessage(error)}`);
      }

      const confidence = evidence.length > 0 ? 0.85 : 0;

      return {
        strategyKind: "execution", strategyId,
        findings: [], confidence, costUsd,
        durationMs: Date.now() - startTime, evidence,
      };
    },
  };
}

function buildExecutionPrompt(cweIds: string[], finding: Finding): string {
  return [
    `You are a security researcher constructing a proof-of-concept for ${cweIds.join(", ")}.`,
    "",
    "## Finding",
    `File: ${finding.filePath}:${finding.startLine}`,
    `Rule: ${finding.ruleId}`,
    `Message: ${finding.message}`,
    "",
    "## Instructions",
    "1. Read the vulnerable code and understand the data flow",
    "2. Construct a concrete exploit INPUT that would trigger the vulnerability",
    "3. Describe the expected behavior when the exploit succeeds",
    "4. Identify any preconditions required (auth, specific headers, etc.)",
    "5. Describe the attack vector (HTTP request, CLI argument, etc.)",
    "",
    "The test case should be specific and executable — not abstract.",
    "Use Read and Grep to understand the exact code path.",
  ].join("\n");
}

interface TestCase {
  input: string;
  expectedBehavior: string;
  exploitDescription: string;
  confidence: number;
  preconditions?: string[];
  attackVector?: string;
}

function parseTestCase(raw: unknown): TestCase | null {
  if (!raw || typeof raw !== "object") return null;
  const obj = raw as Record<string, unknown>;
  const tc = obj["testCase"] as Record<string, unknown> | undefined;
  if (!tc) return null;

  return {
    input: String(tc["input"] ?? ""),
    expectedBehavior: String(tc["expectedBehavior"] ?? ""),
    exploitDescription: String(tc["exploitDescription"] ?? ""),
    confidence: typeof tc["confidence"] === "number" ? tc["confidence"] : 0.5,
    preconditions: Array.isArray(tc["preconditions"]) ? tc["preconditions"].map(String) : undefined,
    attackVector: typeof tc["attackVector"] === "string" ? tc["attackVector"] : undefined,
  };
}
