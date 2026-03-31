import type { Finding } from "../../scanners/types.js";
import type { RepoContext } from "../../types.js";
import { createLogger } from "../../logger.js";
import { toErrorMessage } from "../../utils.js";
import type { AnalysisStrategy, StrategyInput, StrategyResult, StrategyEvidence } from "../types.js";
import { resolveTaskModel, resolveTaskRuntime } from "../../agents/tasks/runtime-overrides.js";

const log = createLogger({ stage: "strategy-dataflow" });

const SUPPORTED_CWES = new Set([
  "CWE-89", "CWE-79", "CWE-918", "CWE-78", "CWE-94", "CWE-22", "CWE-502",
  "CWE-943", "CWE-1336",
]);

const DATAFLOW_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["flows"],
  properties: {
    flows: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["source", "sink", "sanitized", "confidence"],
        properties: {
          source: { type: "string" },
          sink: { type: "string" },
          sourceFile: { type: "string" },
          sourceLine: { type: "integer" },
          sinkFile: { type: "string" },
          sinkLine: { type: "integer" },
          sanitized: { type: "boolean" },
          sanitizerName: { type: "string" },
          confidence: { type: "number" },
          description: { type: "string" },
        },
      },
    },
  },
} as const;

/** Create a dataflow strategy for a specific CWE class. */
export function createDataflowStrategy(strategyId: string, cweIds: string[]): AnalysisStrategy {
  return {
    id: strategyId,
    kind: "dataflow",
    displayName: `Dataflow Tracing (${cweIds.join(", ")})`,
    costTier: 4,

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

      const prompt = buildDataflowPrompt(cweIds, input.finding);

      try {
        let structuredOutput: unknown;

        for await (const message of runtime.query({
          prompt,
          options: {
            cwd,
            model,
            allowedTools: ["Read", "Glob", "Grep", "GetCallers", "GetCallees"],
            permissionMode: "dontAsk",
            outputFormat: {
              type: "json_schema",
              schema: DATAFLOW_SCHEMA,
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

        const flows = parseFlows(structuredOutput);
        for (const flow of flows) {
          if (!flow.sanitized && flow.confidence > 0.5) {
            evidence.push({
              kind: "taint-flow",
              description: `Unsanitized flow: ${flow.source} -> ${flow.sink} (${flow.description})`,
              filePath: flow.sinkFile,
              startLine: flow.sinkLine,
            });
          }
        }
      } catch (error) {
        log.warn(`Dataflow strategy failed: ${toErrorMessage(error)}`);
      }

      const confidence = evidence.length > 0
        ? Math.min(0.9, 0.5 + evidence.length * 0.15)
        : 0;

      return {
        strategyKind: "dataflow", strategyId,
        findings: [], confidence, costUsd,
        durationMs: Date.now() - startTime, evidence,
      };
    },
  };
}

function buildDataflowPrompt(cweIds: string[], finding?: Finding): string {
  const findingContext = finding
    ? `\n## Known Finding\nFile: ${finding.filePath}:${finding.startLine}\nRule: ${finding.ruleId}\nMessage: ${finding.message}\n`
    : "";

  return [
    `You are a dataflow analyzer. Trace source-to-sink data flows for vulnerability class ${cweIds.join(", ")}.`,
    findingContext,
    "## Instructions",
    "1. Identify SOURCES: where user-controlled data enters (HTTP params, headers, body, env vars, file reads)",
    "2. Identify SINKS: where data reaches dangerous operations (SQL queries, command execution, file writes, HTML rendering)",
    "3. For each source-sink pair, trace the data flow through the code:",
    "   - Follow variable assignments, function calls, and returns",
    "   - Check for sanitization/validation along the path",
    "   - Note if the data is transformed (encoded, escaped, validated)",
    "4. Report each flow with confidence level",
    "",
    "Use Read, Grep, GetCallers, GetCallees to trace the flow.",
    "Focus on flows that are NOT sanitized — these are potential vulnerabilities.",
  ].join("\n");
}

interface DataflowResult {
  source: string;
  sink: string;
  sourceFile?: string;
  sourceLine?: number;
  sinkFile?: string;
  sinkLine?: number;
  sanitized: boolean;
  sanitizerName?: string;
  confidence: number;
  description?: string;
}

function parseFlows(raw: unknown): DataflowResult[] {
  if (!raw || typeof raw !== "object") return [];
  const obj = raw as Record<string, unknown>;
  if (!Array.isArray(obj["flows"])) return [];
  return (obj["flows"] as Array<Record<string, unknown>>)
    .filter((f) => typeof f["source"] === "string" && typeof f["sink"] === "string")
    .map((f) => ({
      source: f["source"] as string,
      sink: f["sink"] as string,
      sourceFile: f["sourceFile"] as string | undefined,
      sourceLine: f["sourceLine"] as number | undefined,
      sinkFile: f["sinkFile"] as string | undefined,
      sinkLine: f["sinkLine"] as number | undefined,
      sanitized: f["sanitized"] === true,
      sanitizerName: f["sanitizerName"] as string | undefined,
      confidence: typeof f["confidence"] === "number" ? f["confidence"] : 0.5,
      description: f["description"] as string | undefined,
    }));
}
