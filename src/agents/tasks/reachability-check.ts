import type { Finding } from "../../scanners/types.js";
import { toErrorMessage } from "../../utils.js";
import { createLogger } from "../../logger.js";
import type { AgentTask, TaskContext } from "../types.js";
import { resolveTaskModel, resolveTaskRuntime } from "./runtime-overrides.js";

const log = createLogger({ stage: "reachability-check" });

const REACHABILITY_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["results"],
  properties: {
    results: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["fingerprint", "reachable", "reason"],
        properties: {
          fingerprint: { type: "string" },
          reachable: { type: "string", enum: ["true", "false", "unknown"] },
          reason: { type: "string" },
          entryPoints: { type: "array", items: { type: "string" } },
        },
      },
    },
  },
} as const;

export interface ReachabilityResult {
  fingerprint: string;
  reachable: "true" | "false" | "unknown";
  reason: string;
  entryPoints?: string[];
}

function buildPrompt(findings: Finding[]): string {
  const findingList = findings
    .map((f, i) => [
      `### Finding ${i + 1}`,
      `Fingerprint: ${f.fingerprint}`,
      `File: ${f.filePath}:${f.startLine}`,
      `Rule: ${f.ruleId}`,
      `Message: ${f.message}`,
    ].join("\n"))
    .join("\n\n");

  return [
    "You are a code reachability analyzer. For each finding below, determine whether the",
    "flagged code is reachable from an entry point (route handler, main function, event listener,",
    "CLI command handler, cron job, message consumer, or test setup).",
    "",
    "Use GetCallers to trace each finding's function upward toward entry points.",
    "Use Grep and Glob to find route definitions, app.listen, main(), exports.",
    "",
    "## Findings to check",
    findingList,
    "",
    "## Output",
    "For each finding, report:",
    '- reachable: "true" if there is a path from an entry point, "false" if the code is dead/unreachable, "unknown" if you cannot determine',
    "- reason: Brief explanation of the reachability path or why it's unreachable",
    "- entryPoints: List of entry point file:line that can reach this code (if reachable)",
  ].join("\n");
}

interface ReachabilityRawOutput {
  results: Array<{
    fingerprint?: unknown;
    reachable?: unknown;
    reason?: unknown;
    entryPoints?: unknown;
  }>;
}

function isReachabilityRawOutput(raw: unknown): raw is ReachabilityRawOutput {
  return (
    raw !== null &&
    typeof raw === "object" &&
    "results" in raw &&
    Array.isArray((raw as ReachabilityRawOutput).results)
  );
}

function parseResults(raw: unknown, findings: Finding[]): Map<string, ReachabilityResult> {
  const results = new Map<string, ReachabilityResult>();
  const fingerprintSet = new Set(findings.map((f) => f.fingerprint));

  if (isReachabilityRawOutput(raw)) {
    for (const item of raw.results) {
      if (!item || typeof item !== "object") continue;
      const fp = String(item.fingerprint ?? "");
      if (!fp || !fingerprintSet.has(fp)) continue;
      const reachable = item.reachable === "false" ? "false" : item.reachable === "true" ? "true" : "unknown";
      results.set(fp, {
        fingerprint: fp,
        reachable,
        reason: String(item.reason ?? ""),
        entryPoints: Array.isArray(item.entryPoints) ? item.entryPoints.map(String) : undefined,
      });
    }
  }

  // Fill missing with unknown
  for (const f of findings) {
    if (!results.has(f.fingerprint)) {
      results.set(f.fingerprint, {
        fingerprint: f.fingerprint,
        reachable: "unknown",
        reason: "Not analyzed",
      });
    }
  }

  return results;
}

export const reachabilityCheckTask: AgentTask<Finding[], Finding[]> = {
  id: "reachability-check",
  displayName: "Reachability Check",
  outputKind: "findings",
  dependsOn: [],

  async run(input, context): Promise<Finding[]> {
    if (!Array.isArray(input) || input.length === 0) {
      return input ?? [];
    }

    const model = resolveTaskModel(context, "reachability-check");
    const workingRoot = context.workRoot ?? context.scanPath ?? context.repoRoot;
    const maxPerBatch = 20;
    const allResults = new Map<string, ReachabilityResult>();

    // Process in batches
    for (let i = 0; i < input.length; i += maxPerBatch) {
      const batch = input.slice(i, i + maxPerBatch);
      const prompt = buildPrompt(batch);
      const runtime = resolveTaskRuntime(context);

      try {
        let structuredOutput: unknown;
        for await (const message of runtime.query({
          prompt,
          options: {
            cwd: workingRoot,
            model,

            allowedTools: ["Read", "Glob", "Grep", "GetCallers"],
            permissionMode: "dontAsk",
            outputFormat: {
              type: "json_schema",
              schema: REACHABILITY_SCHEMA,
              strict: true,
              retryInvalidStructuredOutput: 1,
            },
          },
        })) {
          if (message.type === "result" && "result" in message) {
            structuredOutput = message.structuredOutput;
          }
        }

        const batchResults = parseResults(structuredOutput, batch);
        for (const [fp, result] of batchResults) {
          allResults.set(fp, result);
        }
      } catch (error) {
        log.error(`Reachability batch error: ${toErrorMessage(error)}`);
        // On error, mark all as unknown
        for (const f of batch) {
          allResults.set(f.fingerprint, {
            fingerprint: f.fingerprint,
            reachable: "unknown",
            reason: `Analysis error: ${toErrorMessage(error)}`,
          });
        }
      }
    }

    // Tag findings with reachability info
    return input.map((finding) => {
      const result = allResults.get(finding.fingerprint);
      if (!result) return finding;

      const reachabilityTag = result.reachable;
      const scorePenalty = reachabilityTag === "false" ? 15 : 0;
      return {
        ...finding,
        reachable: reachabilityTag,
        adjustedScore: Math.max(0, (finding.adjustedScore ?? finding.score) - scorePenalty),
      };
    });
  },
};
