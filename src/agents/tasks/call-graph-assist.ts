import { getCodeIntelligenceProvider } from "../../analysis-support/code-intelligence.js";
import { toErrorMessage } from "../../utils.js";
import { createLogger } from "../../logger.js";
import type { Finding } from "../../scanners/types.js";
import type { AgentTask, TaskContext } from "../types.js";

const log = createLogger({ stage: "call-graph-assist" });

/** Minimum score threshold — only enrich findings worth verifying. */
const SCORE_THRESHOLD = 7;
/** Max callers to trace per finding to limit cost. */
const MAX_CALLERS = 5;

/**
 * Call-graph-assist: enriches high-score findings with call-chain evidence
 * from the code intelligence provider. NOT an LLM call — uses existing
 * getCallers() infrastructure to trace who calls the vulnerable function.
 *
 * Contributes ranking data + prompt evidence; never gates.
 */
export const callGraphAssistTask: AgentTask<Finding[], Finding[]> = {
  id: "call-graph-assist",
  displayName: "Call-Graph Assist",
  outputKind: "findings",
  dependsOn: [],

  async run(input, context): Promise<Finding[]> {
    if (!Array.isArray(input) || input.length === 0) {
      return input ?? [];
    }

    const repoRoot = context.scanPath ?? context.repoRoot;
    let provider;
    try {
      provider = await getCodeIntelligenceProvider(repoRoot);
    } catch (error) {
      log.warn(`Could not initialize code intelligence: ${toErrorMessage(error)}`);
      return input;
    }

    const enriched: Finding[] = [];

    for (const finding of input) {
      const score = finding.adjustedScore ?? finding.score;
      if (score < SCORE_THRESHOLD) {
        enriched.push(finding);
        continue;
      }

      try {
        // Extract a likely function name from the finding context
        const functionName = extractFunctionName(finding);
        if (!functionName) {
          enriched.push(finding);
          continue;
        }

        const callers = await provider.getCallers({
          functionName,
          searchPath: repoRoot,
          maxResults: MAX_CALLERS,
        });

        if (callers.length === 0) {
          enriched.push(finding);
          continue;
        }

        const callChainSummary = `Call chain: ${callers.join(" <- ")} <- ${functionName}`;
        const existingEvidence = finding.evidence ?? "";
        const separator = existingEvidence.length > 0 ? "\n\n" : "";
        enriched.push({
          ...finding,
          evidence: `${existingEvidence}${separator}${callChainSummary}`,
        });
      } catch (error) {
        log.debug(`Call-graph assist skipped for ${finding.fingerprint}: ${toErrorMessage(error)}`);
        enriched.push(finding);
      }
    }

    return enriched;
  },
};

/**
 * Extract a function name from the finding's context — uses ruleId suffix,
 * the sink function, or falls back to the taint path's last step symbol.
 */
function extractFunctionName(finding: Finding): string | undefined {
  // Use sinkFunction if available (set by SSRF, NoSQL, etc.)
  const sink = (finding as unknown as Record<string, unknown>)["sinkFunction"];
  if (typeof sink === "string" && sink.length > 0) {
    return sink;
  }

  // Use the last taint path step's message as a heuristic
  if (finding.taintPath && finding.taintPath.length > 0) {
    const lastStep = finding.taintPath[finding.taintPath.length - 1];
    if (lastStep.message) {
      // Extract function-like identifier from message
      const match = lastStep.message.match(/\b([a-zA-Z_]\w+)\s*\(/);
      if (match) {
        return match[1];
      }
    }
  }

  // Try extracting from the rule ID (e.g., "ssrf-detect" -> skip, "js/sql-injection" -> skip)
  // This is too generic to be useful, return undefined
  return undefined;
}
