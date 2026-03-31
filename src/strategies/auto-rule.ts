import type { Finding } from "../scanners/types.js";
import type { TaskContext } from "../agents/types.js";
import { createLogger } from "../logger.js";
import { toErrorMessage } from "../utils.js";
import { resolveTaskModel, resolveTaskRuntime } from "../agents/tasks/runtime-overrides.js";
import type { GeneratedRule, StrategyEvidence } from "./types.js";

const log = createLogger({ stage: "auto-rule" });

const RULE_GENERATION_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["rule"],
  properties: {
    rule: {
      type: "object",
      additionalProperties: false,
      required: ["kind", "ruleContent", "description"],
      properties: {
        kind: { type: "string", enum: ["semgrep", "grep-pattern"] },
        ruleContent: { type: "string" },
        description: { type: "string" },
      },
    },
  },
} as const;

/**
 * Extract a reusable detection rule from a confirmed finding.
 * Uses an LLM call to generalize the specific finding into a pattern.
 */
export async function generateRule(
  finding: Finding,
  evidence: StrategyEvidence[],
  context: TaskContext,
): Promise<GeneratedRule | null> {
  const runtime = resolveTaskRuntime(context);
  const model = resolveTaskModel(context, "multi-strategy");
  const cwd = context.scanPath ?? context.repoRoot;

  const evidenceStr = evidence
    .map((e) => `- [${e.kind}] ${e.description}`)
    .join("\n");

  const prompt = [
    "You are a security rule engineer. A vulnerability was confirmed by multiple analysis strategies.",
    "Generate a reusable detection rule that can find similar vulnerabilities in other parts of the codebase.",
    "",
    "## Confirmed Finding",
    `File: ${finding.filePath}:${finding.startLine}`,
    `Rule: ${finding.ruleId}`,
    `CWE: ${finding.cwe.join(", ")}`,
    `Message: ${finding.message}`,
    "",
    "## Evidence from Multiple Strategies",
    evidenceStr,
    "",
    "## Instructions",
    "1. Read the vulnerable code to understand the exact pattern",
    "2. Generalize the pattern — what makes this code vulnerable?",
    "3. Generate EITHER a Semgrep rule (YAML) OR a grep regex pattern",
    "   - Prefer Semgrep for structural patterns (function calls, data flow)",
    "   - Prefer grep for simple string patterns",
    "4. The rule should catch similar code elsewhere, not just this exact instance",
    "5. Avoid rules that are too broad (high false positive rate)",
  ].join("\n");

  try {
    let structuredOutput: unknown;

    for await (const message of runtime.query({
      prompt,
      options: {
        cwd,
        model,
        allowedTools: ["Read", "Grep"],
        permissionMode: "dontAsk",
        outputFormat: {
          type: "json_schema",
          schema: RULE_GENERATION_SCHEMA,
          strict: true,
          retryInvalidStructuredOutput: 1,
        },
      },
    })) {
      if (message.type === "result" && "result" in message) {
        structuredOutput = message.structuredOutput;
      }
    }

    if (!structuredOutput || typeof structuredOutput !== "object") return null;
    const obj = structuredOutput as Record<string, unknown>;
    const rule = obj["rule"] as Record<string, unknown> | undefined;
    if (!rule) return null;

    const kind = rule["kind"] === "semgrep" ? "semgrep" : "grep-pattern";
    const ruleContent = String(rule["ruleContent"] ?? "");
    const description = String(rule["description"] ?? "");

    if (!ruleContent) return null;

    return {
      kind,
      vulnClass: finding.cwe[0] ?? "unknown",
      cweIds: finding.cwe,
      ruleContent,
      description,
      sourceFinding: {
        fingerprint: finding.fingerprint,
        filePath: finding.filePath,
        startLine: finding.startLine,
      },
    };
  } catch (error) {
    log.warn(`Rule generation failed: ${toErrorMessage(error)}`);
    return null;
  }
}
