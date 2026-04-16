/**
 * deep-semantic-cwe-select — LLM picks which memory-safety / deep semantic
 * CWE classes are relevant for this project.
 *
 * Mirrors taint-iris/cwe-select.ts in structure but targets native-code
 * vulnerability classes: integer overflow, sentinel collisions, buffer
 * overflows, use-after-free, missing mitigations, unsafe block violations.
 *
 * Only activates when the repo contains C, C++, Rust, or Go.
 */

import { createLogger } from "../../../logger.js";
import { coerceRepoContext } from "../../../repo-context.js";
import { attachTaskOutputMeta } from "../../../task-output-meta.js";
import type { ScanOpts } from "../../../types.js";
import { toErrorMessage } from "../../../utils.js";
import type { AgentTask, TaskContext } from "../../types.js";
import { resolveTaskModel, resolveTaskRuntime } from "../runtime-overrides.js";
import type { CweSelection, CweSelectOutput } from "../taint-iris/cwe-select.js";
import { DEEP_SEMANTIC_CWE_MENU, isDeepSemanticLanguage } from "./types.js";

const log = createLogger({ stage: "deep-semantic-cwe-select" });

const CWE_SELECT_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["cwes"],
  properties: {
    cwes: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["id", "name", "reason"],
        properties: {
          id: { type: "string" },
          name: { type: "string" },
          reason: { type: "string" },
        },
      },
    },
  },
} as const;

function buildPrompt(repoContext: ReturnType<typeof coerceRepoContext>): string {
  const contextLines = repoContext
    ? [
        "## Project context",
        `- Languages: ${repoContext.languages.join(", ") || "unknown"}`,
        `- Frameworks: ${repoContext.frameworks.join(", ") || "unknown"}`,
        `- Entry points: ${repoContext.entryPoints.join(", ") || "unknown"}`,
        "",
      ]
    : ["## Project context", "No context available — select broadly.", ""];

  const cweMenuLines = DEEP_SEMANTIC_CWE_MENU.map(
    (c) => `- ${c.id}: ${c.name} (e.g., ${c.exemplar})`,
  );

  return [
    "You are a security analyst specializing in memory safety and low-level vulnerability classes.",
    "Based on the project's tech stack and languages, select the CWE classes that are RELEVANT.",
    "",
    "Only include CWEs where the project's language and code patterns could plausibly produce that bug class.",
    "For example:",
    "- C/C++ codebases: most CWEs below are relevant, especially integer overflow, buffer overflow, and use-after-free.",
    "- Rust codebases: focus on unsafe blocks, FFI boundary issues, and type confusion.",
    "- Go codebases: focus on integer overflow at FFI/cgo boundaries, slice bounds, and goroutine-related resource lifetime issues.",
    "",
    ...contextLines,
    "## Deep semantic CWE classes to consider",
    ...cweMenuLines,
    "",
    "You may include CWEs not in this list if they're relevant to the project's native-code surface.",
    "For each selected CWE, explain WHY it's relevant to this specific project.",
  ].join("\n");
}

export const deepSemanticCweSelectTask: AgentTask<ScanOpts, CweSelectOutput> = {
  id: "deep-semantic-cwe-select",
  displayName: "Deep Semantic CWE Selector",
  outputKind: "custom",
  dependsOn: ["context-gatherer"],

  condition(upstreamOutputs) {
    const ctx = coerceRepoContext(upstreamOutputs.get("context-gatherer"));
    if (!ctx) return false;
    return ctx.languages.some((l) => isDeepSemanticLanguage(l));
  },

  async run(_input, context): Promise<CweSelectOutput> {
    const runtime = resolveTaskRuntime(context);
    const model = resolveTaskModel(context, "deep-semantic-cwe-select");
    const repoContext = coerceRepoContext(context.upstreamOutputs.get("context-gatherer"));
    const prompt = buildPrompt(repoContext);

    log.info(`Selecting relevant deep-semantic CWE classes (model=${model})`);

    let structuredOutput: unknown;
    let costUsd = 0;

    try {
      for await (const message of runtime.query({
        prompt,
        options: {
          cwd: context.repoRoot,
          model,
          allowedTools: ["Read", "Grep", "Glob"],
          permissionMode: "dontAsk",
          outputFormat: {
            type: "json_schema",
            schema: CWE_SELECT_SCHEMA,
            strict: true,
            retryInvalidStructuredOutput: 1,
          },
        },
      })) {
        if (message.type === "result" && "result" in message) {
          structuredOutput = message.structuredOutput;
          if (typeof message.totalCostUsd === "number") costUsd = message.totalCostUsd;
        }
      }
    } catch (error) {
      throw new Error(`[deep-semantic-cwe-select] Agent error: ${toErrorMessage(error)}`);
    }

    const parsed = parseOutput(structuredOutput);
    log.info(
      `Selected ${parsed.cwes.length} CWE classes: ${parsed.cwes.map((c) => c.id).join(", ")}`,
    );

    return attachTaskOutputMeta(parsed, { costUsd });
  },
};

function parseOutput(raw: unknown): CweSelectOutput {
  if (!raw || typeof raw !== "object") return { cwes: [] };
  const obj = raw as Record<string, unknown>;
  const cwes = Array.isArray(obj["cwes"]) ? obj["cwes"] : [];
  return {
    cwes: cwes
      .filter((c): c is Record<string, unknown> => typeof c === "object" && c !== null)
      .map(
        (c): CweSelection => ({
          id: String(c["id"] ?? "").trim(),
          name: String(c["name"] ?? "").trim(),
          reason: String(c["reason"] ?? "").trim(),
        }),
      )
      .filter((c) => c.id && c.name),
  };
}

// Exported for testing
export const __deepSemanticCweSelectInternals = {
  buildPrompt,
  parseOutput,
};
