/**
 * taint-cwe-select — LLM picks which CWE classes are relevant for this project.
 * Pure classification: reads project context, outputs a CWE list.
 * No tools needed, no CodeQL — just one structured LLM call.
 */

import { createLogger } from "../../../logger.js";
import { coerceRepoContext } from "../../../repo-context.js";
import { attachTaskOutputMeta } from "../../../task-output-meta.js";
import type { ScanOpts } from "../../../types.js";
import { toErrorMessage } from "../../../utils.js";
import type { DagNodeImpl } from "../../types.js";
import { resolveTaskModel, resolveTaskRuntime } from "../runtime-overrides.js";

const log = createLogger({ stage: "taint-cwe-select" });

export interface CweSelection {
  id: string;
  name: string;
  reason: string;
}

export interface CweSelectOutput {
  cwes: CweSelection[];
}

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
        `- Auth patterns: ${repoContext.authPatterns.join(", ") || "unknown"}`,
        `- ORM/DB: ${repoContext.ormOrDb.join(", ") || "unknown"}`,
        `- Entry points: ${repoContext.entryPoints.join(", ") || "unknown"}`,
        "",
      ]
    : ["## Project context", "No context available — select broadly.", ""];

  return [
    "You are a security analyst selecting which vulnerability classes to check for a given project.",
    "Based on the project's tech stack, select the CWE classes that are RELEVANT.",
    "",
    "Only include CWEs where the project's stack could plausibly have that vulnerability type.",
    "Do NOT include CWEs that don't apply (e.g., no XSS for a pure backend API with no HTML rendering,",
    "no LDAP injection if no LDAP client is used).",
    "",
    ...contextLines,
    "## Common CWE classes to consider",
    "- CWE-22: Path Traversal (file I/O with user input)",
    "- CWE-78: OS Command Injection (exec/system calls)",
    "- CWE-79: Cross-Site Scripting (HTML rendering, template injection)",
    "- CWE-89: SQL Injection (database queries with string interpolation)",
    "- CWE-94: Code Injection (eval, dynamic code execution)",
    "- CWE-502: Unsafe Deserialization (untrusted data unmarshaling)",
    "- CWE-611: XXE (XML parsing with external entities)",
    "- CWE-918: SSRF (server-side HTTP requests with user-controlled URLs)",
    "- CWE-74: Injection (general — LDAP, template, header, log injection)",
    "- CWE-113: HTTP Header Injection",
    "- CWE-601: Open Redirect",
    "- CWE-327: Weak Cryptography",
    "- CWE-798: Hardcoded Credentials",
    "",
    "You may include CWEs not in this list if they're relevant to the project.",
    "For each selected CWE, explain WHY it's relevant to this specific project.",
  ].join("\n");
}

export const taintCweSelectTask: DagNodeImpl<ScanOpts, CweSelectOutput> = {
  id: "taint-cwe-select",
  displayName: "Taint CWE Selector",
  outputKind: "custom",
  dependsOn: ["context-gatherer"],

  async run(input, context): Promise<CweSelectOutput> {
    const runtime = resolveTaskRuntime(context);
    const model = resolveTaskModel(context, "taint-cwe-select");
    const params = (input ?? {}) as unknown as Record<string, unknown>;
    const taskConfig = {
      ...(context.config.taskConfig["taint-cwe-select"] ?? {}),
      ...(context.config.taskConfig["pipeline:taint-cwe-select"] ?? {}),
      ...(context.config.taskConfig["taint-iris"] ?? {}),
      ...(context.config.taskConfig["taint-iris:hunt"] ?? {}),
    };
    const maxBudgetUsd = readPositiveNumber(params["maxBudgetUsd"] ?? taskConfig["maxBudgetUsd"]);
    const repoContext = coerceRepoContext(context.upstreamOutputs.get("context-gatherer"));
    const prompt = buildPrompt(repoContext);

    log.info(`Selecting relevant CWE classes (model=${model})`);

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
          ...(maxBudgetUsd !== undefined ? { maxBudgetUsd } : {}),
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
      throw new Error(`[taint-cwe-select] Agent error: ${toErrorMessage(error)}`);
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
      .map((c) => ({
        id: String(c["id"] ?? "").trim(),
        name: String(c["name"] ?? "").trim(),
        reason: String(c["reason"] ?? "").trim(),
      }))
      .filter((c) => c.id && c.name),
  };
}

function readPositiveNumber(value: unknown): number | undefined {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric <= 0) return undefined;
  return numeric;
}
