import { getLogger } from "../../logger.js";
import { languageGeneralHintsModule } from "../../prompts/language-tuning.js";
import { coerceRepoContext } from "../../repo-context.js";
import { attachTaskOutputMeta } from "../../task-output-meta.js";
import type { EnrichedRepoContext, RepoContext } from "../../types.js";
import { isRecord, toErrorMessage } from "../../utils.js";
import type { AgentTask, TaskContext } from "../types.js";
import { resolveTaskAllowedTools, resolveTaskModel } from "./runtime-overrides.js";

const log = getLogger("context-enricher");

const ENRICHED_CONTEXT_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: [
    "customMiddleware",
    "customSanitizers",
    "trustBoundaries",
    "dataClassifications",
    "architecturalNotes",
  ],
  properties: {
    customMiddleware: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["name", "filePath", "purpose"],
        properties: {
          name: { type: "string" },
          filePath: { type: "string" },
          purpose: { type: "string" },
          appliesTo: { type: "string" },
        },
      },
    },
    customSanitizers: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["name", "filePath", "sanitizationType"],
        properties: {
          name: { type: "string" },
          filePath: { type: "string" },
          sanitizationType: { type: "string" },
          usedBy: { type: "string" },
        },
      },
    },
    trustBoundaries: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["name", "description"],
        properties: {
          name: { type: "string" },
          description: { type: "string" },
          entryPoints: { type: "array", items: { type: "string" } },
        },
      },
    },
    dataClassifications: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["dataType", "sensitivity"],
        properties: {
          dataType: { type: "string" },
          sensitivity: {
            type: "string",
            enum: ["public", "internal", "confidential", "restricted"],
          },
          locations: { type: "array", items: { type: "string" } },
        },
      },
    },
    architecturalNotes: {
      type: "array",
      items: { type: "string" },
    },
  },
} as const;

interface ContextEnricherConfig {
  model: string;
}

function resolveConfig(ctx: TaskContext): ContextEnricherConfig {
  const model = resolveTaskModel(ctx, "context-enricher", "context-enrichment");
  return { model };
}

function buildPrompt(repoContext: RepoContext | undefined): string {
  const contextLines = repoContext
    ? [
        "## Heuristic repo context (from context-gatherer)",
        `- Languages: ${repoContext.languages.join(", ") || "unknown"}`,
        `- Frameworks: ${repoContext.frameworks.join(", ") || "unknown"}`,
        `- Auth patterns: ${repoContext.authPatterns.join(", ") || "unknown"}`,
        `- Sanitization libs: ${repoContext.sanitizationLibs.join(", ") || "unknown"}`,
        `- ORM/DB: ${repoContext.ormOrDb.join(", ") || "unknown"}`,
        `- Entry points: ${repoContext.entryPoints.join(", ") || "unknown"}`,
        "",
      ]
    : [];

  return [
    "You are a senior security architect performing deep context analysis of a codebase.",
    "Your goal is to discover security-relevant architectural details that heuristic analysis misses.",
    "",
    ...contextLines,
    languageGeneralHintsModule(repoContext),
    "## Analysis tasks",
    "",
    "### 1. Custom middleware discovery",
    "Search for application-specific middleware (auth, logging, rate limiting, CORS, validation).",
    "Use Glob to find middleware directories, then Read key files.",
    "For each middleware: name, file path, purpose, and what routes it applies to.",
    "",
    "### 2. Custom sanitizer discovery",
    "Search for application-specific sanitization/validation functions (not library imports).",
    "Look for functions that escape, validate, normalize, or filter user input.",
    "For each sanitizer: name, file path, what type of sanitization, and where it's used.",
    "",
    "### 3. Trust boundary mapping",
    "Identify trust boundaries: where external input enters the system, where privilege levels change,",
    "where data crosses service boundaries. Name each boundary and describe its entry points.",
    "",
    "### 4. Data classification",
    "Identify sensitive data types handled by the application (PII, credentials, financial, health).",
    "Note where they're stored, processed, and transmitted. Classify sensitivity level.",
    "",
    "### 5. Architectural notes",
    "Document any security-relevant architectural patterns you discover:",
    "- Service mesh / API gateway configurations",
    "- Event-driven patterns that affect data flow",
    "- Caching layers that might bypass access controls",
    "- Background job processors that handle sensitive data",
    "- Multi-tenancy isolation mechanisms",
    "",
    "## Constraints",
    "- Only report what you can verify by reading actual code.",
    "- Keep each discovery concise and actionable for downstream security analysis.",
    "- If a category yields no results, return an empty array for it.",
  ].join("\n");
}

function normalizeOutput(raw: unknown): EnrichedRepoContext["enrichment"] {
  if (!isRecord(raw)) {
    return {
      customMiddleware: [],
      customSanitizers: [],
      trustBoundaries: [],
      dataClassifications: [],
      architecturalNotes: [],
    };
  }

  return {
    customMiddleware: normalizeArray(raw["customMiddleware"], (item) => {
      if (!isRecord(item)) return null;
      return {
        name: asString(item["name"]),
        filePath: asString(item["filePath"]),
        purpose: asString(item["purpose"]),
        appliesTo: asOptionalString(item["appliesTo"]),
      };
    }),
    customSanitizers: normalizeArray(raw["customSanitizers"], (item) => {
      if (!isRecord(item)) return null;
      return {
        name: asString(item["name"]),
        filePath: asString(item["filePath"]),
        sanitizationType: asString(item["sanitizationType"]),
        usedBy: asOptionalString(item["usedBy"]),
      };
    }),
    trustBoundaries: normalizeArray(raw["trustBoundaries"], (item) => {
      if (!isRecord(item)) return null;
      return {
        name: asString(item["name"]),
        description: asString(item["description"]),
        entryPoints: normalizeStringArray(item["entryPoints"]),
      };
    }),
    dataClassifications: normalizeArray(raw["dataClassifications"], (item) => {
      if (!isRecord(item)) return null;
      const sensitivity = asString(item["sensitivity"]);
      if (!["public", "internal", "confidential", "restricted"].includes(sensitivity)) return null;
      return {
        dataType: asString(item["dataType"]),
        sensitivity: sensitivity as "public" | "internal" | "confidential" | "restricted",
        locations: normalizeStringArray(item["locations"]),
      };
    }),
    architecturalNotes: normalizeStringArray(raw["architecturalNotes"]),
  };
}

export const contextEnricherTask: AgentTask<unknown, EnrichedRepoContext["enrichment"]> = {
  id: "context-enricher",
  displayName: "LLM Context Enricher",
  outputKind: "custom",
  dependsOn: ["context-gatherer"],

  async run(_input, context): Promise<EnrichedRepoContext["enrichment"]> {
    context.signal?.throwIfAborted();
    const { model } = resolveConfig(context);
    const workRoot = context.workRoot ?? context.repoRoot;
    const repoContext = coerceRepoContext(context.upstreamOutputs.get("context-gatherer"));
    const prompt = buildPrompt(repoContext);
    const runtime = context.runtime;

    let structuredOutput: unknown;
    let resultText = "";
    let costUsd = 0;

    const tag = "[context-enricher]";
    log.info({ model }, "Starting context enrichment");

    // Forward the caller's abort signal into the runtime so Ctrl+C in the
    // shell actually cancels this call instead of leaking an in-flight LLM
    // query that keeps spending tokens after the operator has moved on.
    const abortController = new AbortController();
    if (context.signal) {
      if (context.signal.aborted) abortController.abort();
      else context.signal.addEventListener("abort", () => abortController.abort(), { once: true });
    }

    try {
      for await (const message of runtime.query({
        prompt,
        options: {
          cwd: workRoot,
          model,
          abortController,

          allowedTools: resolveTaskAllowedTools(context),
          permissionMode: "dontAsk",
          outputFormat: {
            type: "json_schema",
            schema: ENRICHED_CONTEXT_SCHEMA,
            strict: true,
            retryInvalidStructuredOutput: 2,
          },
        },
      })) {
        if (message.type !== "result") continue;
        if (typeof message.totalCostUsd === "number" && Number.isFinite(message.totalCostUsd)) {
          costUsd = message.totalCostUsd;
        }
        if ("result" in message) {
          resultText = message.result;
          structuredOutput = message.structuredOutput;
        }
      }
    } catch (error) {
      throw new Error(`${tag} Agent error: ${toErrorMessage(error)}`);
    }

    const enrichment = normalizeOutput(structuredOutput ?? parseJson(resultText, tag));
    return attachTaskOutputMeta(enrichment, { costUsd });
  },
};

function normalizeArray<T>(value: unknown, mapper: (item: unknown) => T | null): T[] {
  if (!Array.isArray(value)) return [];
  const results: T[] = [];
  for (const item of value) {
    const mapped = mapper(item);
    if (mapped !== null) results.push(mapped);
  }
  return results;
}

function normalizeStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.map((v) => String(v).trim()).filter(Boolean);
}

function asString(value: unknown): string {
  if (typeof value === "string") return value;
  if (value == null) return "";
  return String(value);
}

function asOptionalString(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  return value.trim() || undefined;
}

function parseJson(text: string, tag: string): unknown {
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new Error(`${tag} Invalid JSON output: ${toErrorMessage(error)}`);
  }
}

export const __contextEnricherInternals = {
  resolveConfig,
  buildPrompt,
  normalizeOutput,
};
