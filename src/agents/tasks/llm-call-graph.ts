import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { getCodeIntelligenceProvider } from "../../analysis-support/code-intelligence.js";
import { createLogger } from "../../logger.js";
import { coerceRepoContext } from "../../repo-context.js";
import { attachTaskOutputMeta } from "../../task-output-meta.js";
import { normalizeCostUsd, toErrorMessage } from "../../utils.js";
import type { Finding, TaintPathStep } from "../../scanners/types.js";
import type { ApplicationModel, ApplicationRoute } from "../../types.js";
import type { AgentTask, TaskContext } from "../types.js";
import { resolveTaskRuntime } from "./runtime-overrides.js";

const log = createLogger({ stage: "llm-call-graph" });

/** Max entry points to analyze to keep costs bounded. */
const MAX_ENTRY_POINTS = 10;
/** Max depth for call chain traversal. */
const MAX_DEPTH = 4;
/** Max file size to read for LLM context. */
const MAX_FILE_BYTES = 100_000;

export interface LlmCallGraphOutput {
  findings: Finding[];
  analyzedEntryPoints: number;
  discoveredPaths: number;
}

/**
 * LLM-driven call graph discovery: starts from application entry points
 * (API routes, request handlers) and uses an LLM to trace data flows
 * across function boundaries, identifying where user-controlled input
 * reaches security-sensitive sinks without sanitization.
 */
export const llmCallGraphTask: AgentTask<Finding[], LlmCallGraphOutput> = {
  id: "llm-call-graph",
  displayName: "LLM Call-Graph Discovery",
  outputKind: "findings",
  dependsOn: ["context-gatherer", "app-model-build"],

  condition(upstreamOutputs, config) {
    // Only run if call graph assist is enabled
    return config.callGraphAssistEnabled === true;
  },

  async run(input, context): Promise<LlmCallGraphOutput> {
    const findings = Array.isArray(input) ? input : [];
    const repoRoot = context.scanPath ?? context.repoRoot;
    const runtime = resolveTaskRuntime(context);
    const model = context.config.model;

    // Get application model for entry points
    const appModel = context.upstreamOutputs.get("app-model-build") as ApplicationModel | undefined;
    const repoContext = coerceRepoContext(context.upstreamOutputs.get("context-gatherer"));

    if (!appModel || !appModel.routes || appModel.routes.length === 0) {
      log.info("No entry points found in application model, skipping LLM call graph");
      return attachTaskOutputMeta({ findings, analyzedEntryPoints: 0, discoveredPaths: 0 }, { costUsd: 0 });
    }

    let provider;
    try {
      provider = await getCodeIntelligenceProvider(repoRoot);
    } catch (error) {
      log.warn(`Could not initialize code intelligence: ${toErrorMessage(error)}`);
      return attachTaskOutputMeta({ findings, analyzedEntryPoints: 0, discoveredPaths: 0 }, { costUsd: 0 });
    }

    // Select high-value entry points to analyze
    const entryPoints = selectEntryPoints(appModel.routes);
    let totalCostUsd = 0;
    let discoveredPaths = 0;
    const newFindings: Finding[] = [];

    for (const entry of entryPoints) {
      try {
        // Read the entry point source
        const sourceContent = await readSourceSafe(path.join(repoRoot, entry.filePath));
        if (!sourceContent) continue;

        // Get static call chain as seed for LLM
        const functionName = extractHandlerName(entry);
        const staticCallees = functionName
          ? await provider.getCallees({ functionName, filePath: path.join(repoRoot, entry.filePath) }).catch(() => [])
          : [];

        // Build context for LLM analysis
        const calleeSnippets: string[] = [];
        for (const callee of staticCallees.slice(0, 5)) {
          const results = await provider.getCallers({
            functionName: callee,
            searchPath: repoRoot,
            maxResults: 1,
          }).catch(() => []);
          if (results.length > 0) {
            const snippet = await provider.getSnippet(results[0], 1).catch(() => undefined);
            if (snippet) calleeSnippets.push(`// ${callee}:\n${snippet}`);
          }
        }

        // Query LLM to trace tainted data flows
        const prompt = buildCallGraphPrompt(entry, sourceContent, staticCallees, calleeSnippets, repoContext);
        let resultText = "";
        let costUsd = 0;

        for await (const message of runtime.query({
          prompt,
          options: {
            cwd: repoRoot,
            model,
            maxTurns: 1,
            temperature: 0,
            allowedTools: [],
            permissionMode: "dontAsk",
            outputFormat: {
              type: "json_schema",
              schema: CALL_GRAPH_SCHEMA,
            },
          },
        })) {
          if (message.type === "result") {
            if (typeof message.totalCostUsd === "number") costUsd = message.totalCostUsd;
            if ("result" in message && typeof message.result === "string") resultText = message.result;
          }
        }

        totalCostUsd += normalizeCostUsd(costUsd);

        // Parse LLM response
        const paths = parseCallGraphResponse(resultText);
        for (const taintedPath of paths) {
          if (taintedPath.severity === "none") continue;
          discoveredPaths++;

          const taintPath: TaintPathStep[] = taintedPath.steps.map((step) => ({
            filePath: step.file || entry.filePath,
            line: step.line || 0,
            message: step.description,
          }));

          newFindings.push({
            scanner: "agentic",
            fingerprint: `lcg-${createHash("sha256").update(`${entry.filePath}:${entry.method}:${taintedPath.sinkType}:${taintedPath.steps.map((s) => s.function).join(">")}`).digest("hex").slice(0, 16)}`,
            ruleId: `call-graph-${taintedPath.sinkType}`,
            filePath: entry.filePath,
            startLine: entry.startLine || 1,
            severity: taintedPath.severity === "high" ? "ERROR" : "WARNING",
            message: taintedPath.description,
            evidence: `Entry point: ${entry.method} ${entry.path}\nSink: ${taintedPath.sinkType}\nCall chain: ${taintedPath.steps.map((s) => s.function).join(" -> ")}`,
            scannerConfidence: "HIGH",
            subcategory: [taintedPath.sinkType],
            likelihood: taintedPath.severity === "high" ? "high" : "medium",
            impact: taintedPath.severity === "high" ? "high" : "medium",
            cwe: taintedPath.cwe || [],
            score: taintedPath.severity === "high" ? 9 : 6,
            taintPath,
            engineProvenance: [{ kind: "agentic", detail: `llm-call-graph: traced from ${entry.method} ${entry.path}` }],
          });
        }
      } catch (error) {
        log.debug(`LLM call graph failed for ${entry.filePath}: ${toErrorMessage(error)}`);
      }
    }

    // Merge with existing findings, deduplicating by file+line+CWE
    const existingKeys = new Set(findings.map((f) => `${f.filePath}:${f.startLine}:${f.cwe.join(",")}`));
    const unique = newFindings.filter((f) => !existingKeys.has(`${f.filePath}:${f.startLine}:${f.cwe.join(",")}`));

    log.info(`LLM call graph: analyzed ${entryPoints.length} entry points, discovered ${discoveredPaths} tainted paths, ${unique.length} new findings`);

    return attachTaskOutputMeta(
      {
        findings: [...findings, ...unique],
        analyzedEntryPoints: entryPoints.length,
        discoveredPaths,
      },
      { costUsd: totalCostUsd },
    );
  },
};

function selectEntryPoints(routes: ApplicationRoute[]): ApplicationRoute[] {
  // Prioritize routes that handle user input (POST, PUT, PATCH) and auth-related routes
  const scored = routes.map((route) => {
    let score = 0;
    if (["POST", "PUT", "PATCH", "DELETE"].includes(route.method?.toUpperCase() ?? "")) score += 3;
    if (route.path?.includes("auth") || route.path?.includes("login") || route.path?.includes("admin")) score += 2;
    if (route.path?.includes("upload") || route.path?.includes("import") || route.path?.includes("exec")) score += 2;
    if (route.path?.includes("api")) score += 1;
    return { route, score };
  });

  return scored
    .sort((a, b) => b.score - a.score)
    .slice(0, MAX_ENTRY_POINTS)
    .map(({ route }) => route);
}

function extractHandlerName(route: ApplicationRoute): string | undefined {
  if (route.handlerSymbol && typeof route.handlerSymbol === "string") {
    return route.handlerSymbol;
  }
  return undefined;
}

async function readSourceSafe(filePath: string): Promise<string | undefined> {
  try {
    const content = await readFile(filePath, "utf-8");
    if (content.length > MAX_FILE_BYTES) {
      return content.slice(0, MAX_FILE_BYTES) + "\n// ... truncated";
    }
    return content;
  } catch {
    return undefined;
  }
}

interface TaintedPath {
  description: string;
  sinkType: string;
  severity: "high" | "medium" | "low" | "none";
  cwe: string[];
  steps: Array<{
    function: string;
    file?: string;
    line?: number;
    description: string;
  }>;
}

function parseCallGraphResponse(text: string): TaintedPath[] {
  try {
    const parsed = JSON.parse(text);
    if (Array.isArray(parsed?.taintedPaths)) {
      return parsed.taintedPaths.filter((p: unknown): p is TaintedPath =>
        typeof p === "object" && p !== null && "description" in p && "sinkType" in p,
      );
    }
    return [];
  } catch {
    // Try to extract JSON from markdown fence
    const match = text.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
    if (match) {
      try {
        const parsed = JSON.parse(match[1]);
        if (Array.isArray(parsed?.taintedPaths)) {
          return parsed.taintedPaths;
        }
      } catch { /* fall through */ }
    }
    return [];
  }
}

const CALL_GRAPH_SCHEMA = {
  type: "object" as const,
  properties: {
    taintedPaths: {
      type: "array" as const,
      items: {
        type: "object" as const,
        properties: {
          description: { type: "string" as const },
          sinkType: { type: "string" as const },
          severity: { type: "string" as const, enum: ["high", "medium", "low", "none"] },
          cwe: { type: "array" as const, items: { type: "string" as const } },
          steps: {
            type: "array" as const,
            items: {
              type: "object" as const,
              properties: {
                function: { type: "string" as const },
                file: { type: "string" as const },
                line: { type: "number" as const },
                description: { type: "string" as const },
              },
              required: ["function", "description"],
            },
          },
        },
        required: ["description", "sinkType", "severity", "steps"],
      },
    },
  },
  required: ["taintedPaths"],
};

function buildCallGraphPrompt(
  entry: ApplicationRoute,
  sourceContent: string,
  staticCallees: string[],
  calleeSnippets: string[],
  repoContext: unknown,
): string {
  const contextSection = repoContext && typeof repoContext === "object" && "languages" in repoContext
    ? `\nProject: ${(repoContext as Record<string, unknown>).languages ?? "unknown"} application\n`
    : "";

  return `You are a security researcher performing inter-procedural taint analysis.

Analyze this API endpoint for security vulnerabilities by tracing how user-controlled input flows through the call chain to security-sensitive sinks.
${contextSection}
## Entry Point
${entry.method?.toUpperCase() ?? "GET"} ${entry.path ?? "/unknown"}
File: ${entry.filePath}

## Source Code
\`\`\`
${sourceContent}
\`\`\`

${staticCallees.length > 0 ? `## Static Call Graph\nThis handler calls: ${staticCallees.join(", ")}\n` : ""}
${calleeSnippets.length > 0 ? `## Called Function Snippets\n${calleeSnippets.join("\n\n")}\n` : ""}

## Task
Trace user-controlled input from this entry point through the call chain. For each path where tainted data reaches a security-sensitive sink (SQL query, file system, command execution, crypto operation, authentication check, SSRF target, etc.) WITHOUT adequate sanitization, report it.

For each tainted path, provide:
- description: What the vulnerability is
- sinkType: Category (sql-injection, command-injection, ssrf, path-traversal, auth-bypass, crypto-misuse, etc.)
- severity: high/medium/low/none
- cwe: Applicable CWE IDs
- steps: The call chain from entry point to sink

If no tainted paths are found, return an empty array. Be precise — only report paths where tainted data actually reaches a sink without sanitization.`;
}
