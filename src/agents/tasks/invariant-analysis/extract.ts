import { getAgentRuntime } from "../../../agent-runtime/index.js";
import type { ScanOpts, RepoContext } from "../../../types.js";
import { isRecord, toErrorMessage } from "../../../utils.js";
import type { AgentTask, TaskContext } from "../../types.js";
import {
  resolveInvariantAnalysisConfig,
  INVARIANT_EXTRACT_SCHEMA,
  type Invariant,
  type InvariantDocument,
  type InvariantKind,
} from "./types.js";

const VALID_KINDS = new Set<InvariantKind>([
  "precondition", "postcondition", "class-invariant",
  "loop-invariant", "data-invariant", "security-invariant",
]);

const VALID_RELEVANCE = new Set(["high", "medium", "low", "none"]);

function buildExtractionPrompt(repoContext: RepoContext | undefined, securityOnly: boolean, maxInvariants: number): string {
  const contextLines = repoContext
    ? [
        "## Repository context",
        `- Languages: ${repoContext.languages.join(", ") || "unknown"}`,
        `- Frameworks: ${repoContext.frameworks.join(", ") || "unknown"}`,
        `- Auth patterns: ${repoContext.authPatterns.join(", ") || "unknown"}`,
        `- Entry points: ${repoContext.entryPoints.join(", ") || "unknown"}`,
        "",
      ]
    : [];

  return [
    "You are an invariant extraction agent.",
    "Analyze the codebase and infer invariants — conditions that must always hold for correct and secure behavior.",
    "",
    ...contextLines,
    "## What to look for",
    "- Assert statements and guard clauses",
    "- Type annotations and contracts",
    "- Middleware chains (auth required, rate limiting)",
    "- Error handling patterns (what conditions trigger errors)",
    "- API contracts (request/response schemas)",
    "- Database constraints (NOT NULL, UNIQUE, CHECK)",
    "- Comments and documentation stating requirements",
    "",
    securityOnly
      ? "Focus on security-relevant invariants: authentication checks, authorization guards, input validation, output encoding, cryptographic requirements."
      : "Extract all invariants, including functional correctness invariants.",
    "",
    "## Instructions",
    "1. Use Glob to discover security-critical files (auth middleware, route handlers, data access layers).",
    "2. Use Read to analyze each file and infer invariants.",
    "3. For each invariant, specify the exact scope (file, lines, function), a human-readable statement, and confidence.",
    `4. Return at most ${maxInvariants} invariants, prioritized by security relevance.`,
    "",
    "Each invariant needs a unique id like 'inv-1', 'inv-2', etc.",
  ].join("\n");
}

function parseInvariants(raw: unknown, securityOnly: boolean, maxInvariants: number): Invariant[] {
  if (!isRecord(raw) || !Array.isArray(raw["invariants"])) return [];

  const invariants: Invariant[] = [];
  for (const item of raw["invariants"] as unknown[]) {
    if (!isRecord(item)) continue;
    const inv = normalizeInvariant(item);
    if (!inv) continue;
    if (securityOnly && inv.securityRelevance === "none") continue;
    invariants.push(inv);
  }

  return invariants.slice(0, maxInvariants);
}

function normalizeInvariant(item: Record<string, unknown>): Invariant | null {
  const id = typeof item["id"] === "string" ? item["id"].trim() : "";
  const kind = typeof item["kind"] === "string" && VALID_KINDS.has(item["kind"] as InvariantKind)
    ? (item["kind"] as InvariantKind) : "security-invariant";
  const filePath = typeof item["filePath"] === "string" ? item["filePath"].trim() : "";
  const statement = typeof item["statement"] === "string" ? item["statement"].trim() : "";
  const derivedFrom = typeof item["derivedFrom"] === "string" ? item["derivedFrom"].trim() : "";

  if (!id || !filePath || !statement) return null;

  const startLine = Math.max(1, Math.floor(Number(item["startLine"]) || 1));
  const endLine = Math.max(startLine, Math.floor(Number(item["endLine"]) || startLine));
  const confidence = normalizeUnitNumber(item["confidence"]);
  const securityRelevance = typeof item["securityRelevance"] === "string" && VALID_RELEVANCE.has(item["securityRelevance"])
    ? (item["securityRelevance"] as Invariant["securityRelevance"]) : "low";

  return {
    id,
    kind,
    scope: {
      filePath,
      startLine,
      endLine,
      functionName: typeof item["functionName"] === "string" ? item["functionName"].trim() || undefined : undefined,
      className: typeof item["className"] === "string" ? item["className"].trim() || undefined : undefined,
    },
    statement,
    formalExpression: typeof item["formalExpression"] === "string" ? item["formalExpression"].trim() || undefined : undefined,
    confidence,
    derivedFrom: derivedFrom || "code analysis",
    securityRelevance,
    category: typeof item["category"] === "string" ? item["category"].trim() || undefined : undefined,
  };
}

function normalizeUnitNumber(value: unknown): number {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return 0;
  return Math.max(0, Math.min(1, numeric));
}

export const invariantExtractTask: AgentTask<ScanOpts, InvariantDocument> = {
  id: "invariant-extract",
  displayName: "Invariant Extraction",
  outputKind: "custom",
  dependsOn: ["context-gatherer"],

  async run(_input, context): Promise<InvariantDocument> {
    const cfg = resolveInvariantAnalysisConfig(context.config);
    const repoContext = context.upstreamOutputs.get("context-gatherer") as RepoContext | undefined;
    const prompt = buildExtractionPrompt(repoContext, cfg.securityOnly, cfg.maxInvariants);
    const runtime = getAgentRuntime();

    let structuredOutput: unknown;
    let resultText = "";

    const tag = "[invariant-extract]";
    console.error(`${tag} Starting extraction (model=${cfg.extractionModel})`);

    try {
      for await (const message of runtime.query({
        prompt,
        options: {
          cwd: context.repoRoot,
          model: cfg.extractionModel,
          allowedTools: ["Read", "Glob", "Grep"],
          permissionMode: "dontAsk",
          outputFormat: {
            type: "json_schema",
            schema: INVARIANT_EXTRACT_SCHEMA,
          },
        },
      })) {
        if (message.type !== "result") continue;
        if ("result" in message) {
          resultText = message.result;
          structuredOutput = message.structuredOutput;
        }
      }
    } catch (error) {
      console.error(`${tag} Error: ${toErrorMessage(error)}`);
      return { version: "1.0", invariants: [], coverage: { filesAnalyzed: 0, functionsAnalyzed: 0, invariantsFound: 0 } };
    }

    const parsed = structuredOutput ?? parseJson(resultText);
    const invariants = parseInvariants(parsed, cfg.securityOnly, cfg.maxInvariants);

    console.error(`${tag} Extracted ${invariants.length} invariants`);

    return {
      version: "1.0",
      invariants,
      coverage: {
        filesAnalyzed: new Set(invariants.map((inv) => inv.scope.filePath)).size,
        functionsAnalyzed: new Set(invariants.filter((inv) => inv.scope.functionName).map((inv) => `${inv.scope.filePath}:${inv.scope.functionName}`)).size,
        invariantsFound: invariants.length,
      },
    };
  },
};

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return { invariants: [] };
  }
}

export const __invariantExtractInternals = {
  buildExtractionPrompt,
  parseInvariants,
  normalizeInvariant,
};
