import {
  antiHallucinationModule,
  frameworkAwarenessModule,
} from "../../prompts/modules.js";
import {
  languageTuningModule,
  languageInvestigationModule,
  languageAntiHallucinationExtras,
} from "../../prompts/language-tuning.js";
import { coerceRepoContext, coerceFileIndex } from "../../repo-context.js";
import { scoreFindingMetadata } from "../../scanners/scoring.js";
import type { Finding, TriageAgentConfig } from "../../scanners/types.js";
import { attachTaskOutputMeta } from "../../task-output-meta.js";
import type { FileIndex, RepoContext, ScanOpts } from "../../types.js";
import { isRecord, toErrorMessage } from "../../utils.js";
import { createLogger } from "../../logger.js";
import { getProfilesForTask, formatProfilesForPrompt } from "../../security-profiles.js";
import type { AgentTask, TaskContext } from "../types.js";
import { preReadFilesForTask, type PreReadResult } from "./pre-read.js";
import { formatFileTreeForPrompt, formatPreReadForPrompt, formatPatternMatchesForPrompt } from "./pre-read-prompt.js";
import { resolveTaskModel, resolveTaskPositiveInt, resolveTaskRuntime } from "./runtime-overrides.js";
import { buildThreatModelLeadsSection, resolveThreatModelOutput } from "./threat-model-guidance.js";
import { buildApplicationModelSection, buildThreatScenarioEvidenceSection } from "./scenario-guidance.js";
import { resolveTaskAllowedTools } from "./runtime-overrides.js";
import type { ApplicationModel } from "../../types.js";
import { normalizeFilePath, computeDetectionFingerprint, parseJson } from "./detection-task-utils.js";

const log = createLogger({ stage: "graphql-security" });

const GRAPHQL_SECURITY_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["findings"],
  properties: {
    findings: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["category", "filePath", "startLine", "severity", "description", "cwe", "confidence", "rationale"],
        properties: {
          category: { type: "string", enum: ["introspection-enabled", "nested-query-dos", "missing-auth-resolver", "batch-attack"] },
          filePath: { type: "string" },
          startLine: { type: "integer", minimum: 1 },
          severity: { type: "string", enum: ["ERROR", "WARNING", "INFO"] },
          description: { type: "string" },
          cwe: { type: "string" },
          confidence: { type: "string", enum: ["HIGH", "MEDIUM", "LOW"] },
          rationale: { type: "string" },
          apiOrFunction: { type: "string" },
          inputSource: { type: "string" },
        },
      },
    },
  },
} as const;

interface GraphqlSecurityFinding {
  category: string;
  filePath: string;
  startLine: number;
  severity: string;
  description: string;
  cwe: string;
  confidence: string;
  rationale: string;
  apiOrFunction?: string;
  inputSource?: string;
}

interface GraphqlSecurityConfig {
  model: string;
  maxFindings: number;
}

function resolveConfig(ctx: TaskContext): GraphqlSecurityConfig {
  const model = resolveTaskModel(ctx, "graphql-security");
  const maxFindings = resolveTaskPositiveInt(ctx, "graphql-security", "maxFindings", 50);
  return { model, maxFindings };
}

function buildPrompt(repoContext: RepoContext | undefined, maxFindings: number, profileLines: string[] = [], fileIndex?: FileIndex, preRead?: PreReadResult, threatModelContext?: string, appModelContext?: string, scenarioContext?: string): string {
  const patternMatchText = formatPatternMatchesForPrompt(fileIndex, ["eval-exec", "auth-session"]);

  const contextLines = repoContext
    ? [
        "## Repository context",
        `- Languages: ${repoContext.languages.join(", ") || "unknown"}`,
        `- Frameworks: ${repoContext.frameworks.join(", ") || "unknown"}`,
        `- Sanitization libs: ${repoContext.sanitizationLibs.join(", ") || "unknown"}`,
        "",
      ]
    : [];

  const frameworkGuidance = repoContext?.frameworks.length
    ? [
        "## Framework-specific guidance",
        "When analyzing GraphQL implementations, account for built-in protections:",
        "- Apollo Server v4: introspection disabled in production by default",
        "- Hasura: has built-in depth limiting and rate limiting configuration",
        "- graphql-shield: provides rule-based auth middleware for resolvers",
        "- graphql-depth-limit / graphql-query-complexity: dedicated depth/complexity limiting",
        "Do NOT flag implementations that use these protections correctly.",
        "",
      ]
    : [];

  return [
    "You are a senior application security engineer specializing in GraphQL API security.",
    "You have deep expertise in GraphQL attack vectors including introspection abuse,",
    "query complexity attacks, authorization bypasses, and batching exploits.",
    "",
    "Your task: systematically identify GraphQL security vulnerabilities in the repository's",
    "GraphQL server configuration, schema definitions, and resolver implementations.",
    "",
    ...contextLines,
    ...frameworkGuidance,
    ...(profileLines.length > 0 ? [...profileLines, ""] : []),
    ...(threatModelContext ? [threatModelContext, ""] : []),
    ...(appModelContext ? [appModelContext, ""] : []),
    ...(scenarioContext ? [scenarioContext, ""] : []),
    "## Categories to detect",
    "",
    languageTuningModule({ taskId: "graphql-security", repoContext, frameworks: repoContext?.frameworks }) ||
    "### introspection-enabled (CWE-200)",
    "GraphQL introspection queries enabled in production environments. Introspection exposes",
    "the entire schema including types, fields, queries, mutations, and subscriptions.",
    "Check for:",
    "- Apollo Server without `introspection: false` in production config",
    "- Express-graphql with graphiql: true in production",
    "- Yoga/Mercurius/Helix without introspection disabled",
    "- Missing environment-based introspection toggle",
    "Only flag when introspection is clearly enabled in production configuration.",
    "",
    "### nested-query-dos (CWE-400)",
    "Missing query depth or complexity limiting that allows deeply nested queries to cause DoS.",
    "A query like `{ user { friends { friends { friends { ... } } } } }` can exponentially",
    "increase database load. Check for:",
    "- No graphql-depth-limit or equivalent middleware",
    "- No graphql-query-complexity or cost analysis plugin",
    "- No persisted queries / query allowlisting in production",
    "- Self-referential types without depth protection",
    "Only flag when recursive/self-referential types exist AND no depth/complexity limiting is configured.",
    "",
    "### missing-auth-resolver (CWE-862)",
    "GraphQL resolvers that access sensitive data or perform mutations without authentication",
    "or authorization checks. Check for:",
    "- Resolvers returning user data without checking auth context",
    "- Mutation resolvers without permission checks",
    "- Missing graphql-shield rules or @auth directives",
    "- Subscription resolvers without connection auth",
    "Only flag resolvers that handle sensitive operations without any auth middleware or context checks.",
    "",
    "### batch-attack (CWE-799)",
    "GraphQL batch queries or alias attacks without rate limiting. An attacker can send",
    "multiple operations in a single request to bypass per-request rate limits. Check for:",
    "- No limit on query aliases (e.g., `{ a1: login(...), a2: login(...), ... }`)",
    "- Batch query support without per-operation rate limiting",
    "- Missing dataloader or N+1 protection combined with batch access",
    "Only flag when batch/alias queries are possible AND no per-operation rate limiting exists.",
    "",
    formatFileTreeForPrompt(fileIndex, patternMatchText.length > 0),
    formatPreReadForPrompt(preRead ?? { files: [], totalBytes: 0, truncated: false }),
    patternMatchText,
    "## Investigation methodology",
    ...(preRead && preRead.files.length > 0
      ? [
          "1. Start by analyzing the pre-loaded files above for GraphQL security issues.",
          "2. Use Glob/Grep only for additional files not already provided.",
          "3. Use Read to inspect additional GraphQL configuration and resolver files.",
          "4. Check for depth-limit, query-complexity, or rate-limiting middleware.",
          "5. Inspect schema definitions for self-referential types.",
        ]
      : [
          "1. Use Grep to find GraphQL server setup (ApolloServer, express-graphql, graphql-yoga,",
          "   Mercurius, type-graphql, @nestjs/graphql).",
          "2. Use Read to inspect server configuration for introspection settings and middleware.",
          "3. Use Grep to find resolver definitions and check for auth context usage.",
          "4. Use Grep to find depth-limit, query-complexity, or rate-limiting middleware.",
          "5. Use Read to inspect schema definitions for self-referential types.",
        ]),
    `6. Return at most ${maxFindings} findings, prioritized by severity.`,
    "",
    antiHallucinationModule({
      extra: [
        "Only report GraphQL security issues you can verify from actual code.",
        "Do NOT flag development-only GraphQL configurations (check NODE_ENV/environment toggles).",
        "Do NOT flag resolvers that correctly check authentication context.",
        "Confidence HIGH only if the misconfiguration or missing protection is clearly verified.",
        ...languageAntiHallucinationExtras({ taskId: "graphql-security", repoContext, frameworks: repoContext?.frameworks }),
      ],
    }),
    frameworkAwarenessModule(repoContext),
    "",
    `Return at most ${maxFindings} findings, prioritized by severity and confidence.`,
    "Filter out any finding where your confidence would be below MEDIUM.",
  ].filter(Boolean).join("\n");
}

function normalizeFindings(raw: unknown, repoRoot: string, repoName: string, maxFindings: number): Finding[] {
  if (!isRecord(raw) || !Array.isArray(raw["findings"])) return [];

  const deduped = new Map<string, Finding>();
  for (const item of raw["findings"] as unknown[]) {
    if (!isRecord(item)) continue;
    const f = item as unknown as GraphqlSecurityFinding;
    if (!f.filePath?.trim()) continue;

    const filePath = normalizeFilePath(repoRoot, f.filePath);
    const cweList = f.cwe ? [f.cwe] : [];
    const fingerprint = computeFingerprint(repoName, filePath, f);

    const apiInfo = f.apiOrFunction ? ` [${f.apiOrFunction}]` : "";

    const finding: Finding = {
      taskId: "graphql-security-detect",
      fingerprint,
      ruleId: `graphql-security/${f.category || "unknown"}`,
      filePath,
      startLine: Math.max(1, Math.floor(Number(f.startLine) || 1)),
      severity: f.severity || "WARNING",
      message: `${f.description || "GraphQL security issue"}${apiInfo}`,
      evidence: f.rationale || null,
      scannerConfidence: f.confidence || "MEDIUM",
      subcategory: ["vuln"],
      likelihood: f.confidence || "MEDIUM",
      impact: f.severity === "ERROR" ? "HIGH" : f.severity === "INFO" ? "LOW" : "MEDIUM",
      cwe: cweList,
      score: scoreFindingMetadata({
        severity: f.severity,
        likelihood: f.confidence,
        impact: f.severity === "ERROR" ? "HIGH" : f.severity === "INFO" ? "LOW" : "MEDIUM",
        subcategory: ["vuln"],
        cwe: cweList,
      }),
      proofState: "symbolic_only",
      engineProvenance: [{ kind: "agentic", detail: "LLM-driven graphql-security-detect analysis" }],
    };

    const existing = deduped.get(fingerprint);
    if (!existing || finding.score > existing.score) {
      deduped.set(fingerprint, finding);
    }
  }

  return [...deduped.values()]
    .sort((a, b) => b.score - a.score)
    .slice(0, maxFindings);
}

function computeFingerprint(repoName: string, filePath: string, f: GraphqlSecurityFinding): string {
  return computeDetectionFingerprint([repoName, "graphql-security", f.category, filePath, String(f.startLine)]);
}

export const graphqlSecurityTask: AgentTask<ScanOpts, Finding[]> = {
  id: "graphql-security-detect",
  displayName: "GraphQL Security Detector",
  outputKind: "findings",
  dependsOn: ["context-gatherer", "app-model-build", "threat-scenario-build"],

  async run(_input, context): Promise<Finding[]> {
    const { model, maxFindings } = resolveConfig(context);
    const repoContext = coerceRepoContext(context.upstreamOutputs.get("context-gatherer"));
    const fileIndex = coerceFileIndex(context.upstreamOutputs.get("context-gatherer"));
    const preRead = await preReadFilesForTask("graphql-security-detect", fileIndex, context.repoRoot);
    const profiles = context.securityProfiles
      ? getProfilesForTask(context.securityProfiles, "graphql-security-detect")
      : [];
    const profileLines = formatProfilesForPrompt(profiles);
    const threatModelContext = buildThreatModelLeadsSection(
      "graphql-security-detect",
      resolveThreatModelOutput(context.upstreamOutputs),
      fileIndex,
      preRead,
    );
    const applicationModel = context.upstreamOutputs.get("app-model-build") as ApplicationModel | undefined;
    const scenarioOutput = context.upstreamOutputs.get("threat-scenario-build");
    const appModelContext = buildApplicationModelSection("graphql-security-detect", applicationModel);
    const scenarioContext = await buildThreatScenarioEvidenceSection("graphql-security-detect", context.repoRoot, applicationModel, scenarioOutput);
    const prompt = buildPrompt(repoContext, maxFindings, profileLines, fileIndex, preRead, threatModelContext, appModelContext, scenarioContext);
    const runtime = resolveTaskRuntime(context);

    let structuredOutput: unknown;
    let resultText = "";
    let costUsd = 0;

    const tag = "[graphql-security]";
    log.info(`Starting scan (model=${model})`);

    try {
      for await (const message of runtime.query({
        prompt,
        options: {
          cwd: context.repoRoot,
          model,

          allowedTools: resolveTaskAllowedTools(context),
          permissionMode: "dontAsk",
          outputFormat: {
            type: "json_schema",
            schema: GRAPHQL_SECURITY_SCHEMA,
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

    return attachTaskOutputMeta(
      normalizeFindings(
        structuredOutput ?? parseJson(resultText, tag),
        context.repoRoot,
        context.repoName,
        maxFindings,
      ),
      { costUsd },
    );
  },

  triageAgentConfig(finding: Finding, repoName: string): TriageAgentConfig {
    return {
      prompt: [
        `You are triaging a GraphQL security finding in "${repoName}".`,
        "",
        `Rule: ${finding.ruleId}`,
        `File: ${finding.filePath}:${finding.startLine}`,
        `Message: ${finding.message}`,
        finding.evidence ? `Rationale: ${finding.evidence}` : "",
        "",
        "Verify:",
        "1. The GraphQL configuration or resolver actually exists at the reported location.",
        "2. The security issue is present in production (not just development mode).",
        "3. No middleware, plugins, or configuration mitigates the reported vulnerability.",
      ].filter(Boolean).join("\n"),
    };
  },
};

export const __graphqlSecurityInternals = {
  resolveConfig,
  buildPrompt,
  normalizeFindings,
  computeFingerprint,
};
