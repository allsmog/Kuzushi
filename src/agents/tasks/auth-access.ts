import { createHash } from "node:crypto";
import path from "node:path";
import { getAgentRuntime } from "../../agent-runtime/index.js";
import { scoreFindingMetadata } from "../../scanners/scoring.js";
import type { Finding, TriageAgentConfig } from "../../scanners/types.js";
import type { RepoContext, ScanOpts } from "../../types.js";
import { isRecord, toErrorMessage } from "../../utils.js";
import type { AgentTask, TaskContext } from "../types.js";

const AUTH_ACCESS_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["findings"],
  properties: {
    findings: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["pattern", "filePath", "startLine", "severity", "description", "cwe", "confidence", "rationale"],
        properties: {
          pattern: { type: "string", enum: ["unprotected-endpoint", "missing-role-check", "idor", "default-credentials"] },
          filePath: { type: "string" },
          startLine: { type: "integer", minimum: 1 },
          severity: { type: "string", enum: ["ERROR", "WARNING", "INFO"] },
          description: { type: "string" },
          cwe: { type: "string" },
          confidence: { type: "string", enum: ["HIGH", "MEDIUM", "LOW"] },
          rationale: { type: "string" },
          endpoint: { type: "string" },
          httpMethod: { type: "string" },
        },
      },
    },
  },
} as const;

interface AuthAccessFinding {
  pattern: string;
  filePath: string;
  startLine: number;
  severity: string;
  description: string;
  cwe: string;
  confidence: string;
  rationale: string;
  endpoint?: string;
  httpMethod?: string;
}

interface AuthAccessConfig {
  model: string;
  maxFindings: number;
}

function resolveConfig(ctx: TaskContext): AuthAccessConfig {
  const raw = ctx.config.scannerConfig["auth-access"];
  const model = (isRecord(raw) && typeof raw["model"] === "string" && raw["model"].trim())
    ? raw["model"].trim()
    : ctx.config.model;
  const maxFindings = (isRecord(raw) && typeof raw["maxFindings"] === "number" && raw["maxFindings"] >= 1)
    ? Math.floor(raw["maxFindings"])
    : 50;
  return { model, maxFindings };
}

function buildPrompt(repoContext: RepoContext | undefined, maxFindings: number): string {
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
    "You are an authentication and access control analysis agent.",
    "Analyze the repository for auth/access control vulnerabilities using a two-phase approach.",
    "",
    ...contextLines,
    "## Phase 1: Map auth architecture",
    "Use Glob to find middleware, decorators, guards, and auth-related files.",
    "Identify the auth patterns used (JWT, session, OAuth, etc.).",
    "Build a mental model of which routes are protected and how.",
    "",
    "## Phase 2: Find violations",
    "Use Glob to find all route handlers and API endpoints.",
    "Check if auth middleware is applied consistently.",
    "Flag gaps and inconsistencies.",
    "",
    "## Patterns to detect",
    "",
    "### unprotected-endpoint (CWE-862)",
    "State-changing endpoint (POST/PUT/DELETE) without auth middleware.",
    "",
    "### missing-role-check (CWE-863)",
    "Admin/privileged endpoint accessible to regular users.",
    "",
    "### idor (CWE-639)",
    "Resource access using user-supplied ID without ownership validation.",
    "",
    "### default-credentials (CWE-798)",
    "Hardcoded passwords in seed/migration/config files.",
    "",
    `Return at most ${maxFindings} findings, prioritized by severity.`,
    "Only report concrete issues with evidence in code.",
  ].join("\n");
}

function normalizeFindings(raw: unknown, repoRoot: string, repoName: string, maxFindings: number): Finding[] {
  if (!isRecord(raw) || !Array.isArray(raw["findings"])) return [];

  const deduped = new Map<string, Finding>();
  for (const item of raw["findings"] as unknown[]) {
    if (!isRecord(item)) continue;
    const f = item as unknown as AuthAccessFinding;
    if (!f.filePath?.trim()) continue;

    const filePath = normalizeFilePath(repoRoot, f.filePath);
    const cweList = f.cwe ? [f.cwe] : [];
    const fingerprint = computeFingerprint(repoName, filePath, f);

    const endpointInfo = f.endpoint
      ? ` (${f.httpMethod ?? "?"} ${f.endpoint})`
      : "";

    const finding: Finding = {
      scanner: "auth-access-detect",
      fingerprint,
      ruleId: `auth-access/${f.pattern || "unknown"}`,
      filePath,
      startLine: Math.max(1, Math.floor(Number(f.startLine) || 1)),
      severity: f.severity || "WARNING",
      message: `${f.description || "Auth/access control issue"}${endpointInfo}`,
      evidence: f.rationale || null,
      scannerConfidence: f.confidence || "MEDIUM",
      subcategory: ["vuln"],
      likelihood: f.confidence || "MEDIUM",
      impact: f.severity === "ERROR" ? "HIGH" : "MEDIUM",
      cwe: cweList,
      score: scoreFindingMetadata({
        severity: f.severity,
        likelihood: f.confidence,
        impact: f.severity === "ERROR" ? "HIGH" : "MEDIUM",
        subcategory: ["vuln"],
      }),
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

function computeFingerprint(repoName: string, filePath: string, f: AuthAccessFinding): string {
  const source = [repoName, "auth-access", f.pattern, filePath, String(f.startLine)].join("|");
  return createHash("sha256").update(source).digest("hex");
}

function normalizeFilePath(repoRoot: string, filePath: string): string {
  if (!path.isAbsolute(filePath)) return filePath;
  const relative = path.relative(repoRoot, filePath);
  if (relative.startsWith("..")) return filePath;
  return relative || filePath;
}

export const authAccessTask: AgentTask<ScanOpts, Finding[]> = {
  id: "auth-access-detect",
  displayName: "Auth/Access Control Analyzer",
  outputKind: "findings",
  dependsOn: ["context-gatherer"],

  async run(_input, context): Promise<Finding[]> {
    const { model, maxFindings } = resolveConfig(context);
    const repoContext = context.upstreamOutputs.get("context-gatherer") as RepoContext | undefined;
    const prompt = buildPrompt(repoContext, maxFindings);
    const runtime = getAgentRuntime();

    let structuredOutput: unknown;
    let resultText = "";

    const tag = "[auth-access]";
    console.error(`${tag} Starting scan (model=${model})`);

    try {
      for await (const message of runtime.query({
        prompt,
        options: {
          cwd: context.repoRoot,
          model,
          allowedTools: ["Read", "Glob", "Grep"],
          permissionMode: "dontAsk",
          outputFormat: {
            type: "json_schema",
            schema: AUTH_ACCESS_SCHEMA,
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
      return [];
    }

    return normalizeFindings(
      structuredOutput ?? parseJson(resultText),
      context.repoRoot,
      context.repoName,
      maxFindings,
    );
  },

  triageAgentConfig(finding: Finding, repoName: string): TriageAgentConfig {
    return {
      prompt: [
        `You are triaging an auth/access control finding in "${repoName}".`,
        "",
        `Rule: ${finding.ruleId}`,
        `File: ${finding.filePath}:${finding.startLine}`,
        `Message: ${finding.message}`,
        finding.evidence ? `Rationale: ${finding.evidence}` : "",
        "",
        "Verify the endpoint is truly unprotected or the access control is genuinely missing.",
        "Check for middleware applied at router/app level that might not be visible at the handler.",
      ].filter(Boolean).join("\n"),
    };
  },
};

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return { findings: [] };
  }
}

export const __authAccessInternals = {
  resolveConfig,
  buildPrompt,
  normalizeFindings,
  computeFingerprint,
};
