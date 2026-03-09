import { createHash } from "node:crypto";
import path from "node:path";
import { getAgentRuntime } from "../../agent-runtime/index.js";
import { coerceRepoContext } from "../../repo-context.js";
import { scoreFindingMetadata } from "../../scanners/scoring.js";
import type { Finding, TriageAgentConfig } from "../../scanners/types.js";
import { attachTaskOutputMeta } from "../../task-output-meta.js";
import type { RepoContext, ScanOpts } from "../../types.js";
import { isRecord, toErrorMessage } from "../../utils.js";
import { getProfilesForTask, formatProfilesForPrompt } from "../../security-profiles.js";
import type { AgentTask, TaskContext } from "../types.js";

const SECURITY_MISCONFIG_SCHEMA = {
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
          category: { type: "string", enum: ["debug-mode", "missing-headers", "insecure-cors", "insecure-cookies", "default-credentials", "exposed-admin", "verbose-errors"] },
          filePath: { type: "string" },
          startLine: { type: "integer", minimum: 1 },
          severity: { type: "string", enum: ["ERROR", "WARNING", "INFO"] },
          description: { type: "string" },
          cwe: { type: "string" },
          confidence: { type: "string", enum: ["HIGH", "MEDIUM", "LOW"] },
          rationale: { type: "string" },
        },
      },
    },
  },
} as const;

interface SecurityMisconfigFinding {
  category: string;
  filePath: string;
  startLine: number;
  severity: string;
  description: string;
  cwe: string;
  confidence: string;
  rationale: string;
}

interface SecurityMisconfigConfig {
  model: string;
  maxFindings: number;
}

function resolveConfig(ctx: TaskContext): SecurityMisconfigConfig {
  const raw = ctx.config.scannerConfig["security-misconfig-detect"];
  const model = (isRecord(raw) && typeof raw["model"] === "string" && raw["model"].trim())
    ? raw["model"].trim()
    : ctx.config.model;
  const maxFindings = (isRecord(raw) && typeof raw["maxFindings"] === "number" && raw["maxFindings"] >= 1)
    ? Math.floor(raw["maxFindings"])
    : 50;
  return { model, maxFindings };
}

function buildPrompt(repoContext: RepoContext | undefined, maxFindings: number, profileLines: string[] = []): string {
  const contextLines = repoContext
    ? [
        "## Repository context",
        `- Languages: ${repoContext.languages.join(", ") || "unknown"}`,
        `- Frameworks: ${repoContext.frameworks.join(", ") || "unknown"}`,
        "",
      ]
    : [];

  return [
    "You are a security hardening specialist with deep expertise in application security configuration.",
    "You have reviewed hundreds of production deployments for misconfigurations and know the difference",
    "between development convenience settings and genuine security risks.",
    "",
    "Analyze the repository for security misconfigurations. Only report findings where you",
    "have HIGH or MEDIUM confidence the misconfiguration is genuinely risky — not merely suboptimal.",
    "",
    ...contextLines,
    ...(profileLines.length > 0 ? [...profileLines, ""] : []),
    "## Categories to check",
    "",
    "### debug-mode (CWE-489)",
    "Bad: DEBUG=True in production Django, Flask debug=True, Express morgan dev mode in production.",
    "Check for debug flags in config files, environment defaults, and application entry points.",
    "",
    "### missing-headers (CWE-16)",
    "Bad: Missing Content-Security-Policy, Strict-Transport-Security (HSTS), X-Frame-Options,",
    "X-Content-Type-Options headers in HTTP responses. Check middleware, server config, meta tags.",
    "",
    "### insecure-cors (CWE-942)",
    "Bad: CORS with `*` origin combined with credentials, overly permissive Access-Control-Allow-Origin,",
    "reflecting arbitrary Origin headers without validation.",
    "",
    "### insecure-cookies (CWE-614)",
    "Bad: Missing Secure flag on session cookies, missing HttpOnly flag, missing SameSite attribute.",
    "Check cookie configuration in session middleware and auth code.",
    "",
    "### default-credentials (CWE-798)",
    "Bad: Default admin passwords, hardcoded database credentials used in non-test code,",
    "default API keys shipped in configuration.",
    "",
    "### exposed-admin (CWE-200)",
    "Bad: Admin panels accessible without authentication, /admin routes without auth middleware,",
    "debug endpoints (/__debug__, /phpinfo, /server-status) exposed.",
    "",
    "### verbose-errors (CWE-209)",
    "Bad: Stack traces returned in HTTP responses, detailed error messages with internal paths,",
    "database error details exposed to users.",
    "",
    "## Instructions",
    "1. Use Glob to find config files, middleware, server setup, and route definitions.",
    "2. Use Read to inspect configuration and middleware chain.",
    "3. Use Grep to search for debug flags, CORS config, cookie settings, and error handlers.",
    `4. Return at most ${maxFindings} findings, prioritized by severity.`,
    "",
    "## Anti-hallucination constraints",
    "- Only report misconfigurations you can verify in code. Do not assume defaults.",
    "- Do NOT infer or speculate about code you haven't read.",
    "- Account for framework defaults that may provide secure configuration automatically.",
    "- Confidence must reflect your actual certainty: HIGH only if misconfiguration is unambiguous.",
    repoContext?.frameworks.length
      ? `- Account for framework defaults: ${repoContext.frameworks.join(", ")} may provide secure defaults.`
      : "",
  ].filter(Boolean).join("\n");
}

function normalizeFindings(raw: unknown, repoRoot: string, repoName: string, maxFindings: number): Finding[] {
  if (!isRecord(raw) || !Array.isArray(raw["findings"])) return [];

  const deduped = new Map<string, Finding>();
  for (const item of raw["findings"] as unknown[]) {
    if (!isRecord(item)) continue;
    const f = item as unknown as SecurityMisconfigFinding;
    if (!f.filePath?.trim()) continue;

    const filePath = normalizeFilePath(repoRoot, f.filePath);
    const cweList = f.cwe ? [f.cwe] : [];
    const fingerprint = computeFingerprint(repoName, filePath, f);

    const finding: Finding = {
      scanner: "security-misconfig-detect",
      fingerprint,
      ruleId: `security-misconfig/${f.category || "unknown"}`,
      filePath,
      startLine: Math.max(1, Math.floor(Number(f.startLine) || 1)),
      severity: f.severity || "WARNING",
      message: `${f.description || "Security misconfiguration detected"}`,
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

function computeFingerprint(repoName: string, filePath: string, f: SecurityMisconfigFinding): string {
  const source = [repoName, "security-misconfig", f.category, filePath, String(f.startLine)].join("|");
  return createHash("sha256").update(source).digest("hex");
}

function normalizeFilePath(repoRoot: string, filePath: string): string {
  if (!path.isAbsolute(filePath)) return filePath;
  const relative = path.relative(repoRoot, filePath);
  if (relative.startsWith("..")) return filePath;
  return relative || filePath;
}

export const securityMisconfigTask: AgentTask<ScanOpts, Finding[]> = {
  id: "security-misconfig-detect",
  displayName: "Security Misconfiguration Detector",
  outputKind: "findings",
  dependsOn: ["context-gatherer"],

  async run(_input, context): Promise<Finding[]> {
    const { model, maxFindings } = resolveConfig(context);
    const repoContext = coerceRepoContext(context.upstreamOutputs.get("context-gatherer"));
    const profiles = context.securityProfiles
      ? getProfilesForTask(context.securityProfiles, "security-misconfig-detect")
      : [];
    const profileLines = formatProfilesForPrompt(profiles);
    const prompt = buildPrompt(repoContext, maxFindings, profileLines);
    const runtime = getAgentRuntime();

    let structuredOutput: unknown;
    let resultText = "";
    let costUsd = 0;

    const tag = "[security-misconfig]";
    console.error(`${tag} Starting scan (model=${model})`);

    try {
      for await (const message of runtime.query({
        prompt,
        options: {
          cwd: context.repoRoot,
          model,
          maxTurns: undefined,
          allowedTools: ["Read", "Glob", "Grep"],
          permissionMode: "dontAsk",
          outputFormat: {
            type: "json_schema",
            schema: SECURITY_MISCONFIG_SCHEMA,
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
        `You are triaging a security misconfiguration finding in "${repoName}".`,
        "",
        `Rule: ${finding.ruleId}`,
        `File: ${finding.filePath}:${finding.startLine}`,
        `Message: ${finding.message}`,
        finding.evidence ? `Rationale: ${finding.evidence}` : "",
        "",
        "Verify the misconfiguration is genuine and affects production environments.",
        "Check if there are compensating controls or if the setting only applies to development.",
      ].filter(Boolean).join("\n"),
    };
  },
};

function parseJson(text: string, tag: string): unknown {
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new Error(`${tag} Invalid JSON output: ${toErrorMessage(error)}`);
  }
}

export const __securityMisconfigInternals = {
  resolveConfig,
  buildPrompt,
  normalizeFindings,
  computeFingerprint,
};
