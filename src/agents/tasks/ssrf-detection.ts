import { createHash } from "node:crypto";
import path from "node:path";
import { getAgentRuntime } from "../../agent-runtime/index.js";
import {
  antiHallucinationModule,
  frameworkAwarenessModule,
} from "../../prompts/modules.js";
import { coerceRepoContext } from "../../repo-context.js";
import { scoreFindingMetadata } from "../../scanners/scoring.js";
import type { Finding, TriageAgentConfig } from "../../scanners/types.js";
import { attachTaskOutputMeta } from "../../task-output-meta.js";
import type { RepoContext, ScanOpts } from "../../types.js";
import { isRecord, toErrorMessage } from "../../utils.js";
import { createLogger } from "../../logger.js";
import { getProfilesForTask, formatProfilesForPrompt } from "../../security-profiles.js";
import type { AgentTask, TaskContext } from "../types.js";

const log = createLogger({ stage: "ssrf-detect" });

const SSRF_DETECTION_SCHEMA = {
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
          category: { type: "string", enum: ["url-from-user-input", "missing-allowlist", "redirect-following", "internal-service-url", "cloud-metadata", "scheme-confusion", "websocket-ssrf"] },
          filePath: { type: "string" },
          startLine: { type: "integer", minimum: 1 },
          severity: { type: "string", enum: ["ERROR", "WARNING", "INFO"] },
          description: { type: "string" },
          cwe: { type: "string" },
          confidence: { type: "string", enum: ["HIGH", "MEDIUM", "LOW"] },
          rationale: { type: "string" },
          sinkFunction: { type: "string" },
          inputSource: { type: "string" },
        },
      },
    },
  },
} as const;

interface SsrfDetectionFinding {
  category: string;
  filePath: string;
  startLine: number;
  severity: string;
  description: string;
  cwe: string;
  confidence: string;
  rationale: string;
  sinkFunction?: string;
  inputSource?: string;
}

interface SsrfDetectionConfig {
  model: string;
  maxFindings: number;
}

function resolveConfig(ctx: TaskContext): SsrfDetectionConfig {
  const raw = ctx.config.scannerConfig["ssrf-detect"];
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
    "You are an SSRF (Server-Side Request Forgery) specialist with deep expertise in identifying",
    "and exploiting SSRF vulnerabilities. You are familiar with WooYun bypass techniques, DNS rebinding,",
    "and URL parser inconsistencies used in real-world attacks.",
    "",
    "Analyze the repository for SSRF vulnerabilities. Only report findings where you",
    "have HIGH or MEDIUM confidence the vulnerability is exploitable — not merely theoretical.",
    "",
    ...contextLines,
    ...(profileLines.length > 0 ? [...profileLines, ""] : []),
    "## Categories to check",
    "",
    "### url-from-user-input (CWE-918)",
    "User-controlled URLs passed to HTTP client functions without validation.",
    "Sink functions: fetch, axios, http.get, urllib, HttpClient, requests.get, http.request.",
    "Check if URL/host/path components come from request parameters, headers, or body.",
    "",
    "### missing-allowlist (CWE-918)",
    "HTTP requests to user-controlled destinations without domain/IP allowlist validation.",
    "Look for URL fetching code that lacks hostname validation against an allowlist.",
    "",
    "### redirect-following (CWE-918)",
    "HTTP clients configured to follow redirects with user-controlled initial URLs.",
    "Redirects can bypass hostname validation by first hitting an allowed domain.",
    "",
    "### internal-service-url (CWE-918)",
    "Requests to internal services (localhost, 127.0.0.1, 169.254.169.254, internal hostnames)",
    "constructed from user input.",
    "",
    "### cloud-metadata (CWE-918)",
    "Requests that can reach cloud metadata endpoints:",
    "- AWS IMDSv1: `http://169.254.169.254/latest/meta-data/` (no auth required)",
    "- AWS IMDSv2: Check if PUT for token + GET with token header are both reachable",
    "- GCP: `http://metadata.google.internal/computeMetadata/v1/`",
    "- Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01`",
    "",
    "### scheme-confusion (CWE-918)",
    "Non-HTTP schemes that bypass URL validation:",
    "- `gopher://` — can craft arbitrary TCP packets",
    "- `file://` — read local files",
    "- `dict://` — port scanning and service enumeration",
    "- Check if URL parsing only validates http/https but doesn't reject other schemes",
    "",
    "### websocket-ssrf (CWE-918)",
    "WebSocket upgrade requests with user-controlled URLs:",
    "- `new WebSocket(userInput)` or ws.connect with user-controlled URL",
    "- WebSocket libraries that follow HTTP redirects",
    "",
    "## Bypass patterns to look for",
    "- DNS rebinding: domain resolves to internal IP after initial validation",
    "- IPv6-mapped IPv4: `::ffff:127.0.0.1` bypasses IPv4-only checks",
    "- Decimal IP: `2130706433` (127.0.0.1 in decimal)",
    "- Octal IP: `0177.0.0.1` (127.0.0.1 in octal)",
    "- URL parser inconsistencies: different parsing between validator and HTTP client",
    "- CRLF injection in URLs: `http://allowed.com%0d%0a`",
    "- Redirect chains: initial request to allowed domain redirects to internal IP",
    "- IPv4-mapped IPv6: `[::ffff:127.0.0.1]` or `[::ffff:a]` bypasses IPv4-only checks",
    "- Encoded localhost: `http://0x7f000001`, `http://0177.0.0.1`, `http://0.0.0.0`",
    "- DNS rebinding: domain that resolves to internal IP after TTL expires",
    "",
    "## Instructions",
    "1. Use Grep to find HTTP client usage (fetch, axios, http.get, urllib, requests, HttpClient)",
    "2. Use Read to trace data flow from user input to HTTP request sink",
    "3. Check for URL validation, allowlists, and redirect configuration",
    `4. Return at most ${maxFindings} findings, prioritized by severity.`,
    "",
    antiHallucinationModule({
      extra: [
        "Only report SSRF where you can verify user input reaches an HTTP request sink.",
        "Do NOT report internal-only HTTP calls with hardcoded URLs.",
        "Do NOT report HTTP calls in test files or development scripts.",
      ],
    }),
    frameworkAwarenessModule(repoContext),
  ].filter(Boolean).join("\n");
}

function normalizeFindings(raw: unknown, repoRoot: string, repoName: string, maxFindings: number): Finding[] {
  if (!isRecord(raw) || !Array.isArray(raw["findings"])) return [];

  const deduped = new Map<string, Finding>();
  for (const item of raw["findings"] as unknown[]) {
    if (!isRecord(item)) continue;
    const f = item as unknown as SsrfDetectionFinding;
    if (!f.filePath?.trim()) continue;

    const filePath = normalizeFilePath(repoRoot, f.filePath);
    const fingerprint = computeFingerprint(repoName, filePath, f);

    const sinkInfo = f.sinkFunction ? ` via ${f.sinkFunction}` : "";
    const sourceInfo = f.inputSource ? ` from ${f.inputSource}` : "";

    const finding: Finding = {
      scanner: "ssrf-detect",
      fingerprint,
      ruleId: `ssrf/${f.category || "unknown"}`,
      filePath,
      startLine: Math.max(1, Math.floor(Number(f.startLine) || 1)),
      severity: f.severity || "ERROR",
      message: `${f.description || "Potential SSRF vulnerability"}${sinkInfo}${sourceInfo}`,
      evidence: f.rationale || null,
      scannerConfidence: f.confidence || "MEDIUM",
      subcategory: ["vuln"],
      likelihood: f.confidence || "MEDIUM",
      impact: f.severity === "ERROR" ? "HIGH" : f.severity === "INFO" ? "LOW" : "MEDIUM",
      cwe: ["CWE-918"],
      score: scoreFindingMetadata({
        severity: f.severity,
        likelihood: f.confidence,
        impact: f.severity === "ERROR" ? "HIGH" : f.severity === "INFO" ? "LOW" : "MEDIUM",
        subcategory: ["vuln"],
        cwe: ["CWE-918"],
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

function computeFingerprint(repoName: string, filePath: string, f: SsrfDetectionFinding): string {
  const source = [repoName, "ssrf-detect", f.category, filePath, String(f.startLine)].join("|");
  return createHash("sha256").update(source).digest("hex");
}

function normalizeFilePath(repoRoot: string, filePath: string): string {
  if (!path.isAbsolute(filePath)) return filePath;
  const relative = path.relative(repoRoot, filePath);
  if (relative.startsWith("..")) return filePath;
  return relative || filePath;
}

export const ssrfDetectionTask: AgentTask<ScanOpts, Finding[]> = {
  id: "ssrf-detect",
  displayName: "SSRF Detector",
  outputKind: "findings",
  dependsOn: ["context-gatherer"],

  async run(_input, context): Promise<Finding[]> {
    const { model, maxFindings } = resolveConfig(context);
    const repoContext = coerceRepoContext(context.upstreamOutputs.get("context-gatherer"));
    const profiles = context.securityProfiles
      ? getProfilesForTask(context.securityProfiles, "ssrf-detect")
      : [];
    const profileLines = formatProfilesForPrompt(profiles);
    const prompt = buildPrompt(repoContext, maxFindings, profileLines);
    const runtime = getAgentRuntime();

    let structuredOutput: unknown;
    let resultText = "";
    let costUsd = 0;

    const tag = "[ssrf-detect]";
    log.info(`Starting scan (model=${model})`);

    try {
      for await (const message of runtime.query({
        prompt,
        options: {
          cwd: context.repoRoot,
          model,
          maxTurns: context.config.taskMaxTurns ?? 15,
          allowedTools: ["Read", "Glob", "Grep"],
          permissionMode: "dontAsk",
          outputFormat: {
            type: "json_schema",
            schema: SSRF_DETECTION_SCHEMA,
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
        `You are triaging an SSRF detection finding in "${repoName}".`,
        "",
        `Rule: ${finding.ruleId}`,
        `File: ${finding.filePath}:${finding.startLine}`,
        `Message: ${finding.message}`,
        finding.evidence ? `Rationale: ${finding.evidence}` : "",
        "",
        "Verify the SSRF vulnerability is exploitable:",
        "- Is the URL/host truly user-controlled?",
        "- Are there allowlists or validation in place?",
        "- Can the HTTP client reach internal services?",
        "- Are redirects followed that could bypass validation?",
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

export const __ssrfDetectionInternals = {
  resolveConfig,
  buildPrompt,
  normalizeFindings,
  computeFingerprint,
};
