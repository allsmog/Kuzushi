import { createLogger } from "../../logger.js";
import {
  languageAntiHallucinationExtras,
  languageInvestigationModule,
  languageTuningModule,
} from "../../prompts/language-tuning.js";
import { antiHallucinationModule, frameworkAwarenessModule } from "../../prompts/modules.js";
import { coerceFileIndex, coerceRepoContext } from "../../repo-context.js";
import { scoreFindingMetadata } from "../../scanners/scoring.js";
import type { Finding, TriageAgentConfig } from "../../scanners/types.js";
import { formatProfilesForPrompt, getProfilesForTask } from "../../security-profiles.js";
import { attachTaskOutputMeta } from "../../task-output-meta.js";
import type { ApplicationModel, FileIndex, RepoContext, ScanOpts } from "../../types.js";
import { isRecord, toErrorMessage } from "../../utils.js";
import type { AgentTask, TaskContext } from "../types.js";
import {
  computeDetectionFingerprint,
  dedupAndRankFindings,
  type LensResult,
  normalizeFilePath,
  runLens,
} from "./detection-task-utils.js";
import { type PreReadResult, preReadFilesForTask } from "./pre-read.js";
import {
  formatFileTreeForPrompt,
  formatPatternMatchesForPrompt,
  formatPreReadForPrompt,
} from "./pre-read-prompt.js";
import {
  resolveTaskAllowedTools,
  resolveTaskModel,
  resolveTaskPositiveInt,
  resolveTaskRuntime,
} from "./runtime-overrides.js";
import {
  buildApplicationModelSection,
  buildThreatScenarioEvidenceSection,
} from "./scenario-guidance.js";
import { buildThreatModelLeadsSection, resolveThreatModelOutput } from "./threat-model-guidance.js";

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
        required: [
          "category",
          "filePath",
          "startLine",
          "severity",
          "description",
          "cwe",
          "confidence",
          "rationale",
        ],
        properties: {
          category: {
            type: "string",
            enum: [
              "url-from-user-input",
              "missing-allowlist",
              "redirect-following",
              "internal-service-url",
              "cloud-metadata",
              "scheme-confusion",
              "websocket-ssrf",
            ],
          },
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
  const model = resolveTaskModel(ctx, "ssrf-detect");
  const maxFindings = resolveTaskPositiveInt(ctx, "ssrf-detect", "maxFindings", 50);
  return { model, maxFindings };
}

function buildPrompt(
  repoContext: RepoContext | undefined,
  maxFindings: number,
  profileLines: string[] = [],
  fileIndex?: FileIndex,
  preRead?: PreReadResult,
  threatModelContext?: string,
  appModelContext?: string,
  scenarioContext?: string,
): string {
  const patternMatchText = formatPatternMatchesForPrompt(fileIndex, ["eval-exec"]);

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
    ...(threatModelContext ? [threatModelContext, ""] : []),
    ...(appModelContext ? [appModelContext, ""] : []),
    ...(scenarioContext ? [scenarioContext, ""] : []),
    "## Categories to check",
    "",
    languageTuningModule({
      taskId: "ssrf-detection",
      repoContext,
      frameworks: repoContext?.frameworks,
    }) || "### url-from-user-input (CWE-918)",
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
    formatFileTreeForPrompt(fileIndex, patternMatchText.length > 0),
    formatPreReadForPrompt(preRead ?? { files: [], totalBytes: 0, truncated: false }),
    patternMatchText,
    "## Instructions",
    ...(preRead && preRead.files.length > 0
      ? [
          "1. Start by analyzing the pre-loaded files above for SSRF vulnerabilities.",
          "2. Use Glob/Grep only for additional files not already provided.",
          "3. Use Read to trace data flow from user input to HTTP request sink.",
        ]
      : [
          "1. Use Grep to find HTTP client usage (fetch, axios, http.get, urllib, requests, HttpClient)",
          "2. Use Read to trace data flow from user input to HTTP request sink",
          "3. Check for URL validation, allowlists, and redirect configuration",
        ]),
    `4. Return at most ${maxFindings} findings, prioritized by severity.`,
    "",
    antiHallucinationModule({
      extra: [
        "Only report SSRF where you can verify user input reaches an HTTP request sink.",
        "Do NOT report internal-only HTTP calls with hardcoded URLs.",
        "Do NOT report HTTP calls in test files or development scripts.",
        ...languageAntiHallucinationExtras({
          taskId: "ssrf-detection",
          repoContext,
          frameworks: repoContext?.frameworks,
        }),
      ],
    }),
    frameworkAwarenessModule(repoContext),
  ]
    .filter(Boolean)
    .join("\n");
}

function normalizeFindings(
  raw: unknown,
  repoRoot: string,
  repoName: string,
  maxFindings: number,
): Finding[] {
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
      taskId: "ssrf-detect",
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
      proofState: "symbolic_only",
      engineProvenance: [{ kind: "agentic", detail: "LLM-driven ssrf-detect analysis" }],
    };

    const existing = deduped.get(fingerprint);
    if (!existing || finding.score > existing.score) {
      deduped.set(fingerprint, finding);
    }
  }

  return [...deduped.values()].sort((a, b) => b.score - a.score).slice(0, maxFindings);
}

function computeFingerprint(repoName: string, filePath: string, f: SsrfDetectionFinding): string {
  return computeDetectionFingerprint([
    repoName,
    "ssrf-detect",
    f.category,
    filePath,
    String(f.startLine),
  ]);
}

export const ssrfDetectionTask: AgentTask<ScanOpts, Finding[]> = {
  id: "ssrf-detect",
  displayName: "SSRF Detector",
  outputKind: "findings",
  dependsOn: ["context-gatherer", "app-model-build", "threat-scenario-build"],

  async run(_input, context): Promise<Finding[]> {
    const { model, maxFindings } = resolveConfig(context);
    const repoContext = coerceRepoContext(context.upstreamOutputs.get("context-gatherer"));
    const fileIndex = coerceFileIndex(context.upstreamOutputs.get("context-gatherer"));
    const preRead = await preReadFilesForTask("ssrf-detect", fileIndex, context.repoRoot);
    const profiles = context.securityProfiles
      ? getProfilesForTask(context.securityProfiles, "ssrf-detect")
      : [];
    const profileLines = formatProfilesForPrompt(profiles);
    const threatModelContext = buildThreatModelLeadsSection(
      "ssrf-detect",
      resolveThreatModelOutput(context.upstreamOutputs),
      fileIndex,
      preRead,
    );
    const applicationModel = context.upstreamOutputs.get("app-model-build") as
      | ApplicationModel
      | undefined;
    const scenarioOutput = context.upstreamOutputs.get("threat-scenario-build");
    const appModelContext = buildApplicationModelSection("ssrf-detect", applicationModel);
    const scenarioContext = await buildThreatScenarioEvidenceSection(
      "ssrf-detect",
      context.repoRoot,
      applicationModel,
      scenarioOutput,
    );

    const tag = "[ssrf-detect]";

    const perLensMax = Math.ceil(maxFindings / 2);
    log.info(`Starting multi-lens scan (model=${model})`);

    // Run lenses in parallel: local sink review + cross-function dataflow
    const lensPromises: Array<Promise<LensResult>> = [
      runSsrfLens(
        buildLocalSinkPrompt(
          repoContext,
          perLensMax,
          profileLines,
          preRead,
          threatModelContext,
          appModelContext,
          scenarioContext,
        ),
        context,
        model,
        `${tag}/local-sink`,
      ).catch((error) => {
        log.error(`${tag}/local-sink lens error: ${toErrorMessage(error)}`);
        return { output: { findings: [] }, costUsd: 0 };
      }),
      runSsrfLens(
        buildCrossFunctionPrompt(
          repoContext,
          perLensMax,
          profileLines,
          fileIndex,
          preRead,
          threatModelContext,
          appModelContext,
          scenarioContext,
        ),
        context,
        model,
        `${tag}/cross-function`,
      ).catch((error) => {
        log.error(`${tag}/cross-function lens error: ${toErrorMessage(error)}`);
        return { output: { findings: [] }, costUsd: 0 };
      }),
    ];

    const lensResults = await Promise.all(lensPromises);
    let totalCostUsd = 0;

    // Merge all lens outputs through existing dedup
    const allFindings: Finding[] = [];
    for (const result of lensResults) {
      totalCostUsd += result.costUsd;
      allFindings.push(
        ...normalizeFindings(result.output, context.repoRoot, context.repoName, perLensMax),
      );
    }

    return attachTaskOutputMeta(dedupAndRankFindings(allFindings, maxFindings), {
      costUsd: totalCostUsd,
    });
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
      ]
        .filter(Boolean)
        .join("\n"),
    };
  },
};

function runSsrfLens(
  prompt: string,
  context: TaskContext,
  model: string,
  tag: string,
): Promise<LensResult> {
  return runLens(prompt, context, model, tag, SSRF_DETECTION_SCHEMA);
}

function buildLocalSinkPrompt(
  repoContext: RepoContext | undefined,
  maxFindings: number,
  profileLines: string[],
  preRead: PreReadResult | undefined,
  threatModelContext?: string,
  appModelContext?: string,
  scenarioContext?: string,
): string {
  return [
    "You are an SSRF specialist. LENS: LOCAL SINK REVIEW.",
    "Focus ONLY on HTTP client calls visible in the pre-loaded files. Do NOT use Glob/Grep.",
    "Check each call for user-controlled URL parameters, missing allowlists, and redirect following.",
    "",
    ...(profileLines.length > 0 ? [...profileLines, ""] : []),
    ...(threatModelContext ? [threatModelContext, ""] : []),
    ...(appModelContext ? [appModelContext, ""] : []),
    ...(scenarioContext ? [scenarioContext, ""] : []),
    formatPreReadForPrompt(preRead ?? { files: [], totalBytes: 0, truncated: false }),
    "",
    "## Sink functions to check",
    "fetch, axios, http.get, urllib, HttpClient, requests.get, http.request, got, undici, superagent",
    "",
    `Return at most ${maxFindings} findings.`,
    "",
    antiHallucinationModule({
      extra: [
        "Only report SSRF where user input reaches an HTTP request sink in the provided files.",
        "Do NOT report internal-only HTTP calls with hardcoded URLs.",
        ...languageAntiHallucinationExtras({
          taskId: "ssrf-detection",
          repoContext,
          frameworks: repoContext?.frameworks,
        }),
      ],
    }),
    frameworkAwarenessModule(repoContext),
  ]
    .filter(Boolean)
    .join("\n");
}

function buildCrossFunctionPrompt(
  repoContext: RepoContext | undefined,
  maxFindings: number,
  profileLines: string[],
  fileIndex: FileIndex | undefined,
  preRead: PreReadResult | undefined,
  threatModelContext?: string,
  appModelContext?: string,
  scenarioContext?: string,
): string {
  const patternMatchText = formatPatternMatchesForPrompt(fileIndex, ["eval-exec"]);
  return [
    "You are an SSRF specialist. LENS: CROSS-FUNCTION DATAFLOW.",
    "Trace user input across function boundaries to HTTP request sinks.",
    "Focus on multi-hop data flows: request handler → utility → HTTP client.",
    "Use Grep to find HTTP client usage, then Read to trace cross-function data flow.",
    "",
    ...(profileLines.length > 0 ? [...profileLines, ""] : []),
    ...(threatModelContext ? [threatModelContext, ""] : []),
    ...(appModelContext ? [appModelContext, ""] : []),
    ...(scenarioContext ? [scenarioContext, ""] : []),
    formatFileTreeForPrompt(fileIndex, patternMatchText.length > 0),
    formatPreReadForPrompt(preRead ?? { files: [], totalBytes: 0, truncated: false }),
    patternMatchText,
    "",
    "## Cross-function patterns to check",
    "- Request handler extracts URL/host → passes to utility → utility calls HTTP client",
    "- URL constructed from multiple user inputs across helpers",
    "- Redirect target resolution spanning middleware and route handlers",
    "",
    `Return at most ${maxFindings} findings.`,
    "",
    antiHallucinationModule({
      extra: [
        "Only report SSRF where you can verify user input crosses at least one function boundary to reach an HTTP sink.",
        "Do NOT report single-file, obvious cases — focus on non-trivial data flows.",
        ...languageAntiHallucinationExtras({
          taskId: "ssrf-detection",
          repoContext,
          frameworks: repoContext?.frameworks,
        }),
      ],
    }),
    frameworkAwarenessModule(repoContext),
  ]
    .filter(Boolean)
    .join("\n");
}

export const __ssrfDetectionInternals = {
  resolveConfig,
  buildPrompt,
  buildLocalSinkPrompt,
  buildCrossFunctionPrompt,
  normalizeFindings,
  computeFingerprint,
  runLens: runSsrfLens,
};
