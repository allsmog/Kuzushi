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
import type { FileIndex, RepoContext, ScanOpts } from "../../types.js";
import { isRecord, toErrorMessage } from "../../utils.js";
import type { AgentTask, TaskContext } from "../types.js";
import {
  computeDetectionFingerprint,
  normalizeFilePath,
  parseJson,
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
import { buildThreatModelLeadsSection, resolveThreatModelOutput } from "./threat-model-guidance.js";

const log = createLogger({ stage: "race-condition" });

const RACE_CONDITION_SCHEMA = {
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
          "pattern",
          "filePath",
          "startLine",
          "severity",
          "description",
          "cwe",
          "confidence",
          "rationale",
        ],
        properties: {
          pattern: {
            type: "string",
            enum: [
              "toctou",
              "double-spend",
              "unprotected-shared-state",
              "rate-limit-bypass",
              "file-race",
            ],
          },
          filePath: { type: "string" },
          startLine: { type: "integer", minimum: 1 },
          severity: { type: "string", enum: ["ERROR", "WARNING", "INFO"] },
          description: { type: "string" },
          cwe: { type: "string" },
          confidence: { type: "string", enum: ["HIGH", "MEDIUM", "LOW"] },
          rationale: { type: "string" },
          sharedResource: { type: "string" },
          concurrencyMechanism: { type: "string" },
        },
      },
    },
  },
} as const;

interface RaceConditionFinding {
  pattern: string;
  filePath: string;
  startLine: number;
  severity: string;
  description: string;
  cwe: string;
  confidence: string;
  rationale: string;
  sharedResource?: string;
  concurrencyMechanism?: string;
}

interface RaceConditionConfig {
  model: string;
  maxFindings: number;
}

function resolveConfig(ctx: TaskContext): RaceConditionConfig {
  const model = resolveTaskModel(ctx, "race-condition");
  const maxFindings = resolveTaskPositiveInt(ctx, "race-condition", "maxFindings", 50);
  return { model, maxFindings };
}

function buildPrompt(
  repoContext: RepoContext | undefined,
  maxFindings: number,
  profileLines: string[] = [],
  fileIndex?: FileIndex,
  preRead?: PreReadResult,
  threatModelContext?: string,
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
    "You are a senior concurrency security specialist who has triaged hundreds of race condition",
    "and TOCTOU bugs. You understand that most concurrency patterns are benign — only flag issues",
    "where concurrent access has concrete security impact (data corruption, privilege escalation,",
    "financial loss), not mere functional bugs.",
    "",
    "Analyze the repository for security-relevant race conditions and concurrency issues.",
    "",
    ...contextLines,
    ...(profileLines.length > 0 ? [...profileLines, ""] : []),
    ...(threatModelContext ? [threatModelContext, ""] : []),
    "## Detection strategy",
    "1. Identify concurrent execution patterns (goroutines, async/await, threads, worker_threads, multiprocessing).",
    "2. For each concurrent section, identify shared state (globals, DB rows, files, cache entries).",
    "3. Check if shared state is protected (locks, transactions, atomics, mutexes).",
    "4. Flag unprotected concurrent access with security impact.",
    "",
    "## Patterns to detect",
    "",
    languageTuningModule({
      taskId: "race-condition",
      repoContext,
      frameworks: repoContext?.frameworks,
    }) || "### toctou (CWE-367)",
    "Time-of-check to time-of-use: checking a condition then acting on it without atomicity.",
    "Examples: file existence check then open, permission check then action, balance check then debit.",
    "",
    "### double-spend (CWE-362)",
    "Multiple concurrent requests can exhaust a resource beyond its limit.",
    "Examples: coupon redemption, balance deduction, inventory decrement without DB transaction.",
    "",
    "### unprotected-shared-state (CWE-362)",
    "Shared mutable state accessed concurrently without synchronization.",
    "Examples: global counters, shared maps/dicts, file writes from multiple goroutines/threads.",
    "",
    "### rate-limit-bypass (CWE-362)",
    "Non-atomic rate limit check-then-increment:",
    "- Read counter, compare to limit, then increment — concurrent requests bypass the limit",
    "- In-memory rate limiters without atomic operations",
    "- Redis rate limiters using separate GET and INCR instead of Lua script or MULTI",
    "",
    "### file-race (CWE-367)",
    "File system TOCTOU:",
    "- Check file existence/permissions then read/write without locking",
    "- Temporary file creation in shared directories without exclusive flags",
    "- Symlink races: checking target then following link",
    "",
    formatFileTreeForPrompt(fileIndex, patternMatchText.length > 0),
    formatPreReadForPrompt(preRead ?? { files: [], totalBytes: 0, truncated: false }),
    patternMatchText,
    ...(preRead && preRead.files.length > 0
      ? [
          "## Investigation approach",
          "1. Start by analyzing the pre-loaded files above for race condition vulnerabilities.",
          "2. Use Glob/Grep only for additional files not already provided.",
          "3. Use Read to inspect additional files with concurrent access patterns.",
          "",
        ]
      : []),
    `Return at most ${maxFindings} findings, prioritized by severity.`,
    "",
    antiHallucinationModule({
      extra: [
        "Only report issues where concurrent access is plausible and has security impact.",
        "Verify that the code is actually executed concurrently before reporting.",
        "Confidence HIGH only if race is clearly exploitable.",
        ...languageAntiHallucinationExtras({
          taskId: "race-condition",
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
    const f = item as unknown as RaceConditionFinding;
    if (!f.filePath?.trim()) continue;

    const filePath = normalizeFilePath(repoRoot, f.filePath);
    const cweList = f.cwe ? [f.cwe] : [];
    const fingerprint = computeFingerprint(repoName, filePath, f);

    const resourceInfo = f.sharedResource ? ` [resource: ${f.sharedResource}]` : "";

    const finding: Finding = {
      taskId: "race-condition-detect",
      fingerprint,
      ruleId: `race-condition/${f.pattern || "unknown"}`,
      filePath,
      startLine: Math.max(1, Math.floor(Number(f.startLine) || 1)),
      severity: f.severity || "WARNING",
      message: `${f.description || "Race condition"}${resourceInfo}`,
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
      engineProvenance: [{ kind: "agentic", detail: "LLM-driven race-condition-detect analysis" }],
    };

    const existing = deduped.get(fingerprint);
    if (!existing || finding.score > existing.score) {
      deduped.set(fingerprint, finding);
    }
  }

  return [...deduped.values()].sort((a, b) => b.score - a.score).slice(0, maxFindings);
}

function computeFingerprint(repoName: string, filePath: string, f: RaceConditionFinding): string {
  return computeDetectionFingerprint([
    repoName,
    "race-condition",
    f.pattern,
    filePath,
    String(f.startLine),
  ]);
}

export const raceConditionTask: AgentTask<ScanOpts, Finding[]> = {
  id: "race-condition-detect",
  displayName: "Race Condition Detector",
  outputKind: "findings",
  dependsOn: ["context-gatherer"],

  async run(_input, context): Promise<Finding[]> {
    const { model, maxFindings } = resolveConfig(context);
    const repoContext = coerceRepoContext(context.upstreamOutputs.get("context-gatherer"));
    const fileIndex = coerceFileIndex(context.upstreamOutputs.get("context-gatherer"));
    const preRead = await preReadFilesForTask("race-condition-detect", fileIndex, context.repoRoot);
    const profiles = context.securityProfiles
      ? getProfilesForTask(context.securityProfiles, "race-condition-detect")
      : [];
    const profileLines = formatProfilesForPrompt(profiles);
    const threatModelContext = buildThreatModelLeadsSection(
      "race-condition-detect",
      resolveThreatModelOutput(context.upstreamOutputs),
      fileIndex,
      preRead,
    );
    const prompt = buildPrompt(
      repoContext,
      maxFindings,
      profileLines,
      fileIndex,
      preRead,
      threatModelContext,
    );
    const runtime = resolveTaskRuntime(context);

    let structuredOutput: unknown;
    let resultText = "";
    let costUsd = 0;

    const tag = "[race-condition]";
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
            schema: RACE_CONDITION_SCHEMA,
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
        `You are triaging a race condition finding in "${repoName}".`,
        "",
        `Rule: ${finding.ruleId}`,
        `File: ${finding.filePath}:${finding.startLine}`,
        `Message: ${finding.message}`,
        finding.evidence ? `Rationale: ${finding.evidence}` : "",
        "",
        "Verify the race condition is exploitable:",
        "1. Is the code actually executed concurrently?",
        "2. Is the shared resource truly unprotected?",
        "3. Does the race have security impact (not just a functional bug)?",
      ]
        .filter(Boolean)
        .join("\n"),
    };
  },
};

export const __raceConditionInternals = {
  resolveConfig,
  buildPrompt,
  normalizeFindings,
  computeFingerprint,
};
