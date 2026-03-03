import { createHash } from "node:crypto";
import path from "node:path";
import { getAgentRuntime } from "../../agent-runtime/index.js";
import { scoreFindingMetadata } from "../../scanners/scoring.js";
import type { Finding, TriageAgentConfig } from "../../scanners/types.js";
import type { RepoContext, ScanOpts } from "../../types.js";
import { isRecord, toErrorMessage } from "../../utils.js";
import type { AgentTask, TaskContext } from "../types.js";

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
        required: ["pattern", "filePath", "startLine", "severity", "description", "cwe", "confidence", "rationale"],
        properties: {
          pattern: { type: "string", enum: ["toctou", "double-spend", "unprotected-shared-state"] },
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
  const raw = ctx.config.scannerConfig["race-condition"];
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
        "",
      ]
    : [];

  return [
    "You are a race condition detection agent.",
    "Analyze the repository for security-relevant race conditions and concurrency issues.",
    "",
    ...contextLines,
    "## Detection strategy",
    "1. Identify concurrent execution patterns (goroutines, async/await, threads, worker_threads, multiprocessing).",
    "2. For each concurrent section, identify shared state (globals, DB rows, files, cache entries).",
    "3. Check if shared state is protected (locks, transactions, atomics, mutexes).",
    "4. Flag unprotected concurrent access with security impact.",
    "",
    "## Patterns to detect",
    "",
    "### toctou (CWE-367)",
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
    `Return at most ${maxFindings} findings, prioritized by severity.`,
    "Only report issues where concurrent access is plausible and has security impact.",
  ].join("\n");
}

function normalizeFindings(raw: unknown, repoRoot: string, repoName: string, maxFindings: number): Finding[] {
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
      scanner: "race-condition-detect",
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

function computeFingerprint(repoName: string, filePath: string, f: RaceConditionFinding): string {
  const source = [repoName, "race-condition", f.pattern, filePath, String(f.startLine)].join("|");
  return createHash("sha256").update(source).digest("hex");
}

function normalizeFilePath(repoRoot: string, filePath: string): string {
  if (!path.isAbsolute(filePath)) return filePath;
  const relative = path.relative(repoRoot, filePath);
  if (relative.startsWith("..")) return filePath;
  return relative || filePath;
}

export const raceConditionTask: AgentTask<ScanOpts, Finding[]> = {
  id: "race-condition-detect",
  displayName: "Race Condition Detector",
  outputKind: "findings",
  dependsOn: ["context-gatherer"],

  async run(_input, context): Promise<Finding[]> {
    const { model, maxFindings } = resolveConfig(context);
    const repoContext = context.upstreamOutputs.get("context-gatherer") as RepoContext | undefined;
    const prompt = buildPrompt(repoContext, maxFindings);
    const runtime = getAgentRuntime();

    let structuredOutput: unknown;
    let resultText = "";

    const tag = "[race-condition]";
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
            schema: RACE_CONDITION_SCHEMA,
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

export const __raceConditionInternals = {
  resolveConfig,
  buildPrompt,
  normalizeFindings,
  computeFingerprint,
};
