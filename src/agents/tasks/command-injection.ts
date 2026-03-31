// This file contains DETECTION PATTERNS for a security scanner.
// The patterns match dangerous coding practices in scanned repositories.
// References to exec(), system(), etc. are DETECTION TARGETS, not code this file runs.

import { createHash } from "node:crypto";
import path from "node:path";
import {
  antiHallucinationModule,
  frameworkAwarenessModule,
} from "../../prompts/modules.js";
import { coerceRepoContext, coerceFileIndex } from "../../repo-context.js";
import { scoreFindingMetadata } from "../../scanners/scoring.js";
import type { Finding, TriageAgentConfig } from "../../scanners/types.js";
import { attachTaskOutputMeta } from "../../task-output-meta.js";
import type { FileIndex, RepoContext, ScanOpts } from "../../types.js";
import { isRecord, toErrorMessage } from "../../utils.js";
import { createLogger } from "../../logger.js";
import type { AgentTask, TaskContext } from "../types.js";
import { preReadFilesForTask, type PreReadResult } from "./pre-read.js";
import { formatFileTreeForPrompt, formatPreReadForPrompt, formatPatternMatchesForPrompt } from "./pre-read-prompt.js";
import { resolveTaskModel, resolveTaskPositiveInt, resolveTaskRuntime, resolveTaskAllowedTools } from "./runtime-overrides.js";
import { buildApplicationModelSection, buildThreatScenarioEvidenceSection } from "./scenario-guidance.js";
import type { ApplicationModel } from "../../types.js";

const log = createLogger({ stage: "command-injection" });

const COMMAND_INJECTION_SCHEMA = {
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
          category: { type: "string", enum: ["shell-execution", "argument-injection", "indirect-command", "env-var-injection"] },
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

interface CommandInjectionFinding {
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

function buildPrompt(repoContext: RepoContext | undefined, maxFindings: number, fileIndex?: FileIndex, preRead?: PreReadResult, appModelContext?: string, scenarioContext?: string): string {
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
    "You are a senior application security engineer specializing in OS command injection (CWE-78).",
    "Your task: systematically identify command injection vectors where attacker-controlled input",
    "reaches shell-execution functions without proper sanitization.",
    "",
    ...contextLines,
    ...(appModelContext ? [appModelContext, ""] : []),
    ...(scenarioContext ? [scenarioContext, ""] : []),
    "## Categories to detect",
    "",
    "### shell-execution (CWE-78)",
    "Direct shell command execution with user input via shell-invoking APIs.",
    "In Node.js: child_process functions with shell interpretation enabled, or template-string command building.",
    "In Python: os.system(), subprocess with shell=True, os.popen().",
    "In Ruby: backticks, system(), %x{}.",
    "In Java: Runtime.getRuntime().exec() with shell wrapper.",
    "Key: execFile/spawn WITHOUT shell option are SAFE against metacharacter injection.",
    "Only flag when user-controlled input reaches a shell-interpreting function.",
    "",
    "### argument-injection (CWE-88)",
    "User input passed as arguments to commands can inject flags/options.",
    "Even safe APIs are vulnerable if user controls arguments: e.g. git clone with user-controlled URL.",
    "Attacker can inject --upload-pack, --config, -o flags. Check for -- separator usage.",
    "",
    "### indirect-command (CWE-78)",
    "User input controls which command is executed: command lookup tables, dynamic binary paths,",
    "PATH manipulation, or symlink following. Pattern: commands[userInput] or dynamic binary resolution.",
    "",
    "### env-var-injection (CWE-78)",
    "User input set as environment variables that influence command behavior.",
    "LD_PRELOAD, PATH, NODE_OPTIONS, PYTHONPATH injection via environment assignment from user data.",
    "",
    formatFileTreeForPrompt(fileIndex, patternMatchText.length > 0),
    formatPreReadForPrompt(preRead ?? { files: [], totalBytes: 0, truncated: false }),
    patternMatchText,
    "## Investigation methodology",
    ...(preRead && preRead.files.length > 0
      ? [
          "1. Analyze pre-loaded files for command execution sinks.",
          "2. Use Grep to find additional shell-execution calls.",
          "3. Trace data flow from HTTP/CLI input to command sinks.",
        ]
      : [
          "1. Use Grep to find shell-execution calls: child_process, subprocess, os.system, Runtime, Process.",
          "2. Read each match to determine if user input flows to the command string.",
          "3. Check for shell option in spawn/execFile — without shell, metacharacter injection is not possible.",
        ]),
    "4. Verify no input validation/sanitization (allowlists, shell-quote, escapeShellArg).",
    "5. Distinguish shell-invoking from non-shell APIs — this is critical.",
    "",
    antiHallucinationModule({
      extra: [
        "execFile/spawn WITHOUT shell:true do NOT allow shell metacharacter injection.",
        "Do NOT flag commands with hardcoded strings and no user input.",
        "Do NOT flag uses of shell-quote, escapeshellarg, or equivalent sanitization.",
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
    const f = item as unknown as CommandInjectionFinding;
    if (!f.filePath?.trim()) continue;

    const filePath = path.isAbsolute(f.filePath) ? (path.relative(repoRoot, f.filePath) || f.filePath) : f.filePath;
    const cweList = f.cwe ? [f.cwe] : ["CWE-78"];
    const source = [repoName, "command-injection", f.category, filePath, String(f.startLine)].join("|");
    const fingerprint = createHash("sha256").update(source).digest("hex");
    const sinkInfo = f.sinkFunction ? ` [${f.sinkFunction}]` : "";

    const finding: Finding = {
      scanner: "command-injection-detect",
      fingerprint,
      ruleId: `command-injection/${f.category || "unknown"}`,
      filePath,
      startLine: Math.max(1, Math.floor(Number(f.startLine) || 1)),
      severity: f.severity || "ERROR",
      message: `${f.description || "Potential command injection"}${sinkInfo}`,
      evidence: f.rationale || null,
      scannerConfidence: f.confidence || "HIGH",
      subcategory: ["vuln"],
      likelihood: f.confidence || "HIGH",
      impact: "HIGH",
      cwe: cweList,
      score: scoreFindingMetadata({
        severity: f.severity || "ERROR",
        likelihood: f.confidence || "HIGH",
        impact: "HIGH",
        subcategory: ["vuln"],
        cwe: cweList,
      }),
    };

    const existing = deduped.get(fingerprint);
    if (!existing || finding.score > existing.score) {
      deduped.set(fingerprint, finding);
    }
  }

  return [...deduped.values()].sort((a, b) => b.score - a.score).slice(0, maxFindings);
}

export const commandInjectionTask: AgentTask<ScanOpts, Finding[]> = {
  id: "command-injection-detect",
  displayName: "Command Injection Detector",
  outputKind: "findings",
  dependsOn: ["context-gatherer", "app-model-build", "threat-scenario-build"],

  async run(_input, context): Promise<Finding[]> {
    const model = resolveTaskModel(context, "command-injection-detect");
    const maxFindings = resolveTaskPositiveInt(context, "command-injection-detect", "maxFindings", 50);
    const repoContext = coerceRepoContext(context.upstreamOutputs.get("context-gatherer"));
    const fileIndex = coerceFileIndex(context.upstreamOutputs.get("context-gatherer"));
    const preRead = await preReadFilesForTask("command-injection-detect", fileIndex, context.repoRoot);
    const applicationModel = context.upstreamOutputs.get("app-model-build") as ApplicationModel | undefined;
    const scenarioOutput = context.upstreamOutputs.get("threat-scenario-build");
    const appModelContext = buildApplicationModelSection("command-injection-detect", applicationModel);
    const scenarioContext = await buildThreatScenarioEvidenceSection("command-injection-detect", context.repoRoot, applicationModel, scenarioOutput);

    const runtime = resolveTaskRuntime(context);
    const prompt = buildPrompt(repoContext, maxFindings, fileIndex, preRead, appModelContext, scenarioContext);
    let structuredOutput: unknown;
    let costUsd = 0;

    for await (const message of runtime.query({
      prompt,
      options: {
        cwd: context.repoRoot,
        model,

        allowedTools: resolveTaskAllowedTools(context),
        permissionMode: "dontAsk",
        outputFormat: {
          type: "json_schema",
          schema: COMMAND_INJECTION_SCHEMA,
          strict: true,
          retryInvalidStructuredOutput: 1,
        },
      },
    })) {
      if (message.type !== "result") continue;
      if (typeof message.totalCostUsd === "number" && Number.isFinite(message.totalCostUsd)) costUsd = message.totalCostUsd;
      if ("result" in message) structuredOutput = message.structuredOutput;
    }

    const findings = normalizeFindings(structuredOutput, context.repoRoot, context.repoName, maxFindings);
    log.info(`Found ${findings.length} command injection findings (cost=$${costUsd.toFixed(4)})`);
    return attachTaskOutputMeta(findings, { costUsd });
  },

  triageAgentConfig(finding: Finding, repoName: string): TriageAgentConfig {
    return {
      prompt: [
        `You are triaging a command injection finding in "${repoName}".`,
        `Rule: ${finding.ruleId}`,
        `File: ${finding.filePath}:${finding.startLine}`,
        `Message: ${finding.message}`,
        finding.evidence ? `Rationale: ${finding.evidence}` : "",
        "",
        "Verify:",
        "1. The command execution function exists at the reported location.",
        "2. Distinguish shell-invoking APIs from safe alternatives (execFile vs exec).",
        "3. User input actually reaches the command string or arguments.",
        "4. No sanitization (shell-quote, escapeShellArg, allowlist) prevents exploitation.",
      ].filter(Boolean).join("\n"),
    };
  },
};
