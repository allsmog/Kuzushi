// This file contains DETECTION PATTERNS for a security scanner.
// References to deserialization APIs are DETECTION TARGETS in scanned repositories.
// This file does NOT perform any deserialization itself.

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
import { attachTaskOutputMeta } from "../../task-output-meta.js";
import type { ApplicationModel, FileIndex, RepoContext, ScanOpts } from "../../types.js";
import { isRecord } from "../../utils.js";
import type { AgentTask, TaskContext } from "../types.js";
import { computeDetectionFingerprint, normalizeFilePath } from "./detection-task-utils.js";
import { type PreReadResult, preReadFilesForTask } from "./pre-read.js";
import { formatFileTreeForPrompt, formatPreReadForPrompt } from "./pre-read-prompt.js";
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

const log = createLogger({ stage: "deserialization" });

const DESERIALIZATION_SCHEMA = {
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
            enum: ["unsafe-deserialize", "object-injection", "gadget-chain", "yaml-load"],
          },
          filePath: { type: "string" },
          startLine: { type: "integer", minimum: 1 },
          severity: { type: "string", enum: ["ERROR", "WARNING", "INFO"] },
          description: { type: "string" },
          cwe: { type: "string" },
          confidence: { type: "string", enum: ["HIGH", "MEDIUM", "LOW"] },
          rationale: { type: "string" },
          deserializerApi: { type: "string" },
          inputSource: { type: "string" },
        },
      },
    },
  },
} as const;

interface DeserializationFinding {
  category: string;
  filePath: string;
  startLine: number;
  severity: string;
  description: string;
  cwe: string;
  confidence: string;
  rationale: string;
  deserializerApi?: string;
  inputSource?: string;
}

function buildPrompt(
  repoContext: RepoContext | undefined,
  maxFindings: number,
  fileIndex?: FileIndex,
  preRead?: PreReadResult,
  appModelContext?: string,
  scenarioContext?: string,
): string {
  const contextLines = repoContext
    ? [
        "## Repository context",
        `- Languages: ${repoContext.languages.join(", ") || "unknown"}`,
        `- Frameworks: ${repoContext.frameworks.join(", ") || "unknown"}`,
        "",
      ]
    : [];

  // NOTE: The prompt below mentions dangerous deserialization APIs as DETECTION TARGETS.
  // These are patterns to search for in scanned repositories, not code this scanner runs.
  return [
    "You are a senior application security engineer specializing in insecure deserialization (CWE-502).",
    "Your task: identify deserialization of untrusted data that can lead to RCE, DoS, or object injection.",
    "",
    ...contextLines,
    ...(appModelContext ? [appModelContext, ""] : []),
    ...(scenarioContext ? [scenarioContext, ""] : []),
    "## Categories to detect",
    "",
    languageTuningModule({
      taskId: "deserialization-detection",
      repoContext,
      frameworks: repoContext?.frameworks,
    }) || "### unsafe-deserialize (CWE-502)",
    "Deserialization of untrusted data using dangerous APIs.",
    "Python: unsafe deserialization via binary object loaders, shelve, marshal, yaml.load without SafeLoader.",
    "Java: ObjectInputStream.readObject(), XMLDecoder, XStream without security framework.",
    "Node.js: node-serialize, js-yaml.load() with DEFAULT_SCHEMA (allows code execution tags).",
    "Ruby: Marshal.load(), YAML.load() (use YAML.safe_load instead).",
    "PHP: unserialize() with user input.",
    ".NET: BinaryFormatter, NetDataContractSerializer, SoapFormatter.",
    "",
    "### object-injection (CWE-502)",
    "Controlled object creation via deserialization enabling property manipulation.",
    "PHP magic methods (__wakeup, __destruct, __toString) triggered during unserialize.",
    "Python __reduce__, __setstate__ methods in deserialized objects.",
    "Java readObject()/readResolve() with attacker-controlled class.",
    "",
    "### gadget-chain (CWE-502)",
    "Known deserialization gadget chain libraries in dependencies.",
    "Java: Commons Collections, Spring, Apache POI, Jackson polymorphic typing.",
    ".NET: ObjectDataProvider, TypeConfuseDelegate, PSObject.",
    "",
    "### yaml-load (CWE-502)",
    "YAML parsing with unsafe loaders that allow code execution.",
    "Python: yaml.load() without Loader=SafeLoader or yaml.safe_load().",
    "Ruby: YAML.load() instead of YAML.safe_load().",
    "Node.js: js-yaml.load() with DEFAULT_SCHEMA instead of DEFAULT_SAFE_SCHEMA.",
    "",
    formatFileTreeForPrompt(fileIndex, false),
    formatPreReadForPrompt(preRead ?? { files: [], totalBytes: 0, truncated: false }),
    "## Investigation methodology",
    ...(preRead && preRead.files.length > 0
      ? [
          "1. Analyze pre-loaded files for deserialization calls.",
          "2. Use Grep to find additional deserialization APIs.",
        ]
      : [
          "1. Use Grep to find deserialization APIs: unserialize, ObjectInputStream,",
          "   yaml.load, Marshal.load, BinaryFormatter, node-serialize.",
          "2. Read each to determine if input is user-controlled.",
        ]),
    "3. Check if safe alternatives are available (yaml.safe_load, JSON.parse, SafeLoader).",
    "4. Check dependency list for known gadget chain libraries.",
    "5. Trace data flow from user input to deserialization sink.",
    "",
    antiHallucinationModule({
      extra: [
        "JSON.parse() is SAFE - do NOT flag it.",
        "yaml.safe_load() and YAML.safe_load() are SAFE.",
        "Deserialization of hardcoded/internal data with no user input path is low risk.",
        "Do NOT flag serialization (only deserialization of untrusted data).",
        ...languageAntiHallucinationExtras({
          taskId: "deserialization-detection",
          repoContext,
          frameworks: repoContext?.frameworks,
        }),
      ],
    }),
    frameworkAwarenessModule(repoContext),
    "",
    `Return at most ${maxFindings} findings, prioritized by severity and confidence.`,
    "Filter out any finding where your confidence would be below MEDIUM.",
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
    const f = item as unknown as DeserializationFinding;
    if (!f.filePath?.trim()) continue;

    const filePath = normalizeFilePath(repoRoot, f.filePath);
    const cweList = f.cwe ? [f.cwe] : ["CWE-502"];
    const fingerprint = computeDetectionFingerprint([
      repoName,
      "deserialization",
      f.category,
      filePath,
      String(f.startLine),
    ]);

    const finding: Finding = {
      taskId: "deserialization-detect",
      fingerprint,
      ruleId: `deserialization/${f.category || "unknown"}`,
      filePath,
      startLine: Math.max(1, Math.floor(Number(f.startLine) || 1)),
      severity: f.severity || "ERROR",
      message: `${f.description || "Insecure deserialization"}${f.deserializerApi ? ` [${f.deserializerApi}]` : ""}`,
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
      proofState: "symbolic_only",
      engineProvenance: [{ kind: "agentic", detail: "LLM-driven deserialization-detect analysis" }],
    };

    const existing = deduped.get(fingerprint);
    if (!existing || finding.score > existing.score) {
      deduped.set(fingerprint, finding);
    }
  }

  return [...deduped.values()].sort((a, b) => b.score - a.score).slice(0, maxFindings);
}

export const deserializationDetectionTask: AgentTask<ScanOpts, Finding[]> = {
  id: "deserialization-detect",
  displayName: "Insecure Deserialization Detector",
  outputKind: "findings",
  dependsOn: ["context-gatherer", "app-model-build", "threat-scenario-build"],

  async run(_input, context): Promise<Finding[]> {
    const model = resolveTaskModel(context, "deserialization-detect");
    const maxFindings = resolveTaskPositiveInt(
      context,
      "deserialization-detect",
      "maxFindings",
      50,
    );
    const repoContext = coerceRepoContext(context.upstreamOutputs.get("context-gatherer"));
    const fileIndex = coerceFileIndex(context.upstreamOutputs.get("context-gatherer"));
    const preRead = await preReadFilesForTask(
      "deserialization-detect",
      fileIndex,
      context.repoRoot,
    );
    const applicationModel = context.upstreamOutputs.get("app-model-build") as
      | ApplicationModel
      | undefined;
    const scenarioOutput = context.upstreamOutputs.get("threat-scenario-build");
    const appModelContext = buildApplicationModelSection(
      "deserialization-detect",
      applicationModel,
    );
    const scenarioContext = await buildThreatScenarioEvidenceSection(
      "deserialization-detect",
      context.repoRoot,
      applicationModel,
      scenarioOutput,
    );

    const runtime = resolveTaskRuntime(context);
    const prompt = buildPrompt(
      repoContext,
      maxFindings,
      fileIndex,
      preRead,
      appModelContext,
      scenarioContext,
    );
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
          schema: DESERIALIZATION_SCHEMA,
          strict: true,
          retryInvalidStructuredOutput: 1,
        },
      },
    })) {
      if (message.type !== "result") continue;
      if (typeof message.totalCostUsd === "number" && Number.isFinite(message.totalCostUsd))
        costUsd = message.totalCostUsd;
      if ("result" in message) structuredOutput = message.structuredOutput;
    }

    const findings = normalizeFindings(
      structuredOutput,
      context.repoRoot,
      context.repoName,
      maxFindings,
    );
    log.info(`Found ${findings.length} deserialization findings (cost=$${costUsd.toFixed(4)})`);
    return attachTaskOutputMeta(findings, { costUsd });
  },

  triageAgentConfig(finding: Finding, repoName: string): TriageAgentConfig {
    return {
      prompt: [
        `You are triaging an insecure deserialization finding in "${repoName}".`,
        `Rule: ${finding.ruleId}`,
        `File: ${finding.filePath}:${finding.startLine}`,
        `Message: ${finding.message}`,
        finding.evidence ? `Rationale: ${finding.evidence}` : "",
        "",
        "Verify:",
        "1. The deserialization call exists at the reported location.",
        "2. The data being deserialized is user-controlled or from untrusted source.",
        "3. A safe alternative is not being used (yaml.safe_load, JSON.parse, etc.).",
        "4. No input validation or type filtering prevents exploitation.",
      ]
        .filter(Boolean)
        .join("\n"),
    };
  },
};
