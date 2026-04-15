/**
 * Sharp-edges detection task — three adversarial personas probe for API
 * design footguns across six categories (Trail of Bits methodology from
 * [un]prompted 2026).
 *
 * Personas:
 * - The Scoundrel: Can a malicious dev disable security via config?
 * - The Lazy Developer: Will copy-pasting the first example lead to insecure code?
 * - The Confused Developer: Can params be swapped without type errors?
 *
 * Categories: algorithm-selection, dangerous-defaults, primitive-vs-semantic,
 * configuration-cliff, silent-failure, stringly-typed-security.
 */
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
import { resolveTaskModel, resolveTaskPositiveInt, resolveTaskRuntime, resolveTaskAllowedTools } from "./runtime-overrides.js";
import { buildThreatModelLeadsSection, resolveThreatModelOutput } from "./threat-model-guidance.js";
import { buildApplicationModelSection, buildThreatScenarioEvidenceSection } from "./scenario-guidance.js";
import type { ApplicationModel } from "../../types.js";
import {
  normalizeFilePath,
  computeDetectionFingerprint,
  dedupAndRankFindings,
  runLens,
  type LensResult,
} from "./detection-task-utils.js";

const log = createLogger({ stage: "sharp-edges-detect" });

type SharpEdgesCategory =
  | "algorithm-selection"
  | "dangerous-defaults"
  | "primitive-vs-semantic"
  | "configuration-cliff"
  | "silent-failure"
  | "stringly-typed-security";

type Persona = "scoundrel" | "lazy-developer" | "confused-developer";

/** CWE per category. */
const CATEGORY_CWE: Record<SharpEdgesCategory, string> = {
  "algorithm-selection": "CWE-327",
  "dangerous-defaults": "CWE-1188",
  "primitive-vs-semantic": "CWE-676",
  "configuration-cliff": "CWE-16",
  "silent-failure": "CWE-755",
  "stringly-typed-security": "CWE-697",
};

const SHARP_EDGES_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["findings"],
  properties: {
    findings: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["category", "filePath", "startLine", "severity", "description", "cwe", "confidence", "rationale", "persona"],
        properties: {
          category: { type: "string", enum: ["algorithm-selection", "dangerous-defaults", "primitive-vs-semantic", "configuration-cliff", "silent-failure", "stringly-typed-security"] },
          filePath: { type: "string" },
          startLine: { type: "integer", minimum: 1 },
          severity: { type: "string", enum: ["ERROR", "WARNING", "INFO"] },
          description: { type: "string" },
          cwe: { type: "string" },
          confidence: { type: "string", enum: ["HIGH", "MEDIUM", "LOW"] },
          rationale: { type: "string" },
          persona: { type: "string", enum: ["scoundrel", "lazy-developer", "confused-developer"] },
        },
      },
    },
  },
} as const;

interface SharpEdgesFinding {
  category: SharpEdgesCategory;
  filePath: string;
  startLine: number;
  severity: string;
  description: string;
  cwe: string;
  confidence: string;
  rationale: string;
  persona: Persona;
}

interface SharpEdgesConfig {
  model: string;
  maxFindings: number;
}

function resolveConfig(ctx: TaskContext): SharpEdgesConfig {
  const model = resolveTaskModel(ctx, "sharp-edges-detect");
  const maxFindings = resolveTaskPositiveInt(ctx, "sharp-edges-detect", "maxFindings", 50);
  return { model, maxFindings };
}

// ---------------------------------------------------------------------------
// Persona prompts
// ---------------------------------------------------------------------------

function buildScoundrelPrompt(
  repoContext: RepoContext | undefined,
  maxFindings: number,
  profileLines: string[] = [],
  fileIndex?: FileIndex,
  preRead?: PreReadResult,
  threatModelContext?: string,
  appModelContext?: string,
  scenarioContext?: string,
): string {
  const patternMatchText = formatPatternMatchesForPrompt(fileIndex, ["config-security", "crypto-import"]);
  const contextLines = repoContext
    ? [
        "## Repository context",
        `- Languages: ${repoContext.languages.join(", ") || "unknown"}`,
        `- Frameworks: ${repoContext.frameworks.join(", ") || "unknown"}`,
        "",
      ]
    : [];

  return [
    "You are The Scoundrel — a malicious insider developer.",
    "You have full access to the codebase and want to weaken or disable security controls",
    "through configuration changes, algorithm selection overrides, or parameter manipulation,",
    "all while making the changes look like legitimate code.",
    "",
    "Find places where a single config change, flag toggle, or parameter override can",
    "disable or weaken security. Focus on:",
    "",
    languageTuningModule({ taskId: "sharp-edges-detect", repoContext, frameworks: repoContext?.frameworks }) || "",
    "### algorithm-selection (CWE-327)",
    "Can a caller choose a weak algorithm (e.g., AES-ECB, MD5, SHA1) when the API offers stronger options?",
    "Is the algorithm parameter user-controllable or easily overridden?",
    "",
    "### dangerous-defaults (CWE-1188)",
    "Are there security-sensitive options that default to insecure values?",
    "Examples: `verify: false`, `secure: false`, `cors: '*'`, `debug: true`, `httpOnly: false`.",
    "",
    "### configuration-cliff (CWE-16)",
    "Does removing or changing one config option silently disable entire security layers?",
    "Example: removing one middleware disables all auth, or omitting a header bypasses CSRF.",
    "",
    ...contextLines,
    ...(profileLines.length > 0 ? [...profileLines, ""] : []),
    ...(threatModelContext ? [threatModelContext, ""] : []),
    ...(appModelContext ? [appModelContext, ""] : []),
    ...(scenarioContext ? [scenarioContext, ""] : []),
    formatFileTreeForPrompt(fileIndex, patternMatchText.length > 0),
    formatPreReadForPrompt(preRead ?? { files: [], totalBytes: 0, truncated: false }),
    patternMatchText,
    "",
    "## Instructions",
    "1. Start by analyzing the pre-loaded files above for the categories listed.",
    "2. Use Grep to find config/option files and security-sensitive defaults not already provided.",
    "3. Use Read to verify specific config values and their defaults.",
    `4. Return at most ${maxFindings} findings. Set persona to "scoundrel" for all findings.`,
    "",
    antiHallucinationModule({
      extra: [
        "Only report findings where you can point to a specific config option, flag, or parameter that weakens security.",
        "Do NOT report general coding style issues or theoretical concerns without concrete code locations.",
        "Do NOT re-report simple misconfiguration findings — focus on API DESIGN issues where the insecure path is easy.",
        ...languageAntiHallucinationExtras({ taskId: "sharp-edges-detect", repoContext, frameworks: repoContext?.frameworks }),
      ],
    }),
    frameworkAwarenessModule(repoContext),
  ].filter(Boolean).join("\n");
}

function buildLazyDeveloperPrompt(
  repoContext: RepoContext | undefined,
  maxFindings: number,
  profileLines: string[] = [],
  fileIndex?: FileIndex,
  preRead?: PreReadResult,
  threatModelContext?: string,
  appModelContext?: string,
  scenarioContext?: string,
): string {
  const patternMatchText = formatPatternMatchesForPrompt(fileIndex, ["config-security", "crypto-import"]);
  const contextLines = repoContext
    ? [
        "## Repository context",
        `- Languages: ${repoContext.languages.join(", ") || "unknown"}`,
        `- Frameworks: ${repoContext.frameworks.join(", ") || "unknown"}`,
        "",
      ]
    : [];

  return [
    "You are The Lazy Developer — you copy-paste the first code example you find.",
    "You never read beyond the first usage pattern. You use defaults for everything.",
    "Find places where the obvious, lazy usage path leads to insecure behavior.",
    "",
    "Focus on:",
    "",
    "### dangerous-defaults (CWE-1188)",
    "What happens when you call a security-sensitive function with no options?",
    "Are the defaults safe? Example: `createSession()` with no `secure` flag, `encrypt()` with no algorithm specified.",
    "",
    "### primitive-vs-semantic (CWE-676)",
    "Are developers using low-level crypto primitives (e.g., `crypto.createCipheriv`) instead of",
    "higher-level semantic APIs (e.g., `libsodium.seal`)? Are there raw SQL string concatenations",
    "instead of parameterized queries? Is there manual JWT parsing instead of a validated library?",
    "",
    "### silent-failure (CWE-755)",
    "Do try/catch blocks swallow authentication or authorization errors and return success?",
    "Does a failed validation silently fall through to allow access?",
    "Are error conditions handled by logging and continuing rather than aborting?",
    "",
    ...contextLines,
    ...(profileLines.length > 0 ? [...profileLines, ""] : []),
    ...(threatModelContext ? [threatModelContext, ""] : []),
    ...(appModelContext ? [appModelContext, ""] : []),
    ...(scenarioContext ? [scenarioContext, ""] : []),
    formatFileTreeForPrompt(fileIndex, patternMatchText.length > 0),
    formatPreReadForPrompt(preRead ?? { files: [], totalBytes: 0, truncated: false }),
    patternMatchText,
    "",
    "## Instructions",
    "1. Start by analyzing the pre-loaded files above for dangerous defaults and primitive API usage.",
    "2. Use Grep to find security-sensitive function calls and their default configurations.",
    "3. Use Read to verify what happens when functions are called with no options.",
    `4. Return at most ${maxFindings} findings. Set persona to "lazy-developer" for all findings.`,
    "",
    antiHallucinationModule({
      extra: [
        "Only report findings where the default or most obvious usage path is insecure.",
        "Do NOT report issues that require intentional misconfiguration — focus on what happens with zero effort.",
        "Do NOT report findings in test files or development scripts.",
        ...languageAntiHallucinationExtras({ taskId: "sharp-edges-detect", repoContext, frameworks: repoContext?.frameworks }),
      ],
    }),
    frameworkAwarenessModule(repoContext),
  ].filter(Boolean).join("\n");
}

function buildConfusedDeveloperPrompt(
  repoContext: RepoContext | undefined,
  maxFindings: number,
  profileLines: string[] = [],
  fileIndex?: FileIndex,
  preRead?: PreReadResult,
  threatModelContext?: string,
  appModelContext?: string,
  scenarioContext?: string,
): string {
  const patternMatchText = formatPatternMatchesForPrompt(fileIndex, ["config-security", "crypto-import"]);
  const contextLines = repoContext
    ? [
        "## Repository context",
        `- Languages: ${repoContext.languages.join(", ") || "unknown"}`,
        `- Frameworks: ${repoContext.frameworks.join(", ") || "unknown"}`,
        "",
      ]
    : [];

  return [
    "You are The Confused Developer — you sometimes confuse similar-looking parameters,",
    "use string comparisons where enums should be used, and misunderstand error-handling semantics.",
    "Find places where such confusion leads to security bypass.",
    "",
    "Focus on:",
    "",
    "### stringly-typed-security (CWE-697)",
    'Are there security checks using string comparison like `role === "admin"` where a typo',
    "or case mismatch would bypass access control? Are there permission checks against",
    "free-form string values instead of enums or constants?",
    "",
    "### configuration-cliff (CWE-16)",
    "Can similar-looking config keys be confused with different security implications?",
    "Example: `allowOrigin` vs `allowOrigins`, `token` vs `tokenSecret`, where using the wrong one",
    "silently degrades security.",
    "",
    "### silent-failure (CWE-755)",
    "Are there error paths where the wrong exception type is caught, causing a security",
    "check to be silently skipped? Does catching a broad exception swallow a specific",
    "auth/permission error?",
    "",
    ...contextLines,
    ...(profileLines.length > 0 ? [...profileLines, ""] : []),
    ...(threatModelContext ? [threatModelContext, ""] : []),
    ...(appModelContext ? [appModelContext, ""] : []),
    ...(scenarioContext ? [scenarioContext, ""] : []),
    formatFileTreeForPrompt(fileIndex, patternMatchText.length > 0),
    formatPreReadForPrompt(preRead ?? { files: [], totalBytes: 0, truncated: false }),
    patternMatchText,
    "",
    "## Instructions",
    "1. Use the pre-loaded files and file tree above for initial analysis.",
    "2. Use Grep to find string-based security checks, broad exception handlers, and similar-looking config keys.",
    "3. Use Read to verify specific parameter confusion or error-handling issues.",
    `4. Return at most ${maxFindings} findings. Set persona to "confused-developer" for all findings.`,
    "",
    antiHallucinationModule({
      extra: [
        "Only report findings where parameter confusion, string comparison, or error handling issues lead to a concrete security bypass.",
        "Do NOT report general code quality issues or stylistic concerns.",
        "Do NOT report findings where types already prevent the confusion.",
        ...languageAntiHallucinationExtras({ taskId: "sharp-edges-detect", repoContext, frameworks: repoContext?.frameworks }),
      ],
    }),
    frameworkAwarenessModule(repoContext),
  ].filter(Boolean).join("\n");
}

// ---------------------------------------------------------------------------
// Lens runner
// ---------------------------------------------------------------------------

function runSharpEdgesLens(
  prompt: string,
  context: TaskContext,
  model: string,
  tag: string,
): Promise<LensResult> {
  return runLens(prompt, context, model, tag, SHARP_EDGES_SCHEMA);
}

// ---------------------------------------------------------------------------
// Finding normalization
// ---------------------------------------------------------------------------

function normalizeFindings(raw: unknown, repoRoot: string, repoName: string, maxFindings: number): Finding[] {
  if (!isRecord(raw) || !Array.isArray(raw["findings"])) return [];

  const deduped = new Map<string, Finding>();
  for (const item of raw["findings"] as unknown[]) {
    if (!isRecord(item)) continue;
    const f = item as unknown as SharpEdgesFinding;
    if (!f.filePath?.trim()) continue;

    const filePath = normalizeFilePath(repoRoot, f.filePath);
    const fingerprint = computeFingerprint(repoName, filePath, f);
    const cwe = CATEGORY_CWE[f.category] ?? "CWE-16";

    const finding: Finding = {
      taskId: "sharp-edges-detect",
      fingerprint,
      ruleId: `sharp-edges/${f.category || "unknown"}`,
      filePath,
      startLine: Math.max(1, Math.floor(Number(f.startLine) || 1)),
      severity: f.severity || "WARNING",
      message: `[${f.persona}] ${f.description || "API design footgun"}`,
      evidence: f.rationale || null,
      scannerConfidence: f.confidence || "MEDIUM",
      subcategory: ["vuln"],
      likelihood: f.confidence || "MEDIUM",
      impact: f.severity === "ERROR" ? "HIGH" : f.severity === "INFO" ? "LOW" : "MEDIUM",
      cwe: [cwe],
      score: scoreFindingMetadata({
        severity: f.severity,
        likelihood: f.confidence,
        impact: f.severity === "ERROR" ? "HIGH" : f.severity === "INFO" ? "LOW" : "MEDIUM",
        subcategory: ["vuln"],
        cwe: [cwe],
      }),
      proofState: "symbolic_only",
      engineProvenance: [{ kind: "agentic", detail: "LLM-driven sharp-edges-detect analysis" }],
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

function computeFingerprint(repoName: string, filePath: string, f: SharpEdgesFinding): string {
  return computeDetectionFingerprint([repoName, "sharp-edges-detect", f.category, filePath, String(f.startLine)]);
}

// ---------------------------------------------------------------------------
// Task definition
// ---------------------------------------------------------------------------

export const sharpEdgesDetectTask: AgentTask<ScanOpts, Finding[]> = {
  id: "sharp-edges-detect",
  displayName: "Sharp Edges Detector (Trail of Bits)",
  outputKind: "findings",
  dependsOn: ["context-gatherer", "app-model-build", "threat-scenario-build"],

  async run(_input, context): Promise<Finding[]> {
    const { model, maxFindings } = resolveConfig(context);
    const repoContext = coerceRepoContext(context.upstreamOutputs.get("context-gatherer"));
    const fileIndex = coerceFileIndex(context.upstreamOutputs.get("context-gatherer"));
    const preRead = await preReadFilesForTask("sharp-edges-detect", fileIndex, context.repoRoot);
    const profiles = context.securityProfiles
      ? getProfilesForTask(context.securityProfiles, "sharp-edges-detect")
      : [];
    const profileLines = formatProfilesForPrompt(profiles);
    const threatModelContext = buildThreatModelLeadsSection(
      "sharp-edges-detect",
      resolveThreatModelOutput(context.upstreamOutputs),
      fileIndex,
      preRead,
    );
    const applicationModel = context.upstreamOutputs.get("app-model-build") as ApplicationModel | undefined;
    const scenarioOutput = context.upstreamOutputs.get("threat-scenario-build");
    const appModelContext = buildApplicationModelSection("sharp-edges-detect", applicationModel);
    const scenarioContext = await buildThreatScenarioEvidenceSection("sharp-edges-detect", context.repoRoot, applicationModel, scenarioOutput);

    const tag = "[sharp-edges-detect]";
    const perLensMax = Math.ceil(maxFindings / 3);
    log.info(`Starting three-persona scan (model=${model})`);

    const lensPromises: Array<Promise<LensResult>> = [
      runSharpEdgesLens(
        buildScoundrelPrompt(repoContext, perLensMax, profileLines, fileIndex, preRead, threatModelContext, appModelContext, scenarioContext),
        context, model, `${tag}/scoundrel`,
      ).catch((error) => {
        log.error(`${tag}/scoundrel lens error: ${toErrorMessage(error)}`);
        return { output: { findings: [] }, costUsd: 0 };
      }),
      runSharpEdgesLens(
        buildLazyDeveloperPrompt(repoContext, perLensMax, profileLines, fileIndex, preRead, threatModelContext, appModelContext, scenarioContext),
        context, model, `${tag}/lazy-developer`,
      ).catch((error) => {
        log.error(`${tag}/lazy-developer lens error: ${toErrorMessage(error)}`);
        return { output: { findings: [] }, costUsd: 0 };
      }),
      runSharpEdgesLens(
        buildConfusedDeveloperPrompt(repoContext, perLensMax, profileLines, fileIndex, preRead, threatModelContext, appModelContext, scenarioContext),
        context, model, `${tag}/confused-developer`,
      ).catch((error) => {
        log.error(`${tag}/confused-developer lens error: ${toErrorMessage(error)}`);
        return { output: { findings: [] }, costUsd: 0 };
      }),
    ];

    const lensResults = await Promise.all(lensPromises);
    let totalCostUsd = 0;

    const allFindings: Finding[] = [];
    for (const result of lensResults) {
      totalCostUsd += result.costUsd;
      allFindings.push(...normalizeFindings(result.output, context.repoRoot, context.repoName, perLensMax));
    }

    return attachTaskOutputMeta(
      dedupAndRankFindings(allFindings, maxFindings),
      { costUsd: totalCostUsd },
    );
  },

  triageAgentConfig(finding: Finding, repoName: string): TriageAgentConfig {
    return {
      prompt: [
        `You are triaging an API sharp-edge finding in "${repoName}".`,
        "",
        `Rule: ${finding.ruleId}`,
        `File: ${finding.filePath}:${finding.startLine}`,
        `Message: ${finding.message}`,
        finding.evidence ? `Rationale: ${finding.evidence}` : "",
        "",
        "Verify this API design footgun is real and exploitable:",
        "- Is the insecure default/path actually reachable in production?",
        "- Can the config change/parameter confusion lead to a concrete security bypass?",
        "- Are there compensating controls elsewhere that mitigate this?",
      ].filter(Boolean).join("\n"),
    };
  },
};

// Exported for testing
export const __sharpEdgesDetectInternals = {
  resolveConfig,
  buildScoundrelPrompt,
  buildLazyDeveloperPrompt,
  buildConfusedDeveloperPrompt,
  normalizeFindings,
  computeFingerprint,
  runLens: runSharpEdgesLens,
};
