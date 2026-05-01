/**
 * Declarative catalog of editable KuzushiConfig fields, grouped into sections
 * for the interactive `/config` editor.
 *
 * Adding a new config option? Append a descriptor here. Anything not listed
 * is still surfaced under the synthetic "Other" section at runtime, so no
 * field can silently disappear from the UI.
 */
import { BUS_BACKENDS } from "../../config/defaults.js";

export type SectionId =
  | "runtime"
  | "scan"
  | "triage"
  | "verify"
  | "poc"
  | "report"
  | "advanced"
  | "tasks"
  | "other";

export interface SectionMeta {
  id: SectionId;
  title: string;
  description: string;
}

export const SECTIONS: ReadonlyArray<SectionMeta> = [
  {
    id: "runtime",
    title: "Runtime & Model",
    description: "Default model, runtime backend, message bus.",
  },
  {
    id: "scan",
    title: "Scan Pipeline",
    description: "Tasks, scan mode, severity filters, exclusions, caching.",
  },
  {
    id: "triage",
    title: "Triage",
    description: "Triage concurrency, batching, FP filtering, strategy.",
  },
  {
    id: "verify",
    title: "Verification",
    description: "Post-triage exploitability verification stage.",
  },
  { id: "poc", title: "PoC Harness", description: "Proof-of-concept generation and execution." },
  { id: "report", title: "Reporting & Output", description: "Report file outputs and audit log." },
  {
    id: "advanced",
    title: "Advanced / Experimental",
    description: "Variants, multi-strategy, taint, dynamic, patching.",
  },
  { id: "tasks", title: "Task Config", description: "Per-task overrides keyed by task id." },
  { id: "other", title: "Other", description: "Fields without a registered descriptor." },
];

export type FieldType =
  | { kind: "bool" }
  | { kind: "number"; min?: number; max?: number; integer?: boolean; nullable?: boolean }
  | { kind: "string"; optional?: boolean }
  | { kind: "stringList" }
  | { kind: "enum"; values: ReadonlyArray<string>; multi?: boolean }
  | { kind: "object" };

export interface FieldDescriptor {
  /** Dotted path into KuzushiConfig (e.g. "verify", "taskConfig.taint-analysis.tiMode"). */
  path: string;
  /** Display label shown to the user. */
  label: string;
  /** One-line description shown beneath the value. */
  description: string;
  section: SectionId;
  type: FieldType;
}

const VERDICTS = ["tp", "fp", "needs_review"] as const;
const SEVERITIES = ["ERROR", "WARNING", "INFO"] as const;

export const FIELDS: ReadonlyArray<FieldDescriptor> = [
  // ── Runtime & Model ─────────────────────────────────────────────────────
  {
    path: "model",
    section: "runtime",
    label: "model",
    description: "Default LLM identifier (e.g. anthropic:claude-sonnet-4-6).",
    type: { kind: "string" },
  },
  {
    path: "busBackend",
    section: "runtime",
    label: "busBackend",
    description: "Pipeline event bus backend.",
    type: { kind: "enum", values: [...BUS_BACKENDS] },
  },
  {
    path: "ensembleModels",
    section: "runtime",
    label: "ensembleModels",
    description: "Optional ensemble models for eligible agentic tasks.",
    type: { kind: "stringList" },
  },
  {
    path: "costBudgetUsd",
    section: "runtime",
    label: "costBudgetUsd",
    description: "Hard cap on pipeline LLM spend in USD.",
    type: { kind: "number", min: 0, nullable: true },
  },

  // ── Scan Pipeline ───────────────────────────────────────────────────────
  {
    path: "scanMode",
    section: "scan",
    label: "scanMode",
    description: "Sequential or concurrent scanner execution.",
    type: { kind: "enum", values: ["sequential", "concurrent"] },
  },
  {
    path: "tasks",
    section: "scan",
    label: "tasks",
    description: "Enabled task IDs in execution order.",
    type: { kind: "stringList" },
  },
  {
    path: "severity",
    section: "scan",
    label: "severity",
    description: "Severity levels surfaced from scanners.",
    type: { kind: "enum", values: SEVERITIES, multi: true },
  },
  {
    path: "excludePatterns",
    section: "scan",
    label: "excludePatterns",
    description: "Path patterns excluded from scanning.",
    type: { kind: "stringList" },
  },
  {
    path: "diffBase",
    section: "scan",
    label: "diffBase",
    description: "Git ref for differential review (e.g. main).",
    type: { kind: "string", optional: true },
  },
  {
    path: "enableContextGathering",
    section: "scan",
    label: "enableContextGathering",
    description: "Run pre-scan repository context gathering.",
    type: { kind: "bool" },
  },
  {
    path: "enableContextEnrichment",
    section: "scan",
    label: "enableContextEnrichment",
    description: "Run LLM context enrichment task.",
    type: { kind: "bool" },
  },
  {
    path: "enableDynamicTaskSelection",
    section: "scan",
    label: "enableDynamicTaskSelection",
    description: "Choose tasks dynamically based on repo context.",
    type: { kind: "bool" },
  },
  {
    path: "prioritizeFindings",
    section: "scan",
    label: "prioritizeFindings",
    description: "Sort findings by score before triage.",
    type: { kind: "bool" },
  },
  {
    path: "incrementalCache",
    section: "scan",
    label: "incrementalCache",
    description: "Reuse cached results for unchanged inputs.",
    type: { kind: "bool" },
  },
  {
    path: "incrementalDepTracking",
    section: "scan",
    label: "incrementalDepTracking",
    description: "Track dependency edges for incremental invalidation.",
    type: { kind: "bool" },
  },
  {
    path: "incrementalCacheTtlDays",
    section: "scan",
    label: "incrementalCacheTtlDays",
    description: "Days before cached results are considered stale.",
    type: { kind: "number", min: 1, integer: true },
  },

  // ── Triage ──────────────────────────────────────────────────────────────
  {
    path: "triageConcurrency",
    section: "triage",
    label: "triageConcurrency",
    description: "In-flight triage workers.",
    type: { kind: "number", min: 1, integer: true },
  },
  {
    path: "triageBatchSize",
    section: "triage",
    label: "triageBatchSize",
    description: "Findings per triage LLM call.",
    type: { kind: "number", min: 1, integer: true },
  },
  {
    path: "triageMaxFindings",
    section: "triage",
    label: "triageMaxFindings",
    description: "Cap on findings entering triage.",
    type: { kind: "number", min: 1, integer: true },
  },
  {
    path: "triageMinScore",
    section: "triage",
    label: "triageMinScore",
    description: "Minimum score (0-100) to enter triage.",
    type: { kind: "number", min: 0, max: 100, integer: true },
  },
  {
    path: "maxTriageRetries",
    section: "triage",
    label: "maxTriageRetries",
    description: "Retries on transient triage worker failure.",
    type: { kind: "number", min: 0, integer: true },
  },
  {
    path: "enforceTriageEvidence",
    section: "triage",
    label: "enforceTriageEvidence",
    description: "Re-prompt triage when evidence is thin.",
    type: { kind: "bool" },
  },
  {
    path: "fpFilterEnabled",
    section: "triage",
    label: "fpFilterEnabled",
    description: "Hard FP suppression filter pre-triage.",
    type: { kind: "bool" },
  },
  {
    path: "fpFilterCustomExclusions",
    section: "triage",
    label: "fpFilterCustomExclusions",
    description: "Additional regex patterns for FP suppression.",
    type: { kind: "stringList" },
  },
  {
    path: "designDecisionClassifier",
    section: "triage",
    label: "designDecisionClassifier",
    description: "Auto-classify by-design verdicts pre-triage.",
    type: { kind: "bool" },
  },
  {
    path: "llmRescoreEnabled",
    section: "triage",
    label: "llmRescoreEnabled",
    description: "Two-stage LLM rescoring after FP filter.",
    type: { kind: "bool" },
  },
  {
    path: "llmRescoreThreshold",
    section: "triage",
    label: "llmRescoreThreshold",
    description: "Min rescore (0-10) to keep a finding.",
    type: { kind: "number", min: 0, max: 10 },
  },
  {
    path: "triageStrategy",
    section: "triage",
    label: "triageStrategy",
    description: "Single-agent or multi-agent triage panel.",
    type: { kind: "enum", values: ["single", "multi-agent"] },
  },
  {
    path: "triageSpecialistMaxTurns",
    section: "triage",
    label: "triageSpecialistMaxTurns",
    description: "Max turns per specialist sub-agent (null = unlimited).",
    type: { kind: "number", min: 1, integer: true, nullable: true },
  },
  {
    path: "skipTriageForHighConfidenceAgentic",
    section: "triage",
    label: "skipTriageForHighConfidenceAgentic",
    description: "Bypass triage for high-confidence agentic findings.",
    type: { kind: "bool" },
  },

  // ── Verification ────────────────────────────────────────────────────────
  {
    path: "verify",
    section: "verify",
    label: "verify",
    description: "Run post-triage exploitability verification.",
    type: { kind: "bool" },
  },
  {
    path: "verifyMaxTurns",
    section: "verify",
    label: "verifyMaxTurns",
    description: "Max turns per verification agent.",
    type: { kind: "number", min: 1, integer: true, nullable: true },
  },
  {
    path: "verifyConcurrency",
    section: "verify",
    label: "verifyConcurrency",
    description: "In-flight verification workers.",
    type: { kind: "number", min: 1, integer: true },
  },
  {
    path: "verifyBatchSize",
    section: "verify",
    label: "verifyBatchSize",
    description: "Findings per verification LLM call.",
    type: { kind: "number", min: 1, integer: true },
  },
  {
    path: "verifyVerdicts",
    section: "verify",
    label: "verifyVerdicts",
    description: "Triage verdicts that enter verification.",
    type: { kind: "enum", values: VERDICTS, multi: true },
  },
  {
    path: "verifyMinConfidence",
    section: "verify",
    label: "verifyMinConfidence",
    description: "Minimum triage confidence (0-1) to verify.",
    type: { kind: "number", min: 0, max: 1 },
  },
  {
    path: "verifyGateEnabled",
    section: "verify",
    label: "verifyGateEnabled",
    description: "Cheap LLM gate to decide verify/auto-accept/skip.",
    type: { kind: "bool" },
  },
  {
    path: "maxVerifyRetries",
    section: "verify",
    label: "maxVerifyRetries",
    description: "Retries on transient verification worker failure.",
    type: { kind: "number", min: 0, integer: true },
  },
  {
    path: "verifyRefinementMaxIterations",
    section: "verify",
    label: "verifyRefinementMaxIterations",
    description: "Max refinement iterations under execution feedback.",
    type: { kind: "number", min: 1, integer: true },
  },
  {
    path: "verifyReflectionInterval",
    section: "verify",
    label: "verifyReflectionInterval",
    description: "Reflection guidance every N failed attempts.",
    type: { kind: "number", min: 1, integer: true },
  },

  // ── PoC Harness ─────────────────────────────────────────────────────────
  {
    path: "pocHarness",
    section: "poc",
    label: "pocHarness",
    description: "Run post-verification PoC harness generation.",
    type: { kind: "bool" },
  },
  {
    path: "pocHarnessMaxTurns",
    section: "poc",
    label: "pocHarnessMaxTurns",
    description: "Max turns per PoC harness agent.",
    type: { kind: "number", min: 1, integer: true, nullable: true },
  },
  {
    path: "pocHarnessConcurrency",
    section: "poc",
    label: "pocHarnessConcurrency",
    description: "In-flight PoC harness workers.",
    type: { kind: "number", min: 1, integer: true },
  },
  {
    path: "maxPocHarnessRetries",
    section: "poc",
    label: "maxPocHarnessRetries",
    description: "Retries on transient PoC worker failure.",
    type: { kind: "number", min: 0, integer: true },
  },
  {
    path: "pocExecute",
    section: "poc",
    label: "pocExecute",
    description: "Execute generated PoC harnesses.",
    type: { kind: "bool" },
  },
  {
    path: "pocSandbox",
    section: "poc",
    label: "pocSandbox",
    description: "Sandbox backend for PoC execution.",
    type: { kind: "enum", values: ["docker", "process"] },
  },
  {
    path: "pocExecTimeoutMs",
    section: "poc",
    label: "pocExecTimeoutMs",
    description: "Per-PoC execution timeout in ms.",
    type: { kind: "number", min: 1, integer: true },
  },
  {
    path: "pocRefinementMaxIterations",
    section: "poc",
    label: "pocRefinementMaxIterations",
    description: "Max PoC refinement iterations.",
    type: { kind: "number", min: 1, integer: true },
  },
  {
    path: "pocReflectionInterval",
    section: "poc",
    label: "pocReflectionInterval",
    description: "Reflection guidance every N failed PoC attempts.",
    type: { kind: "number", min: 1, integer: true },
  },

  // ── Reporting & Output ──────────────────────────────────────────────────
  {
    path: "reportOutput",
    section: "report",
    label: "reportOutput",
    description: "Markdown report output path.",
    type: { kind: "string", optional: true },
  },
  {
    path: "sarifOutput",
    section: "report",
    label: "sarifOutput",
    description: "SARIF report output path.",
    type: { kind: "string", optional: true },
  },
  {
    path: "jsonOutput",
    section: "report",
    label: "jsonOutput",
    description: "JSON report output path.",
    type: { kind: "string", optional: true },
  },
  {
    path: "csvOutput",
    section: "report",
    label: "csvOutput",
    description: "CSV report output path.",
    type: { kind: "string", optional: true },
  },
  {
    path: "jsonlOutput",
    section: "report",
    label: "jsonlOutput",
    description: "JSONL report output path.",
    type: { kind: "string", optional: true },
  },
  {
    path: "auditLog",
    section: "report",
    label: "auditLog",
    description: "Persist per-run JSONL audit logs.",
    type: { kind: "bool" },
  },

  // ── Advanced / Experimental ─────────────────────────────────────────────
  {
    path: "variantAnalysis",
    section: "advanced",
    label: "variantAnalysis",
    description: "Run post-triage variant analysis.",
    type: { kind: "bool" },
  },
  {
    path: "variantAnalysisMaxFindings",
    section: "advanced",
    label: "variantAnalysisMaxFindings",
    description: "Cap on variant findings per confirmed TP.",
    type: { kind: "number", min: 1, integer: true },
  },
  {
    path: "variantRuleSweepEnabled",
    section: "advanced",
    label: "variantRuleSweepEnabled",
    description: "Sweep codebase with generated custom rules.",
    type: { kind: "bool" },
  },
  {
    path: "autoRuleGeneration",
    section: "advanced",
    label: "autoRuleGeneration",
    description: "Generate Semgrep rules from verified TPs.",
    type: { kind: "bool" },
  },
  {
    path: "multiStrategyMode",
    section: "advanced",
    label: "multiStrategyMode",
    description: "Multi-strategy analysis mode.",
    type: { kind: "enum", values: ["off", "adaptive", "full"] },
  },
  {
    path: "multiStrategyBudgetUsd",
    section: "advanced",
    label: "multiStrategyBudgetUsd",
    description: "USD budget per finding across all strategies.",
    type: { kind: "number", min: 0 },
  },
  {
    path: "multiStrategyPerStrategyBudgetUsd",
    section: "advanced",
    label: "multiStrategyPerStrategyBudgetUsd",
    description: "USD budget per individual strategy.",
    type: { kind: "number", min: 0 },
  },
  {
    path: "multiStrategyTimeoutMs",
    section: "advanced",
    label: "multiStrategyTimeoutMs",
    description: "Per-strategy timeout in ms.",
    type: { kind: "number", min: 1, integer: true },
  },
  {
    path: "multiStrategyAutoRuleGeneration",
    section: "advanced",
    label: "multiStrategyAutoRuleGeneration",
    description: "Auto-generate rules from confirmed multi-strategy findings.",
    type: { kind: "bool" },
  },
  {
    path: "multiStrategyRescanWithRules",
    section: "advanced",
    label: "multiStrategyRescanWithRules",
    description: "Rescan codebase with generated rules.",
    type: { kind: "bool" },
  },
  {
    path: "taintDiffBase",
    section: "advanced",
    label: "taintDiffBase",
    description: "Git ref for taint differential slicing.",
    type: { kind: "string", optional: true },
  },
  {
    path: "taintDiffMode",
    section: "advanced",
    label: "taintDiffMode",
    description: "Differential taint behavior when diffBase is set.",
    type: { kind: "enum", values: ["delta", "baseline"] },
  },
  {
    path: "taintGroundingEnabled",
    section: "advanced",
    label: "taintGroundingEnabled",
    description: "Deterministic grounding for taint supplements.",
    type: { kind: "bool" },
  },
  {
    path: "astIndexEnabled",
    section: "advanced",
    label: "astIndexEnabled",
    description: "Cheap structural index support layer.",
    type: { kind: "bool" },
  },
  {
    path: "callGraphAssistEnabled",
    section: "advanced",
    label: "callGraphAssistEnabled",
    description: "Call-graph assist enrichment for high-value findings.",
    type: { kind: "bool" },
  },
  {
    path: "codeGraphEnabled",
    section: "advanced",
    label: "codeGraphEnabled",
    description: "LLM-powered code graph build/enrich.",
    type: { kind: "bool" },
  },
  {
    path: "chainAnalysis",
    section: "advanced",
    label: "chainAnalysis",
    description: "Post-triage exploitation chain analysis.",
    type: { kind: "bool" },
  },
  {
    path: "dynamicAnalysisEnabled",
    section: "advanced",
    label: "dynamicAnalysisEnabled",
    description: "Targeted dynamic analysis tasks.",
    type: { kind: "bool" },
  },
  {
    path: "coverageGuidedEnabled",
    section: "advanced",
    label: "coverageGuidedEnabled",
    description: "Coverage-guided refinement in dynamic lane.",
    type: { kind: "bool" },
  },
  {
    path: "dynamicMaxIterations",
    section: "advanced",
    label: "dynamicMaxIterations",
    description: "Max refinement iterations for dynamic tasks.",
    type: { kind: "number", min: 1, integer: true },
  },
  {
    path: "dynamicMaxCandidates",
    section: "advanced",
    label: "dynamicMaxCandidates",
    description: "Max findings routed into dynamic lane.",
    type: { kind: "number", min: 1, integer: true },
  },
  {
    path: "dynamicMinScore",
    section: "advanced",
    label: "dynamicMinScore",
    description: "Min ranking score for dynamic candidates.",
    type: { kind: "number", min: 0 },
  },
  {
    path: "dynamicPerFindingBudgetUsd",
    section: "advanced",
    label: "dynamicPerFindingBudgetUsd",
    description: "Per-finding USD budget for dynamic analysis.",
    type: { kind: "number", min: 0 },
  },
  {
    path: "cryptoBehavioralTestEnabled",
    section: "advanced",
    label: "cryptoBehavioralTestEnabled",
    description: "Crypto behavioral runtime confirmation.",
    type: { kind: "bool" },
  },
  {
    path: "cryptoBehavioralTimeoutMs",
    section: "advanced",
    label: "cryptoBehavioralTimeoutMs",
    description: "Crypto behavioral harness timeout in ms.",
    type: { kind: "number", min: 1, integer: true },
  },
  {
    path: "cryptoBehavioralMaxFindings",
    section: "advanced",
    label: "cryptoBehavioralMaxFindings",
    description: "Max crypto findings routed into behavioral test.",
    type: { kind: "number", min: 1, integer: true },
  },
  {
    path: "cryptoBehavioralPerFindingBudgetUsd",
    section: "advanced",
    label: "cryptoBehavioralPerFindingBudgetUsd",
    description: "Per-finding USD budget for crypto behavioral test.",
    type: { kind: "number", min: 0 },
  },
  {
    path: "patchingEnabled",
    section: "advanced",
    label: "patchingEnabled",
    description: "Patch synthesis and validation pipeline.",
    type: { kind: "bool" },
  },
  {
    path: "patchMaxIterations",
    section: "advanced",
    label: "patchMaxIterations",
    description: "Max patch synthesis iterations.",
    type: { kind: "number", min: 1, integer: true },
  },
  {
    path: "patchBuildCommand",
    section: "advanced",
    label: "patchBuildCommand",
    description: "Build command override for patch validation.",
    type: { kind: "string", optional: true },
  },
  {
    path: "patchTestCommand",
    section: "advanced",
    label: "patchTestCommand",
    description: "Test command override for patch validation.",
    type: { kind: "string", optional: true },
  },
  {
    path: "autoPatchEnabled",
    section: "advanced",
    label: "autoPatchEnabled",
    description: "Auto-generate patches in pipeline.",
    type: { kind: "bool" },
  },
  {
    path: "autoPatchAfter",
    section: "advanced",
    label: "autoPatchAfter",
    description: "Trigger threshold for auto-patch.",
    type: { kind: "enum", values: ["verify", "poc", "triage"] },
  },
  {
    path: "patchVerifyDepth",
    section: "advanced",
    label: "patchVerifyDepth",
    description: "Depth of re-verification after patching.",
    type: { kind: "enum", values: ["task", "triage", "full"] },
  },
  {
    path: "patchConcurrency",
    section: "advanced",
    label: "patchConcurrency",
    description: "Max concurrent patch synthesis tasks.",
    type: { kind: "number", min: 1, integer: true },
  },
  {
    path: "confidenceCalibration",
    section: "advanced",
    label: "confidenceCalibration",
    description: "Per-step confidence calibration.",
    type: { kind: "bool" },
  },
  {
    path: "trajectoryMemory",
    section: "advanced",
    label: "trajectoryMemory",
    description: "Cross-run trajectory exemplars in triage prompt.",
    type: { kind: "bool" },
  },
  {
    path: "trajectoryMaxExemplars",
    section: "advanced",
    label: "trajectoryMaxExemplars",
    description: "Max trajectory exemplars injected.",
    type: { kind: "number", min: 0, integer: true },
  },
  {
    path: "streamingEnabled",
    section: "advanced",
    label: "streamingEnabled",
    description: "Enable streaming bus output.",
    type: { kind: "bool" },
  },
  {
    path: "streamingPort",
    section: "advanced",
    label: "streamingPort",
    description: "Port for streaming output (0 = auto).",
    type: { kind: "number", min: 0, integer: true },
  },
  {
    path: "precedentsPath",
    section: "advanced",
    label: "precedentsPath",
    description: "Path to organization precedents file.",
    type: { kind: "string", optional: true },
  },
  {
    path: "securityProfilesPath",
    section: "advanced",
    label: "securityProfilesPath",
    description: "Path to security profiles file.",
    type: { kind: "string", optional: true },
  },
  {
    path: "triagePromptFile",
    section: "advanced",
    label: "triagePromptFile",
    description: "Custom triage prompt file path.",
    type: { kind: "string", optional: true },
  },
  {
    path: "verifyPromptFile",
    section: "advanced",
    label: "verifyPromptFile",
    description: "Custom verification prompt file path.",
    type: { kind: "string", optional: true },
  },
  {
    path: "retryBackoffMs",
    section: "advanced",
    label: "retryBackoffMs",
    description: "Initial retry backoff in ms.",
    type: { kind: "number", min: 0, integer: true },
  },
  {
    path: "retryBackoffMultiplier",
    section: "advanced",
    label: "retryBackoffMultiplier",
    description: "Backoff multiplier per retry attempt.",
    type: { kind: "number", min: 0 },
  },
];

const FIELD_PATHS = new Set(FIELDS.map((f) => f.path));

/**
 * Returns true if `key` (a top-level KuzushiConfig key) is registered as a
 * descriptor or is `taskConfig` (handled separately as a drill-down section).
 * Anything else falls into the "Other" catch-all.
 */
export function isKnownTopLevelField(key: string): boolean {
  return FIELD_PATHS.has(key) || key === "taskConfig";
}

/** Lookup a descriptor by exact path. */
export function getFieldDescriptor(path: string): FieldDescriptor | undefined {
  return FIELDS.find((f) => f.path === path);
}

/** All descriptors in a section, in declared order. */
export function fieldsInSection(section: SectionId): ReadonlyArray<FieldDescriptor> {
  return FIELDS.filter((f) => f.section === section);
}

/** Infer a reasonable FieldType for an unknown leaf value (used for "Other" and taskConfig drill-down). */
export function inferFieldType(value: unknown): FieldType {
  if (typeof value === "boolean") return { kind: "bool" };
  if (typeof value === "number") return { kind: "number" };
  if (typeof value === "string") return { kind: "string", optional: true };
  if (Array.isArray(value)) return { kind: "stringList" };
  if (value && typeof value === "object") return { kind: "object" };
  return { kind: "string", optional: true };
}
