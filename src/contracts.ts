/**
 * Stable wire-value contracts shared by API DTOs, event payloads, schemas,
 * persistence, and UI consumers.
 *
 * Keep these arrays append-only unless a release explicitly migrates persisted
 * data and serialized API responses. Types are derived from the arrays so the
 * runtime validators and TypeScript surface cannot drift independently.
 */

export const VERDICTS = ["tp", "fp", "needs_review", "by_design"] as const;
export type Verdict = (typeof VERDICTS)[number];

export const DISPLAY_SEVERITIES = ["critical", "high", "medium", "low"] as const;
export type DisplaySeverity = (typeof DISPLAY_SEVERITIES)[number];

export const BUS_BACKENDS = ["in-process"] as const;
export type BusBackend = (typeof BUS_BACKENDS)[number];

export const SCAN_MODES = ["sequential", "concurrent"] as const;
export type ScanMode = (typeof SCAN_MODES)[number];

export const PROOF_VERDICTS = [
  "exploited",
  "blocked_by_security",
  "out_of_scope",
  "false_positive",
] as const;
export type ProofVerdict = (typeof PROOF_VERDICTS)[number];

export const POC_EXECUTION_VERDICTS = ["PASS", "FAIL", "ERROR", "TIMEOUT"] as const;
export type PocExecutionVerdict = (typeof POC_EXECUTION_VERDICTS)[number];

export const POC_SANDBOX_BACKENDS = ["docker", "process"] as const;
export type PocSandboxBackend = (typeof POC_SANDBOX_BACKENDS)[number];

export const TRIAGE_STRATEGIES = ["single", "multi-agent"] as const;
export type TriageStrategy = (typeof TRIAGE_STRATEGIES)[number];

export const DATA_SENSITIVITIES = ["public", "internal", "confidential", "restricted"] as const;
export type DataSensitivity = (typeof DATA_SENSITIVITIES)[number];

export const EXPLOIT_CHAIN_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM"] as const;
export type ExploitChainSeverity = (typeof EXPLOIT_CHAIN_SEVERITIES)[number];

export const PROOF_STATES = [
  "symbolic_only",
  "execution_attempted",
  "execution_confirmed",
  "execution_rejected",
  "inconclusive",
] as const;
export type ProofState = (typeof PROOF_STATES)[number];

export const PROOF_STATE_PRECEDENCE = {
  symbolic_only: 0,
  inconclusive: 1,
  execution_attempted: 2,
  execution_rejected: 3,
  execution_confirmed: 4,
} as const satisfies Record<ProofState, number>;

export const ENGINE_PROVENANCE_KINDS = [
  "semgrep",
  "codeql",
  "taint-analysis",
  "agentic",
  "dynamic",
] as const;
export type EngineProvenanceKind = (typeof ENGINE_PROVENANCE_KINDS)[number];

export const DYNAMIC_ANALYSIS_STATUSES = ["confirmed", "interesting", "rejected", "error"] as const;
export type DynamicAnalysisStatus = (typeof DYNAMIC_ANALYSIS_STATUSES)[number];

export const DYNAMIC_COVERAGE_MODES = ["none", "node-v8", "python-coverage"] as const;
export type DynamicCoverageMode = (typeof DYNAMIC_COVERAGE_MODES)[number];

export const PATCH_STATUSES = [
  "APPLY_FAILED",
  "BUILD_FAILED",
  "STILL_VULNERABLE",
  "TESTS_FAILED",
  "SOUND",
  "VERIFIED",
  "UNKNOWN",
] as const;
export type PatchStatus = (typeof PATCH_STATUSES)[number];

export const PIPELINE_RUN_STATUSES = [
  "scanning",
  "triaging",
  "verifying",
  "poc-harnessing",
  "dynamic-analyzing",
  "interrupted",
  "complete",
  "error",
  "aborted",
] as const;
export type PipelineRunStatus = (typeof PIPELINE_RUN_STATUSES)[number];

export const ACTIVE_PIPELINE_RUN_STATUSES = [
  "scanning",
  "triaging",
  "verifying",
  "poc-harnessing",
  "dynamic-analyzing",
] as const satisfies readonly PipelineRunStatus[];

export const REPORT_MODES = ["full", "suppress"] as const;
export type ReportMode = (typeof REPORT_MODES)[number];

export function isOneOf<const T extends readonly string[]>(
  values: T,
  value: string | null | undefined,
): value is T[number] {
  return typeof value === "string" && (values as readonly string[]).includes(value);
}
