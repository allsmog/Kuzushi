import type { ThreatModelDocument } from "../../agents/tasks/threat-modeling/types.js";
import type { Finding } from "../../scanners/types.js";
import type { RepoContext } from "../../types.js";
import type {
  RankedTaintIrisNextCweCatalogEntry,
  TaintIrisNextStructuralQuery,
} from "./cwe-reference.js";

export type TaintIrisNextMode = "plan" | "hunt";
export type TaintIrisNextBackend =
  | "auto"
  | "structural"
  | "codeql"
  | "semgrep"
  | "joern"
  | "language";

export interface TaintIrisNextInput {
  target?: string;
  backend?: TaintIrisNextBackend;
  mode?: TaintIrisNextMode;
  languages?: string[];
  maxCwes?: number;
  maxCatalogEntries?: number;
  maxCandidatesPerCwe?: number;
  maxEvidencePerCwe?: number;
  maxFilesPerQuery?: number;
  maxSpecsPerCwe?: number;
  maxAgentFindings?: number;
  codeqlAnalyzeTimeoutMs?: number;
  minEvidenceLevel?: TaintIrisNextMinEvidenceLevel;
  maxBudgetUsd?: number;
}

export type TaintIrisNextMinEvidenceLevel = "path" | "linked" | "candidate";

export interface TaintIrisNextCaps {
  maxCatalogEntries: number;
  maxCandidatesPerCwe: number;
  maxEvidencePerCwe: number;
  maxFilesPerQuery: number;
  maxSpecsPerCwe: number;
  maxAgentFindings: number;
  codeqlAnalyzeTimeoutMs: number;
  minEvidenceLevel: TaintIrisNextMinEvidenceLevel;
}

export interface TaintIrisNextBackendChoice {
  requested: TaintIrisNextBackend;
  selected: Exclude<TaintIrisNextBackend, "auto">;
  codeqlDbPath?: string;
  corroborateWithCodeql?: boolean;
  structuralTool: "rg" | "ast-grep";
  warnings: string[];
}

export interface TaintIrisNextPlan {
  target: string;
  scanRoot: string;
  repoRoot: string;
  mode: TaintIrisNextMode;
  caps: TaintIrisNextCaps;
  languages: string[];
  contextStatus: TaintIrisNextArtifactStatus;
  threatModelStatus: TaintIrisNextArtifactStatus;
  repoContext?: RepoContext;
  threatModel?: ThreatModelDocument;
  catalog: RankedTaintIrisNextCweCatalogEntry[];
  structuralQueries: TaintIrisNextStructuralQuery[];
  promptCatalog: string;
  backend: TaintIrisNextBackendChoice;
  maxBudgetUsd?: number;
}

export interface TaintIrisNextArtifactStatus {
  ok: boolean;
  path?: string;
  reason: string;
}

export type TaintIrisNextEvidenceConfidence = "low" | "medium" | "high";
export type TaintIrisNextEvidenceRole = TaintIrisNextStructuralQuery["role"];
export type TaintIrisNextEvidenceLevel = "candidate" | "linked" | "path";
export type TaintIrisNextAgentStatus =
  | "valid-json"
  | "repaired-json"
  | "invalid-json"
  | "no-selection"
  | "no-selection-fallback";
export type TaintIrisNextCweTrack = "taint" | "control";
export type TaintIrisNextSpecRole = "source" | "sink" | "sanitizer" | "propagator";
export type TaintIrisNextSpecKind =
  | "internal-param-source"
  | "external-return-source"
  | "external-arg-sink"
  | "sanitizer"
  | "propagator"
  | "guard"
  | "control-context";

export interface TaintIrisNextCandidate {
  id: string;
  cwe: string;
  taintClass: string;
  track: TaintIrisNextCweTrack;
  role: TaintIrisNextEvidenceRole;
  kind: TaintIrisNextSpecKind;
  pattern: string;
  filePath: string;
  line: number;
  snippet: string;
  language: string;
  confidence: TaintIrisNextEvidenceConfidence;
  catalogSignal: string;
  source: "structural" | "context" | "codeql";
  enclosingSymbol?: string;
  callExpression?: string;
  assignedVariable?: string;
  argumentIndex?: number;
  receiver?: string;
  nearbySanitizers?: string[];
}

export interface TaintIrisNextLabeledSpec {
  id: string;
  cwe: string;
  taintClass: string;
  track: TaintIrisNextCweTrack;
  role: TaintIrisNextSpecRole;
  kind: TaintIrisNextSpecKind;
  apiName: string;
  pattern: string;
  filePath?: string;
  line?: number;
  argumentIndex?: number;
  parameterIndex?: number;
  confidence: TaintIrisNextEvidenceConfidence;
  rationale: string;
  catalogSignal: string;
}

export interface TaintIrisNextEvidence {
  cwe: string;
  taintClass: string;
  track?: TaintIrisNextCweTrack;
  role: TaintIrisNextEvidenceRole;
  pattern: string;
  filePath: string;
  line: number;
  snippet: string;
  language: string;
  confidence: TaintIrisNextEvidenceConfidence;
  catalogSignal: string;
  evidenceLevel?: TaintIrisNextEvidenceLevel;
  source?: "structural" | "codeql" | "agent" | "context";
  candidateId?: string;
  linkedStoryId?: string;
  enclosingSymbol?: string;
  callExpression?: string;
  assignedVariable?: string;
  argumentIndex?: number;
  receiver?: string;
  nearbySanitizers?: string[];
}

export interface TaintIrisNextLinkedStory {
  id: string;
  cwe: string;
  taintClass: string;
  track: TaintIrisNextCweTrack;
  evidenceLevel: "linked";
  filePath: string;
  language: string;
  sourceCandidateId: string;
  sinkCandidateId: string;
  sourceLine: number;
  sinkLine: number;
  sharedTokens: string[];
  enclosingSymbol?: string;
  sanitizerCandidateIds?: string[];
  rationale: string;
}

export interface TaintIrisNextPhaseCounts {
  [cwe: string]: number;
}

export interface TaintIrisNextTriageSummary {
  finding: number;
  candidate: number;
  rejected: number;
}

export type TaintIrisNextOutcome =
  | "missing-context"
  | "planned"
  | "codeql-paths-produced"
  | "linked-evidence"
  | "candidate-only"
  | "backend-no-paths"
  | "agent-no-selection"
  | "agent-output-invalid"
  | "timeout-fallback"
  | "structural-only";

export interface TaintIrisNextEvidenceResult {
  backend: Exclude<TaintIrisNextBackend, "auto">;
  tool: "rg" | "ast-grep" | "codeql" | "semgrep" | "joern" | "language";
  evidence: TaintIrisNextEvidence[];
  candidates: TaintIrisNextCandidate[];
  linkedStories: TaintIrisNextLinkedStory[];
  labeledSpecs: TaintIrisNextLabeledSpec[];
  queryCount: number;
  candidateCounts: TaintIrisNextPhaseCounts;
  labeledSpecCounts: TaintIrisNextPhaseCounts;
  linkedStoryCount: number;
  backendPathCount: number;
  structuralEngine: "rg" | "ast-grep";
  triageSummary: TaintIrisNextTriageSummary;
  outcome: TaintIrisNextOutcome;
  legacyComparisonStatus?: string;
  warnings: string[];
  artifacts?: {
    codeqlLanguage?: string;
    codeqlQueryPath?: string;
    codeqlQueryPaths?: string[];
    codeqlCompileStatus?: "not-run" | "passed" | "failed";
    codeqlQueryStatuses?: Array<{
      cwe: string;
      queryPath: string;
      compileStatus: "not-run" | "passed" | "failed";
      analyzeStatus: "not-run" | "passed" | "failed";
      evidenceRows: number;
      warning?: string;
    }>;
  };
}

export interface TaintIrisNextAgentSelection {
  cwe: string;
  reason?: string;
  signalCitations?: readonly string[];
  catalogSignals?: readonly string[];
  sourceSpec?: string;
  sinkSpec?: string;
  sanitizerSpec?: string;
  customCweRationale?: string;
}

export interface TaintIrisNextAgentFinding {
  title: string;
  cwe: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  confidence?: "high" | "medium" | "low";
  evidenceLevel?: TaintIrisNextEvidenceLevel;
  filePath: string;
  startLine: number;
  message: string;
  sourceSinkTrace: string;
  catalogSignals?: string[];
  customCweRationale?: string;
  taintPath?: Array<{
    filePath: string;
    line: number;
    message?: string;
    snippet?: string;
  }>;
}

export interface TaintIrisNextAgentTriageDecision {
  status: "finding" | "candidate" | "rejected";
  cwe: string;
  evidenceLevel: TaintIrisNextEvidenceLevel;
  rationale: string;
  filePath?: string;
  line?: number;
  catalogSignals?: string[];
}

export interface TaintIrisNextAgentOutput {
  selectedCwes: TaintIrisNextAgentSelection[];
  findings: TaintIrisNextAgentFinding[];
  triage: TaintIrisNextAgentTriageDecision[];
  notes?: string[];
}

export interface TaintIrisNextAgentResult {
  agentRuntimeBackend: string;
  agentStatus: TaintIrisNextAgentStatus;
  selectedCwes: TaintIrisNextAgentSelection[];
  findings: Finding[];
  reviewCandidates: Finding[];
  triage: TaintIrisNextAgentTriageDecision[];
  triageSummary: TaintIrisNextTriageSummary;
  outcome: TaintIrisNextOutcome;
  rawOutput: unknown;
  structuredOutputValid: boolean;
  structuredOutputRetryCount: number;
  parseError?: string;
  resultTextExcerpt?: string;
  warnings: string[];
  costUsd: number;
}
