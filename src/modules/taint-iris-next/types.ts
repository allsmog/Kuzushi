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
  maxCatalogEntries?: number;
  maxEvidencePerCwe?: number;
  maxFilesPerQuery?: number;
  maxAgentFindings?: number;
}

export interface TaintIrisNextCaps {
  maxCatalogEntries: number;
  maxEvidencePerCwe: number;
  maxFilesPerQuery: number;
  maxAgentFindings: number;
}

export interface TaintIrisNextBackendChoice {
  requested: TaintIrisNextBackend;
  selected: Exclude<TaintIrisNextBackend, "auto">;
  codeqlDbPath?: string;
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
  repoContext?: RepoContext;
  threatModel?: ThreatModelDocument;
  catalog: RankedTaintIrisNextCweCatalogEntry[];
  structuralQueries: TaintIrisNextStructuralQuery[];
  promptCatalog: string;
  backend: TaintIrisNextBackendChoice;
}

export type TaintIrisNextEvidenceConfidence = "low" | "medium" | "high";
export type TaintIrisNextEvidenceRole = TaintIrisNextStructuralQuery["role"];

export interface TaintIrisNextEvidence {
  cwe: string;
  taintClass: string;
  role: TaintIrisNextEvidenceRole;
  pattern: string;
  filePath: string;
  line: number;
  snippet: string;
  language: string;
  confidence: TaintIrisNextEvidenceConfidence;
  catalogSignal: string;
}

export interface TaintIrisNextEvidenceResult {
  backend: Exclude<TaintIrisNextBackend, "auto">;
  tool: "rg" | "ast-grep" | "codeql" | "semgrep" | "joern" | "language";
  evidence: TaintIrisNextEvidence[];
  queryCount: number;
  warnings: string[];
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

export interface TaintIrisNextAgentOutput {
  selectedCwes: TaintIrisNextAgentSelection[];
  findings: TaintIrisNextAgentFinding[];
  notes?: string[];
}

export interface TaintIrisNextAgentResult {
  selectedCwes: TaintIrisNextAgentSelection[];
  findings: Finding[];
  rawOutput: unknown;
  warnings: string[];
  costUsd: number;
}
