import type { ScanOpts } from "../types.js";

export type ScannerId = string;
export type ScannerConfig = Record<string, unknown>;

export interface CorroboratingSignal {
  scanner: ScannerId;
  fingerprint: string;
  ruleId: string;
  filePath: string;
  startLine: number;
  cwe: string[];
  score: number;
}

export interface SuppressionReason {
  id: string;
  kind: "hard" | "soft";
  description: string;
  scorePenalty?: number;
}

export interface TaintPathStep {
  filePath: string;
  line: number;
  message?: string;
  snippet?: string;
}

export type ProofState =
  | "symbolic_only"
  | "execution_attempted"
  | "execution_confirmed"
  | "execution_rejected"
  | "inconclusive";

export interface EngineProvenance {
  kind: "semgrep" | "codeql" | "taint-analysis" | "agentic" | "dynamic";
  detail: string;
}

// Single finding type shared by all scanners.
export interface Finding {
  scanner: ScannerId;
  fingerprint: string;
  ruleId: string;
  filePath: string;
  startLine: number;
  severity: string;
  message: string;
  /** Optional scanner-provided evidence (for example, source-to-sink flow summaries). */
  evidence?: string | null;
  scannerConfidence: string;
  subcategory: string[];
  likelihood: string;
  impact: string;
  cwe: string[];
  score: number;
  adjustedScore?: number;
  taintPath?: TaintPathStep[];
  proofState?: ProofState;
  engineProvenance?: EngineProvenance[];
  corroboratingSignals?: CorroboratingSignal[];
  suppressionReasons?: SuppressionReason[];
}

export type AllowedTriageTool =
  | "Read"
  | "Glob"
  | "Grep"
  | "GetCallers"
  | "GetCallees"
  | "GetFunctionBody"
  | "GoToDefinition"
  | "FindReferences"
  | "TypeAtPosition";

export interface TriageAgentConfig {
  /** Prompt for the Agent SDK query(). Finding metadata + investigation instructions. */
  prompt: string;
  /** Override default tools. Defaults to ["Read", "Glob", "Grep"]. */
  allowedTools?: AllowedTriageTool[];
  /** Override default max turns. Defaults to config.triageMaxTurns. */
  maxTurns?: number;
}

export interface ScannerPlugin {
  readonly id: ScannerId;
  readonly displayName: string;
  scan(repoRoot: string, opts: ScanOpts, config: ScannerConfig): Promise<Finding[]>;
  triageAgentConfig(finding: Finding, repoName: string): TriageAgentConfig;
  init?(config: ScannerConfig): Promise<void>;
}
