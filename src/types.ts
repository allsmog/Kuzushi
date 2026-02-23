/** Scanner backend — today just semgrep. Type exists for later. */
export type Scanner = "semgrep";

/** LLM backend — today just anthropic. Type exists for later. */
export type LLMBackend = "anthropic";

/** Provider-agnostic LLM client. Implementations live in src/llm/. */
export interface LLMClient {
  complete(system: string, user: string): Promise<string>;
}

/** Verdict assigned by AI triage. */
export type Verdict = "tp" | "fp" | "needs_review";

/** Options for running a scan. */
export interface ScanOpts {
  severity: string[];
  maxFindings?: number;
  excludePatterns: string[];
  fresh: boolean;
}

/** A raw finding from Semgrep before AI triage. */
export interface RawFinding {
  fingerprint: string;
  ruleId: string;
  filePath: string;
  startLine: number;
  severity: string;
  message: string;
  semgrepConfidence: string;
  subcategory: string[];
  likelihood: string;
  impact: string;
  cwe: string[];
  score: number;
}

/** Result of AI triage for a single finding. */
export interface TriageResult {
  fingerprint: string;
  verdict: Verdict;
  confidence: number;
  rationale: string;
  verificationSteps: string[];
  fixPatch: string | null;
}

/** User configuration stored at ~/.kuzushi/config.json. */
export interface KuzushiConfig {
  /** LLM model identifier (e.g. "claude-sonnet-4-20250514"). */
  model: string;
  /** Max tokens for LLM response. */
  maxTokens: number;
  /** Default severity filter (e.g. ["ERROR", "WARNING"]). */
  severity: string[];
  /** Default exclude patterns for Semgrep. */
  excludePatterns: string[];
}

/** A persisted finding row from SQLite. */
export interface FindingRow {
  fingerprint: string;
  repo: string;
  ref: string;
  ruleId: string;
  filePath: string;
  startLine: number;
  severity: string;
  message: string;
  verdict: Verdict;
  confidence: number;
  rationale: string;
  verificationSteps: string;
  fixPatch: string | null;
  createdAt: string;
  updatedAt: string;
}
