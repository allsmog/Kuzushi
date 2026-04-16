export type CryptoBehavioralTestType =
  | "timing"
  | "ecb-mode"
  | "weak-hash"
  | "weak-prng"
  | "key-length"
  | "edge-case";

export type CryptoBehavioralVerdict = "vulnerable" | "secure" | "inconclusive" | "error";

export type CryptoBehavioralExecutionVerdict = "PASS" | "FAIL" | "ERROR" | "TIMEOUT";

export interface TimingAnalysisResult {
  constantTime: boolean;
  tStatistic: number | null;
  pValue: number | null;
  meanANs: number | null;
  meanBNs: number | null;
  iterations: number | null;
}

export interface WycheproofResult {
  confirmed: boolean;
  observedBehavior: string;
  expectedBehavior: string;
}

export interface CryptoBehavioralScriptOutput {
  fingerprint: string;
  testType: CryptoBehavioralTestType;
  verdict: CryptoBehavioralVerdict;
  summary: string;
  timing?: Partial<TimingAnalysisResult>;
  observedBehavior?: string;
  expectedBehavior?: string;
  algorithmConfirmed?: string;
  keyLengthBits?: number;
  confirmed?: boolean;
}

export interface CryptoBehavioralHarnessResult {
  fingerprint: string;
  testType: CryptoBehavioralTestType;
  scriptPath: string | null;
  language: string | null;
  scriptContent: string | null;
  parsed: boolean;
  parseError: string | null;
  skipped: boolean;
  skipReason: string | null;
  costUsd?: number;
}

export interface CryptoBehavioralHarnessOutput {
  result: CryptoBehavioralHarnessResult;
  costUsd: number;
}

export interface CryptoBehavioralRun {
  runId: string;
  pipelineRunId?: string;
  fingerprint: string;
  repo: string;
  testType: CryptoBehavioralTestType;
  verdict: CryptoBehavioralVerdict;
  harnessPath?: string | null;
  harnessLanguage?: string | null;
  executionExitCode?: number | null;
  executionVerdict?: CryptoBehavioralExecutionVerdict;
  executionStdout?: string;
  executionStderr?: string;
  executionDurationMs?: number | null;
  tStatistic?: number | null;
  pValue?: number | null;
  meanANs?: number | null;
  meanBNs?: number | null;
  timingIterations?: number | null;
  observedBehavior?: string;
  expectedBehavior?: string;
  algorithmConfirmed?: string;
  keyLengthBits?: number | null;
  costUsd?: number;
  metadata?: Record<string, unknown>;
  createdAt?: string;
  updatedAt?: string;
}
