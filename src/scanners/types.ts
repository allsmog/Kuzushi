import type { ScanOpts } from "../types.js";

export type ScannerId = string;
export type ScannerConfig = Record<string, unknown>;

// Single finding type shared by all scanners.
export interface Finding {
  scanner: ScannerId;
  fingerprint: string;
  ruleId: string;
  filePath: string;
  startLine: number;
  severity: string;
  message: string;
  scannerConfidence: string;
  subcategory: string[];
  likelihood: string;
  impact: string;
  cwe: string[];
  score: number;
}

export type AllowedTriageTool = "Read" | "Glob" | "Grep";

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
