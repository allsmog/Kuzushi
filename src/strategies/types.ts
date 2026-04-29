import type { DagRunContext } from "../agents/types.js";
import type { Finding } from "../scanners/types.js";
import type { RepoContext } from "../types.js";

/** Classification of an analysis strategy. */
export type StrategyKind = "syntactic" | "dataflow" | "reasoning" | "execution";

/** Evidence produced by a strategy. */
export interface StrategyEvidence {
  kind: "pattern-match" | "taint-flow" | "reasoning-chain" | "execution-result";
  description: string;
  filePath?: string;
  startLine?: number;
  snippet?: string;
}

/** Result returned by a single strategy execution. */
export interface StrategyResult {
  strategyKind: StrategyKind;
  strategyId: string;
  findings: Finding[];
  confidence: number;
  costUsd: number;
  durationMs: number;
  evidence: StrategyEvidence[];
  generatedRules?: GeneratedRule[];
}

/** Input provided to a strategy. */
export interface StrategyInput {
  /** When running as refinement of an existing finding. */
  finding?: Finding;
  repoRoot: string;
  repoName: string;
  context: DagRunContext;
  budgetUsd?: number;
}

/** An analysis strategy that can be registered and dispatched. */
export interface AnalysisStrategy<TConfig = unknown> {
  readonly id: string;
  readonly kind: StrategyKind;
  readonly displayName: string;
  /** Relative cost estimate: 1 = cheapest, 10 = most expensive. */
  readonly costTier: number;
  /** Can this strategy run for the given CWE/vuln class? */
  appliesTo(cweIds: string[], repoContext?: RepoContext): boolean;
  /** Execute the strategy. */
  run(input: StrategyInput, config: TConfig): Promise<StrategyResult>;
}

/** A generated rule for variant scanning. */
export interface GeneratedRule {
  kind: "semgrep" | "grep-pattern";
  vulnClass: string;
  cweIds: string[];
  ruleContent: string;
  description: string;
  sourceFinding: { fingerprint: string; filePath: string; startLine: number };
}

/** Multi-strategy execution mode. */
export type MultiStrategyMode = "off" | "adaptive" | "full";
