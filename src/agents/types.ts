import type { MessageBus } from "../bus/types.js";
import type { Finding, TriageAgentConfig } from "../scanners/types.js";
import type { KuzushiConfig } from "../types.js";

/** What kind of output this task produces. */
export type TaskOutputKind = "findings" | "threat-model" | "verdict" | "report" | "custom";

/** Shared context provided to every task execution. */
export interface TaskContext {
  runId: string;
  repoRoot: string;
  repoName: string;
  config: KuzushiConfig;
  bus: MessageBus;
  /** Outputs from completed dependency tasks, keyed by task ID. */
  upstreamOutputs: Map<string, unknown>;
}

/**
 * A unit of work in the agentic pipeline.
 * Could be a scanner, triage agent, threat modeler, or any custom task.
 */
export interface AgentTask<TInput = unknown, TOutput = unknown> {
  readonly id: string;
  readonly displayName: string;
  readonly outputKind: TaskOutputKind;
  readonly dependsOn: string[];

  run(input: TInput, context: TaskContext): Promise<TOutput>;
  init?(config: Record<string, unknown>): Promise<void>;
  triageAgentConfig?(finding: Finding, repoName: string): TriageAgentConfig;
}
