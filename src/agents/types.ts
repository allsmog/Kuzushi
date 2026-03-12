import type { MessageBus } from "../bus/types.js";
import type { Finding, TriageAgentConfig } from "../scanners/types.js";
import type { KuzushiConfig, SecurityProfile } from "../types.js";
import type { KnowledgeRegistry } from "../knowledge/types.js";

/** What kind of output this task produces. */
export type TaskOutputKind = "findings" | "threat-model" | "verdict" | "report" | "custom";

/** Shared context provided to every task execution. */
export interface TaskContext {
  runId: string;
  repoRoot: string;
  scanPath?: string;
  repoName: string;
  config: KuzushiConfig;
  bus: MessageBus;
  /** Outputs from completed dependency tasks, keyed by task ID. */
  upstreamOutputs: Map<string, unknown>;
  /** Domain-specific security profiles loaded from project config. */
  securityProfiles?: SecurityProfile[];
  /** Knowledge base registry for domain-specific vulnerability knowledge. */
  knowledgeRegistry?: KnowledgeRegistry;
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
