import type Database from "better-sqlite3";
import type { AgentRuntime } from "../agent-runtime/types.js";
import type { MessageBus } from "../bus/types.js";
import type { KnowledgeRegistry } from "../knowledge/types.js";
import type { ToolPolicy } from "../prompts/tool-policy.js";
import type { Finding, TriageAgentConfig } from "../scanners/types.js";
import type { KuzushiConfig, SecurityProfile } from "../types.js";

/** What kind of output this task produces. */
export type TaskOutputKind = "findings" | "threat-model" | "verdict" | "report" | "custom";

/** Prompt rendering mode for agent tasks. */
export type PromptMode = "full" | "minimal" | "none";

/** Shared context provided to every task execution. */
export interface TaskContext {
  runId: string;
  /** Actual repository root for the pipeline run. */
  projectRoot?: string;
  /** Effective scan scope for the current task, usually scanPath ?? projectRoot. */
  workRoot?: string;
  /**
   * @deprecated Backward-compatible alias for workRoot.
   * Prefer projectRoot for repo-wide state and workRoot for scan-scoped work.
   */
  repoRoot: string;
  scanPath?: string;
  repoName: string;
  dbPath?: string;
  config: KuzushiConfig;
  runtime: AgentRuntime;
  bus: MessageBus;
  /** Outputs from completed dependency tasks, keyed by task ID. */
  upstreamOutputs: Map<string, unknown>;
  /** Domain-specific security profiles loaded from project config. */
  securityProfiles?: SecurityProfile[];
  /** Knowledge base registry for domain-specific vulnerability knowledge. */
  knowledgeRegistry?: KnowledgeRegistry;
  /** Optional prompt overrides applied at runtime. */
  promptOverrides?: {
    systemPromptAppend?: string;
    systemPromptPrepend?: string;
  };
  /** Optional database handle for regression detection and historical queries. */
  db?: Database.Database;
  /** Optional per-execution model override used by internal orchestration features such as ensembles. */
  modelOverride?: string;
  /**
   * Abort signal propagated from the shell/tool-invocation layer. Tasks that
   * spawn LLM queries should forward this (wrapped in an AbortController
   * passed to `runtime.query`) so Ctrl+C actually cancels in-flight work
   * instead of letting it print after the operator has already aborted.
   */
  signal?: AbortSignal;
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

  /** Optional condition evaluated before running. Return false to skip. */
  condition?: (upstreamOutputs: Map<string, unknown>, config: KuzushiConfig) => boolean;

  /** Prompt rendering mode: full (default), minimal (sub-agents), none (routing only). */
  promptMode?: PromptMode;

  /** Tool policy for this task (allow/deny specific tools). */
  toolPolicy?: ToolPolicy;

  run(input: TInput, context: TaskContext): Promise<TOutput>;
  init?(config: Record<string, unknown>): Promise<void>;
  triageAgentConfig?(finding: Finding, repoName: string): TriageAgentConfig;
}
