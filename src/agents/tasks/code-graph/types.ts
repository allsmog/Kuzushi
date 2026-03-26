/** Node classifications in the code graph. */
export type CodeGraphNodeKind =
  | "entry-http"
  | "entry-cli"
  | "entry-event"
  | "entry-cron"
  | "entry-background"
  | "middleware"
  | "controller"
  | "service"
  | "data-access"
  | "external-call"
  | "sanitizer"
  | "validator"
  | "transformer"
  | "unknown";

/** Edge classifications in the code graph. */
export type CodeGraphEdgeKind =
  | "calls"
  | "imports"
  | "middleware-chain"
  | "callback"
  | "promise-chain"
  | "event-emit"
  | "event-listen"
  | "di-inject"
  | "dynamic-dispatch"
  | "data-flow"
  | "config-read"
  | "serialization";

/** Provenance of a graph node or edge. */
export type GraphSource = "static" | "llm" | "hybrid";

/** A single node in the code graph representing a code location. */
export interface CodeGraphNode {
  nodeId: string;
  filePath: string;
  startLine: number;
  symbol: string | null;
  nodeKind: CodeGraphNodeKind;
  framework: string | null;
  metadata: Record<string, unknown>;
  confidence: number;
  source: GraphSource;
}

/** A directed edge between two nodes in the code graph. */
export interface CodeGraphEdge {
  edgeId: string;
  fromNodeId: string;
  toNodeId: string;
  edgeKind: CodeGraphEdgeKind;
  dataLabel: string | null;
  ordinal: number | null;
  confidence: number;
  source: GraphSource;
}

/** A materialized path from an entry point to a target node. */
export interface CodeGraphPath {
  pathId: string;
  entryNodeId: string;
  targetNodeId: string;
  hopCount: number;
  nodeIds: string[];
  edgeIds: string[];
  hasSanitizer: boolean;
  sanitizerNodeIds: string[];
  confidence: number;
}

/** Output of the code-graph-build task. */
export interface CodeGraphOutput {
  nodes: CodeGraphNode[];
  edges: CodeGraphEdge[];
  paths: CodeGraphPath[];
  stats: {
    totalNodes: number;
    totalEdges: number;
    totalPaths: number;
    staticNodes: number;
    llmInferredNodes: number;
    entryPoints: number;
    tracedEntryPoints: number;
    costUsd: number;
  };
}

/** Graph-derived context attached to a finding for triage enrichment. */
export interface FindingGraphContext {
  reachable: "true" | "false" | "unknown";
  hopsFromEntry: number | null;
  nearestEntryPoint: string | null;
  path: CodeGraphPath | null;
  sanitizersOnPath: Array<{ nodeId: string; symbol: string; filePath: string }>;
  summary: string;
}

/** Configuration for the code graph system. */
export interface CodeGraphConfig {
  /** LLM model for gap-filling (defaults to config.model). */
  model?: string;
  /** Max entry points to trace via LLM. Default 50. */
  maxEntryPoints?: number;
  /** Max depth per LLM trace. Default 15. */
  maxHopsPerTrace?: number;
  /** LLM turn budget per trace. Default 10. */
  maxTurnsPerTrace?: number;
  /** Prefer tracing entry points near scan findings. Default true. */
  prioritizeNearFindings?: boolean;
  /** Persist graph to SQLite. Default true. */
  persistGraph?: boolean;
  /** Reuse graph from previous runs. Default true. */
  warmStart?: boolean;
}
