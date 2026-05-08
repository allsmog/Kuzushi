import type { AgentRuntime } from "../agent-runtime/types.js";

export type ModulePriority = "critical" | "high" | "medium" | "low";

export type ModuleKind =
  | "workspace-member"
  | "standalone"
  | "solution-project"
  | "bazel-package"
  | "native-root"
  | "go-workspace-member";

export type ProductKind =
  | "workspace-root"
  | "solution"
  | "go-workspace"
  | "cargo-workspace"
  | "bazel-workspace";

export interface DiscoveredModule {
  name: string;
  /** Canonical repo-relative path — the sole internal key. */
  path: string;
  /**
   * Additional repo-relative paths the scanner should analyze with this module.
   * Scanners see files across all these paths plus `path`.
   * May overlap across modules when shared packages serve both.
   */
  includePaths?: string[];
  description: string;
  language: string;
  buildSystem?: string;
  moduleKind: ModuleKind;
  /** Path to the parent product/container, if any. */
  productPath?: string;
  /** Metadata files/signals that led to this module being discovered. */
  discoveryEvidence: string[];
  priority?: ModulePriority;
  securitySignals?: string[];
}

export interface DiscoveredProduct {
  path: string;
  kind: ProductKind;
  /** Leaf module paths belonging to this product. */
  children: string[];
  discoveryEvidence: string[];
}

export interface DiscoveryResult {
  modules: DiscoveredModule[];
  products: DiscoveredProduct[];
  costUsd: number;
  reasoning: string;
}

export interface DiscoveryOptions {
  maxModules?: number;
  maxDepth?: number;
  /** If provided, LLM refinement runs after the metadata pass. */
  runtime?: AgentRuntime;
  /** Model override for the LLM refinement call. */
  model?: string;
}
