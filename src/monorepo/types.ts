/**
 * Types for the phased monorepo scan architecture.
 *
 * Phase 0: Static Intelligence (dependency graph, attack surface, interaction edges)
 * Phase 1: Architectural Threat Model (one LLM call for cross-module DFD + STRIDE)
 * Phase 2: Per-Module Scans (budget-aware, adaptive depth, shared context)
 * Phase 3: Cross-Module Stitching (boundary matching across modules)
 */

import type { DiscoveredModule, ModulePriority } from "../discovery/types.js";
import type { DfdElement, TrustBoundary, StrideThreat } from "../agents/tasks/threat-modeling/types.js";
import type { KuzushiConfig } from "../types.js";

// ── Phase 0: Static Intelligence ───────────────────────────────────────

export interface ModuleDependencyGraph {
  /** Adjacency list: module name → set of module names it depends on. */
  dependsOn: Map<string, Set<string>>;
  /** Reverse adjacency: module name → set of module names that depend on it. */
  dependedOnBy: Map<string, Set<string>>;
  /** Per-module metrics derived from the graph. */
  nodes: Map<string, ModuleDependencyNode>;
}

export interface ModuleDependencyNode {
  moduleId: string;
  modulePath: string;
  /** Number of modules that depend on this one. Higher = more critical. */
  inDegree: number;
  /** Number of modules this one depends on. */
  outDegree: number;
  /** Rank by in-degree: 0 = most depended-on. */
  dependencyRank: number;
}

export type EntryPointType =
  | "http-route"
  | "websocket"
  | "cli-command"
  | "webhook"
  | "rpc-listener"
  | "event-listener";

export interface AttackSurfaceAnnotation {
  isExternalFacing: boolean;
  entryPointTypes: EntryPointType[];
  entryPointCount: number;
  detectedFrameworks: string[];
}

export type InteractionType =
  | "import"
  | "rpc"
  | "shared-db"
  | "event"
  | "http-client";

export interface ModuleInteractionEdge {
  source: string;
  target: string;
  interactionType: InteractionType;
  evidence: string[];
}

export interface StaticIntelligence {
  dependencyGraph: ModuleDependencyGraph;
  attackSurfaces: Map<string, AttackSurfaceAnnotation>;
  interactionEdges: ModuleInteractionEdge[];
}

// ── Phase 1: Architectural Threat Model ────────────────────────────────

export interface MonorepoDataFlow {
  id: string;
  sourceModule: string;
  targetModule: string;
  dataType: string;
  protocol: string;
  trustBoundaryCrossings: string[];
  securityConcerns: string[];
}

export interface ModuleRiskAssessment {
  moduleName: string;
  riskLevel: ModulePriority;
  rationale: string;
  recommendedScanDepth: ScanDepth;
  focusAreas: string[];
}

export type ScanDepth = "deep" | "standard" | "fast" | "skip";

export interface CrossModuleHypothesis {
  id: string;
  title: string;
  description: string;
  moduleChain: string[];
  attackVector: string;
  cweIds: string[];
  severity: "critical" | "high" | "medium" | "low";
}

export interface MonorepoThreatModel {
  dfd: {
    elements: DfdElement[];
    trustBoundaries: Array<TrustBoundary & { modules: string[] }>;
    dataFlows: MonorepoDataFlow[];
  };
  threats: StrideThreat[];
  moduleRiskAssessments: ModuleRiskAssessment[];
  crossModuleHypotheses: CrossModuleHypothesis[];
}

// ── Phase 2: Budget + Scan Planning ────────────────────────────────────

export interface MonorepoBudget {
  totalBudgetUsd: number;
  spentUsd: number;
  phase0CostUsd: number;
  phase1CostUsd: number;
  phase2CostUsd: number;
  phase3CostUsd: number;
  /** Reserve ~10% for Phase 3 cross-module analysis. */
  reservedForPhase3Usd: number;
}

export interface ModuleScanPlan {
  module: DiscoveredModule;
  scanDepth: ScanDepth;
  configOverrides: Partial<KuzushiConfig>;
  /** Cross-module hypotheses relevant to this module. */
  scanDirectives: CrossModuleHypothesis[];
  estimatedCostUsd: number;
}

// ── Shared Context (passed to per-module pipelines) ────────────────────

export interface MonorepoSharedContext {
  architecturalThreatModel: MonorepoThreatModel;
  moduleRiskAssessment: ModuleRiskAssessment;
  crossModuleHypotheses: CrossModuleHypothesis[];
  dependencyGraph: ModuleDependencyGraph;
  attackSurface: AttackSurfaceAnnotation;
}

// ── Module Interaction Graph (assembled after Phase 3) ─────────────────

export interface ModuleInteractionGraph {
  nodes: Array<{
    moduleId: string;
    isExternalFacing: boolean;
    findingCount: number;
    riskLevel: string;
  }>;
  edges: Array<{
    source: string;
    target: string;
    protocols: string[];
    dataTypes: string[];
    crossesTrustBoundary: boolean;
    findings: string[];
  }>;
  blastRadius: Map<string, string[]>;
}
