/**
 * Phase 1 — Architectural threat model for the entire monorepo.
 *
 * One LLM call that receives the complete static intelligence (dependency
 * graph, attack surfaces, interaction edges) and produces a cross-module
 * DFD with STRIDE threats, per-module risk assessments, and cross-module
 * vulnerability hypotheses.
 *
 * Cost: ~$0.50-1.00 (single structured agent query).
 */

import type { AgentRuntime } from "../agent-runtime/types.js";
import { runStructuredAgentQuery } from "../agent-runtime/execution.js";
import type { DiscoveredModule } from "../discovery/types.js";
import { isRecord, toErrorMessage } from "../utils.js";
import { getLogger } from "../logger.js";
import type {
  StaticIntelligence,
  MonorepoThreatModel,
  ModuleRiskAssessment,
  CrossModuleHypothesis,
  MonorepoDataFlow,
  ScanDepth,
} from "./types.js";
import { formatDependencyGraphSummary } from "./dependency-graph.js";
import { formatAttackSurfaceSummary } from "./attack-surface.js";

const log = getLogger("monorepo-arch");

// ── Schema ─────────────────────────────────────────────────────────────

const ARCHITECTURAL_ANALYSIS_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: [
    "dfd",
    "threats",
    "moduleRiskAssessments",
    "crossModuleHypotheses",
  ],
  properties: {
    dfd: {
      type: "object",
      additionalProperties: false,
      required: ["elements", "trustBoundaries", "dataFlows"],
      properties: {
        elements: {
          type: "array",
          items: {
            type: "object",
            additionalProperties: false,
            required: ["id", "type", "name", "description", "trustZone"],
            properties: {
              id: { type: "string" },
              type: { type: "string", enum: ["external-entity", "process", "data-store", "data-flow"] },
              name: { type: "string" },
              description: { type: "string" },
              trustZone: { type: "string" },
            },
          },
        },
        trustBoundaries: {
          type: "array",
          items: {
            type: "object",
            additionalProperties: false,
            required: ["id", "name", "innerZone", "outerZone", "modules"],
            properties: {
              id: { type: "string" },
              name: { type: "string" },
              innerZone: { type: "string" },
              outerZone: { type: "string" },
              modules: { type: "array", items: { type: "string" } },
              crossingFlows: { type: "array", items: { type: "string" } },
            },
          },
        },
        dataFlows: {
          type: "array",
          items: {
            type: "object",
            additionalProperties: false,
            required: ["id", "sourceModule", "targetModule", "dataType", "protocol"],
            properties: {
              id: { type: "string" },
              sourceModule: { type: "string" },
              targetModule: { type: "string" },
              dataType: { type: "string" },
              protocol: { type: "string" },
              trustBoundaryCrossings: { type: "array", items: { type: "string" } },
              securityConcerns: { type: "array", items: { type: "string" } },
            },
          },
        },
      },
    },
    threats: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["id", "elementId", "category", "title", "description", "impact"],
        properties: {
          id: { type: "string" },
          elementId: { type: "string" },
          category: { type: "string", enum: ["spoofing", "tampering", "repudiation", "information-disclosure", "denial-of-service", "elevation-of-privilege"] },
          title: { type: "string" },
          description: { type: "string" },
          attackVector: { type: "string" },
          preconditions: { type: "array", items: { type: "string" } },
          impact: { type: "string", enum: ["critical", "high", "medium", "low"] },
          likelihood: { type: "string", enum: ["high", "medium", "low"] },
          existingMitigations: { type: "array", items: { type: "string" } },
          missingMitigations: { type: "array", items: { type: "string" } },
          relatedCwe: { type: "array", items: { type: "string" } },
          affectedFiles: { type: "array", items: { type: "object", additionalProperties: false, required: ["filePath", "startLine"], properties: { filePath: { type: "string" }, startLine: { type: "integer" } } } },
        },
      },
    },
    moduleRiskAssessments: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["moduleName", "riskLevel", "rationale", "recommendedScanDepth", "focusAreas"],
        properties: {
          moduleName: { type: "string" },
          riskLevel: { type: "string", enum: ["critical", "high", "medium", "low"] },
          rationale: { type: "string" },
          recommendedScanDepth: { type: "string", enum: ["deep", "standard", "fast", "skip"] },
          focusAreas: { type: "array", items: { type: "string" } },
        },
      },
    },
    crossModuleHypotheses: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["id", "title", "description", "moduleChain", "attackVector", "severity"],
        properties: {
          id: { type: "string" },
          title: { type: "string" },
          description: { type: "string" },
          moduleChain: { type: "array", items: { type: "string" } },
          attackVector: { type: "string" },
          cweIds: { type: "array", items: { type: "string" } },
          severity: { type: "string", enum: ["critical", "high", "medium", "low"] },
        },
      },
    },
  },
} as const;

// ── System Prompt ──────────────────────────────────────────────────────

const SYSTEM_PROMPT = [
  "You are a security architect analyzing a monorepo's cross-module architecture.",
  "",
  "Your job is to produce an architectural threat model at the MODULE level — not file-level.",
  "Focus on how modules interact, where trust boundaries exist between them, and where",
  "cross-module data flows could introduce vulnerabilities that no single-module scan would find.",
  "",
  "For each module, assess its security risk and recommend a scan depth:",
  "  deep     — External-facing, handles auth/crypto/secrets, high dependency centrality. Full scanner suite.",
  "  standard — Processes user data, has some external surface, moderate risk. Standard scanners + taint analysis.",
  "  fast     — Internal library, low risk, no direct external surface. Static scanners only (semgrep).",
  "  skip     — Test infrastructure, docs, build scripts, CI config. No security scan needed.",
  "",
  "For cross-module hypotheses, identify specific attack scenarios that span multiple modules.",
  "Example: 'User input enters via module A's webhook handler, passes through module B's",
  "credential store without validation, and reaches module C's code execution engine.'",
  "",
  "Be concrete and specific. Reference actual module names from the input.",
].join("\n");

// ── Public API ──────────────────────────────────────────────────────────

export interface ArchitecturalAnalysisOptions {
  model: string;
  runtime: AgentRuntime;
  monorepoRoot: string;
}

export interface ArchitecturalAnalysisResult {
  threatModel: MonorepoThreatModel;
  costUsd: number;
}

/**
 * Run the architectural threat model analysis for the monorepo.
 * Single LLM call: receives static intelligence, produces cross-module DFD + STRIDE.
 */
export async function buildArchitecturalThreatModel(
  modules: DiscoveredModule[],
  staticIntel: StaticIntelligence,
  options: ArchitecturalAnalysisOptions,
): Promise<ArchitecturalAnalysisResult> {
  const prompt = buildPrompt(modules, staticIntel);

  log.info(`Running architectural threat model for ${modules.length} modules`);

  const result = await runStructuredAgentQuery({
    prompt,
    cwd: options.monorepoRoot,
    model: options.model,
    allowedTools: [],
    runtimeOptions: {
      runtime: options.runtime,
      maxOutputTokens: 8192,
      thinkingDisabled: true,
    },
    schema: ARCHITECTURAL_ANALYSIS_SCHEMA as unknown as Record<string, unknown>,
    strict: true,
    systemPromptPrefix: SYSTEM_PROMPT,
    retryInvalidStructuredOutput: 1,
  });

  if (result.executionError) {
    log.error(`Architectural analysis failed: ${result.executionError}`);
    // Return a minimal fallback so scanning can continue
    return {
      threatModel: buildFallbackThreatModel(modules),
      costUsd: result.costUsd,
    };
  }

  const parsed = parseResult(result.structuredOutput, modules);
  log.info(
    `Architectural analysis complete: ${parsed.threats.length} threats, ` +
    `${parsed.moduleRiskAssessments.length} risk assessments, ` +
    `${parsed.crossModuleHypotheses.length} cross-module hypotheses ($${result.costUsd.toFixed(4)})`,
  );

  return { threatModel: parsed, costUsd: result.costUsd };
}

// ── Prompt Construction ────────────────────────────────────────────────

function buildPrompt(
  modules: DiscoveredModule[],
  staticIntel: StaticIntelligence,
): string {
  const sections: string[] = [];

  // Module list
  sections.push("## Modules\n");
  for (const m of modules) {
    const surface = staticIntel.attackSurfaces.get(m.name);
    const depNode = staticIntel.dependencyGraph.nodes.get(m.name);
    const surfaceTag = surface?.isExternalFacing ? " [EXTERNAL]" : "";
    const depTag = depNode ? ` (depended on by ${depNode.inDegree} modules)` : "";
    const frameworks = surface?.detectedFrameworks.length
      ? ` — ${surface.detectedFrameworks.join(", ")}`
      : "";
    sections.push(`- **${m.name}**${surfaceTag}${depTag}: ${m.path}${frameworks}`);
    if (m.description) sections.push(`  ${m.description}`);
    if (surface?.entryPointTypes.length) {
      sections.push(`  Entry points: ${surface.entryPointTypes.join(", ")} (${surface.entryPointCount} total)`);
    }
    if (m.securitySignals?.length) {
      sections.push(`  Security signals: ${m.securitySignals.join(", ")}`);
    }
  }

  // Dependency graph
  sections.push("\n## Dependency Graph\n");
  sections.push(formatDependencyGraphSummary(staticIntel.dependencyGraph));

  // Attack surfaces
  sections.push("\n## Attack Surface Summary\n");
  sections.push(formatAttackSurfaceSummary(staticIntel.attackSurfaces));

  // Interaction edges
  if (staticIntel.interactionEdges.length > 0) {
    sections.push("\n## Detected Cross-Module Interactions\n");
    for (const edge of staticIntel.interactionEdges.slice(0, 30)) {
      sections.push(`- ${edge.source} → ${edge.target} (${edge.interactionType})`);
    }
  }

  sections.push("\n## Instructions\n");
  sections.push("Produce an architectural threat model with:");
  sections.push("1. A module-level DFD with trust boundaries and data flows between modules");
  sections.push("2. STRIDE threats at the monorepo level (focus on cross-module attack paths)");
  sections.push("3. A risk assessment and recommended scan depth for EVERY module");
  sections.push("4. Cross-module vulnerability hypotheses — specific attack scenarios spanning multiple modules");

  return sections.join("\n");
}

// ── Result Parsing ─────────────────────────────────────────────────────

function parseResult(raw: unknown, modules: DiscoveredModule[]): MonorepoThreatModel {
  if (!isRecord(raw)) return buildFallbackThreatModel(modules);

  const dfd = isRecord(raw["dfd"]) ? raw["dfd"] : {};
  const elements = Array.isArray(dfd["elements"]) ? dfd["elements"] : [];
  const trustBoundaries = Array.isArray(dfd["trustBoundaries"]) ? dfd["trustBoundaries"] : [];
  const dataFlows = Array.isArray(dfd["dataFlows"]) ? dfd["dataFlows"] : [];
  const threats = Array.isArray(raw["threats"]) ? raw["threats"] : [];
  const riskAssessments = Array.isArray(raw["moduleRiskAssessments"]) ? raw["moduleRiskAssessments"] : [];
  const hypotheses = Array.isArray(raw["crossModuleHypotheses"]) ? raw["crossModuleHypotheses"] : [];

  return {
    dfd: {
      elements: elements as MonorepoThreatModel["dfd"]["elements"],
      trustBoundaries: trustBoundaries as MonorepoThreatModel["dfd"]["trustBoundaries"],
      dataFlows: dataFlows.map((df: Record<string, unknown>) => ({
        id: String(df["id"] ?? ""),
        sourceModule: String(df["sourceModule"] ?? ""),
        targetModule: String(df["targetModule"] ?? ""),
        dataType: String(df["dataType"] ?? ""),
        protocol: String(df["protocol"] ?? ""),
        trustBoundaryCrossings: Array.isArray(df["trustBoundaryCrossings"]) ? df["trustBoundaryCrossings"] as string[] : [],
        securityConcerns: Array.isArray(df["securityConcerns"]) ? df["securityConcerns"] as string[] : [],
      })) as MonorepoDataFlow[],
    },
    threats: threats as MonorepoThreatModel["threats"],
    moduleRiskAssessments: riskAssessments.map((r: Record<string, unknown>) => ({
      moduleName: String(r["moduleName"] ?? ""),
      riskLevel: validateRiskLevel(r["riskLevel"]),
      rationale: String(r["rationale"] ?? ""),
      recommendedScanDepth: validateScanDepth(r["recommendedScanDepth"]),
      focusAreas: Array.isArray(r["focusAreas"]) ? r["focusAreas"] as string[] : [],
    })) as ModuleRiskAssessment[],
    crossModuleHypotheses: hypotheses.map((h: Record<string, unknown>) => ({
      id: String(h["id"] ?? ""),
      title: String(h["title"] ?? ""),
      description: String(h["description"] ?? ""),
      moduleChain: Array.isArray(h["moduleChain"]) ? h["moduleChain"] as string[] : [],
      attackVector: String(h["attackVector"] ?? ""),
      cweIds: Array.isArray(h["cweIds"]) ? h["cweIds"] as string[] : [],
      severity: validateRiskLevel(h["severity"]),
    })) as CrossModuleHypothesis[],
  };
}

function validateRiskLevel(value: unknown): "critical" | "high" | "medium" | "low" {
  if (value === "critical" || value === "high" || value === "medium" || value === "low") return value;
  return "medium";
}

function validateScanDepth(value: unknown): ScanDepth {
  if (value === "deep" || value === "standard" || value === "fast" || value === "skip") return value;
  return "standard";
}

/**
 * Fallback threat model when the LLM call fails.
 * Assigns scan depth based on LLM-discovery priority alone.
 */
function buildFallbackThreatModel(modules: DiscoveredModule[]): MonorepoThreatModel {
  return {
    dfd: { elements: [], trustBoundaries: [], dataFlows: [] },
    threats: [],
    moduleRiskAssessments: modules.map((m) => ({
      moduleName: m.name,
      riskLevel: m.priority ?? "medium",
      rationale: "Fallback: architectural analysis unavailable",
      recommendedScanDepth: fallbackDepth(m.priority),
      focusAreas: m.securitySignals ?? [],
    })),
    crossModuleHypotheses: [],
  };
}

function fallbackDepth(priority?: string): ScanDepth {
  switch (priority) {
    case "critical": return "deep";
    case "high": return "standard";
    case "medium": return "fast";
    default: return "fast";
  }
}
