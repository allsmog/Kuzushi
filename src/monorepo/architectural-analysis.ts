/**
 * Phase 1 — Architectural threat model for the entire monorepo.
 *
 * One LLM call receives static intelligence plus per-module shared context and
 * produces a module-level DFD, STRIDE threats, explicit per-module task plans,
 * and cross-module hypotheses.
 */

import type { AgentRuntime } from "../agent-runtime/types.js";
import { runStructuredAgentQuery } from "../agent-runtime/execution.js";
import { __taskSelectorInternals, SELECTABLE_TASK_IDS } from "../agents/tasks/task-selector.js";
import type { DiscoveredModule, ModulePriority } from "../discovery/types.js";
import { normalizeTaskCapabilityIds } from "../capabilities.js";
import { isRecord } from "../utils.js";
import { getLogger } from "../logger.js";
import type {
  CrossModuleHypothesis,
  ModuleTaskRecommendation,
  MonorepoContextIndex,
  MonorepoDataFlow,
  MonorepoThreatModel,
  StaticIntelligence,
} from "./types.js";
import { formatDependencyGraphSummary } from "./dependency-graph.js";
import { formatAttackSurfaceSummary } from "./attack-surface.js";

const log = getLogger("monorepo-arch");

const MONOREPO_TASK_ALLOWLIST = [...SELECTABLE_TASK_IDS]
  .filter((taskId) => taskId !== "taint-cwe-select")
  .sort();

const MONOREPO_TASK_ALLOWLIST_SET = new Set(MONOREPO_TASK_ALLOWLIST);

const ARCHITECTURAL_ANALYSIS_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: [
    "dfd",
    "threats",
    "modulePlans",
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
            required: ["id", "sourceModulePath", "targetModulePath", "dataType", "protocol"],
            properties: {
              id: { type: "string" },
              sourceModulePath: { type: "string" },
              targetModulePath: { type: "string" },
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
    modulePlans: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["modulePath", "riskLevel", "rationale", "recommendedTasks", "focusAreas"],
        properties: {
          modulePath: { type: "string" },
          riskLevel: { type: "string", enum: ["critical", "high", "medium", "low"] },
          rationale: { type: "string" },
          recommendedTasks: { type: "array", items: { type: "string" } },
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

const SYSTEM_PROMPT = [
  "You are a security architect analyzing a monorepo's cross-module architecture.",
  "",
  "Produce one module-level threat model for the whole monorepo.",
  "Do not invent module names or module identifiers.",
  "Every module reference must use the exact modulePath values provided in the prompt.",
  "",
  "For each module, recommend exact task IDs from the allowlist below.",
  "Do not emit depth levels, presets, infrastructure tasks, or alias names.",
  "Do not emit task-selector, context-gatherer, context-enricher, or taint-cwe-select.",
  "",
  "Use more tasks only when justified by the module's actual attack surface, trust boundaries, and role.",
  "Cross-module hypotheses should directly influence task recommendations for the affected modules.",
  "",
  "Task allowlist:",
  ...MONOREPO_TASK_ALLOWLIST.map((taskId) => `- ${taskId}`),
].join("\n");

export interface ArchitecturalAnalysisOptions {
  model: string;
  runtime: AgentRuntime;
  monorepoRoot: string;
}

export interface ArchitecturalAnalysisResult {
  threatModel: MonorepoThreatModel;
  costUsd: number;
}

export async function buildArchitecturalThreatModel(
  modules: DiscoveredModule[],
  staticIntel: StaticIntelligence,
  contextIndex: MonorepoContextIndex,
  options: ArchitecturalAnalysisOptions,
): Promise<ArchitecturalAnalysisResult> {
  const prompt = buildPrompt(modules, staticIntel, contextIndex);

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
    return {
      threatModel: buildFallbackThreatModel(modules, staticIntel, contextIndex),
      costUsd: result.costUsd,
    };
  }

  const parsed = parseResult(result.structuredOutput, modules, staticIntel, contextIndex);
  log.info(
    `Architectural analysis complete: ${parsed.threats.length} threats, ` +
    `${parsed.modulePlans.length} module plans, ` +
    `${parsed.crossModuleHypotheses.length} cross-module hypotheses ($${result.costUsd.toFixed(4)})`,
  );

  return { threatModel: parsed, costUsd: result.costUsd };
}

function buildPrompt(
  modules: DiscoveredModule[],
  staticIntel: StaticIntelligence,
  contextIndex: MonorepoContextIndex,
): string {
  const sections: string[] = [];

  sections.push("## Modules\n");
  for (const module of modules) {
    const surface = staticIntel.attackSurfaces.get(module.path);
    const depNode = staticIntel.dependencyGraph.nodes.get(module.path);
    const shared = contextIndex.modules.get(module.path);
    const surfaceTag = surface?.isExternalFacing ? " [EXTERNAL]" : "";
    const depTag = depNode ? ` (depended on by ${depNode.inDegree} modules)` : "";
    sections.push(`- modulePath: ${module.path}${surfaceTag}${depTag}`);
    sections.push(`  name: ${module.name}`);
    if (module.description) {
      sections.push(`  description: ${module.description}`);
    }
    if (module.language) {
      sections.push(`  language: ${module.language}`);
    }
    if (surface?.entryPointTypes.length) {
      sections.push(`  attackSurface: ${surface.entryPointTypes.join(", ")} (${surface.entryPointCount} total)`);
    }
    if (shared) {
      sections.push(`  frameworks: ${shared.repoContext.frameworks.join(", ") || "none"}`);
      sections.push(`  authPatterns: ${shared.repoContext.authPatterns.join(", ") || "none"}`);
      sections.push(`  databases: ${shared.repoContext.ormOrDb.join(", ") || "none"}`);
      sections.push(`  entryPoints: ${shared.repoContext.entryPoints.slice(0, 6).join(", ") || "none"}`);
    }
    const dependsOn = [...(staticIntel.dependencyGraph.dependsOn.get(module.path) ?? [])];
    if (dependsOn.length > 0) {
      sections.push(`  dependsOn: ${dependsOn.join(", ")}`);
    }
  }

  sections.push("\n## Dependency Graph\n");
  sections.push(formatDependencyGraphSummary(staticIntel.dependencyGraph));

  sections.push("\n## Attack Surface Summary\n");
  sections.push(formatAttackSurfaceSummary(staticIntel.attackSurfaces));

  if (staticIntel.interactionEdges.length > 0) {
    sections.push("\n## Detected Cross-Module Interactions\n");
    for (const edge of staticIntel.interactionEdges.slice(0, 30)) {
      sections.push(`- ${edge.source} → ${edge.target} (${edge.interactionType})`);
    }
  }

  sections.push("\n## Instructions\n");
  sections.push("1. Produce a module-level DFD with trust boundaries and inter-module data flows.");
  sections.push("2. Produce STRIDE threats focused on meaningful attack paths.");
  sections.push("3. Produce a module plan for EVERY modulePath with exact recommendedTasks from the allowlist only.");
  sections.push("4. Cross-module hypotheses must use modulePath in moduleChain and should influence the recommendedTasks of affected modules.");
  sections.push("5. Use the smallest defensible task set. Do not use depth labels or presets.");

  return sections.join("\n");
}

function parseResult(
  raw: unknown,
  modules: DiscoveredModule[],
  staticIntel: StaticIntelligence,
  contextIndex: MonorepoContextIndex,
): MonorepoThreatModel {
  if (!isRecord(raw)) {
    return buildFallbackThreatModel(modules, staticIntel, contextIndex);
  }

  const modulePathSet = new Set(modules.map((module) => module.path));
  const dfd = isRecord(raw["dfd"]) ? raw["dfd"] : {};
  const elements = Array.isArray(dfd["elements"]) ? dfd["elements"] : [];
  const trustBoundaries = Array.isArray(dfd["trustBoundaries"]) ? dfd["trustBoundaries"] : [];
  const dataFlows = Array.isArray(dfd["dataFlows"]) ? dfd["dataFlows"] : [];
  const threats = Array.isArray(raw["threats"]) ? raw["threats"] : [];
  const modulePlans = Array.isArray(raw["modulePlans"]) ? raw["modulePlans"] : [];
  const hypotheses = Array.isArray(raw["crossModuleHypotheses"]) ? raw["crossModuleHypotheses"] : [];

  const parsedHypotheses = hypotheses
    .filter(isRecord)
    .map((hypothesis) => ({
      id: String(hypothesis["id"] ?? ""),
      title: String(hypothesis["title"] ?? ""),
      description: String(hypothesis["description"] ?? ""),
      moduleChain: Array.isArray(hypothesis["moduleChain"])
        ? (hypothesis["moduleChain"] as unknown[]).map(String).filter((modulePath) => modulePathSet.has(modulePath))
        : [],
      attackVector: String(hypothesis["attackVector"] ?? ""),
      cweIds: Array.isArray(hypothesis["cweIds"]) ? (hypothesis["cweIds"] as unknown[]).map(String) : [],
      severity: validateRiskLevel(hypothesis["severity"]),
    })) as CrossModuleHypothesis[];

  const parsedPlanMap = new Map<string, ModuleTaskRecommendation>();
  for (const plan of modulePlans) {
    if (!isRecord(plan)) {
      continue;
    }
    const modulePath = String(plan["modulePath"] ?? "");
    if (!modulePathSet.has(modulePath)) {
      continue;
    }

    parsedPlanMap.set(modulePath, {
      modulePath,
      riskLevel: validateRiskLevel(plan["riskLevel"]),
      rationale: String(plan["rationale"] ?? ""),
      recommendedTasks: normalizeRecommendedTasks(plan["recommendedTasks"]),
      focusAreas: Array.isArray(plan["focusAreas"]) ? (plan["focusAreas"] as unknown[]).map(String) : [],
    });
  }

  for (const module of modules) {
    if (!parsedPlanMap.has(module.path)) {
      parsedPlanMap.set(module.path, buildFallbackModulePlan(module, staticIntel, contextIndex));
    }
  }

  const mergedPlans = [...parsedPlanMap.values()].map((plan) =>
    augmentPlanWithHypotheses(plan, parsedHypotheses),
  );

  return {
    dfd: {
      elements: elements as MonorepoThreatModel["dfd"]["elements"],
      trustBoundaries: trustBoundaries
        .filter(isRecord)
        .map((boundary) => ({
          ...boundary,
          modules: Array.isArray(boundary["modules"])
            ? (boundary["modules"] as unknown[]).map(String).filter((modulePath) => modulePathSet.has(modulePath))
            : [],
        })) as MonorepoThreatModel["dfd"]["trustBoundaries"],
      dataFlows: dataFlows
        .filter(isRecord)
        .map((flow) => ({
          id: String(flow["id"] ?? ""),
          sourceModulePath: String(flow["sourceModulePath"] ?? ""),
          targetModulePath: String(flow["targetModulePath"] ?? ""),
          dataType: String(flow["dataType"] ?? ""),
          protocol: String(flow["protocol"] ?? ""),
          trustBoundaryCrossings: Array.isArray(flow["trustBoundaryCrossings"])
            ? (flow["trustBoundaryCrossings"] as unknown[]).map(String)
            : [],
          securityConcerns: Array.isArray(flow["securityConcerns"])
            ? (flow["securityConcerns"] as unknown[]).map(String)
            : [],
        }))
        .filter((flow) => modulePathSet.has(flow.sourceModulePath) && modulePathSet.has(flow.targetModulePath)) as MonorepoDataFlow[],
    },
    threats: threats as MonorepoThreatModel["threats"],
    modulePlans: mergedPlans,
    crossModuleHypotheses: parsedHypotheses,
  };
}

function normalizeRecommendedTasks(raw: unknown): string[] {
  const taskIds = Array.isArray(raw) ? raw.map(String) : [];
  return normalizeTaskCapabilityIds(taskIds)
    .filter((taskId) => MONOREPO_TASK_ALLOWLIST_SET.has(taskId));
}

function augmentPlanWithHypotheses(
  plan: ModuleTaskRecommendation,
  hypotheses: CrossModuleHypothesis[],
): ModuleTaskRecommendation {
  const tasks = new Set(plan.recommendedTasks);
  for (const hypothesis of hypotheses) {
    if (!hypothesis.moduleChain.includes(plan.modulePath)) {
      continue;
    }
    for (const taskId of inferTasksFromHypothesis(hypothesis)) {
      tasks.add(taskId);
    }
  }
  return {
    ...plan,
    recommendedTasks: [...tasks].filter((taskId) => MONOREPO_TASK_ALLOWLIST_SET.has(taskId)).sort(),
  };
}

function inferTasksFromHypothesis(hypothesis: CrossModuleHypothesis): string[] {
  const text = `${hypothesis.title} ${hypothesis.description} ${hypothesis.attackVector}`.toLowerCase();
  const inferred = new Set<string>();

  if (/ssrf|server-side request/.test(text)) inferred.add("ssrf-detect");
  if (/command|shell|exec/.test(text)) inferred.add("command-injection-detect");
  if (/template|ssti/.test(text)) inferred.add("template-injection-detect");
  if (/prototype/.test(text)) inferred.add("prototype-pollution-detect");
  if (/graphql/.test(text)) inferred.add("graphql-security-detect");
  if (/deserial/.test(text)) inferred.add("deserialization-detect");
  if (/xxe|xml external/.test(text)) inferred.add("xxe-detect");
  if (/auth|authorization|rbac|acl|permission/.test(text)) inferred.add("auth-logic-detect");
  if (/secret|crypto|credential|token|key/.test(text)) inferred.add("secrets-crypto-detect");
  if (/dependency|supply chain|package/.test(text)) inferred.add("supply-chain-detect");
  if (/race|concurrency/.test(text)) inferred.add("race-condition-detect");
  if (/taint|input|injection|untrusted|flow/.test(text)) inferred.add("taint-iris");

  return [...inferred];
}

function buildFallbackThreatModel(
  modules: DiscoveredModule[],
  staticIntel: StaticIntelligence,
  contextIndex: MonorepoContextIndex,
): MonorepoThreatModel {
  return {
    dfd: { elements: [], trustBoundaries: [], dataFlows: [] },
    threats: [],
    modulePlans: modules.map((module) => buildFallbackModulePlan(module, staticIntel, contextIndex)),
    crossModuleHypotheses: [],
  };
}

function buildFallbackModulePlan(
  module: DiscoveredModule,
  staticIntel: StaticIntelligence,
  contextIndex: MonorepoContextIndex,
): ModuleTaskRecommendation {
  const shared = contextIndex.modules.get(module.path);
  const selection = __taskSelectorInternals.selectTasks(shared?.repoContext);
  const baseTasks = normalizeRecommendedTasks(selection.recommendedTasks);
  const surface = staticIntel.attackSurfaces.get(module.path);
  const depNode = staticIntel.dependencyGraph.nodes.get(module.path);
  const recommendedTasks = new Set(baseTasks);

  if (surface?.isExternalFacing) {
    recommendedTasks.add("taint-iris");
  }
  if ((surface?.entryPointCount ?? 0) > 0) {
    recommendedTasks.add("threat-model-randori");
  }

  return {
    modulePath: module.path,
    riskLevel: fallbackRiskLevel(surface?.isExternalFacing === true, depNode?.inDegree ?? 0),
    rationale: "Fallback: deterministic monorepo task selection from module context and attack surface.",
    recommendedTasks: [...recommendedTasks].filter((taskId) => MONOREPO_TASK_ALLOWLIST_SET.has(taskId)).sort(),
    focusAreas: buildFocusAreas(shared),
  };
}

function buildFocusAreas(
  shared: MonorepoContextIndex["modules"] extends Map<string, infer T> ? T | undefined : never,
): string[] {
  if (!shared) {
    return [];
  }
  return [
    ...shared.repoContext.frameworks,
    ...shared.repoContext.authPatterns,
    ...shared.attackSurface.entryPointTypes,
  ].slice(0, 8);
}

function fallbackRiskLevel(isExternalFacing: boolean, inDegree: number): ModulePriority {
  if (isExternalFacing && inDegree >= 2) return "critical";
  if (isExternalFacing || inDegree >= 2) return "high";
  if (inDegree >= 1) return "medium";
  return "low";
}

function validateRiskLevel(value: unknown): ModulePriority {
  if (value === "critical" || value === "high" || value === "medium" || value === "low") {
    return value;
  }
  return "medium";
}

export const __architecturalAnalysisInternals = {
  inferTasksFromHypothesis,
  normalizeRecommendedTasks,
  buildFallbackModulePlan,
  MONOREPO_TASK_ALLOWLIST,
};
