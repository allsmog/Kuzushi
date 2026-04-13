/**
 * Phase 3 — Cross-module data flow stitching.
 *
 * After all per-module scans complete, collects boundary manifests from
 * each module's taint analysis (if it ran), matches entry/exit points
 * across modules using the existing cross-service stitch infrastructure,
 * and generates cross-module findings.
 *
 * Reuses `matchBoundariesHeuristically` and `STITCH_RESPONSE_SCHEMA`
 * from `src/agents/tasks/taint-analysis/cross-service/stitch.ts`.
 */

import { createHash } from "node:crypto";
import type { AgentRuntime } from "../agent-runtime/types.js";
import { runStructuredAgentQuery } from "../agent-runtime/execution.js";
import { matchBoundariesHeuristically } from "../agents/tasks/taint-analysis/cross-service/stitch.js";
import {
  STITCH_RESPONSE_SCHEMA,
  type BoundaryManifest,
  type StitchedEdge,
  type CrossServicePath,
  type StitchLlmResponse,
} from "../agents/tasks/taint-analysis/cross-service/types.js";
import { scoreFindingMetadata } from "../scanners/scoring.js";
import type { Finding } from "../scanners/types.js";
import { isRecord, normalizeCostUsd, toErrorMessage } from "../utils.js";
import { getLogger } from "../logger.js";
import type { ModuleInteractionEdge, ModuleInteractionGraph, MonorepoThreatModel } from "./types.js";

const log = getLogger("cross-module-trace");

// ── Public API ──────────────────────────────────────────────────────────

export interface CrossModuleTracingOptions {
  model: string;
  runtime: AgentRuntime;
  monorepoRoot: string;
}

export interface CrossModuleTracingResult {
  findings: Finding[];
  interactionGraph: ModuleInteractionGraph;
  paths: CrossServicePath[];
  costUsd: number;
}

/**
 * Run cross-module stitching to discover vulnerabilities spanning module boundaries.
 *
 * @param boundaries — Boundary manifests collected from each module's taint analysis
 * @param perModuleFindings — Findings from all per-module scans
 * @param staticEdges — Interaction edges from Phase 0 static analysis
 * @param threatModel — Architectural threat model from Phase 1
 */
export async function traceAcrossModules(
  boundaries: BoundaryManifest[],
  perModuleFindings: Map<string, Finding[]>,
  staticEdges: ModuleInteractionEdge[],
  threatModel: MonorepoThreatModel | null,
  options: CrossModuleTracingOptions,
): Promise<CrossModuleTracingResult> {
  if (boundaries.length < 2) {
    log.info("Fewer than 2 module boundaries — skipping cross-module tracing");
    return {
      findings: [],
      interactionGraph: buildInteractionGraph(boundaries, [], staticEdges, perModuleFindings, threatModel),
      paths: [],
      costUsd: 0,
    };
  }

  log.info(`Stitching boundaries across ${boundaries.length} modules`);

  // Step 1: Heuristic matching — deterministic, $0
  const heuristicEdges = matchBoundariesHeuristically(boundaries);
  log.info(`Heuristic matching: ${heuristicEdges.length} edges`);

  // Step 2: LLM semantic validation (one call)
  let validatedEdges = heuristicEdges;
  let costUsd = 0;

  if (options.runtime) {
    try {
      const llmResult = await validateWithLlm(boundaries, heuristicEdges, options);
      validatedEdges = llmResult.edges;
      costUsd = llmResult.costUsd;
      log.info(`LLM validation: ${validatedEdges.length} validated edges ($${costUsd.toFixed(4)})`);
    } catch (error) {
      log.warn(`LLM stitch validation failed, using heuristic edges: ${toErrorMessage(error)}`);
    }
  }

  // Step 3: Build cross-module paths from validated edges
  const paths = buildCrossModulePaths(validatedEdges, boundaries);
  log.info(`Discovered ${paths.length} cross-module data flow paths`);

  // Step 4: Convert paths to findings
  const findings = paths.map((p) => pathToFinding(p, options.monorepoRoot));

  // Step 5: Assemble interaction graph
  const graph = buildInteractionGraph(boundaries, validatedEdges, staticEdges, perModuleFindings, threatModel);

  return { findings, interactionGraph: graph, paths, costUsd };
}

// ── LLM Validation ─────────────────────────────────────────────────────

async function validateWithLlm(
  boundaries: BoundaryManifest[],
  heuristicEdges: StitchedEdge[],
  options: CrossModuleTracingOptions,
): Promise<{ edges: StitchedEdge[]; costUsd: number }> {
  const prompt = buildStitchPrompt(boundaries, heuristicEdges);

  const result = await runStructuredAgentQuery({
    prompt,
    cwd: options.monorepoRoot,
    model: options.model,
    allowedTools: [],
    runtimeOptions: {
      runtime: options.runtime,
      maxOutputTokens: 4096,
      thinkingDisabled: true,
    },
    schema: STITCH_RESPONSE_SCHEMA as unknown as Record<string, unknown>,
    strict: true,
    systemPromptPrefix: STITCH_SYSTEM_PROMPT,
  });

  if (result.executionError) {
    throw new Error(result.executionError);
  }

  const parsed = parseStitchResult(result.structuredOutput, boundaries, heuristicEdges);
  return { edges: parsed, costUsd: result.costUsd };
}

const STITCH_SYSTEM_PROMPT = [
  "You are validating cross-module data flow connections in a monorepo.",
  "For each proposed edge (exit point in module A → entry point in module B),",
  "confirm whether the data actually flows between them based on the boundary descriptions.",
  "Also identify any additional cross-module flows not captured by heuristic matching.",
  "Focus on security-relevant flows: user input, credentials, file paths, SQL fragments.",
].join("\n");

function buildStitchPrompt(
  boundaries: BoundaryManifest[],
  heuristicEdges: StitchedEdge[],
): string {
  const sections: string[] = [];

  sections.push("## Module Boundaries\n");
  for (const b of boundaries) {
    sections.push(`### ${b.serviceId} (${b.servicePath})`);
    sections.push(`Entry points: ${b.entryPoints.length}`);
    for (const ep of b.entryPoints.slice(0, 10)) {
      sections.push(`  [ENTRY] ${ep.callable} (${ep.protocol}) — ${ep.dataDescription}`);
    }
    sections.push(`Exit points: ${b.exitPoints.length}`);
    for (const ex of b.exitPoints.slice(0, 10)) {
      sections.push(`  [EXIT] ${ex.callable} (${ex.protocol}) — ${ex.dataDescription}`);
    }
    sections.push("");
  }

  sections.push("## Proposed Edges (from heuristic matching)\n");
  for (const edge of heuristicEdges) {
    sections.push(
      `- ${edge.source.serviceId}::${edge.source.point.callable} → ${edge.target.serviceId}::${edge.target.point.callable} (${edge.matchMethod}, confidence: ${edge.confidence})`,
    );
  }

  sections.push("\nValidate each proposed edge and identify any missing cross-module flows.");
  return sections.join("\n");
}

function parseStitchResult(
  raw: unknown,
  boundaries: BoundaryManifest[],
  heuristicEdges: StitchedEdge[],
): StitchedEdge[] {
  if (!isRecord(raw)) return heuristicEdges;

  const validated = Array.isArray(raw["validatedEdges"]) ? raw["validatedEdges"] : [];
  const validMap = new Map<string, boolean>();
  for (const v of validated) {
    if (isRecord(v)) {
      validMap.set(`${v["sourcePointId"]}→${v["targetPointId"]}`, v["valid"] === true);
    }
  }

  // Filter heuristic edges by LLM validation
  const confirmed = heuristicEdges.filter((edge) => {
    const key = `${edge.source.boundaryPointId}→${edge.target.boundaryPointId}`;
    return validMap.get(key) !== false; // keep if confirmed or not mentioned
  });

  return confirmed;
}

// ── Path Building ──────────────────────────────────────────────────────

function buildCrossModulePaths(
  edges: StitchedEdge[],
  boundaries: BoundaryManifest[],
): CrossServicePath[] {
  // Simple single-hop paths: each edge is a path from source module to target module
  return edges.map((edge) => ({
    serviceChain: [edge.source.serviceId, edge.target.serviceId],
    edges: [edge],
    ultimateSource: {
      serviceId: edge.source.serviceId,
      filePath: edge.source.point.filePath,
      startLine: edge.source.point.startLine,
      description: edge.source.point.dataDescription,
    },
    ultimateSink: {
      serviceId: edge.target.serviceId,
      filePath: edge.target.point.filePath,
      startLine: edge.target.point.startLine,
      description: edge.target.point.dataDescription,
    },
    pathConfidence: edge.confidence,
  }));
}

// ── Finding Conversion ─────────────────────────────────────────────────

function pathToFinding(crossPath: CrossServicePath, monorepoRoot: string): Finding {
  const chain = crossPath.serviceChain.join(" → ");
  const fingerprint = createHash("sha256")
    .update(`cross-module:${crossPath.ultimateSource.filePath}:${crossPath.ultimateSource.startLine}:${crossPath.ultimateSink.filePath}:${crossPath.ultimateSink.startLine}`)
    .digest("hex");

  const score = scoreFindingMetadata({
    severity: "WARNING",
    likelihood: "MEDIUM",
    impact: "HIGH",
  });

  return {
    fingerprint,
    scanner: "cross-module-tracing",
    ruleId: `cross-module/${crossPath.ultimateSource.serviceId}-to-${crossPath.ultimateSink.serviceId}`,
    filePath: crossPath.ultimateSource.filePath,
    startLine: crossPath.ultimateSource.startLine,
    severity: "WARNING",
    message: `Cross-module data flow: ${crossPath.ultimateSource.description} flows from ${crossPath.ultimateSource.serviceId} to ${crossPath.ultimateSink.serviceId} (${crossPath.ultimateSink.description})`,
    evidence: `Data path: ${chain}. Source: ${crossPath.ultimateSource.filePath}:${crossPath.ultimateSource.startLine}. Sink: ${crossPath.ultimateSink.filePath}:${crossPath.ultimateSink.startLine}`,
    scannerConfidence: crossPath.pathConfidence > 0.7 ? "HIGH" : "MEDIUM",
    subcategory: ["vuln"],
    likelihood: "MEDIUM",
    impact: "HIGH",
    cwe: [],
    score,
  };
}

// ── Interaction Graph Assembly ─────────────────────────────────────────

function buildInteractionGraph(
  boundaries: BoundaryManifest[],
  stitchedEdges: StitchedEdge[],
  staticEdges: ModuleInteractionEdge[],
  perModuleFindings: Map<string, Finding[]>,
  threatModel: MonorepoThreatModel | null,
): ModuleInteractionGraph {
  const moduleIds = new Set<string>();
  for (const b of boundaries) moduleIds.add(b.serviceId);
  for (const e of staticEdges) {
    moduleIds.add(e.source);
    moduleIds.add(e.target);
  }

  const nodes = [...moduleIds].map((id) => ({
    moduleId: id,
    isExternalFacing: boundaries.some(
      (b) => b.serviceId === id && b.entryPoints.some((ep) => ep.protocol === "http-server"),
    ),
    findingCount: perModuleFindings.get(id)?.length ?? 0,
    riskLevel: threatModel?.modulePlans.find((plan) => plan.modulePath === id)?.riskLevel ?? "medium",
  }));

  // Merge static edges + stitched edges
  const edgeMap = new Map<string, { source: string; target: string; protocols: Set<string>; dataTypes: Set<string>; findings: string[] }>();

  for (const edge of staticEdges) {
    const key = `${edge.source}→${edge.target}`;
    const existing = edgeMap.get(key) ?? {
      source: edge.source,
      target: edge.target,
      protocols: new Set<string>(),
      dataTypes: new Set<string>(),
      findings: [],
    };
    existing.protocols.add(edge.interactionType);
    edgeMap.set(key, existing);
  }

  for (const edge of stitchedEdges) {
    const key = `${edge.source.serviceId}→${edge.target.serviceId}`;
    const existing = edgeMap.get(key) ?? {
      source: edge.source.serviceId,
      target: edge.target.serviceId,
      protocols: new Set<string>(),
      dataTypes: new Set<string>(),
      findings: [],
    };
    existing.protocols.add(edge.source.point.protocol);
    existing.dataTypes.add(edge.source.point.dataDescription);
    edgeMap.set(key, existing);
  }

  const edges = [...edgeMap.values()].map((e) => ({
    source: e.source,
    target: e.target,
    protocols: [...e.protocols],
    dataTypes: [...e.dataTypes],
    crossesTrustBoundary: false, // TODO: check against threat model boundaries
    findings: e.findings,
  }));

  // Compute blast radius: if module X is compromised, which others are affected?
  const blastRadius = new Map<string, string[]>();
  for (const id of moduleIds) {
    const affected = new Set<string>();
    const queue = [id];
    while (queue.length > 0) {
      const current = queue.pop()!;
      for (const edge of edges) {
        if (edge.source === current && !affected.has(edge.target) && edge.target !== id) {
          affected.add(edge.target);
          queue.push(edge.target);
        }
      }
    }
    blastRadius.set(id, [...affected]);
  }

  return { nodes, edges, blastRadius };
}
