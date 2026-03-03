import { createHash } from "node:crypto";
import { getAgentRuntime } from "../../../../agent-runtime/index.js";
import { scoreFindingMetadata } from "../../../../scanners/scoring.js";
import type { Finding, TriageAgentConfig } from "../../../../scanners/types.js";
import type { ScanOpts } from "../../../../types.js";
import { isRecord, toErrorMessage } from "../../../../utils.js";
import type { AgentTask } from "../../../types.js";
import { resolveTaintAnalysisConfig } from "../types.js";
import {
  resolveCrossServiceConfig,
  STITCH_RESPONSE_SCHEMA,
  type BoundaryManifest,
  type BoundaryPoint,
  type CrossServiceAnalysisOutput,
  type CrossServicePath,
  type StitchedEdge,
  type StitchLlmResponse,
  type StitchMatchMethod,
} from "./types.js";

/**
 * Stitching task: connects boundary points across services using heuristic matching
 * and LLM semantic validation, then generates cross-service Findings.
 */
export const taintAnalysisStitchTask: AgentTask<ScanOpts, Finding[]> = {
  id: "taint-analysis-stitch",
  displayName: "Cross-Service Stitch",
  outputKind: "findings",
  dependsOn: ["taint-analysis-cross-analyze"],
  async run(_input, context): Promise<Finding[]> {
    const cfg = resolveTaintAnalysisConfig(context.config);
    const crossCfg = resolveCrossServiceConfig(cfg);

    const analyzeOutput = context.upstreamOutputs.get("taint-analysis-cross-analyze") as
      | CrossServiceAnalysisOutput
      | undefined;
    if (!analyzeOutput) {
      throw new Error("taint-analysis-stitch requires upstream output from taint-analysis-cross-analyze");
    }

    const { allBoundaries } = analyzeOutput;
    if (allBoundaries.length < 2) {
      // Need at least 2 services to stitch
      return collectIntraServiceFindings(analyzeOutput);
    }

    // Step 1: Deterministic heuristic matching
    const heuristicEdges = matchBoundariesHeuristically(allBoundaries);

    // Step 2: LLM semantic validation + gap-filling
    let validatedEdges = heuristicEdges;
    try {
      validatedEdges = await validateAndEnrichWithLlm(
        allBoundaries,
        heuristicEdges,
        crossCfg.stitchModel,
        context.repoRoot,
      );
    } catch (error) {
      process.stderr.write(
        `[taint-analysis-stitch] LLM validation failed, using heuristic edges only: ${toErrorMessage(error)}\n`,
      );
    }

    // Step 3: Build paths and generate findings
    const filteredEdges = validatedEdges.filter((e) => e.confidence >= crossCfg.stitchThreshold);
    const paths = buildCrossServicePaths(
      filteredEdges,
      allBoundaries,
      analyzeOutput,
      crossCfg.maxPathDepth,
    );

    const crossServiceFindings = paths.map((p) => pathToFinding(p, context.repoName));
    const intraFindings = collectIntraServiceFindings(analyzeOutput);

    return [...intraFindings, ...crossServiceFindings];
  },
  triageAgentConfig(finding, repoName): TriageAgentConfig {
    return {
      prompt: [
        "You are a cross-service taint analysis triage agent.",
        "The finding describes a data flow that spans multiple services in a microservice/monorepo architecture.",
        "The flow was detected by combining per-service CodeQL taint analysis with inter-service boundary stitching.",
        "",
        "## Finding",
        `Repo: ${repoName}`,
        `Scanner: ${finding.scanner}`,
        `Rule: ${finding.ruleId}`,
        `File: ${finding.filePath}:${finding.startLine}`,
        `Severity: ${finding.severity}`,
        `Message: ${finding.message}`,
        `Evidence: ${finding.evidence || "none"}`,
        `CWE: ${finding.cwe.join(", ") || "none"}`,
        `Fingerprint: ${finding.fingerprint}`,
        "",
        "## Investigation instructions",
        "1. Verify the cross-service data flow is real by checking each service boundary in the chain.",
        "2. Confirm the ultimate source receives attacker-controlled input.",
        "3. Confirm the ultimate sink is actually dangerous (e.g., SQL query, command execution).",
        "4. Check for sanitization at any boundary crossing (API gateway validation, schema validation, etc.).",
        "5. Assess whether the services are deployed together and reachable in production.",
        "",
        "## Output requirements",
        "Return ONLY a JSON object with:",
        "fingerprint, verdict(tp|fp|needs_review), confidence(0..1), rationale, verification_steps(array), fix_patch(string|null)",
      ].join("\n"),
    };
  },
};

// ── Heuristic Matching ──────────────────────────────────────────────────

export function matchBoundariesHeuristically(
  boundaries: BoundaryManifest[],
): StitchedEdge[] {
  const edges: StitchedEdge[] = [];
  const exitPoints = collectExitPoints(boundaries);
  const entryPoints = collectEntryPoints(boundaries);

  for (const exit of exitPoints) {
    for (const entry of entryPoints) {
      // Don't match within the same service
      if (exit.serviceId === entry.serviceId) continue;

      const match = matchPair(exit.point, entry.point, entry.serviceId);
      if (match) {
        edges.push({
          source: { serviceId: exit.serviceId, boundaryPointId: exit.point.id, point: exit.point },
          target: { serviceId: entry.serviceId, boundaryPointId: entry.point.id, point: entry.point },
          matchMethod: match.method,
          confidence: match.confidence,
          rationale: match.rationale,
        });
      }
    }
  }

  return edges;
}

interface MatchResult {
  method: StitchMatchMethod;
  confidence: number;
  rationale: string;
}

function matchPair(
  exit: BoundaryPoint,
  entry: BoundaryPoint,
  entryServiceId: string,
): MatchResult | null {
  // URL path exact match
  if (
    exit.routePath
    && entry.routePath
    && normalizeRoute(exit.routePath) === normalizeRoute(entry.routePath)
    && areHttpMethodsCompatible(exit.httpMethod, entry.httpMethod)
  ) {
    return {
      method: "url-path",
      confidence: 0.9,
      rationale: `Exact route path match: ${exit.routePath}`,
    };
  }

  // URL path prefix match
  if (
    exit.routePath
    && entry.routePath
    && normalizeRoute(exit.routePath).startsWith(normalizeRoute(entry.routePath))
  ) {
    return {
      method: "url-path",
      confidence: 0.7,
      rationale: `Route path prefix match: ${exit.routePath} starts with ${entry.routePath}`,
    };
  }

  // Topic/queue name exact match
  if (
    exit.topicOrQueue
    && entry.topicOrQueue
    && exit.topicOrQueue.toLowerCase() === entry.topicOrQueue.toLowerCase()
  ) {
    return {
      method: "topic-name",
      confidence: 0.85,
      rationale: `Topic/queue name match: ${exit.topicOrQueue}`,
    };
  }

  // gRPC method exact match
  if (
    exit.grpcMethod
    && entry.grpcMethod
    && exit.grpcMethod === entry.grpcMethod
  ) {
    return {
      method: "grpc-method",
      confidence: 0.9,
      rationale: `gRPC method match: ${exit.grpcMethod}`,
    };
  }

  // Data entity match (shared DB table)
  if (
    exit.dataEntity
    && entry.dataEntity
    && exit.dataEntity.toLowerCase() === entry.dataEntity.toLowerCase()
  ) {
    return {
      method: "data-entity",
      confidence: 0.6,
      rationale: `Shared data entity: ${exit.dataEntity}`,
    };
  }

  // Service name in URL
  if (
    exit.routePath
    && exit.routePath.toLowerCase().includes(entryServiceId.toLowerCase())
  ) {
    return {
      method: "url-path",
      confidence: 0.5,
      rationale: `Exit URL contains service name "${entryServiceId}": ${exit.routePath}`,
    };
  }

  return null;
}

function normalizeRoute(route: string): string {
  return route
    .replace(/\/+$/, "")
    .replace(/\/+/g, "/")
    .toLowerCase();
}

function areHttpMethodsCompatible(exitMethod?: string, entryMethod?: string): boolean {
  if (!exitMethod || !entryMethod) return true;
  return exitMethod.toUpperCase() === entryMethod.toUpperCase();
}

// ── LLM Validation + Enrichment ─────────────────────────────────────────

async function validateAndEnrichWithLlm(
  boundaries: BoundaryManifest[],
  heuristicEdges: StitchedEdge[],
  model: string,
  repoRoot: string,
): Promise<StitchedEdge[]> {
  const prompt = buildStitchPrompt(boundaries, heuristicEdges);
  const runtime = getAgentRuntime();

  let structuredOutput: unknown;
  let resultText = "";
  let executionError: string | null = null;

  for await (const message of runtime.query({
    prompt,
    options: {
      cwd: repoRoot,
      model,
      maxTurns: undefined,
      allowedTools: [],
      permissionMode: "dontAsk",
      outputFormat: {
        type: "json_schema",
        schema: STITCH_RESPONSE_SCHEMA as unknown as Record<string, unknown>,
        strict: true,
        retryInvalidStructuredOutput: 2,
      },
    },
  })) {
    if (message.type !== "result") continue;
    if (message.subtype === "success" && "result" in message) {
      resultText = (message as { result: string; structuredOutput?: unknown }).result;
      structuredOutput = (message as { result: string; structuredOutput?: unknown }).structuredOutput;
      executionError = null;
    } else {
      const errMsg = "errors" in message
        ? (message as { errors: string[] }).errors.join("; ")
        : message.subtype;
      executionError = errMsg;
      structuredOutput = undefined;
      resultText = "";
    }
  }

  if (executionError && !structuredOutput && !resultText) {
    throw new Error(`Stitch LLM failed: ${executionError}`);
  }

  const response = parseStitchResponse(structuredOutput ?? resultText);

  // Apply LLM validation to heuristic edges
  const validatedEdges: StitchedEdge[] = [];
  const validationMap = new Map<string, { valid: boolean; confidence: number }>();
  for (const v of response.validatedEdges) {
    const key = `${v.sourcePointId}:${v.targetPointId}`;
    validationMap.set(key, { valid: v.valid, confidence: v.confidence });
  }

  for (const edge of heuristicEdges) {
    const key = `${edge.source.boundaryPointId}:${edge.target.boundaryPointId}`;
    const validation = validationMap.get(key);
    if (validation) {
      if (validation.valid) {
        validatedEdges.push({
          ...edge,
          confidence: Math.max(edge.confidence, validation.confidence),
        });
      }
      // Rejected edges are dropped
    } else {
      // Keep unvalidated heuristic edges
      validatedEdges.push(edge);
    }
  }

  // Add LLM-discovered additional edges
  const pointLookup = buildPointLookup(boundaries);
  for (const additional of response.additionalEdges) {
    const sourcePoint = pointLookup.get(`${additional.sourceServiceId}:${additional.sourcePointId}`);
    const targetPoint = pointLookup.get(`${additional.targetServiceId}:${additional.targetPointId}`);
    if (!sourcePoint || !targetPoint) continue;

    validatedEdges.push({
      source: {
        serviceId: additional.sourceServiceId,
        boundaryPointId: additional.sourcePointId,
        point: sourcePoint,
      },
      target: {
        serviceId: additional.targetServiceId,
        boundaryPointId: additional.targetPointId,
        point: targetPoint,
      },
      matchMethod: additional.matchMethod,
      confidence: additional.confidence,
      rationale: additional.rationale,
    });
  }

  return validatedEdges;
}

function buildStitchPrompt(
  boundaries: BoundaryManifest[],
  heuristicEdges: StitchedEdge[],
): string {
  const boundaryPayload = boundaries.map((b) => ({
    serviceId: b.serviceId,
    entryPoints: b.entryPoints.map(pointSummary),
    exitPoints: b.exitPoints.map(pointSummary),
  }));

  const edgePayload = heuristicEdges.map((e) => ({
    sourceService: e.source.serviceId,
    sourcePointId: e.source.boundaryPointId,
    targetService: e.target.serviceId,
    targetPointId: e.target.boundaryPointId,
    matchMethod: e.matchMethod,
    confidence: e.confidence,
    rationale: e.rationale,
  }));

  return [
    "You are a cross-service security analyst validating inter-service data flow connections.",
    "",
    "## Service boundaries",
    JSON.stringify(boundaryPayload, null, 2),
    "",
    "## Heuristic matches to validate",
    JSON.stringify(edgePayload, null, 2),
    "",
    "## Your task",
    "1. Validate each heuristic match: is it a real inter-service connection?",
    "   - Consider route semantics, data types, protocol compatibility.",
    "   - Set `valid: true/false` and adjust `confidence`.",
    "",
    "2. Find additional connections missed by heuristics:",
    "   - Semantic matches (e.g., an exit that fetches 'user-service/api/v2/users' matching an entry at '/api/v2/users')",
    "   - Shared data patterns (e.g., exit writes to 'users' table, entry reads from 'users' table)",
    "",
    "3. Identify end-to-end attack paths that start at a user-facing entry and end at a dangerous sink.",
    "   - Include the CWE (e.g., CWE-89 for SQL injection) and severity.",
    "",
    "Return JSON matching the schema. For `validatedEdges`, use the same sourcePointId/targetPointId from the heuristic matches.",
  ].join("\n");
}

function pointSummary(point: BoundaryPoint): Record<string, unknown> {
  return {
    id: point.id,
    direction: point.direction,
    protocol: point.protocol,
    callable: point.callable,
    routePath: point.routePath,
    httpMethod: point.httpMethod,
    topicOrQueue: point.topicOrQueue,
    grpcMethod: point.grpcMethod,
    dataEntity: point.dataEntity,
    dataDescription: point.dataDescription,
    confidence: point.confidence,
  };
}

// ── Path Construction ───────────────────────────────────────────────────

function buildCrossServicePaths(
  edges: StitchedEdge[],
  boundaries: BoundaryManifest[],
  analyzeOutput: CrossServiceAnalysisOutput,
  maxDepth: number,
): CrossServicePath[] {
  // Build adjacency list: serviceId → outgoing edges
  const adjacency = new Map<string, StitchedEdge[]>();
  for (const edge of edges) {
    const outgoing = adjacency.get(edge.source.serviceId) ?? [];
    outgoing.push(edge);
    adjacency.set(edge.source.serviceId, outgoing);
  }

  // Find all services with user-facing entry points
  const userEntryServices = new Set<string>();
  for (const boundary of boundaries) {
    for (const entry of boundary.entryPoints) {
      if (isUserFacingEntry(entry)) {
        userEntryServices.add(boundary.serviceId);
      }
    }
  }

  // Find all services with dangerous sinks (from intra-service findings)
  const sinkServices = new Map<string, Finding[]>();
  for (const analysis of analyzeOutput.services) {
    if (analysis.intraServiceFindings.length > 0) {
      sinkServices.set(analysis.service.id, analysis.intraServiceFindings);
    }
  }

  const paths: CrossServicePath[] = [];

  // DFS from each user-entry service to find paths to sink services
  for (const startServiceId of userEntryServices) {
    const startBoundary = boundaries.find((b) => b.serviceId === startServiceId);
    if (!startBoundary) continue;

    const userEntries = startBoundary.entryPoints.filter(isUserFacingEntry);
    for (const startEntry of userEntries) {
      dfs(
        startServiceId,
        [startServiceId],
        [],
        startEntry,
        adjacency,
        sinkServices,
        maxDepth,
        paths,
      );
    }
  }

  return paths;
}

function dfs(
  currentService: string,
  chain: string[],
  edgeChain: StitchedEdge[],
  sourceEntry: BoundaryPoint,
  adjacency: Map<string, StitchedEdge[]>,
  sinkServices: Map<string, Finding[]>,
  maxDepth: number,
  paths: CrossServicePath[],
): void {
  if (chain.length >= maxDepth) return;

  // Check if current service has sinks
  const findings = sinkServices.get(currentService);
  if (findings && findings.length > 0 && edgeChain.length > 0) {
    for (const finding of findings) {
      const pathConfidence = edgeChain.reduce(
        (min, e) => Math.min(min, e.confidence),
        1,
      );
      paths.push({
        serviceChain: [...chain],
        edges: [...edgeChain],
        ultimateSource: {
          serviceId: chain[0],
          filePath: sourceEntry.filePath,
          startLine: sourceEntry.startLine,
          description: `${sourceEntry.protocol} ${sourceEntry.callable} (${sourceEntry.dataDescription})`,
        },
        ultimateSink: {
          serviceId: currentService,
          filePath: finding.filePath,
          startLine: finding.startLine,
          description: finding.message,
        },
        pathConfidence,
      });
    }
  }

  // Continue DFS through outgoing edges
  const outgoing = adjacency.get(currentService) ?? [];
  for (const edge of outgoing) {
    const nextService = edge.target.serviceId;
    if (chain.includes(nextService)) continue; // Avoid cycles
    dfs(
      nextService,
      [...chain, nextService],
      [...edgeChain, edge],
      sourceEntry,
      adjacency,
      sinkServices,
      maxDepth,
      paths,
    );
  }
}

function isUserFacingEntry(point: BoundaryPoint): boolean {
  return (
    point.protocol === "http-server"
    || point.protocol === "grpc-server"
    || point.protocol === "message-consume"
  );
}

// ── Finding Generation ──────────────────────────────────────────────────

function pathToFinding(crossPath: CrossServicePath, repoName: string): Finding {
  const chainDesc = crossPath.serviceChain.join(" → ");
  const edgeDescs = crossPath.edges.map(
    (e) =>
      `${e.source.serviceId}:${e.source.point.callable} →[${e.matchMethod}]→ ${e.target.serviceId}:${e.target.point.callable}`,
  );
  const evidence = [
    `Cross-service flow: ${chainDesc}`,
    ...edgeDescs,
    `Source: ${crossPath.ultimateSource.description}`,
    `Sink: ${crossPath.ultimateSink.description}`,
    `Path confidence: ${crossPath.pathConfidence.toFixed(2)}`,
  ].join(" | ");

  const cwe = inferCweFromPath(crossPath);
  const severity = crossPath.pathConfidence >= 0.8 ? "ERROR" : "WARNING";

  const fingerprint = createHash("sha256")
    .update(
      [
        "taint-analysis-stitch",
        crossPath.serviceChain.join("|"),
        crossPath.ultimateSource.serviceId,
        crossPath.ultimateSource.filePath,
        String(crossPath.ultimateSource.startLine),
        crossPath.ultimateSink.serviceId,
        crossPath.ultimateSink.filePath,
        String(crossPath.ultimateSink.startLine),
        repoName,
      ].join(":"),
    )
    .digest("hex")
    .slice(0, 32);

  return {
    scanner: "taint-analysis-stitch",
    fingerprint,
    ruleId: `taint-analysis/cross-service/${cwe.toLowerCase().replaceAll("-", "")}`,
    filePath: crossPath.ultimateSink.filePath,
    startLine: crossPath.ultimateSink.startLine,
    severity,
    message: `[Cross-Service Taint] ${crossPath.ultimateSource.serviceId} → ${crossPath.ultimateSink.serviceId}: ${crossPath.ultimateSink.description}`,
    evidence,
    scannerConfidence: crossPath.pathConfidence >= 0.8 ? "HIGH" : "MEDIUM",
    subcategory: ["vuln"],
    likelihood: crossPath.pathConfidence >= 0.8 ? "HIGH" : "MEDIUM",
    impact: "HIGH",
    cwe: [cwe],
    score: scoreFindingMetadata({
      severity,
      likelihood: crossPath.pathConfidence >= 0.8 ? "HIGH" : "MEDIUM",
      impact: "HIGH",
      subcategory: ["vuln"],
    }),
  };
}

function inferCweFromPath(crossPath: CrossServicePath): string {
  // Try to infer CWE from the sink finding's existing CWE tags
  const sinkDesc = crossPath.ultimateSink.description.toLowerCase();
  if (sinkDesc.includes("sql")) return "CWE-89";
  if (sinkDesc.includes("command") || sinkDesc.includes("injection")) return "CWE-78";
  if (sinkDesc.includes("path") || sinkDesc.includes("traversal")) return "CWE-22";
  if (sinkDesc.includes("ssrf")) return "CWE-918";
  if (sinkDesc.includes("deserialization")) return "CWE-502";
  if (sinkDesc.includes("xss") || sinkDesc.includes("script")) return "CWE-79";
  return "CWE-346"; // Origin Validation Error (generic cross-service)
}

// ── Response Parsing ────────────────────────────────────────────────────

function parseStitchResponse(value: unknown): StitchLlmResponse {
  if (isRecord(value)) {
    return {
      validatedEdges: parseValidatedEdges(value["validatedEdges"]),
      additionalEdges: parseAdditionalEdges(value["additionalEdges"]),
      paths: parseLlmPaths(value["paths"]),
    };
  }

  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(extractJson(value));
      return parseStitchResponse(parsed);
    } catch {
      return { validatedEdges: [], additionalEdges: [], paths: [] };
    }
  }

  return { validatedEdges: [], additionalEdges: [], paths: [] };
}

function parseValidatedEdges(value: unknown): StitchLlmResponse["validatedEdges"] {
  if (!Array.isArray(value)) return [];
  return value
    .filter((item) => isRecord(item))
    .map((item) => ({
      sourcePointId: String(item["sourcePointId"] ?? ""),
      targetPointId: String(item["targetPointId"] ?? ""),
      valid: item["valid"] === true,
      confidence: clampUnit(Number(item["confidence"])),
      rationale: String(item["rationale"] ?? ""),
    }))
    .filter((e) => e.sourcePointId && e.targetPointId);
}

function parseAdditionalEdges(value: unknown): StitchLlmResponse["additionalEdges"] {
  if (!Array.isArray(value)) return [];
  const validMethods = new Set<StitchMatchMethod>([
    "url-path", "topic-name", "grpc-method", "data-entity", "llm-semantic",
  ]);
  return value
    .filter((item) => isRecord(item))
    .map((item) => ({
      sourceServiceId: String(item["sourceServiceId"] ?? ""),
      sourcePointId: String(item["sourcePointId"] ?? ""),
      targetServiceId: String(item["targetServiceId"] ?? ""),
      targetPointId: String(item["targetPointId"] ?? ""),
      matchMethod: validMethods.has(item["matchMethod"] as StitchMatchMethod)
        ? (item["matchMethod"] as StitchMatchMethod)
        : "llm-semantic" as StitchMatchMethod,
      confidence: clampUnit(Number(item["confidence"])),
      rationale: String(item["rationale"] ?? ""),
    }))
    .filter((e) => e.sourceServiceId && e.sourcePointId && e.targetServiceId && e.targetPointId);
}

function parseLlmPaths(value: unknown): StitchLlmResponse["paths"] {
  if (!Array.isArray(value)) return [];
  return value
    .filter((item) => isRecord(item))
    .map((item) => ({
      serviceChain: Array.isArray(item["serviceChain"])
        ? item["serviceChain"].map(String)
        : [],
      description: String(item["description"] ?? ""),
      cwe: String(item["cwe"] ?? ""),
      severity: String(item["severity"] ?? "WARNING"),
    }));
}

// ── Helpers ─────────────────────────────────────────────────────────────

function collectExitPoints(boundaries: BoundaryManifest[]): Array<{ serviceId: string; point: BoundaryPoint }> {
  const out: Array<{ serviceId: string; point: BoundaryPoint }> = [];
  for (const boundary of boundaries) {
    for (const point of boundary.exitPoints) {
      out.push({ serviceId: boundary.serviceId, point });
    }
  }
  return out;
}

function collectEntryPoints(boundaries: BoundaryManifest[]): Array<{ serviceId: string; point: BoundaryPoint }> {
  const out: Array<{ serviceId: string; point: BoundaryPoint }> = [];
  for (const boundary of boundaries) {
    for (const point of boundary.entryPoints) {
      out.push({ serviceId: boundary.serviceId, point });
    }
  }
  return out;
}

function buildPointLookup(boundaries: BoundaryManifest[]): Map<string, BoundaryPoint> {
  const map = new Map<string, BoundaryPoint>();
  for (const boundary of boundaries) {
    for (const point of [...boundary.entryPoints, ...boundary.exitPoints]) {
      map.set(`${boundary.serviceId}:${point.id}`, point);
    }
  }
  return map;
}

function collectIntraServiceFindings(output: CrossServiceAnalysisOutput): Finding[] {
  const findings: Finding[] = [];
  for (const analysis of output.services) {
    findings.push(...analysis.intraServiceFindings);
  }
  return findings;
}

function clampUnit(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(1, value));
}

function extractJson(value: string): string {
  const fenced = value.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
  if (fenced) return fenced[1].trim();
  const first = value.indexOf("{");
  const last = value.lastIndexOf("}");
  if (first >= 0 && last > first) return value.slice(first, last + 1);
  return value;
}

export const __stitchInternals = {
  matchBoundariesHeuristically,
  matchPair,
  buildCrossServicePaths,
  pathToFinding,
  inferCweFromPath,
  parseStitchResponse,
  isUserFacingEntry,
  normalizeRoute,
};
