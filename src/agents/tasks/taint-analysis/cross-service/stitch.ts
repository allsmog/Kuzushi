import { createHash } from "node:crypto";
import type {
  AgentResultErrorMessage,
  AgentResultSuccessMessage,
  AgentRuntime,
} from "../../../../agent-runtime/types.js";
import { scoreFindingMetadata } from "../../../../scanners/scoring.js";
import type { Finding, TriageAgentConfig } from "../../../../scanners/types.js";
import {
  attachTaskOutputMeta,
  getTaskOutputMeta,
  type TaskOutputMeta,
} from "../../../../task-output-meta.js";
import type { ScanOpts } from "../../../../types.js";
import { isRecord, normalizeCostUsd, toErrorMessage } from "../../../../utils.js";
import type { AgentTask } from "../../../types.js";
import { resolveTaintAnalysisConfig } from "../types.js";
import {
  type BoundaryManifest,
  type BoundaryPoint,
  type CrossServiceAnalysisOutput,
  type CrossServicePath,
  resolveCrossServiceConfig,
  STITCH_RESPONSE_SCHEMA,
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
  condition: (_upstreamOutputs, config) => {
    const cfg = resolveTaintAnalysisConfig(config);
    return resolveCrossServiceConfig(cfg).enabled;
  },
  async run(_input, context): Promise<Finding[]> {
    const cfg = resolveTaintAnalysisConfig(context.config);
    const crossCfg = resolveCrossServiceConfig(cfg);

    const analyzeOutput = asCrossServiceAnalysisOutput(
      context.upstreamOutputs.get("taint-analysis-cross-analyze"),
    );
    if (!analyzeOutput) {
      throw new Error(
        "taint-analysis-stitch requires upstream output from taint-analysis-cross-analyze",
      );
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
    let validationCostUsd = 0;
    let stitchDegradation: TaskOutputMeta["degradation"];
    try {
      validatedEdges = await validateAndEnrichWithLlm(
        allBoundaries,
        heuristicEdges,
        crossCfg.stitchModel,
        context.repoRoot,
        context.runtime,
      );
      validationCostUsd = normalizeCostUsd(getTaskOutputMeta(validatedEdges)?.costUsd);
    } catch (error) {
      validationCostUsd = getErrorCostUsd(error);
      const stitchDegradationMessage = toErrorMessage(error);
      process.stderr.write(
        `[taint-analysis-stitch] LLM validation failed, using heuristic edges only: ${stitchDegradationMessage}\n`,
      );
      stitchDegradation = {
        type: "stitch-degradation",
        reason: "llm_validation_failed",
        message: stitchDegradationMessage,
        heuristicEdgeCount: heuristicEdges.length,
      };
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

    const meta: TaskOutputMeta = { costUsd: validationCostUsd };
    if (stitchDegradation) {
      meta.degradation = stitchDegradation;
    }
    return attachTaskOutputMeta([...intraFindings, ...crossServiceFindings], meta);
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
        `Scanner: ${finding.taskId}`,
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

function asCrossServiceAnalysisOutput(value: unknown): CrossServiceAnalysisOutput | undefined {
  if (!isRecord(value)) {
    return undefined;
  }

  if (!Array.isArray(value["services"]) || !Array.isArray(value["allBoundaries"])) {
    return undefined;
  }

  return {
    services: value["services"].flatMap((service) => normalizePerServiceAnalysis(service)),
    allBoundaries: value["allBoundaries"].flatMap((boundary) =>
      normalizeBoundaryManifest(boundary),
    ),
  };
}

function normalizePerServiceAnalysis(value: unknown): CrossServiceAnalysisOutput["services"] {
  if (!isRecord(value) || !isRecord(value["service"])) {
    return [];
  }

  const service = value["service"];
  const id = typeof service["id"] === "string" ? service["id"] : "";
  const rootPath = typeof service["rootPath"] === "string" ? service["rootPath"] : "";
  const language = typeof service["language"] === "string" ? service["language"] : "";
  const boundary = normalizeBoundaryManifest(value["boundary"]).at(0);
  if (!id || !rootPath || !language || !boundary) {
    return [];
  }

  return [
    {
      service: {
        id,
        displayName: typeof service["displayName"] === "string" ? service["displayName"] : id,
        rootPath,
        language,
        framework: typeof service["framework"] === "string" ? service["framework"] : null,
        discoveryMethod: service["discoveryMethod"] === "manifest" ? "manifest" : "auto",
        manifestFiles: Array.isArray(service["manifestFiles"])
          ? service["manifestFiles"].map((item) => String(item))
          : [],
      },
      boundary,
      intraServiceFindings: normalizeFindingArray(value["intraServiceFindings"]),
      taintAnalysisSkipped: Boolean(value["taintAnalysisSkipped"]),
      taintAnalysisSkipReason:
        typeof value["taintAnalysisSkipReason"] === "string"
          ? value["taintAnalysisSkipReason"]
          : undefined,
      durationMs: Math.max(0, Number(value["durationMs"]) || 0),
    },
  ];
}

function normalizeBoundaryManifest(value: unknown): BoundaryManifest[] {
  if (!isRecord(value)) {
    return [];
  }

  const serviceId = typeof value["serviceId"] === "string" ? value["serviceId"] : "";
  const servicePath = typeof value["servicePath"] === "string" ? value["servicePath"] : "";
  if (!serviceId || !servicePath) {
    return [];
  }

  return [
    {
      serviceId,
      servicePath,
      entryPoints: normalizeBoundaryPoints(value["entryPoints"], "entry"),
      exitPoints: normalizeBoundaryPoints(value["exitPoints"], "exit"),
      errors: Array.isArray(value["errors"]) ? value["errors"].map((item) => String(item)) : [],
    },
  ];
}

function normalizeBoundaryPoints(
  value: unknown,
  direction: BoundaryPoint["direction"],
): BoundaryPoint[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.flatMap((point, index) => {
    if (!isRecord(point)) {
      return [];
    }

    const filePath = typeof point["filePath"] === "string" ? point["filePath"] : "";
    const callable = typeof point["callable"] === "string" ? point["callable"] : "";
    if (!filePath || !callable) {
      return [];
    }

    return [
      {
        id: typeof point["id"] === "string" ? point["id"] : `${direction}-${index + 1}`,
        direction,
        protocol:
          typeof point["protocol"] === "string"
            ? (point["protocol"] as BoundaryPoint["protocol"])
            : "unknown",
        filePath,
        startLine: Math.max(1, Number(point["startLine"]) || 1),
        callable,
        routePath: typeof point["routePath"] === "string" ? point["routePath"] : undefined,
        httpMethod: typeof point["httpMethod"] === "string" ? point["httpMethod"] : undefined,
        topicOrQueue: typeof point["topicOrQueue"] === "string" ? point["topicOrQueue"] : undefined,
        grpcMethod: typeof point["grpcMethod"] === "string" ? point["grpcMethod"] : undefined,
        dataEntity: typeof point["dataEntity"] === "string" ? point["dataEntity"] : undefined,
        dataDescription:
          typeof point["dataDescription"] === "string" ? point["dataDescription"] : "data",
        taintedParameters: Array.isArray(point["taintedParameters"])
          ? point["taintedParameters"].map((item) => String(item))
          : [],
        confidence: Number.isFinite(Number(point["confidence"])) ? Number(point["confidence"]) : 0,
        rationale: typeof point["rationale"] === "string" ? point["rationale"] : "",
      },
    ];
  });
}

function normalizeFindingArray(value: unknown): Finding[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.flatMap((finding) => {
    if (!isRecord(finding)) {
      return [];
    }

    const fingerprint = typeof finding["fingerprint"] === "string" ? finding["fingerprint"] : "";
    const ruleId = typeof finding["ruleId"] === "string" ? finding["ruleId"] : "";
    const filePath = typeof finding["filePath"] === "string" ? finding["filePath"] : "";
    const startLine = Number(finding["startLine"]);
    const severity = typeof finding["severity"] === "string" ? finding["severity"] : "";
    const message = typeof finding["message"] === "string" ? finding["message"] : "";
    if (
      !fingerprint ||
      !ruleId ||
      !filePath ||
      !Number.isFinite(startLine) ||
      !severity ||
      !message
    ) {
      return [];
    }

    return [
      {
        taskId: typeof finding["scanner"] === "string" ? finding["scanner"] : "unknown",
        fingerprint,
        ruleId,
        filePath,
        startLine,
        severity,
        message,
        evidence: typeof finding["evidence"] === "string" ? finding["evidence"] : null,
        scannerConfidence:
          typeof finding["scannerConfidence"] === "string"
            ? finding["scannerConfidence"]
            : "MEDIUM",
        subcategory: Array.isArray(finding["subcategory"])
          ? finding["subcategory"].map((item) => String(item))
          : [],
        likelihood: typeof finding["likelihood"] === "string" ? finding["likelihood"] : "MEDIUM",
        impact: typeof finding["impact"] === "string" ? finding["impact"] : "MEDIUM",
        cwe: Array.isArray(finding["cwe"]) ? finding["cwe"].map((item) => String(item)) : [],
        score: Number.isFinite(Number(finding["score"])) ? Number(finding["score"]) : 0,
        taintPath: Array.isArray(finding["taintPath"])
          ? finding["taintPath"].flatMap((step) => {
              if (!isRecord(step)) return [];
              const pathFile = typeof step["filePath"] === "string" ? step["filePath"] : "";
              const pathLine = Number(step["line"]);
              if (!pathFile || !Number.isFinite(pathLine)) {
                return [];
              }
              return [
                {
                  filePath: pathFile,
                  line: pathLine,
                  message: typeof step["message"] === "string" ? step["message"] : undefined,
                  snippet: typeof step["snippet"] === "string" ? step["snippet"] : undefined,
                },
              ];
            })
          : undefined,
        proofState:
          finding["proofState"] === "symbolic_only" ||
          finding["proofState"] === "execution_attempted" ||
          finding["proofState"] === "execution_confirmed" ||
          finding["proofState"] === "execution_rejected" ||
          finding["proofState"] === "inconclusive"
            ? finding["proofState"]
            : undefined,
        engineProvenance: Array.isArray(finding["engineProvenance"])
          ? finding["engineProvenance"].flatMap((entry) => {
              if (!isRecord(entry)) return [];
              const kind = typeof entry["kind"] === "string" ? entry["kind"] : "";
              const detail = typeof entry["detail"] === "string" ? entry["detail"] : "";
              if (!detail) {
                return [];
              }
              if (
                kind !== "semgrep" &&
                kind !== "codeql" &&
                kind !== "taint-analysis" &&
                kind !== "agentic" &&
                kind !== "dynamic"
              ) {
                return [];
              }
              return [{ kind, detail }];
            })
          : undefined,
      },
    ];
  });
}

// ── Heuristic Matching ──────────────────────────────────────────────────

export function matchBoundariesHeuristically(boundaries: BoundaryManifest[]): StitchedEdge[] {
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
          target: {
            serviceId: entry.serviceId,
            boundaryPointId: entry.point.id,
            point: entry.point,
          },
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
    exit.routePath &&
    entry.routePath &&
    normalizeRoute(exit.routePath) === normalizeRoute(entry.routePath) &&
    areHttpMethodsCompatible(exit.httpMethod, entry.httpMethod)
  ) {
    return {
      method: "url-path",
      confidence: 0.9,
      rationale: `Exact route path match: ${exit.routePath}`,
    };
  }

  // URL path prefix match
  if (
    exit.routePath &&
    entry.routePath &&
    normalizeRoute(exit.routePath).startsWith(normalizeRoute(entry.routePath))
  ) {
    return {
      method: "url-path",
      confidence: 0.7,
      rationale: `Route path prefix match: ${exit.routePath} starts with ${entry.routePath}`,
    };
  }

  // Topic/queue name exact match
  if (
    exit.topicOrQueue &&
    entry.topicOrQueue &&
    exit.topicOrQueue.toLowerCase() === entry.topicOrQueue.toLowerCase()
  ) {
    return {
      method: "topic-name",
      confidence: 0.85,
      rationale: `Topic/queue name match: ${exit.topicOrQueue}`,
    };
  }

  // gRPC method exact match
  if (exit.grpcMethod && entry.grpcMethod && exit.grpcMethod === entry.grpcMethod) {
    return {
      method: "grpc-method",
      confidence: 0.9,
      rationale: `gRPC method match: ${exit.grpcMethod}`,
    };
  }

  // Database shared-table match: write → read on same entity gets higher confidence
  if (
    exit.dataEntity &&
    entry.dataEntity &&
    exit.dataEntity.toLowerCase() === entry.dataEntity.toLowerCase()
  ) {
    const isDbWriteToRead =
      exit.protocol === "database-write" && entry.protocol === "database-read";
    return {
      method: "data-entity",
      confidence: isDbWriteToRead ? 0.8 : 0.6,
      rationale: isDbWriteToRead
        ? `Shared database table (write→read): ${exit.dataEntity}`
        : `Shared data entity: ${exit.dataEntity}`,
    };
  }

  // Fuzzy database entity match: normalize table names (strip schema prefix, pluralization)
  if (
    exit.dataEntity &&
    entry.dataEntity &&
    (exit.protocol === "database-write" || exit.protocol === "database-read") &&
    (entry.protocol === "database-write" || entry.protocol === "database-read")
  ) {
    const normalizedExit = normalizeDbEntity(exit.dataEntity);
    const normalizedEntry = normalizeDbEntity(entry.dataEntity);
    if (normalizedExit === normalizedEntry && normalizedExit.length > 0) {
      const isWriteToRead =
        exit.protocol === "database-write" && entry.protocol === "database-read";
      return {
        method: "data-entity",
        confidence: isWriteToRead ? 0.65 : 0.5,
        rationale: `Fuzzy database entity match (${exit.dataEntity} ≈ ${entry.dataEntity})${isWriteToRead ? " write→read" : ""}`,
      };
    }
  }

  // Service name in URL
  if (exit.routePath && exit.routePath.toLowerCase().includes(entryServiceId.toLowerCase())) {
    return {
      method: "url-path",
      confidence: 0.5,
      rationale: `Exit URL contains service name "${entryServiceId}": ${exit.routePath}`,
    };
  }

  return null;
}

function normalizeRoute(route: string): string {
  return route.replace(/\/+$/, "").replace(/\/+/g, "/").toLowerCase();
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
  runtime: AgentRuntime,
): Promise<StitchedEdge[]> {
  const prompt = buildStitchPrompt(boundaries, heuristicEdges);

  let structuredOutput: unknown;
  let resultText = "";
  let executionError: string | null = null;
  let costUsd = 0;

  for await (const message of runtime.query({
    prompt,
    options: {
      cwd: repoRoot,
      model,
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
    if (typeof message.totalCostUsd === "number" && Number.isFinite(message.totalCostUsd)) {
      costUsd = message.totalCostUsd;
    }
    if (message.subtype === "success") {
      const success = message as AgentResultSuccessMessage;
      resultText = success.result;
      structuredOutput = success.structuredOutput;
      executionError = null;
    } else {
      const errMsg = (message as AgentResultErrorMessage).errors.join("; ") || message.subtype;
      executionError = errMsg;
      structuredOutput = undefined;
      resultText = "";
    }
  }

  if (executionError && !structuredOutput && !resultText) {
    throw withCost(new Error(`Stitch LLM failed: ${executionError}`), costUsd);
  }

  let response: StitchLlmResponse;
  try {
    response = parseStitchResponse(structuredOutput ?? resultText);
  } catch (error) {
    throw withCost(new Error(`Stitch response parse failed: ${toErrorMessage(error)}`), costUsd);
  }

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
    const sourcePoint = pointLookup.get(
      `${additional.sourceServiceId}:${additional.sourcePointId}`,
    );
    const targetPoint = pointLookup.get(
      `${additional.targetServiceId}:${additional.targetPointId}`,
    );
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

  return attachTaskOutputMeta(validatedEdges, { costUsd });
}

function buildStitchPrompt(boundaries: BoundaryManifest[], heuristicEdges: StitchedEdge[]): string {
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
      const pathConfidence = edgeChain.reduce((min, e) => Math.min(min, e.confidence), 1);
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
    point.protocol === "http-server" ||
    point.protocol === "grpc-server" ||
    point.protocol === "message-consume" ||
    point.protocol === "database-read"
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
    taskId: "taint-analysis-stitch",
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
  if (sinkDesc.includes("command")) return "CWE-78";
  if (sinkDesc.includes("path") || sinkDesc.includes("traversal")) return "CWE-22";
  if (sinkDesc.includes("ssrf")) return "CWE-918";
  if (sinkDesc.includes("deserialization")) return "CWE-502";
  if (sinkDesc.includes("xss") || sinkDesc.includes("cross-site scripting")) return "CWE-79";
  if (sinkDesc.includes("xxe") || sinkDesc.includes("xml external")) return "CWE-611";
  if (sinkDesc.includes("redirect")) return "CWE-601";
  if (sinkDesc.includes("header injection") || sinkDesc.includes("response splitting"))
    return "CWE-113";
  if (sinkDesc.includes("log injection") || sinkDesc.includes("log forging")) return "CWE-117";
  if (sinkDesc.includes("ldap")) return "CWE-90";
  if (sinkDesc.includes("ssti") || sinkDesc.includes("template injection")) return "CWE-1336";
  if (
    sinkDesc.includes("code injection") ||
    sinkDesc.includes("eval") ||
    sinkDesc.includes("code execution")
  )
    return "CWE-94";
  if (sinkDesc.includes("injection")) return "CWE-78";
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
    } catch (error) {
      throw new Error(`Could not parse stitch response JSON: ${toErrorMessage(error)}`);
    }
  }

  throw new Error("Unexpected stitch response shape");
}

function withCost<T extends Error>(error: T, costUsd: number): T & { costUsd: number } {
  return Object.assign(error, { costUsd });
}

function getErrorCostUsd(error: unknown): number {
  if (!isRecord(error)) {
    return 0;
  }

  return normalizeCostUsd(error["costUsd"]);
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
    "url-path",
    "topic-name",
    "grpc-method",
    "data-entity",
    "llm-semantic",
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
        : ("llm-semantic" as StitchMatchMethod),
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
      serviceChain: Array.isArray(item["serviceChain"]) ? item["serviceChain"].map(String) : [],
      description: String(item["description"] ?? ""),
      cwe: String(item["cwe"] ?? ""),
      severity: String(item["severity"] ?? "WARNING"),
    }));
}

// ── Helpers ─────────────────────────────────────────────────────────────

function collectExitPoints(
  boundaries: BoundaryManifest[],
): Array<{ serviceId: string; point: BoundaryPoint }> {
  const out: Array<{ serviceId: string; point: BoundaryPoint }> = [];
  for (const boundary of boundaries) {
    for (const point of boundary.exitPoints) {
      out.push({ serviceId: boundary.serviceId, point });
    }
  }
  return out;
}

function collectEntryPoints(
  boundaries: BoundaryManifest[],
): Array<{ serviceId: string; point: BoundaryPoint }> {
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

/** Normalize a database entity name for fuzzy matching: strip schema prefix, lowercase, de-pluralize. */
function normalizeDbEntity(entity: string): string {
  let normalized = entity.toLowerCase().trim();
  // Strip schema prefix (e.g., "public.users" → "users", "dbo.orders" → "orders")
  const dotIdx = normalized.lastIndexOf(".");
  if (dotIdx >= 0) {
    normalized = normalized.slice(dotIdx + 1);
  }
  // Simple de-pluralization (handles common cases)
  if (normalized.endsWith("ies")) {
    normalized = normalized.slice(0, -3) + "y";
  } else if (
    normalized.endsWith("ses") ||
    normalized.endsWith("xes") ||
    normalized.endsWith("zes")
  ) {
    normalized = normalized.slice(0, -2);
  } else if (normalized.endsWith("s") && !normalized.endsWith("ss")) {
    normalized = normalized.slice(0, -1);
  }
  return normalized;
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
  normalizeDbEntity,
};
