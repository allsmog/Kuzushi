import { getCodeIntelligenceProvider } from "../../../analysis-support/index.js";
import { createLogger } from "../../../logger.js";
import { coerceRepoContext, coerceContextEnrichment } from "../../../repo-context.js";
import { attachTaskOutputMeta } from "../../../task-output-meta.js";
import type { ApplicationModel, ApplicationRoute, ScanOpts } from "../../../types.js";
import { toErrorMessage } from "../../../utils.js";
import type { AgentTask } from "../../types.js";
import { resolveTaskModel, resolveTaskRuntime, resolveTaskPositiveInt } from "../runtime-overrides.js";
import { buildTracePrompt, TRACE_OUTPUT_SCHEMA } from "./prompts.js";
import {
  makeNodeId,
  makeEdgeId,
  makePathId,
  upsertGraphNode,
  upsertGraphEdge,
  upsertGraphPath,
  getGraphNodesForRepo,
  invalidateStaleNodes,
} from "./store.js";
import type {
  CodeGraphNode,
  CodeGraphEdge,
  CodeGraphPath,
  CodeGraphOutput,
  CodeGraphNodeKind,
  CodeGraphEdgeKind,
} from "./types.js";

const log = createLogger({ stage: "code-graph-build" });

const DEFAULT_MAX_ENTRY_POINTS = 50;
const DEFAULT_MAX_TURNS_PER_TRACE = 10;

interface TraceHop {
  filePath: string;
  startLine: number;
  symbol: string;
  nodeKind: CodeGraphNodeKind;
  edgeKind: CodeGraphEdgeKind;
  dataLabel?: string;
  confidence: number;
}

function coerceApplicationModel(raw: unknown): ApplicationModel | null {
  if (!raw || typeof raw !== "object") return null;
  const obj = raw as Record<string, unknown>;
  if (!Array.isArray(obj["routes"])) return null;
  return raw as ApplicationModel;
}

export const codeGraphBuildTask: AgentTask<ScanOpts, CodeGraphOutput> = {
  id: "code-graph-build",
  displayName: "Code Graph Builder",
  outputKind: "custom",
  dependsOn: ["context-gatherer", "context-enricher", "app-model-build"],

  condition(upstreamOutputs, config) {
    return config.codeGraphEnabled === true;
  },

  async run(_input, context): Promise<CodeGraphOutput> {
    const repo = context.repoName;
    const runId = context.runId;
    const workingRoot = context.scanPath ?? context.repoRoot;
    const db = context.db;

    const repoContext = coerceRepoContext(context.upstreamOutputs.get("context-gatherer"));
    const enrichment = coerceContextEnrichment(context.upstreamOutputs.get("context-enricher"));
    const appModel = coerceApplicationModel(context.upstreamOutputs.get("app-model-build"));

    const graphConfig = (context.config.scannerConfig["code-graph"] ?? {}) as Record<string, unknown>;
    const rawMaxEntryPoints = typeof graphConfig["maxEntryPoints"] === "number" ? graphConfig["maxEntryPoints"] : null;
    const maxEntryPoints = rawMaxEntryPoints != null ? rawMaxEntryPoints : DEFAULT_MAX_ENTRY_POINTS;
    const maxTurnsPerTrace = resolveTaskPositiveInt(context, "code-graph", "maxTurnsPerTrace", DEFAULT_MAX_TURNS_PER_TRACE);
    const model = resolveTaskModel(context, "code-graph");
    const warmStart = (graphConfig as Record<string, unknown>)["warmStart"] !== false;

    const allNodes: CodeGraphNode[] = [];
    const allEdges: CodeGraphEdge[] = [];
    const allPaths: CodeGraphPath[] = [];
    let totalCostUsd = 0;
    let staticNodeCount = 0;
    let llmNodeCount = 0;
    let tracedEntryPoints = 0;

    // ── Phase A: Static skeleton ────────────────────────────────────────

    log.info("Phase A: Building static skeleton from code intelligence");

    const intelligence = await getCodeIntelligenceProvider(workingRoot);
    const importGraph = await intelligence.getImportGraph();

    // Create nodes from import graph edges (deduplicate by nodeId)
    const seenNodeIds = new Set<string>();
    for (const edge of importGraph) {
      const fromId = makeNodeId(repo, edge.fromFilePath, 1, null);
      const toId = makeNodeId(repo, edge.toPath, 1, null);

      if (!seenNodeIds.has(fromId)) {
        seenNodeIds.add(fromId);
        allNodes.push({
          nodeId: fromId, filePath: edge.fromFilePath, startLine: 1, symbol: null,
          nodeKind: "unknown", framework: null, metadata: {}, confidence: 1.0, source: "static",
        });
        staticNodeCount++;
      }
      if (!seenNodeIds.has(toId)) {
        seenNodeIds.add(toId);
        allNodes.push({
          nodeId: toId, filePath: edge.toPath, startLine: 1, symbol: null,
          nodeKind: "unknown", framework: null, metadata: {}, confidence: 1.0, source: "static",
        });
        staticNodeCount++;
      }

      const edgeId = makeEdgeId(fromId, toId, "imports");
      allEdges.push({
        edgeId, fromNodeId: fromId, toNodeId: toId,
        edgeKind: "imports", dataLabel: null, ordinal: null, confidence: 1.0, source: "static",
      });
    }

    // Create entry point nodes from ApplicationModel routes
    const entryRoutes: ApplicationRoute[] = appModel?.routes ?? [];
    for (const route of entryRoutes) {
      const nodeId = makeNodeId(repo, route.filePath, route.startLine, route.handlerSymbol ?? null);
      const entryNode: CodeGraphNode = {
        nodeId, filePath: route.filePath, startLine: route.startLine,
        symbol: route.handlerSymbol ?? null, nodeKind: "entry-http",
        framework: route.framework ?? repoContext?.frameworks[0] ?? null,
        metadata: { method: route.method, path: route.path, middleware: route.middleware },
        confidence: 1.0, source: "static",
      };
      allNodes.push(entryNode);
      staticNodeCount++;
    }

    // Tag sanitizer/middleware nodes from enrichment
    if (enrichment) {
      for (const mw of enrichment.customMiddleware) {
        const nodeId = makeNodeId(repo, mw.filePath, 1, mw.name);
        allNodes.push({
          nodeId, filePath: mw.filePath, startLine: 1, symbol: mw.name,
          nodeKind: "middleware", framework: null,
          metadata: { purpose: mw.purpose }, confidence: 0.9, source: "static",
        });
        staticNodeCount++;
      }
      for (const san of enrichment.customSanitizers) {
        const nodeId = makeNodeId(repo, san.filePath, 1, san.name);
        allNodes.push({
          nodeId, filePath: san.filePath, startLine: 1, symbol: san.name,
          nodeKind: "sanitizer", framework: null,
          metadata: { sanitizationType: san.sanitizationType }, confidence: 0.9, source: "static",
        });
        staticNodeCount++;
      }
    }

    // Persist static graph if DB available
    if (db) {
      if (warmStart) {
        // Check for stale data from previous runs — simplified: just check if nodes exist
        const existingNodes = getGraphNodesForRepo(db, repo);
        if (existingNodes.length > 0) {
          log.info(`Warm start: ${existingNodes.length} existing graph nodes found`);
        }
      }

      for (const node of allNodes) upsertGraphNode(db, repo, runId, node);
      for (const edge of allEdges) upsertGraphEdge(db, repo, runId, edge);
    }

    log.info(`Phase A complete: ${staticNodeCount} nodes, ${allEdges.length} edges from static analysis`);

    // ── Phase B: LLM gap-filling ────────────────────────────────────────

    if (entryRoutes.length === 0) {
      log.info("No entry points found, skipping LLM tracing");
      const output: CodeGraphOutput = {
        nodes: allNodes, edges: allEdges, paths: allPaths,
        stats: {
          totalNodes: allNodes.length, totalEdges: allEdges.length, totalPaths: 0,
          staticNodes: staticNodeCount, llmInferredNodes: 0,
          entryPoints: 0, tracedEntryPoints: 0, costUsd: 0,
        },
      };
      return attachTaskOutputMeta(output, { costUsd: 0 });
    }

    const routesToTrace = entryRoutes.slice(0, maxEntryPoints);
    const frameworks = repoContext?.frameworks ?? [];

    log.info(`Phase B: Tracing ${routesToTrace.length}/${entryRoutes.length} entry points via LLM`);

    const runtime = resolveTaskRuntime(context);

    for (const route of routesToTrace) {
      const prompt = buildTracePrompt({
        method: route.method,
        routePath: route.path,
        handlerSymbol: route.handlerSymbol ?? "unknown",
        filePath: route.filePath,
        startLine: route.startLine,
        frameworks,
        middlewareList: route.middleware,
      });

      try {
        let structuredOutput: unknown;
        let costUsd = 0;

        for await (const message of runtime.query({
          prompt,
          options: {
            cwd: workingRoot,
            model,
            maxTurns: maxTurnsPerTrace,
            allowedTools: ["Read", "Glob", "Grep", "GetCallers", "GetCallees"],
            permissionMode: "dontAsk",
            outputFormat: {
              type: "json_schema",
              schema: TRACE_OUTPUT_SCHEMA,
              strict: true,
              retryInvalidStructuredOutput: 1,
            },
          },
        })) {
          if (message.type === "result" && "result" in message) {
            structuredOutput = message.structuredOutput;
            costUsd = (message as unknown as Record<string, unknown>).totalCostUsd as number ?? 0;
          }
        }

        totalCostUsd += costUsd;

        // Parse trace hops and create nodes/edges
        const hops = parseTraceHops(structuredOutput);
        if (hops.length > 0) {
          const entryNodeId = makeNodeId(repo, route.filePath, route.startLine, route.handlerSymbol ?? null);
          const pathNodeIds: string[] = [entryNodeId];
          const pathEdgeIds: string[] = [];
          let prevNodeId = entryNodeId;
          let hasSanitizer = false;
          const sanitizerNodeIds: string[] = [];

          for (const hop of hops) {
            const nodeId = makeNodeId(repo, hop.filePath, hop.startLine, hop.symbol);
            const node: CodeGraphNode = {
              nodeId, filePath: hop.filePath, startLine: hop.startLine,
              symbol: hop.symbol, nodeKind: hop.nodeKind,
              framework: frameworks[0] ?? null,
              metadata: hop.dataLabel ? { dataLabel: hop.dataLabel } : {},
              confidence: hop.confidence, source: "llm",
            };
            allNodes.push(node);
            llmNodeCount++;

            if (hop.nodeKind === "sanitizer" || hop.nodeKind === "validator") {
              hasSanitizer = true;
              sanitizerNodeIds.push(nodeId);
            }

            const edgeId = makeEdgeId(prevNodeId, nodeId, hop.edgeKind);
            const edge: CodeGraphEdge = {
              edgeId, fromNodeId: prevNodeId, toNodeId: nodeId,
              edgeKind: hop.edgeKind, dataLabel: hop.dataLabel ?? null,
              ordinal: pathNodeIds.length, confidence: hop.confidence, source: "llm",
            };
            allEdges.push(edge);

            pathNodeIds.push(nodeId);
            pathEdgeIds.push(edgeId);
            prevNodeId = nodeId;

            if (db) {
              upsertGraphNode(db, repo, runId, node);
              upsertGraphEdge(db, repo, runId, edge);
            }
          }

          // Materialize path from entry to last hop
          const lastNodeId = prevNodeId;
          const minConfidence = Math.min(...hops.map((h) => h.confidence));
          const pathObj: CodeGraphPath = {
            pathId: makePathId(entryNodeId, lastNodeId, pathNodeIds),
            entryNodeId, targetNodeId: lastNodeId,
            hopCount: hops.length, nodeIds: pathNodeIds, edgeIds: pathEdgeIds,
            hasSanitizer, sanitizerNodeIds, confidence: minConfidence,
          };
          allPaths.push(pathObj);
          if (db) upsertGraphPath(db, repo, runId, pathObj);
        }

        tracedEntryPoints++;
        log.debug(`Traced ${route.method} ${route.path}: ${hops.length} hops, $${costUsd.toFixed(4)}`);
      } catch (error) {
        log.warn(`Failed to trace ${route.method} ${route.path}: ${toErrorMessage(error)}`);
      }
    }

    log.info(
      `Phase B complete: ${llmNodeCount} LLM nodes, ${tracedEntryPoints}/${routesToTrace.length} entry points traced, $${totalCostUsd.toFixed(4)}`,
    );

    const output: CodeGraphOutput = {
      nodes: allNodes,
      edges: allEdges,
      paths: allPaths,
      stats: {
        totalNodes: allNodes.length,
        totalEdges: allEdges.length,
        totalPaths: allPaths.length,
        staticNodes: staticNodeCount,
        llmInferredNodes: llmNodeCount,
        entryPoints: entryRoutes.length,
        tracedEntryPoints,
        costUsd: totalCostUsd,
      },
    };

    return attachTaskOutputMeta(output, { costUsd: totalCostUsd });
  },
};

function parseTraceHops(raw: unknown): TraceHop[] {
  if (!raw || typeof raw !== "object") return [];
  const obj = raw as Record<string, unknown>;
  if (!Array.isArray(obj["hops"])) return [];
  const hops: TraceHop[] = [];
  for (const item of obj["hops"]) {
    if (!item || typeof item !== "object") continue;
    const hop = item as Record<string, unknown>;
    if (typeof hop["filePath"] !== "string" || typeof hop["startLine"] !== "number") continue;
    hops.push({
      filePath: hop["filePath"] as string,
      startLine: hop["startLine"] as number,
      symbol: String(hop["symbol"] ?? "unknown"),
      nodeKind: (hop["nodeKind"] as CodeGraphNodeKind) ?? "unknown",
      edgeKind: (hop["edgeKind"] as CodeGraphEdgeKind) ?? "calls",
      dataLabel: typeof hop["dataLabel"] === "string" ? hop["dataLabel"] : undefined,
      confidence: typeof hop["confidence"] === "number" ? hop["confidence"] : 0.5,
    });
  }
  return hops;
}
