import { readFile } from "node:fs/promises";
import path from "node:path";
import { getCodeIntelligenceProvider } from "../../../analysis-support/index.js";
import { createLogger } from "../../../logger.js";
import { coerceRepoContext, coerceContextEnrichment } from "../../../repo-context.js";
import { attachTaskOutputMeta } from "../../../task-output-meta.js";
import type { ApplicationModel, ApplicationRoute, ScanOpts } from "../../../types.js";
import { toErrorMessage } from "../../../utils.js";
import type { AgentTask } from "../../types.js";
import { resolveTaskModel, resolveTaskRuntime, resolveTaskPositiveInt } from "../runtime-overrides.js";
import { buildTracePrompt, buildDiscoveryPrompt, TRACE_OUTPUT_SCHEMA } from "./prompts.js";
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
const HTTP_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "ALL", "HTTP"]);
const EVENT_ENTRY_METHODS = new Set(["GRPC", "TCP", "UDP", "UNIX"]);

interface TraceHop {
  filePath: string;
  startLine: number;
  symbol: string;
  nodeKind: CodeGraphNodeKind;
  edgeKind: CodeGraphEdgeKind;
  dataLabel?: string;
  confidence: number;
}

interface StaticNodeDescriptor {
  nodeKind: CodeGraphNodeKind;
  framework: string | null;
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
    const appModelRoutes: ApplicationRoute[] = appModel?.routes ?? [];
    const entryRoutes = appModelRoutes.length > 0
      ? appModelRoutes
      : await detectFallbackEntryRoutes(workingRoot, repoContext, importGraph);
    const staticNodeDescriptors = await buildStaticNodeDescriptors(workingRoot, importGraph, entryRoutes);

    if (appModelRoutes.length === 0 && entryRoutes.length > 0) {
      log.info(`No application routes found; using ${entryRoutes.length} synthetic fallback entry point(s)`);
    }

    // Create nodes from import graph edges (deduplicate by nodeId)
    const seenNodeIds = new Set<string>();
    for (const edge of importGraph) {
      const fromId = makeNodeId(repo, edge.fromFilePath, 1, null);
      const toId = makeNodeId(repo, edge.toPath, 1, null);
      const fromDescriptor = staticNodeDescriptors.get(edge.fromFilePath) ?? { nodeKind: "unknown", framework: null };
      const toDescriptor = staticNodeDescriptors.get(edge.toPath) ?? { nodeKind: "unknown", framework: null };

      if (!seenNodeIds.has(fromId)) {
        seenNodeIds.add(fromId);
        allNodes.push({
          nodeId: fromId, filePath: edge.fromFilePath, startLine: 1, symbol: null,
          nodeKind: fromDescriptor.nodeKind, framework: fromDescriptor.framework, metadata: {}, confidence: 1.0, source: "static",
        });
        staticNodeCount++;
      }
      if (!seenNodeIds.has(toId)) {
        seenNodeIds.add(toId);
        allNodes.push({
          nodeId: toId, filePath: edge.toPath, startLine: 1, symbol: null,
          nodeKind: toDescriptor.nodeKind, framework: toDescriptor.framework, metadata: {}, confidence: 1.0, source: "static",
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
    for (const route of entryRoutes) {
      const nodeId = makeNodeId(repo, route.filePath, route.startLine, route.handlerSymbol ?? null);
      const nodeKind = inferRouteNodeKind(route);
      const entryNode: CodeGraphNode = {
        nodeId, filePath: route.filePath, startLine: route.startLine,
        symbol: route.handlerSymbol ?? null, nodeKind,
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

    const routesToTrace = entryRoutes.slice(0, maxEntryPoints);
    const frameworks = repoContext?.frameworks ?? [];
    const discoveryMode = entryRoutes.length === 0;

    const runtime = resolveTaskRuntime(context);

    // Discovery mode: no pre-identified entry points — let the LLM find them
    if (discoveryMode) {
      log.info("Phase B: Discovery mode — LLM will identify entry points and trace paths");

      // Collect project file paths (excluding external deps) for the LLM
      const projectFiles = new Set<string>();
      for (const edge of importGraph) {
        if (!edge.fromFilePath.includes("node_modules") && !edge.fromFilePath.startsWith("github.com/")) {
          projectFiles.add(edge.fromFilePath);
        }
        if (!edge.toPath.includes("node_modules") && !edge.toPath.startsWith("github.com/")) {
          projectFiles.add(edge.toPath);
        }
      }

      // Build threat model summary if available
      const threatModelRaw = context.upstreamOutputs.get("threat-model-randori");
      let threatModelSummary: string | undefined;
      if (threatModelRaw && typeof threatModelRaw === "object") {
        try {
          const tmDoc = threatModelRaw as Record<string, unknown>;
          const threats = Array.isArray(tmDoc["threats"]) ? tmDoc["threats"] : [];
          const topThreats = threats.slice(0, 5).map((t: unknown) => {
            const tr = t as Record<string, unknown>;
            return `- ${String(tr["title"] ?? "")} [${String(tr["category"] ?? "")}]`;
          }).filter(Boolean);
          if (topThreats.length > 0) {
            threatModelSummary = `Top threats identified:\n${topThreats.join("\n")}`;
          }
        } catch { /* non-fatal */ }
      }

      const discoveryPrompt = buildDiscoveryPrompt({
        fileList: [...projectFiles].sort(),
        frameworks,
        languages: repoContext?.languages ?? [],
        threatModelSummary,
        repoContextSummary: repoContext
          ? `Entry points: ${repoContext.entryPoints.join(", ") || "none detected"}\nFrameworks: ${repoContext.frameworks.join(", ") || "none"}\nDB/ORM: ${repoContext.ormOrDb.join(", ") || "none"}`
          : undefined,
      });

      try {
        let structuredOutput: unknown;
        let costUsd = 0;

        for await (const message of runtime.query({
          prompt: discoveryPrompt,
          options: {
            cwd: workingRoot,
            model,
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

        const hops = parseTraceHops(structuredOutput);
        if (hops.length > 0) {
          let prevNodeId: string | null = null;

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

            if (prevNodeId) {
              const edgeId = makeEdgeId(prevNodeId, nodeId, hop.edgeKind);
              const edge: CodeGraphEdge = {
                edgeId, fromNodeId: prevNodeId, toNodeId: nodeId,
                edgeKind: hop.edgeKind, dataLabel: hop.dataLabel ?? null,
                ordinal: null, confidence: hop.confidence, source: "llm",
              };
              allEdges.push(edge);
              if (db) upsertGraphEdge(db, repo, runId, edge);
            }

            if (db) upsertGraphNode(db, repo, runId, node);
            prevNodeId = nodeId;
          }

          tracedEntryPoints++;
        }

        log.info(`Discovery mode complete: ${hops.length} hops traced, $${costUsd.toFixed(4)}`);
      } catch (error) {
        log.warn(`Discovery mode failed: ${toErrorMessage(error)}`);
      }
    } else {
      // Standard mode: trace pre-identified entry points
      log.info(`Phase B: Tracing ${routesToTrace.length}/${entryRoutes.length} entry points via LLM`);
    }

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

function inferRouteNodeKind(route: ApplicationRoute): CodeGraphNodeKind {
  const method = route.method.toUpperCase();
  const routePath = route.path.toLowerCase();

  if (HTTP_METHODS.has(method) || routePath.startsWith("/") || routePath.startsWith("http://") || routePath.startsWith("https://")) {
    return "entry-http";
  }
  if (method === "CLI" || routePath.startsWith("cli://")) {
    return "entry-cli";
  }
  if (method === "INIT" || routePath.startsWith("go://init")) {
    return "entry-background";
  }
  if (EVENT_ENTRY_METHODS.has(method) || routePath.startsWith("grpc://") || routePath.startsWith("tcp://")) {
    return "entry-event";
  }
  if (method === "CRON") {
    return "entry-cron";
  }

  return "unknown";
}

async function buildStaticNodeDescriptors(
  repoRoot: string,
  importGraph: Array<{ fromFilePath: string; toPath: string }>,
  entryRoutes: ApplicationRoute[],
): Promise<Map<string, StaticNodeDescriptor>> {
  const filePaths = new Set<string>();
  for (const edge of importGraph) {
    filePaths.add(edge.fromFilePath);
    filePaths.add(edge.toPath);
  }

  const entryRoutesByFile = new Map<string, ApplicationRoute[]>();
  for (const route of entryRoutes) {
    const existing = entryRoutesByFile.get(route.filePath) ?? [];
    existing.push(route);
    entryRoutesByFile.set(route.filePath, existing);
  }

  const descriptors = await Promise.all(
    [...filePaths].map(async (filePath) => {
      const content = await safeReadRepoFile(repoRoot, filePath);
      return [filePath, classifyStaticNodeFromContent(content, entryRoutesByFile.get(filePath) ?? [])] as const;
    }),
  );

  return new Map(descriptors);
}

function classifyStaticNodeFromContent(
  content: string | null,
  entryRoutes: ApplicationRoute[],
): StaticNodeDescriptor {
  if (entryRoutes.length > 0) {
    const preferredRoute = [...entryRoutes].sort((left, right) => (
      rankNodeKind(inferRouteNodeKind(left)) - rankNodeKind(inferRouteNodeKind(right))
    ))[0];

    return {
      nodeKind: inferRouteNodeKind(preferredRoute),
      framework: preferredRoute.framework ?? inferStaticFramework(content),
    };
  }

  if (!content) {
    return { nodeKind: "unknown", framework: null };
  }

  if (/func(?:\s+\([^)]*\))?\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^)]*http\.ResponseWriter[^)]*\*?http\.Request/m.test(content)) {
    return { nodeKind: "entry-http", framework: "net/http" };
  }
  if (/^\s*func\s+main\s*\(/m.test(content)
    || /\bflag\.(?:String|Bool|Int|Int64|Uint|Uint64|Float64|Duration|Var|Parse)\s*\(/.test(content)
    || /\bcobra\.Command\b/.test(content)
    || /\b[A-Za-z_][A-Za-z0-9_]*\.(?:Execute|ExecuteContext)\s*\(/.test(content)
    || /\bkong\.Parse\s*\(/.test(content)) {
    return { nodeKind: "entry-cli", framework: "CLI" };
  }
  if (/^\s*func\s+init\s*\(/m.test(content)) {
    return { nodeKind: "entry-background", framework: "Go" };
  }
  if (/\b(?:grpc\.NewServer|net\.Listen(?:TCP|UDP|Unix)?)\s*\(/.test(content)) {
    return {
      nodeKind: "entry-event",
      framework: /\bgrpc\.NewServer\s*\(/.test(content) ? "gRPC" : "Go net",
    };
  }
  if (/\b(?:gin\.HandlerFunc|r\.Use\s*\(|e\.Use\s*\(|router\.Use\s*\()/i.test(content)) {
    return { nodeKind: "middleware", framework: inferStaticFramework(content) };
  }
  if (/\b(?:db\.Query|db\.Exec|tx\.Query|tx\.Exec|gorm\.DB)\b/.test(content)) {
    return { nodeKind: "data-access", framework: inferStaticFramework(content) };
  }
  if (/\b(?:exec\.Command|os\.Exit|net\.Dial|grpc\.Dial|sql\.(?:Query|Exec))\b/.test(content)) {
    return { nodeKind: "external-call", framework: inferStaticFramework(content) };
  }

  return {
    nodeKind: "unknown",
    framework: inferStaticFramework(content),
  };
}

function inferStaticFramework(content: string | null): string | null {
  if (!content) {
    return null;
  }
  if (/\bgrpc\.NewServer\s*\(/.test(content)) {
    return "gRPC";
  }
  if (/\bgin\./.test(content)) {
    return "Gin";
  }
  if (/\becho\./i.test(content)) {
    return "Echo";
  }
  if (/\bhttp\.(?:HandleFunc|ListenAndServe)|http\.ResponseWriter|http\.Request\b/.test(content)) {
    return "net/http";
  }
  if (/\b(?:flag\.(?:String|Bool|Int|Int64|Uint|Uint64|Float64|Duration|Var|Parse)|cobra\.Command|kong\.Parse)\b/.test(content)) {
    return "CLI";
  }
  return null;
}

function rankNodeKind(nodeKind: CodeGraphNodeKind): number {
  switch (nodeKind) {
    case "entry-http":
      return 0;
    case "entry-cli":
      return 1;
    case "entry-event":
      return 2;
    case "entry-cron":
      return 3;
    case "entry-background":
      return 4;
    case "middleware":
      return 5;
    case "data-access":
      return 6;
    case "external-call":
      return 7;
    default:
      return 8;
  }
}

async function detectFallbackEntryRoutes(
  repoRoot: string,
  repoContext: ReturnType<typeof coerceRepoContext>,
  importGraph: Array<{ fromFilePath: string; toPath: string }>,
): Promise<ApplicationRoute[]> {
  const candidateFiles = new Set<string>();

  for (const entryPoint of repoContext?.entryPoints ?? []) {
    if (!entryPoint.includes("*")) {
      candidateFiles.add(entryPoint);
    }
  }

  for (const edge of importGraph) {
    if (edge.fromFilePath.endsWith(".go")) {
      candidateFiles.add(edge.fromFilePath);
    }
    if (edge.toPath.endsWith(".go")) {
      candidateFiles.add(edge.toPath);
    }
  }

  const results: ApplicationRoute[] = [];

  for (const filePath of candidateFiles) {
    const content = await safeReadRepoFile(repoRoot, filePath);
    if (!content) {
      continue;
    }
    const lines = content.split(/\r?\n/u);

    // func main()
    const mainLine = lines.findIndex((line) => /^\s*func\s+main\s*\(/.test(line));
    if (mainLine >= 0) {
      results.push({
        id: `CLI|cli://main|${filePath}|${mainLine + 1}`,
        method: "CLI",
        path: "cli://main",
        filePath,
        startLine: mainLine + 1,
        framework: "CLI",
        handlerSymbol: "main",
        middleware: [],
        authMechanisms: [],
      });
    }

    // net.Listen*, grpc.NewServer, http.ListenAndServe*
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (/\bnet\.Listen(?:TCP|UDP|Unix)?\s*\(/.test(line)) {
        results.push({
          id: `TCP|tcp://listener|${filePath}|${i + 1}`,
          method: "TCP", path: "tcp://listener", filePath,
          startLine: i + 1, framework: "Go net",
          handlerSymbol: undefined, middleware: [], authMechanisms: [],
        });
      }
      if (/\bgrpc\.NewServer\s*\(/.test(line)) {
        results.push({
          id: `GRPC|grpc://server|${filePath}|${i + 1}`,
          method: "GRPC", path: "grpc://server", filePath,
          startLine: i + 1, framework: "gRPC",
          handlerSymbol: undefined, middleware: [], authMechanisms: [],
        });
      }
      if (/\bhttp\.ListenAndServe\s*\(/.test(line)) {
        results.push({
          id: `HTTP|http://server|${filePath}|${i + 1}`,
          method: "HTTP", path: "http://server", filePath,
          startLine: i + 1, framework: "net/http",
          handlerSymbol: undefined, middleware: [], authMechanisms: [],
        });
      }
    }
  }

  return results;
}

async function safeReadRepoFile(repoRoot: string, filePath: string): Promise<string | null> {
  try {
    return await readFile(path.join(repoRoot, filePath), "utf-8");
  } catch {
    return null;
  }
}

export const __codeGraphBuildInternals = {
  inferRouteNodeKind,
  classifyStaticNodeFromContent,
  detectFallbackEntryRoutes,
};
