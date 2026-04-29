import { createLogger } from "../../../logger.js";
import type { Finding } from "../../../scanners/types.js";
import { attachTaskOutputMeta } from "../../../task-output-meta.js";
import type { DagNodeImpl } from "../../types.js";
import { getGraphNodeByFileAndLine, getNodeById, getPathsToNode } from "./store.js";
import type {
  CodeGraphNode,
  CodeGraphOutput,
  CodeGraphPath,
  FindingGraphContext,
} from "./types.js";

const log = createLogger({ stage: "code-graph-enrich" });

const SCORE_PENALTY_UNREACHABLE = 15;

function coerceCodeGraphOutput(raw: unknown): CodeGraphOutput | null {
  if (!raw || typeof raw !== "object") return null;
  const obj = raw as Record<string, unknown>;
  if (!Array.isArray(obj["nodes"])) return null;
  return raw as CodeGraphOutput;
}

/** Build a human-readable summary of a graph path for triage prompt injection. */
function buildPathSummary(path: CodeGraphPath, nodeMap: Map<string, CodeGraphNode>): string {
  const parts: string[] = [];
  for (const nodeId of path.nodeIds) {
    const node = nodeMap.get(nodeId);
    if (node) {
      const label = node.symbol ?? node.filePath.split("/").pop() ?? "?";
      parts.push(`${label} (${node.nodeKind})`);
    }
  }
  return parts.join(" -> ");
}

/** Get a FindingGraphContext for a single finding from the code graph. */
function getGraphContextForFinding(
  finding: Finding,
  graphOutput: CodeGraphOutput,
  db: ReturnType<typeof import("better-sqlite3")> | undefined,
  repo: string,
): FindingGraphContext {
  const defaultContext: FindingGraphContext = {
    reachable: "unknown",
    hopsFromEntry: null,
    nearestEntryPoint: null,
    path: null,
    sanitizersOnPath: [],
    summary: "No code graph data available for this finding.",
  };

  // Build in-memory node map from graph output
  const nodeMap = new Map<string, CodeGraphNode>();
  for (const node of graphOutput.nodes) {
    nodeMap.set(node.nodeId, node);
  }

  // Find the graph node nearest to this finding's location
  let targetNode: CodeGraphNode | null = null;

  if (db) {
    targetNode = getGraphNodeByFileAndLine(db, repo, finding.filePath, finding.startLine, 10);
  }

  // Fallback: search in-memory
  if (!targetNode) {
    for (const node of graphOutput.nodes) {
      if (
        node.filePath === finding.filePath &&
        Math.abs(node.startLine - finding.startLine) <= 10
      ) {
        targetNode = node;
        break;
      }
    }
  }

  if (!targetNode) {
    return defaultContext;
  }

  // Find paths to this node
  let paths: CodeGraphPath[] = [];
  if (db) {
    paths = getPathsToNode(db, repo, targetNode.nodeId);
  }

  // Fallback: search in-memory paths
  if (paths.length === 0) {
    paths = graphOutput.paths.filter((p) => p.nodeIds.includes(targetNode!.nodeId));
  }

  if (paths.length === 0) {
    return {
      ...defaultContext,
      reachable: "unknown",
      summary: `Finding at ${finding.filePath}:${finding.startLine} exists in graph but no path from entry point was found.`,
    };
  }

  // Pick the shortest path
  const bestPath = paths.sort((a, b) => a.hopCount - b.hopCount)[0]!;
  const entryNode =
    nodeMap.get(bestPath.entryNodeId) ?? (db ? getNodeById(db, bestPath.entryNodeId) : null);

  const sanitizersOnPath = bestPath.sanitizerNodeIds
    .map((id) => {
      const node = nodeMap.get(id) ?? (db ? getNodeById(db, id) : null);
      return node
        ? { nodeId: id, symbol: node.symbol ?? "unknown", filePath: node.filePath }
        : null;
    })
    .filter(Boolean) as FindingGraphContext["sanitizersOnPath"];

  const entryLabel = entryNode
    ? `${(entryNode.metadata as Record<string, unknown>)["method"] ?? "?"} ${(entryNode.metadata as Record<string, unknown>)["path"] ?? entryNode.symbol ?? "?"}`
    : "unknown entry point";

  // Find hop count from entry to this specific finding node
  const findingIdx = bestPath.nodeIds.indexOf(targetNode.nodeId);
  const hopsFromEntry = findingIdx >= 0 ? findingIdx : bestPath.hopCount;

  const summary = buildPathSummary(bestPath, nodeMap);

  return {
    reachable: "true",
    hopsFromEntry,
    nearestEntryPoint: entryLabel,
    path: bestPath,
    sanitizersOnPath,
    summary: `${hopsFromEntry} hops from ${entryLabel}. Path: ${summary}. ${sanitizersOnPath.length > 0 ? `Sanitizers on path: ${sanitizersOnPath.map((s) => s.symbol).join(", ")}` : "No sanitizers on path."}`,
  };
}

export const codeGraphEnrichTask: DagNodeImpl<Finding[], Finding[]> = {
  id: "code-graph-enrich",
  displayName: "Code Graph Enrichment",
  outputKind: "findings",
  dependsOn: ["code-graph-build"],

  condition(upstreamOutputs, config) {
    return config.codeGraphEnabled === true;
  },

  async run(input, context): Promise<Finding[]> {
    if (!Array.isArray(input) || input.length === 0) {
      return input ?? [];
    }

    const graphOutput = coerceCodeGraphOutput(context.upstreamOutputs.get("code-graph-build"));
    if (!graphOutput) {
      log.warn("No code graph output available, passing findings through unchanged");
      return input;
    }

    const repo = context.repoName;
    const db = context.db;

    log.info(`Enriching ${input.length} findings with code graph context`);

    const enriched = input.map((finding) => {
      const graphContext = getGraphContextForFinding(finding, graphOutput, db, repo);

      // Apply reachability-based score adjustment
      const scorePenalty = graphContext.reachable === "false" ? SCORE_PENALTY_UNREACHABLE : 0;
      const sanitizerPenalty = graphContext.sanitizersOnPath.length > 0 ? 5 : 0;

      return {
        ...finding,
        adjustedScore: Math.max(
          0,
          (finding.adjustedScore ?? finding.score) - scorePenalty - sanitizerPenalty,
        ),
        evidence: [
          finding.evidence ?? "",
          graphContext.summary ? `Code graph: ${graphContext.summary}` : "",
        ]
          .filter(Boolean)
          .join("\n"),
        // Attach graph context as metadata for triage prompt injection
        graphContext,
      } as Finding & { graphContext: FindingGraphContext };
    });

    const reachable = enriched.filter((f) => f.graphContext.reachable === "true").length;
    const unreachable = enriched.filter((f) => f.graphContext.reachable === "false").length;
    const unknown = enriched.filter((f) => f.graphContext.reachable === "unknown").length;

    log.info(
      `Code graph enrichment: ${reachable} reachable, ${unreachable} unreachable, ${unknown} unknown`,
    );

    return attachTaskOutputMeta(enriched, { costUsd: 0 });
  },
};
