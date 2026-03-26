import { createHash } from "node:crypto";
import type Database from "better-sqlite3";
import type {
  CodeGraphNode,
  CodeGraphEdge,
  CodeGraphPath,
  GraphSource,
  CodeGraphNodeKind,
  CodeGraphEdgeKind,
} from "./types.js";

/** Deterministic node ID: hash of repo + filePath + line + symbol. */
export function makeNodeId(repo: string, filePath: string, startLine: number, symbol: string | null): string {
  const source = `${repo}|${filePath}|${startLine}|${symbol ?? ""}`;
  return createHash("sha256").update(source).digest("hex").slice(0, 32);
}

/** Deterministic edge ID: hash of from + to + kind. */
export function makeEdgeId(fromNodeId: string, toNodeId: string, edgeKind: string): string {
  const source = `${fromNodeId}|${toNodeId}|${edgeKind}`;
  return createHash("sha256").update(source).digest("hex").slice(0, 32);
}

/** Deterministic path ID: hash of entry + target + nodeIds. */
export function makePathId(entryNodeId: string, targetNodeId: string, nodeIds: string[]): string {
  const source = `${entryNodeId}|${targetNodeId}|${nodeIds.join(",")}`;
  return createHash("sha256").update(source).digest("hex").slice(0, 32);
}

// ── Node operations ──────────────────────────────────────────────────────

export function upsertGraphNode(db: Database.Database, repo: string, runId: string, node: CodeGraphNode): void {
  db.prepare(`
    INSERT INTO code_graph_nodes (node_id, repo, run_id, file_path, start_line, symbol, node_kind, framework, metadata_json, confidence, source)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(node_id) DO UPDATE SET
      run_id = excluded.run_id,
      node_kind = excluded.node_kind,
      framework = excluded.framework,
      metadata_json = excluded.metadata_json,
      confidence = MAX(code_graph_nodes.confidence, excluded.confidence),
      source = CASE WHEN code_graph_nodes.source != excluded.source THEN 'hybrid' ELSE excluded.source END,
      updated_at = datetime('now')
  `).run(
    node.nodeId, repo, runId, node.filePath, node.startLine, node.symbol,
    node.nodeKind, node.framework, JSON.stringify(node.metadata),
    node.confidence, node.source,
  );
}

export function upsertGraphEdge(db: Database.Database, repo: string, runId: string, edge: CodeGraphEdge): void {
  db.prepare(`
    INSERT INTO code_graph_edges (edge_id, repo, run_id, from_node_id, to_node_id, edge_kind, data_label, ordinal, confidence, source)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(edge_id) DO UPDATE SET
      run_id = excluded.run_id,
      confidence = MAX(code_graph_edges.confidence, excluded.confidence),
      source = CASE WHEN code_graph_edges.source != excluded.source THEN 'hybrid' ELSE excluded.source END
  `).run(
    edge.edgeId, repo, runId, edge.fromNodeId, edge.toNodeId,
    edge.edgeKind, edge.dataLabel, edge.ordinal, edge.confidence, edge.source,
  );
}

export function upsertGraphPath(db: Database.Database, repo: string, runId: string, path: CodeGraphPath): void {
  db.prepare(`
    INSERT INTO code_graph_paths (path_id, repo, run_id, entry_node_id, target_node_id, hop_count, path_node_ids, path_edge_ids, has_sanitizer, sanitizer_nodes, confidence)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(path_id) DO UPDATE SET
      run_id = excluded.run_id,
      confidence = MAX(code_graph_paths.confidence, excluded.confidence)
  `).run(
    path.pathId, repo, runId, path.entryNodeId, path.targetNodeId,
    path.hopCount, JSON.stringify(path.nodeIds), JSON.stringify(path.edgeIds),
    path.hasSanitizer ? 1 : 0, JSON.stringify(path.sanitizerNodeIds),
    path.confidence,
  );
}

// ── Query operations ─────────────────────────────────────────────────────

export function getGraphNodesForRepo(db: Database.Database, repo: string): CodeGraphNode[] {
  const rows = db.prepare(`SELECT * FROM code_graph_nodes WHERE repo = ?`).all(repo) as Array<Record<string, unknown>>;
  return rows.map(rowToNode);
}

export function getEntryNodes(db: Database.Database, repo: string): CodeGraphNode[] {
  const rows = db.prepare(
    `SELECT * FROM code_graph_nodes WHERE repo = ? AND node_kind LIKE 'entry-%'`,
  ).all(repo) as Array<Record<string, unknown>>;
  return rows.map(rowToNode);
}

export function getGraphNodeByFileAndLine(
  db: Database.Database, repo: string, filePath: string, startLine: number, tolerance: number = 10,
): CodeGraphNode | null {
  const row = db.prepare(
    `SELECT * FROM code_graph_nodes WHERE repo = ? AND file_path = ? AND ABS(start_line - ?) <= ? ORDER BY ABS(start_line - ?) ASC LIMIT 1`,
  ).get(repo, filePath, startLine, tolerance, startLine) as Record<string, unknown> | undefined;
  return row ? rowToNode(row) : null;
}

export function getPathsToNode(db: Database.Database, repo: string, targetNodeId: string): CodeGraphPath[] {
  const rows = db.prepare(
    `SELECT * FROM code_graph_paths WHERE repo = ? AND target_node_id = ? ORDER BY hop_count ASC`,
  ).all(repo, targetNodeId) as Array<Record<string, unknown>>;
  return rows.map(rowToPath);
}

export function getEdgesFromNode(db: Database.Database, fromNodeId: string): CodeGraphEdge[] {
  const rows = db.prepare(
    `SELECT * FROM code_graph_edges WHERE from_node_id = ?`,
  ).all(fromNodeId) as Array<Record<string, unknown>>;
  return rows.map(rowToEdge);
}

export function getEdgesToNode(db: Database.Database, toNodeId: string): CodeGraphEdge[] {
  const rows = db.prepare(
    `SELECT * FROM code_graph_edges WHERE to_node_id = ?`,
  ).all(toNodeId) as Array<Record<string, unknown>>;
  return rows.map(rowToEdge);
}

export function getNodeById(db: Database.Database, nodeId: string): CodeGraphNode | null {
  const row = db.prepare(`SELECT * FROM code_graph_nodes WHERE node_id = ?`).get(nodeId) as Record<string, unknown> | undefined;
  return row ? rowToNode(row) : null;
}

/** Remove graph data for files that have been modified since last indexed. */
export function invalidateStaleNodes(db: Database.Database, repo: string, staleFilePaths: string[]): number {
  if (staleFilePaths.length === 0) return 0;

  // Process in chunks to avoid exceeding V8 argument limits on large arrays
  const CHUNK_SIZE = 500;
  let totalRemoved = 0;

  for (let i = 0; i < staleFilePaths.length; i += CHUNK_SIZE) {
    const chunk = staleFilePaths.slice(i, i + CHUNK_SIZE);
    const placeholders = chunk.map(() => "?").join(",");

    db.prepare(`
      DELETE FROM code_graph_edges WHERE repo = ? AND (
        from_node_id IN (SELECT node_id FROM code_graph_nodes WHERE repo = ? AND file_path IN (${placeholders}))
        OR to_node_id IN (SELECT node_id FROM code_graph_nodes WHERE repo = ? AND file_path IN (${placeholders}))
      )
    `).run(repo, repo, ...chunk, repo, ...chunk);

    db.prepare(`
      DELETE FROM code_graph_paths WHERE repo = ? AND (
        entry_node_id IN (SELECT node_id FROM code_graph_nodes WHERE repo = ? AND file_path IN (${placeholders}))
        OR target_node_id IN (SELECT node_id FROM code_graph_nodes WHERE repo = ? AND file_path IN (${placeholders}))
      )
    `).run(repo, repo, ...chunk, repo, ...chunk);

    const result = db.prepare(
      `DELETE FROM code_graph_nodes WHERE repo = ? AND file_path IN (${placeholders})`,
    ).run(repo, ...chunk);
    totalRemoved += result.changes;
  }

  return totalRemoved;
}

// ── Row mappers ──────────────────────────────────────────────────────────

function rowToNode(row: Record<string, unknown>): CodeGraphNode {
  return {
    nodeId: row["node_id"] as string,
    filePath: row["file_path"] as string,
    startLine: row["start_line"] as number,
    symbol: (row["symbol"] as string) ?? null,
    nodeKind: row["node_kind"] as CodeGraphNodeKind,
    framework: (row["framework"] as string) ?? null,
    metadata: row["metadata_json"] ? JSON.parse(row["metadata_json"] as string) : {},
    confidence: row["confidence"] as number,
    source: row["source"] as GraphSource,
  };
}

function rowToEdge(row: Record<string, unknown>): CodeGraphEdge {
  return {
    edgeId: row["edge_id"] as string,
    fromNodeId: row["from_node_id"] as string,
    toNodeId: row["to_node_id"] as string,
    edgeKind: row["edge_kind"] as CodeGraphEdgeKind,
    dataLabel: (row["data_label"] as string) ?? null,
    ordinal: (row["ordinal"] as number) ?? null,
    confidence: row["confidence"] as number,
    source: row["source"] as GraphSource,
  };
}

function rowToPath(row: Record<string, unknown>): CodeGraphPath {
  return {
    pathId: row["path_id"] as string,
    entryNodeId: row["entry_node_id"] as string,
    targetNodeId: row["target_node_id"] as string,
    hopCount: row["hop_count"] as number,
    nodeIds: JSON.parse(row["path_node_ids"] as string),
    edgeIds: JSON.parse(row["path_edge_ids"] as string),
    hasSanitizer: (row["has_sanitizer"] as number) === 1,
    sanitizerNodeIds: row["sanitizer_nodes"] ? JSON.parse(row["sanitizer_nodes"] as string) : [],
    confidence: row["confidence"] as number,
  };
}
