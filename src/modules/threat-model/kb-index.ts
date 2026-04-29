import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import path from "node:path";
import Database from "better-sqlite3";
import type {
  DfdFlow,
  DfdNode,
  EvidenceAnchor,
  StrideThreat,
  ThreatModelDocument,
  ThreatModelReference,
  TrustBoundary,
} from "../../agents/tasks/threat-modeling/types.js";
import { loadPersistentThreatModel } from "../../threat-model-renderer.js";
import { contextSnapshotPath } from "../sast/context-persist.js";

export const THREAT_MODEL_KB_SCHEMA_VERSION = "1";
const KB_FILENAME = "threat-model-kb.sqlite3";
const THREAT_MODEL_FILENAME = ".kuzushi/threat-model.json";
const DEFAULT_SEARCH_LIMIT = 8;
const MAX_SEARCH_LIMIT = 50;

export interface ThreatModelKbMetadata {
  schemaVersion: string;
  threatModelHash: string;
  contextHash: string;
  builtAt: string;
  sourceThreatModelPath: string;
}

export interface ThreatModelKbStats {
  chunks: number;
}

export interface ThreatModelKbStatus {
  path: string;
  exists: boolean;
  current: boolean;
  staleReason?: string;
  metadata?: ThreatModelKbMetadata;
  expected?: Pick<ThreatModelKbMetadata, "schemaVersion" | "threatModelHash" | "contextHash">;
  stats?: ThreatModelKbStats;
}

export interface ThreatModelKbEnsureResult {
  path: string;
  rebuilt: boolean;
  reason: string;
  metadata: ThreatModelKbMetadata;
  stats: ThreatModelKbStats;
}

export interface ThreatModelKbSearchInput {
  query?: string;
  actorId?: string;
  flowIds?: string[];
  threatIds?: string[];
  kinds?: string[];
  limit?: number;
  maxChunkChars?: number;
}

export interface ThreatModelKbSearchHit {
  chunkId: string;
  kind: string;
  title: string;
  summary: string;
  refs: string[];
  score: number;
}

export interface ThreatModelKbSearchResult {
  path: string;
  query: string;
  results: ThreatModelKbSearchHit[];
}

interface ThreatModelKbChunk {
  id: string;
  kind: string;
  title: string;
  summary: string;
  body: string;
  refs: string[];
  actorIds: string[];
  flowIds: string[];
  threatIds: string[];
}

interface ChunkRow {
  id: string;
  kind: string;
  title: string;
  summary: string;
  body: string;
  refs_json: string;
  actor_ids_json: string;
  flow_ids_json: string;
  threat_ids_json: string;
  score?: number;
}

export function threatModelKbPath(repoRoot: string): string {
  return path.join(path.resolve(repoRoot), ".kuzushi", KB_FILENAME);
}

export function threatModelSourcePath(repoRoot: string): string {
  return path.join(path.resolve(repoRoot), THREAT_MODEL_FILENAME);
}

export function ensureThreatModelKbIndex(input: {
  repoRoot: string;
  document?: ThreatModelDocument | null;
  now?: () => Date;
}): ThreatModelKbEnsureResult {
  const repoRoot = path.resolve(input.repoRoot);
  const sourceThreatModelPath = threatModelSourcePath(repoRoot);
  const document = input.document ?? loadPersistentThreatModel(repoRoot);
  if (!document) {
    throw new Error(
      `No persistent threat model found at ${sourceThreatModelPath}. Run /use threat-model then run . first.`,
    );
  }

  const expected = expectedMetadata(repoRoot, document);
  const status = readThreatModelKbStatus(repoRoot, document);
  if (status.current && status.metadata && status.stats) {
    return {
      path: status.path,
      rebuilt: false,
      reason: "current",
      metadata: status.metadata,
      stats: status.stats,
    };
  }

  const kbPath = threatModelKbPath(repoRoot);
  mkdirSync(path.dirname(kbPath), { recursive: true });
  const db = new Database(kbPath);
  try {
    initializeSchema(db);
    const chunks = buildThreatModelKbChunks(document);
    const insert = db.prepare(`
      INSERT INTO chunks (
        id, kind, title, summary, body, refs_json,
        actor_ids_json, flow_ids_json, threat_ids_json
      ) VALUES (
        @id, @kind, @title, @summary, @body, @refs_json,
        @actor_ids_json, @flow_ids_json, @threat_ids_json
      )
    `);
    const insertFts = db.prepare(`
      INSERT INTO chunks_fts (
        chunk_id, title, body, kind, actor_ids, flow_ids, threat_ids
      ) VALUES (
        @id, @title, @body, @kind, @actor_ids, @flow_ids, @threat_ids
      )
    `);
    const insertMeta = db.prepare("INSERT INTO metadata (key, value) VALUES (?, ?)");
    const builtAt = (input.now ?? (() => new Date()))().toISOString();
    const metadata: ThreatModelKbMetadata = {
      ...expected,
      builtAt,
      sourceThreatModelPath,
    };

    db.transaction(() => {
      db.exec("DELETE FROM chunks_fts; DELETE FROM chunks; DELETE FROM metadata;");
      for (const chunk of chunks) {
        const row = {
          id: chunk.id,
          kind: chunk.kind,
          title: chunk.title,
          summary: chunk.summary,
          body: chunk.body,
          refs_json: JSON.stringify(chunk.refs),
          actor_ids_json: JSON.stringify(chunk.actorIds),
          flow_ids_json: JSON.stringify(chunk.flowIds),
          threat_ids_json: JSON.stringify(chunk.threatIds),
          actor_ids: chunk.actorIds.join(" "),
          flow_ids: chunk.flowIds.join(" "),
          threat_ids: chunk.threatIds.join(" "),
        };
        insert.run(row);
        insertFts.run(row);
      }
      for (const [key, value] of Object.entries(metadata)) {
        insertMeta.run(key, value);
      }
    })();

    return {
      path: kbPath,
      rebuilt: true,
      reason: status.staleReason ?? "missing",
      metadata,
      stats: { chunks: chunks.length },
    };
  } finally {
    db.close();
  }
}

export function readThreatModelKbStatus(
  repoRoot: string,
  document?: ThreatModelDocument | null,
): ThreatModelKbStatus {
  const resolvedRoot = path.resolve(repoRoot);
  const kbPath = threatModelKbPath(resolvedRoot);
  const doc = document ?? loadPersistentThreatModel(resolvedRoot);
  const expected = doc ? expectedMetadata(resolvedRoot, doc) : undefined;
  if (!existsSync(kbPath)) {
    return {
      path: kbPath,
      exists: false,
      current: false,
      staleReason: "missing",
      ...(expected ? { expected } : {}),
    };
  }

  let db: Database.Database | undefined;
  try {
    db = new Database(kbPath, { readonly: true, fileMustExist: true });
    const metadata = readMetadata(db);
    const stats = readStats(db);
    const staleReason = expected ? compareMetadata(metadata, expected) : "no-threat-model";
    return {
      path: kbPath,
      exists: true,
      current: staleReason === undefined,
      ...(staleReason ? { staleReason } : {}),
      metadata,
      ...(expected ? { expected } : {}),
      stats,
    };
  } catch (error) {
    return {
      path: kbPath,
      exists: true,
      current: false,
      staleReason: `unreadable: ${error instanceof Error ? error.message : String(error)}`,
      ...(expected ? { expected } : {}),
    };
  } finally {
    db?.close();
  }
}

export function searchThreatModelKb(
  kbPath: string,
  input: ThreatModelKbSearchInput = {},
): ThreatModelKbSearchResult {
  const limit = clampInt(input.limit, DEFAULT_SEARCH_LIMIT, 1, MAX_SEARCH_LIMIT);
  const maxChunkChars = clampInt(input.maxChunkChars, 1200, 200, 8000);
  const query = typeof input.query === "string" ? input.query.trim() : "";
  const db = new Database(kbPath, { readonly: true, fileMustExist: true });
  try {
    const rows = query ? searchRows(db, query, limit * 8) : listRows(db, limit * 8);
    const filtered = rows
      .filter((row) => matchesFilters(row, input))
      .slice(0, limit)
      .map((row, index) => rowToHit(row, index, maxChunkChars));
    return { path: kbPath, query, results: filtered };
  } finally {
    db.close();
  }
}

export function buildThreatModelKbChunks(doc: ThreatModelDocument): ThreatModelKbChunk[] {
  const nodesById = new Map(doc.dfd.nodes.map((node) => [node.id, node]));
  const chunks: ThreatModelKbChunk[] = [];

  for (const node of doc.dfd.nodes) {
    chunks.push(nodeChunk(node));
  }
  for (const flow of doc.dfd.flows) {
    chunks.push(flowChunk(flow, nodesById));
  }
  for (const boundary of doc.dfd.trustBoundaries) {
    chunks.push(boundaryChunk(boundary));
  }
  for (const threat of doc.threats) {
    chunks.push(threatChunk(threat));
    chunks.push(...referenceChunks(threat, "source", threat.sources));
    chunks.push(...referenceChunks(threat, "sink", threat.sinks));
    chunks.push(...referenceChunks(threat, "guard", threat.guards));
    chunks.push(...referenceChunks(threat, "sanitizer", threat.sanitizers));
    chunks.push(...evidenceChunks(threat));
    if (threat.requiredCapabilities?.length) {
      chunks.push({
        id: `${threat.id}:capabilities`,
        kind: "capability",
        title: `Required capabilities for ${threat.title}`,
        summary: threat.requiredCapabilities.join("; "),
        body: [
          `Threat: ${threat.id} ${threat.title}`,
          "Required capabilities:",
          ...threat.requiredCapabilities.map((capability) => `- ${capability}`),
        ].join("\n"),
        refs: [],
        actorIds: threat.actorIds ?? [],
        flowIds: threat.flowIds ?? [],
        threatIds: [threat.id],
      });
    }
  }

  if (doc.narrative?.overview) {
    chunks.push({
      id: "narrative:overview",
      kind: "narrative",
      title: "Threat model overview",
      summary: firstLine(doc.narrative.overview),
      body: doc.narrative.overview,
      refs: [],
      actorIds: [],
      flowIds: [],
      threatIds: [],
    });
  }

  return chunks;
}

function initializeSchema(db: Database.Database): void {
  db.pragma("journal_mode = WAL");
  db.exec(`
    DROP TABLE IF EXISTS chunks_fts;
    DROP TABLE IF EXISTS chunks;
    DROP TABLE IF EXISTS metadata;
    CREATE TABLE IF NOT EXISTS metadata (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS chunks (
      id TEXT PRIMARY KEY,
      kind TEXT NOT NULL,
      title TEXT NOT NULL,
      summary TEXT NOT NULL,
      body TEXT NOT NULL,
      refs_json TEXT NOT NULL,
      actor_ids_json TEXT NOT NULL,
      flow_ids_json TEXT NOT NULL,
      threat_ids_json TEXT NOT NULL
    );
    CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(
      chunk_id UNINDEXED,
      title,
      body,
      kind UNINDEXED,
      actor_ids UNINDEXED,
      flow_ids UNINDEXED,
      threat_ids UNINDEXED
    );
  `);
}

function expectedMetadata(
  repoRoot: string,
  document: ThreatModelDocument,
): Pick<ThreatModelKbMetadata, "schemaVersion" | "threatModelHash" | "contextHash"> {
  return {
    schemaVersion: THREAT_MODEL_KB_SCHEMA_VERSION,
    threatModelHash: hashThreatModel(repoRoot, document),
    contextHash: hashOptionalFile(contextSnapshotPath(repoRoot)),
  };
}

function hashThreatModel(repoRoot: string, document: ThreatModelDocument): string {
  const sourcePath = threatModelSourcePath(repoRoot);
  if (existsSync(sourcePath)) return hashBuffer(readFileSync(sourcePath));
  return hashString(JSON.stringify(document));
}

function hashOptionalFile(filePath: string): string {
  if (!existsSync(filePath)) return "missing";
  return hashBuffer(readFileSync(filePath));
}

function hashString(value: string): string {
  return hashBuffer(Buffer.from(value, "utf8"));
}

function hashBuffer(value: Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function readMetadata(db: Database.Database): ThreatModelKbMetadata {
  const rows = db.prepare("SELECT key, value FROM metadata").all() as Array<{
    key: string;
    value: string;
  }>;
  const record = Object.fromEntries(rows.map((row) => [row.key, row.value]));
  return {
    schemaVersion: String(record["schemaVersion"] ?? ""),
    threatModelHash: String(record["threatModelHash"] ?? ""),
    contextHash: String(record["contextHash"] ?? ""),
    builtAt: String(record["builtAt"] ?? ""),
    sourceThreatModelPath: String(record["sourceThreatModelPath"] ?? ""),
  };
}

function readStats(db: Database.Database): ThreatModelKbStats {
  const row = db.prepare("SELECT COUNT(*) as count FROM chunks").get() as { count: number };
  return { chunks: row.count };
}

function compareMetadata(
  actual: ThreatModelKbMetadata,
  expected: Pick<ThreatModelKbMetadata, "schemaVersion" | "threatModelHash" | "contextHash">,
): string | undefined {
  if (actual.schemaVersion !== expected.schemaVersion) return "schema-version";
  if (actual.threatModelHash !== expected.threatModelHash) return "threat-model-hash";
  if (actual.contextHash !== expected.contextHash) return "context-hash";
  return undefined;
}

function searchRows(db: Database.Database, query: string, limit: number): ChunkRow[] {
  const match = toFtsQuery(query);
  if (!match) return listRows(db, limit);
  try {
    return db
      .prepare(`
        SELECT
          c.*,
          bm25(chunks_fts) AS score
        FROM chunks_fts
        JOIN chunks c ON c.id = chunks_fts.chunk_id
        WHERE chunks_fts MATCH ?
        ORDER BY score ASC
        LIMIT ?
      `)
      .all(match, limit) as ChunkRow[];
  } catch {
    const like = `%${query.replace(/[%_]/g, "\\$&")}%`;
    return db
      .prepare(`
        SELECT *, 1000 AS score
        FROM chunks
        WHERE title LIKE ? ESCAPE '\\' OR body LIKE ? ESCAPE '\\'
        ORDER BY kind, title
        LIMIT ?
      `)
      .all(like, like, limit) as ChunkRow[];
  }
}

function listRows(db: Database.Database, limit: number): ChunkRow[] {
  return db
    .prepare("SELECT *, 1000 AS score FROM chunks ORDER BY kind, title LIMIT ?")
    .all(limit) as ChunkRow[];
}

function matchesFilters(row: ChunkRow, input: ThreatModelKbSearchInput): boolean {
  const actorIds = parseStringArray(row.actor_ids_json);
  const flowIds = parseStringArray(row.flow_ids_json);
  const threatIds = parseStringArray(row.threat_ids_json);
  if (input.actorId && !actorIds.includes(input.actorId)) return false;
  if (input.flowIds?.length && !intersects(flowIds, input.flowIds)) return false;
  if (input.threatIds?.length && !intersects(threatIds, input.threatIds)) return false;
  if (input.kinds?.length && !input.kinds.includes(row.kind)) return false;
  return true;
}

function rowToHit(row: ChunkRow, index: number, maxChunkChars: number): ThreatModelKbSearchHit {
  const body = clampText(row.body, maxChunkChars);
  return {
    chunkId: row.id,
    kind: row.kind,
    title: row.title,
    summary: row.summary || body,
    refs: parseStringArray(row.refs_json),
    score: typeof row.score === "number" ? row.score : index,
  };
}

function nodeChunk(node: DfdNode): ThreatModelKbChunk {
  const refs = evidenceRefs(node.evidenceAnchors);
  return {
    id: `node:${node.id}`,
    kind: "actor",
    title: `${node.id}: ${node.name}`,
    summary: `${node.type} in ${node.trustZone}: ${node.description}`,
    body: [
      `Node ${node.id}: ${node.name}`,
      `Type: ${node.type}`,
      `Trust zone: ${node.trustZone}`,
      `Description: ${node.description}`,
      refs.length ? `Evidence: ${refs.join("; ")}` : "",
    ]
      .filter(Boolean)
      .join("\n"),
    refs,
    actorIds: node.type === "external-entity" ? [node.id] : [],
    flowIds: [],
    threatIds: [],
  };
}

function flowChunk(flow: DfdFlow, nodesById: ReadonlyMap<string, DfdNode>): ThreatModelKbChunk {
  const refs = evidenceRefs(flow.evidenceAnchors);
  const source = nodesById.get(flow.sourceId);
  const target = nodesById.get(flow.targetId);
  const actorIds = [source, target]
    .filter((node): node is DfdNode => node?.type === "external-entity")
    .map((node) => node.id);
  return {
    id: `flow:${flow.id}`,
    kind: "flow",
    title: `${flow.id}: ${flow.name || `${flow.sourceId} -> ${flow.targetId}`}`,
    summary: `${flow.sourceId} -> ${flow.targetId}: ${flow.description}`,
    body: [
      `Flow ${flow.id}: ${flow.name}`,
      `Source: ${flow.sourceId}${source ? ` (${source.name})` : ""}`,
      `Target: ${flow.targetId}${target ? ` (${target.name})` : ""}`,
      flow.protocol ? `Protocol: ${flow.protocol}` : "",
      flow.dataClassification ? `Classification: ${flow.dataClassification}` : "",
      flow.trustBoundaryIds.length ? `Trust boundaries: ${flow.trustBoundaryIds.join(", ")}` : "",
      `Description: ${flow.description}`,
      refs.length ? `Evidence: ${refs.join("; ")}` : "",
    ]
      .filter(Boolean)
      .join("\n"),
    refs,
    actorIds,
    flowIds: [flow.id],
    threatIds: [],
  };
}

function boundaryChunk(boundary: TrustBoundary): ThreatModelKbChunk {
  const refs = evidenceRefs(boundary.evidenceAnchors);
  return {
    id: `boundary:${boundary.id}`,
    kind: "boundary",
    title: `${boundary.id}: ${boundary.name}`,
    summary: `${boundary.outerZone} -> ${boundary.innerZone}`,
    body: [
      `Trust boundary ${boundary.id}: ${boundary.name}`,
      `Outer zone: ${boundary.outerZone}`,
      `Inner zone: ${boundary.innerZone}`,
      boundary.crossingFlowIds.length
        ? `Crossing flows: ${boundary.crossingFlowIds.join(", ")}`
        : "",
      refs.length ? `Evidence: ${refs.join("; ")}` : "",
    ]
      .filter(Boolean)
      .join("\n"),
    refs,
    actorIds: [],
    flowIds: boundary.crossingFlowIds,
    threatIds: [],
  };
}

function threatChunk(threat: StrideThreat): ThreatModelKbChunk {
  const refs = [
    ...affectedRefs(threat),
    ...evidenceRefs(threat.evidenceAnchors),
    ...referenceRefs(threat.sources),
    ...referenceRefs(threat.sinks),
    ...referenceRefs(threat.guards),
    ...referenceRefs(threat.sanitizers),
  ];
  return {
    id: `threat:${threat.id}`,
    kind: "threat",
    title: `${threat.id}: ${threat.title}`,
    summary: `[${threat.impact}/${threat.category}] ${threat.description || threat.attackVector}`,
    body: [
      `Threat ${threat.id}: ${threat.title}`,
      `Category: ${threat.category}`,
      `Impact: ${threat.impact}`,
      `Likelihood: ${threat.likelihood}`,
      `Actor ids: ${(threat.actorIds ?? []).join(", ")}`,
      `Entrypoint ids: ${(threat.entrypointIds ?? []).join(", ")}`,
      `Target ids: ${(threat.targetElementIds ?? []).join(", ")}`,
      `Flow ids: ${(threat.flowIds ?? []).join(", ")}`,
      `Attack vector: ${threat.attackVector}`,
      `Description: ${threat.description}`,
      threat.preconditions.length ? `Preconditions: ${threat.preconditions.join("; ")}` : "",
      threat.existingMitigations.length
        ? `Existing mitigations: ${threat.existingMitigations.join("; ")}`
        : "",
      threat.missingMitigations.length
        ? `Missing mitigations: ${threat.missingMitigations.join("; ")}`
        : "",
      threat.relatedCwe.length ? `Related CWE: ${threat.relatedCwe.join(", ")}` : "",
      threat.requiredCapabilities?.length
        ? `Required capabilities: ${threat.requiredCapabilities.join("; ")}`
        : "",
      refs.length ? `References: ${refs.join("; ")}` : "",
    ]
      .filter(Boolean)
      .join("\n"),
    refs: [...new Set(refs)],
    actorIds: threat.actorIds ?? [],
    flowIds: threat.flowIds ?? [],
    threatIds: [threat.id],
  };
}

function referenceChunks(
  threat: StrideThreat,
  kind: "source" | "sink" | "guard" | "sanitizer",
  refs: ThreatModelReference[] | undefined,
): ThreatModelKbChunk[] {
  return (refs ?? []).map((ref, index) => {
    const location = formatReference(ref);
    return {
      id: `${threat.id}:${kind}:${index + 1}`,
      kind,
      title: `${kind} for ${threat.title}`,
      summary: [ref.name, location, ref.description].filter(Boolean).join(" - "),
      body: [
        `Threat: ${threat.id} ${threat.title}`,
        `Kind: ${kind}`,
        ref.name ? `Name: ${ref.name}` : "",
        ref.elementId ? `Element: ${ref.elementId}` : "",
        location ? `Location: ${location}` : "",
        ref.description ? `Description: ${ref.description}` : "",
      ]
        .filter(Boolean)
        .join("\n"),
      refs: location ? [location] : [],
      actorIds: threat.actorIds ?? [],
      flowIds: threat.flowIds ?? [],
      threatIds: [threat.id],
    };
  });
}

function evidenceChunks(threat: StrideThreat): ThreatModelKbChunk[] {
  return (threat.evidenceAnchors ?? []).map((anchor, index) => {
    const location = formatEvidenceAnchor(anchor);
    return {
      id: `${threat.id}:evidence:${index + 1}`,
      kind: "evidence",
      title: `Evidence for ${threat.title}`,
      summary: `${location} - ${anchor.description}`,
      body: [
        `Threat: ${threat.id} ${threat.title}`,
        `Location: ${location}`,
        anchor.symbol ? `Symbol: ${anchor.symbol}` : "",
        `Description: ${anchor.description}`,
        anchor.snippet ? `Snippet: ${anchor.snippet}` : "",
        anchor.source ? `Source: ${anchor.source}` : "",
      ]
        .filter(Boolean)
        .join("\n"),
      refs: [location],
      actorIds: threat.actorIds ?? [],
      flowIds: threat.flowIds ?? [],
      threatIds: [threat.id],
    };
  });
}

function evidenceRefs(anchors: EvidenceAnchor[] | undefined): string[] {
  return (anchors ?? []).map(formatEvidenceAnchor);
}

function affectedRefs(threat: StrideThreat): string[] {
  return threat.affectedFiles.map((file) => `${file.filePath}:${file.startLine}`);
}

function referenceRefs(refs: ThreatModelReference[] | undefined): string[] {
  return (refs ?? []).map(formatReference).filter(Boolean);
}

function formatEvidenceAnchor(anchor: EvidenceAnchor): string {
  const line = anchor.endLine ? `${anchor.startLine}-${anchor.endLine}` : `${anchor.startLine}`;
  return `${anchor.filePath}:${line}${anchor.symbol ? ` ${anchor.symbol}` : ""}`;
}

function formatReference(ref: ThreatModelReference): string {
  if (ref.filePath) return `${ref.filePath}${ref.startLine ? `:${ref.startLine}` : ""}`;
  return ref.elementId ?? "";
}

function parseStringArray(value: string): string[] {
  try {
    const parsed = JSON.parse(value) as unknown;
    return Array.isArray(parsed)
      ? parsed.filter((item): item is string => typeof item === "string")
      : [];
  } catch {
    return [];
  }
}

function intersects(left: readonly string[], right: readonly string[]): boolean {
  const set = new Set(left);
  return right.some((value) => set.has(value));
}

function toFtsQuery(query: string): string {
  const tokens =
    query
      .toLowerCase()
      .match(/[a-z0-9_.:/-]+/g)
      ?.filter((token) => token.length > 1)
      .slice(0, 20) ?? [];
  return tokens.map((token) => `"${token.replace(/"/g, '""')}"`).join(" OR ");
}

function clampInt(value: unknown, fallback: number, min: number, max: number): number {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(numeric)));
}

function clampText(value: string, maxChars: number): string {
  if (value.length <= maxChars) return value;
  return `${value.slice(0, maxChars - 3)}...`;
}

function firstLine(value: string): string {
  return value.split(/\r?\n/, 1)[0]?.trim() ?? "";
}
