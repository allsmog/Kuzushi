import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import path from "node:path";
import Database from "better-sqlite3";
import type {
  ArtifactKbChunkInput,
  ArtifactKbChunkRow,
  ArtifactKbIndexInput,
  ArtifactKbIndexResult,
  ArtifactKbSearchHit,
  ArtifactKbSearchInput,
  ArtifactKbSearchResult,
} from "./types.js";

const ARTIFACT_KB_SCHEMA_VERSION = "1";
const KB_FILENAME = "artifact-kb.sqlite3";
const DEFAULT_SEARCH_LIMIT = 8;
const MAX_SEARCH_LIMIT = 50;
const DEFAULT_MAX_CHUNK_CHARS = 1200;

export function artifactKbPath(repoRoot: string): string {
  return path.join(path.resolve(repoRoot), ".kuzushi", KB_FILENAME);
}

export function indexArtifactKb(input: ArtifactKbIndexInput): ArtifactKbIndexResult {
  const repoRoot = path.resolve(input.repoRoot);
  const kbPath = artifactKbPath(repoRoot);
  mkdirSync(path.dirname(kbPath), { recursive: true });

  const db = new Database(kbPath);
  try {
    initializeSchema(db);
    const indexedAt = (input.now ?? (() => new Date()))().toISOString();
    const commit = gitCommit(repoRoot);
    const insertMeta = db.prepare(`
      INSERT INTO metadata (key, value) VALUES (?, ?)
      ON CONFLICT(key) DO UPDATE SET value=excluded.value
    `);
    const upsertSource = db.prepare(`
      INSERT INTO artifact_sources (
        id, module_id, run_id, path, abs_path, content_hash, git_commit,
        indexed_at, metadata_json
      ) VALUES (
        @id, @module_id, @run_id, @path, @abs_path, @content_hash, @git_commit,
        @indexed_at, @metadata_json
      )
      ON CONFLICT(id) DO UPDATE SET
        module_id=excluded.module_id,
        run_id=excluded.run_id,
        path=excluded.path,
        abs_path=excluded.abs_path,
        content_hash=excluded.content_hash,
        git_commit=excluded.git_commit,
        indexed_at=excluded.indexed_at,
        metadata_json=excluded.metadata_json
    `);
    const deleteFts = db.prepare(`
      DELETE FROM artifact_chunks_fts
      WHERE chunk_id IN (SELECT id FROM artifact_chunks WHERE source_id = ?)
    `);
    const deleteChunks = db.prepare("DELETE FROM artifact_chunks WHERE source_id = ?");
    const insertChunk = db.prepare(`
      INSERT INTO artifact_chunks (
        id, source_id, module_id, run_id, kind, title, summary, body,
        refs_json, metadata_json, ordinal
      ) VALUES (
        @id, @source_id, @module_id, @run_id, @kind, @title, @summary, @body,
        @refs_json, @metadata_json, @ordinal
      )
    `);
    const insertFts = db.prepare(`
      INSERT INTO artifact_chunks_fts (
        chunk_id, module_id, kind, title, summary, body, source_path, refs
      ) VALUES (
        @id, @module_id, @kind, @title, @summary, @body, @source_path, @refs
      )
    `);

    let chunkCount = 0;
    db.transaction(() => {
      insertMeta.run("schemaVersion", ARTIFACT_KB_SCHEMA_VERSION);
      for (const artifact of input.artifacts) {
        const absPath = resolveArtifactPath(repoRoot, artifact.path);
        const sourcePath = toRepoRelativePath(repoRoot, absPath);
        const content = artifact.content ?? readOptionalFile(absPath);
        const sourceId = hashString([input.moduleId, input.runId ?? "", sourcePath].join("\0"));
        const contentHash = hashString(content);
        const sourceRow = {
          id: sourceId,
          module_id: input.moduleId,
          run_id: input.runId ?? null,
          path: sourcePath,
          abs_path: absPath,
          content_hash: contentHash,
          git_commit: commit,
          indexed_at: indexedAt,
          metadata_json: safeJson(artifact.metadata ?? {}),
        };
        upsertSource.run(sourceRow);
        deleteFts.run(sourceId);
        deleteChunks.run(sourceId);

        artifact.chunks.forEach((chunk, ordinal) => {
          const row = chunkRow({
            chunk,
            sourceId,
            moduleId: input.moduleId,
            runId: input.runId,
            sourcePath,
            ordinal,
          });
          insertChunk.run(row);
          insertFts.run(row);
          chunkCount += 1;
        });
      }
    })();

    return { path: kbPath, sources: input.artifacts.length, chunks: chunkCount };
  } finally {
    db.close();
  }
}

export function searchArtifactKb(
  kbPath: string,
  input: ArtifactKbSearchInput = {},
): ArtifactKbSearchResult {
  const limit = clampInt(input.limit, DEFAULT_SEARCH_LIMIT, 1, MAX_SEARCH_LIMIT);
  const maxChunkChars = clampInt(input.maxChunkChars, DEFAULT_MAX_CHUNK_CHARS, 200, 8000);
  const query = typeof input.query === "string" ? input.query.trim() : "";
  const db = new Database(kbPath, { readonly: true, fileMustExist: true });
  try {
    const rows = query ? searchRows(db, query, input, limit) : listRows(db, input, limit);
    return {
      path: kbPath,
      query,
      results: rows.map((row, index) => rowToHit(row, index, maxChunkChars)),
    };
  } finally {
    db.close();
  }
}

function initializeSchema(db: Database.Database): void {
  db.pragma("journal_mode = WAL");
  db.exec(`
    CREATE TABLE IF NOT EXISTS metadata (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS artifact_sources (
      id TEXT PRIMARY KEY,
      module_id TEXT NOT NULL,
      run_id TEXT,
      path TEXT NOT NULL,
      abs_path TEXT NOT NULL,
      content_hash TEXT NOT NULL,
      git_commit TEXT,
      indexed_at TEXT NOT NULL,
      metadata_json TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS artifact_chunks (
      id TEXT PRIMARY KEY,
      source_id TEXT NOT NULL REFERENCES artifact_sources(id) ON DELETE CASCADE,
      module_id TEXT NOT NULL,
      run_id TEXT,
      kind TEXT NOT NULL,
      title TEXT NOT NULL,
      summary TEXT NOT NULL,
      body TEXT NOT NULL,
      refs_json TEXT NOT NULL,
      metadata_json TEXT NOT NULL,
      ordinal INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_artifact_sources_module ON artifact_sources(module_id);
    CREATE INDEX IF NOT EXISTS idx_artifact_chunks_module_kind ON artifact_chunks(module_id, kind);
    CREATE INDEX IF NOT EXISTS idx_artifact_chunks_run ON artifact_chunks(run_id);
    CREATE VIRTUAL TABLE IF NOT EXISTS artifact_chunks_fts USING fts5(
      chunk_id UNINDEXED,
      module_id UNINDEXED,
      kind UNINDEXED,
      title,
      summary,
      body,
      source_path UNINDEXED,
      refs
    );
  `);
}

function chunkRow(input: {
  chunk: ArtifactKbChunkInput;
  sourceId: string;
  moduleId: string;
  runId?: string;
  sourcePath: string;
  ordinal: number;
}): Record<string, unknown> {
  const idSuffix = input.chunk.id ?? String(input.ordinal);
  const id = `${input.sourceId}:${hashString(idSuffix).slice(0, 16)}`;
  const summary = input.chunk.summary?.trim() || firstLine(input.chunk.body) || input.chunk.title;
  const refs = input.chunk.refs ?? [];
  return {
    id,
    source_id: input.sourceId,
    module_id: input.moduleId,
    run_id: input.runId ?? null,
    kind: input.chunk.kind,
    title: input.chunk.title,
    summary,
    body: input.chunk.body,
    refs_json: safeJson(refs),
    metadata_json: safeJson(input.chunk.metadata ?? {}),
    ordinal: input.ordinal,
    source_path: input.sourcePath,
    refs: refs.join(" "),
  };
}

function searchRows(
  db: Database.Database,
  query: string,
  input: ArtifactKbSearchInput,
  limit: number,
): ArtifactKbChunkRow[] {
  const match = toFtsQuery(query);
  if (!match) return listRows(db, input, limit);
  const filters = sqlFilters(input);
  try {
    return db
      .prepare(`
        SELECT c.*, s.path AS source_path, bm25(artifact_chunks_fts) AS score
        FROM artifact_chunks_fts
        JOIN artifact_chunks c ON c.id = artifact_chunks_fts.chunk_id
        JOIN artifact_sources s ON s.id = c.source_id
        WHERE artifact_chunks_fts MATCH ?
          ${filters.where}
        ORDER BY score ASC
        LIMIT ?
      `)
      .all(match, ...filters.params, limit) as ArtifactKbChunkRow[];
  } catch {
    const like = `%${escapeLike(query)}%`;
    return db
      .prepare(`
        SELECT c.*, s.path AS source_path, 1000 AS score
        FROM artifact_chunks c
        JOIN artifact_sources s ON s.id = c.source_id
        WHERE (c.title LIKE ? ESCAPE '\\'
           OR c.summary LIKE ? ESCAPE '\\'
           OR c.body LIKE ? ESCAPE '\\')
          ${filters.where}
        ORDER BY c.module_id, c.kind, c.title
        LIMIT ?
      `)
      .all(like, like, like, ...filters.params, limit) as ArtifactKbChunkRow[];
  }
}

function listRows(
  db: Database.Database,
  input: ArtifactKbSearchInput,
  limit: number,
): ArtifactKbChunkRow[] {
  const filters = sqlFilters(input);
  return db
    .prepare(`
      SELECT c.*, s.path AS source_path, 1000 AS score
      FROM artifact_chunks c
      JOIN artifact_sources s ON s.id = c.source_id
      ${filters.where ? `WHERE ${filters.where.replace(/^AND\s+/u, "")}` : ""}
      ORDER BY c.module_id, c.kind, c.title
      LIMIT ?
    `)
    .all(...filters.params, limit) as ArtifactKbChunkRow[];
}

function sqlFilters(input: ArtifactKbSearchInput): { where: string; params: unknown[] } {
  const clauses: string[] = [];
  const params: unknown[] = [];
  if (input.moduleId) {
    clauses.push("c.module_id = ?");
    params.push(input.moduleId);
  }
  if (input.runId) {
    clauses.push("c.run_id = ?");
    params.push(input.runId);
  }
  const kinds = input.kinds?.filter((kind) => kind.trim() !== "") ?? [];
  if (kinds.length > 0) {
    clauses.push(`c.kind IN (${kinds.map(() => "?").join(", ")})`);
    params.push(...kinds);
  }
  if (input.path) {
    clauses.push("s.path LIKE ? ESCAPE '\\'");
    params.push(`%${escapeLike(input.path)}%`);
  }
  return {
    where: clauses.length > 0 ? `AND ${clauses.join(" AND ")}` : "",
    params,
  };
}

function rowToHit(
  row: ArtifactKbChunkRow,
  index: number,
  maxChunkChars: number,
): ArtifactKbSearchHit {
  return {
    chunkId: row.id,
    sourceId: row.source_id,
    moduleId: row.module_id,
    kind: row.kind,
    title: row.title,
    summary: row.summary || firstLine(row.body) || row.title,
    body: clampText(row.body, maxChunkChars),
    refs: parseStringArray(row.refs_json),
    sourcePath: row.source_path,
    ...(row.run_id ? { runId: row.run_id } : {}),
    score: typeof row.score === "number" ? row.score : index,
  };
}

function resolveArtifactPath(repoRoot: string, artifactPath: string): string {
  return path.isAbsolute(artifactPath)
    ? path.resolve(artifactPath)
    : path.resolve(repoRoot, artifactPath);
}

function toRepoRelativePath(repoRoot: string, filePath: string): string {
  const rel = path.relative(repoRoot, filePath);
  return rel && !rel.startsWith("..") && !path.isAbsolute(rel) ? rel : filePath;
}

function readOptionalFile(filePath: string): string {
  if (!existsSync(filePath)) return "";
  return readFileSync(filePath, "utf8");
}

function gitCommit(repoRoot: string): string | null {
  try {
    return execFileSync("git", ["-C", repoRoot, "rev-parse", "HEAD"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    return null;
  }
}

function toFtsQuery(query: string): string {
  return query
    .split(/\s+/)
    .map((term) => term.replace(/[^A-Za-z0-9_./:-]/g, ""))
    .filter((term) => term.length > 0)
    .map((term) => `"${term}"`)
    .join(" OR ");
}

function escapeLike(value: string): string {
  return value.replace(/[\\%_]/g, "\\$&");
}

function parseStringArray(value: string): string[] {
  try {
    const parsed = JSON.parse(value) as unknown;
    if (Array.isArray(parsed)) {
      return parsed.filter((item): item is string => typeof item === "string");
    }
  } catch {
    return [];
  }
  return [];
}

function safeJson(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return "{}";
  }
}

function hashString(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function firstLine(value: string): string {
  return (
    value
      .split(/\r?\n/)
      .map((line) => line.trim())
      .find(Boolean) ?? ""
  );
}

function clampText(value: string, maxChars: number): string {
  if (value.length <= maxChars) return value;
  return `${value.slice(0, maxChars).trimEnd()}\n... (${value.length - maxChars} chars omitted)`;
}

function clampInt(value: unknown, fallback: number, min: number, max: number): number {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(numeric)));
}
