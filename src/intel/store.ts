/**
 * SQLite FTS5-backed intel store.
 *
 * Uses SQLite's built-in full-text search for keyword-based retrieval.
 * The interface is designed so a vector backend (sqlite-vss, ChromaDB)
 * can replace FTS5 for semantic search without changing consumers.
 */

import { randomUUID } from "node:crypto";
import type Database from "better-sqlite3";
import type {
  IntelDocument,
  IntelSearchOptions,
  IntelSearchResult,
  IntelSource,
  IntelStore,
} from "./types.js";

/** SQL to create the intel tables. Run once on DB init. */
export function createIntelTables(db: Database.Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS intel_documents (
      id TEXT PRIMARY KEY,
      source TEXT NOT NULL,
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      metadata_json TEXT NOT NULL DEFAULT '{}',
      ingested_at TEXT NOT NULL
    );

    CREATE VIRTUAL TABLE IF NOT EXISTS intel_fts USING fts5(
      title,
      content,
      content='intel_documents',
      content_rowid='rowid'
    );

    CREATE TRIGGER IF NOT EXISTS intel_ai AFTER INSERT ON intel_documents BEGIN
      INSERT INTO intel_fts(rowid, title, content)
        VALUES (new.rowid, new.title, new.content);
    END;

    CREATE TRIGGER IF NOT EXISTS intel_ad AFTER DELETE ON intel_documents BEGIN
      INSERT INTO intel_fts(intel_fts, rowid, title, content)
        VALUES ('delete', old.rowid, old.title, old.content);
    END;

    CREATE TRIGGER IF NOT EXISTS intel_au AFTER UPDATE ON intel_documents BEGIN
      INSERT INTO intel_fts(intel_fts, rowid, title, content)
        VALUES ('delete', old.rowid, old.title, old.content);
      INSERT INTO intel_fts(rowid, title, content)
        VALUES (new.rowid, new.title, new.content);
    END;

    CREATE INDEX IF NOT EXISTS idx_intel_source ON intel_documents(source);
  `);
}

export class SqliteIntelStore implements IntelStore {
  constructor(private readonly db: Database.Database) {}

  ingest(doc: Omit<IntelDocument, "id" | "ingestedAt">): string {
    const id = randomUUID();
    const now = new Date().toISOString();
    this.db.prepare(
      `INSERT INTO intel_documents (id, source, title, content, metadata_json, ingested_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).run(id, doc.source, doc.title, doc.content, JSON.stringify(doc.metadata), now);
    return id;
  }

  ingestBatch(docs: Array<Omit<IntelDocument, "id" | "ingestedAt">>): number {
    const insert = this.db.prepare(
      `INSERT INTO intel_documents (id, source, title, content, metadata_json, ingested_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    );

    const now = new Date().toISOString();
    let count = 0;

    const tx = this.db.transaction(() => {
      for (const doc of docs) {
        const id = randomUUID();
        insert.run(id, doc.source, doc.title, doc.content, JSON.stringify(doc.metadata), now);
        count++;
      }
    });

    tx();
    return count;
  }

  search(query: string, options?: IntelSearchOptions): IntelSearchResult[] {
    const limit = options?.limit ?? 20;
    const conditions: string[] = [];
    const params: unknown[] = [];

    // FTS5 match
    conditions.push("intel_fts MATCH ?");
    params.push(sanitizeFtsQuery(query));

    // Source filter
    if (options?.sources && options.sources.length > 0) {
      const placeholders = options.sources.map(() => "?").join(",");
      conditions.push(`d.source IN (${placeholders})`);
      params.push(...options.sources);
    }

    params.push(limit);

    const sql = `
      SELECT d.*, rank
      FROM intel_fts
      JOIN intel_documents d ON d.rowid = intel_fts.rowid
      WHERE ${conditions.join(" AND ")}
      ORDER BY rank
      LIMIT ?
    `;

    const rows = this.db.prepare(sql).all(...params) as Array<IntelDocumentRow & { rank: number }>;

    return rows.map((row) => ({
      document: rowToDocument(row),
      score: -row.rank,
      snippet: extractSnippet(row.content, query),
    }));
  }

  get(id: string): IntelDocument | null {
    const row = this.db.prepare("SELECT * FROM intel_documents WHERE id = ?").get(id) as IntelDocumentRow | undefined;
    return row ? rowToDocument(row) : null;
  }

  delete(id: string): boolean {
    const result = this.db.prepare("DELETE FROM intel_documents WHERE id = ?").run(id);
    return result.changes > 0;
  }

  count(source?: IntelSource): number {
    if (source) {
      const row = this.db.prepare("SELECT COUNT(*) as cnt FROM intel_documents WHERE source = ?").get(source) as { cnt: number };
      return row.cnt;
    }
    const row = this.db.prepare("SELECT COUNT(*) as cnt FROM intel_documents").get() as { cnt: number };
    return row.cnt;
  }

  clearSource(source: IntelSource): number {
    const result = this.db.prepare("DELETE FROM intel_documents WHERE source = ?").run(source);
    return result.changes;
  }
}

interface IntelDocumentRow {
  id: string;
  source: string;
  title: string;
  content: string;
  metadata_json: string;
  ingested_at: string;
}

function rowToDocument(row: IntelDocumentRow): IntelDocument {
  let metadata: Record<string, unknown> = {};
  try {
    metadata = JSON.parse(row.metadata_json);
  } catch { /* ignore */ }

  return {
    id: row.id,
    source: row.source as IntelSource,
    title: row.title,
    content: row.content,
    metadata,
    ingestedAt: row.ingested_at,
  };
}

/** Sanitize a user query for FTS5 — escape special characters. */
function sanitizeFtsQuery(query: string): string {
  return query
    .replace(/['"]/g, "")
    .replace(/\b(AND|OR|NOT|NEAR)\b/gi, "")
    .trim() || "*";
}

/** Extract a short snippet around the first matching term. */
function extractSnippet(content: string, query: string): string {
  const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
  const lower = content.toLowerCase();

  for (const term of terms) {
    const idx = lower.indexOf(term);
    if (idx >= 0) {
      const start = Math.max(0, idx - 60);
      const end = Math.min(content.length, idx + term.length + 60);
      const prefix = start > 0 ? "..." : "";
      const suffix = end < content.length ? "..." : "";
      return prefix + content.slice(start, end).trim() + suffix;
    }
  }

  return content.slice(0, 120).trim() + (content.length > 120 ? "..." : "");
}
