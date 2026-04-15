/**
 * Intel store types — the knowledge layer for security intelligence.
 *
 * Enables semantic search over CVEs, ATT&CK techniques, CAPEC patterns,
 * past findings, compliance docs, and custom org knowledge.
 */

/** A single document in the intel store. */
export interface IntelDocument {
  /** Unique document ID. */
  id: string;
  /** Which source this document came from. */
  source: IntelSource;
  /** Document title or identifier (e.g. "CVE-2024-1234", "T1190"). */
  title: string;
  /** Full text content for search. */
  content: string;
  /** Structured metadata (severity, CWE, CAPEC ID, etc.). */
  metadata: Record<string, unknown>;
  /** When this document was ingested (ISO timestamp). */
  ingestedAt: string;
}

/** Known intel sources. */
export type IntelSource =
  | "nvd"          // NVD CVE database
  | "attack"       // MITRE ATT&CK techniques
  | "capec"        // MITRE CAPEC patterns
  | "cwe"          // CWE weakness catalog
  | "compliance"   // Compliance framework controls (ISO 27001, NIST, etc.)
  | "findings"     // Past engagement findings
  | "custom";      // User-supplied documents

/** A search result from the intel store. */
export interface IntelSearchResult {
  document: IntelDocument;
  /** Relevance score (higher = more relevant). */
  score: number;
  /** Snippet of matching content. */
  snippet?: string;
}

/** Options for searching the intel store. */
export interface IntelSearchOptions {
  /** Maximum number of results. */
  limit?: number;
  /** Filter by source type. */
  sources?: IntelSource[];
  /** Filter by metadata fields. */
  metadata?: Record<string, unknown>;
}

/** Abstract interface for the intel store backend. */
export interface IntelStore {
  /** Add a document to the store. */
  ingest(doc: Omit<IntelDocument, "id" | "ingestedAt">): string;
  /** Bulk ingest documents. Returns number successfully ingested. */
  ingestBatch(docs: Array<Omit<IntelDocument, "id" | "ingestedAt">>): number;
  /** Search for documents matching a query. */
  search(query: string, options?: IntelSearchOptions): IntelSearchResult[];
  /** Get a document by ID. */
  get(id: string): IntelDocument | null;
  /** Delete a document by ID. */
  delete(id: string): boolean;
  /** Count documents, optionally filtered by source. */
  count(source?: IntelSource): number;
  /** Remove all documents from a source (for re-sync). */
  clearSource(source: IntelSource): number;
}
