/**
 * Knowledge base types — structured domain knowledge for vulnerability
 * detection, triage, and verification.
 */

/** A dangerous code pattern with explanation. */
export interface DangerousPattern {
  pattern: string;
  why: string;
  severity: string;
}

/** A safe code pattern with explanation. */
export interface SafePattern {
  pattern: string;
  why: string;
}

/** A fix example showing before/after with explanation. */
export interface FixExample {
  language: string;
  before: string;
  after: string;
  explanation: string;
}

/** A single domain-specific knowledge module. */
export interface KnowledgeModule {
  /** Unique identifier (e.g. "sqli", "ssrf", "crypto-misuse"). */
  id: string;
  /** CWE identifiers this module covers (e.g. ["CWE-89"]). */
  cwes: string[];
  /** Languages this applies to. Empty = all languages. */
  languages?: string[];
  /** Frameworks this applies to. Empty = all frameworks. */
  frameworks?: string[];
  /** Known dangerous patterns to detect. */
  dangerousPatterns: DangerousPattern[];
  /** Known safe patterns to avoid flagging. */
  safePatterns: SafePattern[];
  /** Bypass techniques for verification. */
  bypassTechniques: string[];
  /** Keywords for detection queries. */
  detectionKeywords: string[];
  /** Fix examples for remediation guidance. */
  fixExamples: FixExample[];
  /** Free-form tags for querying. */
  tags: string[];
}

/** Query parameters for the knowledge registry. */
export interface KnowledgeQuery {
  cwes?: string[];
  vulnType?: string;
  language?: string;
  framework?: string;
  tags?: string[];
}

/** Registry interface for querying knowledge modules. */
export interface KnowledgeRegistry {
  /** Query for matching modules based on criteria. */
  query(q: KnowledgeQuery): KnowledgeModule[];
  /** Get a specific module by ID. */
  getById(id: string): KnowledgeModule | undefined;
  /** Format matching modules into prompt-ready sections. */
  formatForPrompt(modules: KnowledgeModule[], section?: string): string[];
  /** Get all registered module IDs. */
  ids(): string[];
}
