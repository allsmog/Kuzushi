/**
 * Shared attachment subsystem — generic types.
 *
 * The vendor-assessment module pioneered an "attach a file/URL as untrusted
 * reference material" workflow with a parser pipeline (text/PDF/image), a
 * persisted scope (`.kuzushi/<id>/scope.draft.json`), and a nonce-wrapped
 * prompt-injection guard. This package factors those concerns out so the
 * threat-model, context, and carlini-threat-hunt modules can adopt the same pattern
 * without duplicating the parser, prompt rendering, or operator UX. Vendor
 * itself moves onto these types via a custom storage adapter that keeps its
 * existing `scope.draft.json` shape.
 */

/** Lifecycle status for an attached document, identical across consuming modules. */
export type AttachmentStatus = "parsed" | "metadata-only" | "needs-human-review" | "error";

/**
 * A consuming module's kind taxonomy. The shared parser uses `inference` to
 * map filenames to a canonical kind, falling back to `default`. `label`
 * exists so home/`/kb` views can show a human label without pulling each
 * module's bespoke display logic into the shared layer.
 */
export interface KindSpec<K extends string = string> {
  /** Owning module id — used to namespace the storage path and prompt tag. */
  readonly moduleId: string;
  /** Canonical kind enum values. */
  readonly kinds: readonly K[];
  /** Fallback kind when no inference rule matches and no override is given. */
  readonly default: K;
  /** Filename-regex inference, evaluated first-match-wins against `path.basename(source).toLowerCase()`. */
  readonly inference: ReadonlyArray<{ readonly kind: K; readonly pattern: RegExp }>;
  /** Display label for the kind (used by the `/kb` view + module-home block). */
  readonly label: (kind: K) => string;
}

/** A single attached document — the unit of reference material an operator stages. */
export interface AttachmentDocument<K extends string = string> {
  /** 12-char SHA-256 prefix of the resolved source path. Stable across re-attaches. */
  id: string;
  /** Absolute file path or URL the operator passed in. */
  source: string;
  sourceType: "local" | "url";
  kind: K;
  /** Display title — the basename, URL pathname, or operator-provided override. */
  title: string;
  mime?: string;
  sizeBytes?: number;
  /** Pages (only for PDFs that the lite parser could count). */
  pageCount?: number;
  status: AttachmentStatus;
  /** Extracted text body — populated when status is "parsed". */
  extracted?: {
    text: string;
    charCount: number;
    parser: "text" | "pdf-lite" | "none";
  };
  parseWarnings: string[];
  /** ISO timestamp captured at attach time. */
  attachedAt: string;
}

/**
 * The persisted container. New modules write this directly; vendor's existing
 * `VendorAssessmentScope` keeps its richer shape but exposes its `documents`
 * array via a custom storage adapter (see `storage.ts`).
 */
export interface AttachmentScope<K extends string = string> {
  documents: AttachmentDocument<K>[];
  updatedAt: string;
}

/**
 * Pluggable storage. The default adapter persists at
 * `.kuzushi/<moduleId>/attachments.json`. Vendor-assessment passes a custom
 * adapter that reads/writes the `documents` slice of `scope.draft.json` so it
 * keeps its existing on-disk format and `scopeToHomeSlice` derivations.
 */
export interface AttachmentStorageAdapter<K extends string = string> {
  /** Load all attachments for the given workspace. Empty array when nothing is attached. */
  read(cwd: string): AttachmentDocument<K>[];
  /** Persist the full set, overwriting whatever is on disk. Returns the absolute path written. */
  write(cwd: string, docs: AttachmentDocument<K>[]): string;
  /** Remove all attachments. Idempotent. */
  clear(cwd: string): void;
  /**
   * Resolve the file path the adapter writes to. Used by the operator-facing
   * "stored at ..." line in the attach confirmation card and by tests.
   */
  pathFor(cwd: string): string;
}
