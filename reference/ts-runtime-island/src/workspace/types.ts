/** A persistent security engagement workspace. */
export interface Workspace {
  /** Unique workspace identifier (UUID). */
  id: string;
  /** Human-readable name (unique). */
  name: string;
  /** Repository/host targets associated with this workspace. */
  targets: string[];
  /** ISO timestamp of creation. */
  createdAt: string;
  /** ISO timestamp of last access (updated on load). */
  lastAccessedAt: string;
  /** Extensible metadata: cost totals, finding counts, tags, etc. */
  metadata: Record<string, unknown>;
}
