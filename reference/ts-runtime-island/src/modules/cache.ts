/**
 * Module metadata cache — materialized index stored at
 * `<dataDir>/module-cache.json`.
 *
 * Inspired by msfconsole's `modules.cache` table: a persisted metadata
 * snapshot lets `search` and `modules` traverse hundreds of modules
 * without loading every file. Full module instantiation is deferred
 * until `use <id>` is issued.
 *
 * Cache shape (JSON):
 *
 *   {
 *     "version": 1,
 *     "generatedAt": "2026-04-20T12:34:56Z",
 *     "entries": {
 *       "sast": { id, displayName, category, version, description, rank,
 *                 references, disclosureDate, tools: [...], mtime }
 *     }
 *   }
 *
 * Stale-entry detection is mtime-based: if the loader's `mtime` value for
 * a module id doesn't match the cached one, the caller should re-import
 * and call `upsert()` with the fresh metadata.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import type { CopilotModule } from "./types.js";

export const MODULE_CACHE_VERSION = 1;
export const MODULE_CACHE_FILENAME = "module-cache.json";

/** A single module's cached metadata (everything `search` / `info` reads). */
export interface ModuleCacheEntry {
  id: string;
  displayName: string;
  category: CopilotModule["category"];
  version: string;
  description: string;
  rank?: CopilotModule["rank"];
  references?: CopilotModule["references"];
  disclosureDate?: string;
  /**
   * Source-file mtime in ms. Used for invalidation: when the source file
   * changes, the cache entry is considered stale. Callers pass 0 when the
   * source is builtin/in-memory and invalidation isn't applicable.
   */
  mtime: number;
  tools: Array<{
    name: string;
    description: string;
    headless: boolean;
    rank?: CopilotModule["rank"];
    references?: CopilotModule["references"];
  }>;
}

/** Disk shape. */
export interface ModuleCacheFile {
  version: number;
  generatedAt: string;
  entries: Record<string, ModuleCacheEntry>;
}

/**
 * Project the loaded CopilotModule into a JSON-safe cache entry. `mtime`
 * is passed through unchanged so callers can key invalidation on source
 * state (0 for builtins that never rebuild).
 */
export function projectModule(mod: CopilotModule, mtime = 0): ModuleCacheEntry {
  const entry: ModuleCacheEntry = {
    id: mod.id,
    displayName: mod.displayName,
    category: mod.category,
    version: mod.version,
    description: mod.description,
    mtime,
    tools: mod.tools.map((t) => {
      const toolEntry: ModuleCacheEntry["tools"][number] = {
        name: t.name,
        description: t.description,
        headless: t.headless,
      };
      if (t.rank) toolEntry.rank = t.rank;
      if (t.references) toolEntry.references = t.references;
      return toolEntry;
    }),
  };
  if (mod.rank) entry.rank = mod.rank;
  if (mod.references) entry.references = mod.references;
  if (mod.disclosureDate) entry.disclosureDate = mod.disclosureDate;
  return entry;
}

export class ModuleCache {
  private readonly filePath: string;
  private entries = new Map<string, ModuleCacheEntry>();

  constructor(dataDir: string) {
    this.filePath = path.join(dataDir, MODULE_CACHE_FILENAME);
  }

  /**
   * Load the cache from disk. A missing / malformed / mismatched-version
   * file leaves the cache empty — callers should treat any miss as "needs
   * fresh population" and fall through to importing the module.
   */
  load(): void {
    this.entries.clear();
    if (!existsSync(this.filePath)) return;
    try {
      const raw = readFileSync(this.filePath, "utf8");
      const parsed = JSON.parse(raw) as Partial<ModuleCacheFile>;
      if (parsed.version !== MODULE_CACHE_VERSION) return;
      for (const [id, entry] of Object.entries(parsed.entries ?? {})) {
        if (entry && typeof entry === "object") this.entries.set(id, entry as ModuleCacheEntry);
      }
    } catch {
      // Corrupt cache — act as if empty. The next save() rewrites it.
    }
  }

  /** Upsert a single entry. Does not persist until save() is called. */
  upsert(entry: ModuleCacheEntry): void {
    this.entries.set(entry.id, entry);
  }

  /** Upsert directly from a loaded module (convenience). */
  upsertFromModule(mod: CopilotModule, mtime = 0): void {
    this.upsert(projectModule(mod, mtime));
  }

  /** Remove an entry. Returns true if an entry existed. */
  remove(id: string): boolean {
    return this.entries.delete(id);
  }

  /** Lookup a single entry. */
  get(id: string): ModuleCacheEntry | undefined {
    return this.entries.get(id);
  }

  /** Snapshot of all cached entries. */
  all(): ModuleCacheEntry[] {
    return [...this.entries.values()];
  }

  /** Count. */
  size(): number {
    return this.entries.size;
  }

  /**
   * Return the ids whose cached mtime differs from the provided current
   * values — those need to be re-loaded. Missing-from-cache ids also come
   * back as stale so new modules get loaded on first run.
   */
  staleIds(currentMtimes: Record<string, number>): string[] {
    const stale: string[] = [];
    for (const [id, mtime] of Object.entries(currentMtimes)) {
      const cached = this.entries.get(id);
      if (!cached || cached.mtime !== mtime) stale.push(id);
    }
    return stale;
  }

  /** Write the cache to disk. Creates the parent directory if needed. */
  save(): void {
    const dir = path.dirname(this.filePath);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    const file: ModuleCacheFile = {
      version: MODULE_CACHE_VERSION,
      generatedAt: new Date().toISOString(),
      entries: Object.fromEntries(this.entries),
    };
    writeFileSync(this.filePath, `${JSON.stringify(file, null, 2)}\n`, "utf8");
  }
}
