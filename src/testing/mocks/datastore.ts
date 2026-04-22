/**
 * In-memory implementation of `ToolOptionStore` for unit tests.
 *
 * Keys are normalized to upper-case to match the host `Datastore` semantics
 * (msfconsole `set FOO bar` is case-insensitive). Values are stored as their
 * original shape — no string-coercion — so tests can round-trip structured
 * defaults through `get<T>`.
 */

import type { ToolOptionStore } from "../../modules/host-handles.js";

export interface MockToolOptionStore extends ToolOptionStore {
  /** Underlying map (upper-case keys). Exposed for test introspection. */
  readonly entries: Map<string, unknown>;
  /** Seed a value programmatically. Used by `createMockToolContext` overrides. */
  seed(key: string, value: unknown): void;
  /** Drop every stored value. */
  clear(): void;
}

/**
 * Build a `ToolOptionStore` stub backed by an in-memory `Map`. Use `seed()`
 * in test setup to prime the store with options your tool reads.
 *
 * @example
 *   const datastore = createMockOptionStore();
 *   datastore.seed("TRIAGE_MODEL", "claude-haiku");
 *   const ctx = createMockToolContext({ datastore });
 *   expect(ctx.datastore?.get("triage_model")).toBe("claude-haiku");
 */
export function createMockOptionStore(initial: Record<string, unknown> = {}): MockToolOptionStore {
  const entries = new Map<string, unknown>();
  const norm = (key: string): string => key.toUpperCase();
  for (const [k, v] of Object.entries(initial)) entries.set(norm(k), v);

  return {
    entries,
    get<T = unknown>(key: string): T | undefined {
      return entries.get(norm(key)) as T | undefined;
    },
    set(key: string, value: string): string | null {
      entries.set(norm(key), value);
      return null;
    },
    has(key: string): boolean {
      return entries.has(norm(key));
    },
    seed(key: string, value: unknown): void {
      entries.set(norm(key), value);
    },
    clear(): void {
      entries.clear();
    },
  };
}
