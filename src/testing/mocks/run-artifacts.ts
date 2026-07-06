/**
 * In-memory `RunArtifactStore` for unit tests. Captures every `write` call
 * on `.writes` so tests can assert what a tool persisted without touching
 * the filesystem.
 */

import type { RunArtifactStore } from "../../modules/host-handles.js";

export interface RunArtifactWrite {
  name: string;
  content: string | Uint8Array;
}

export interface MockRunArtifactStore extends RunArtifactStore {
  /** Every write observed since the last `clear`. */
  readonly writes: RunArtifactWrite[];
  /** Reset the recorded writes. */
  clear(): void;
}

/**
 * Build a recording `RunArtifactStore` rooted at a virtual path. The default
 * root is `<tmp>/<runId>/<moduleId>`; tests rarely care about the absolute
 * value but `path()` returns it for completeness.
 *
 * Path-traversal validation matches the production store: leading `/`,
 * `..` segments, and absolute paths throw.
 */
export function createMockRunArtifactStore(
  opts: { runId?: string; moduleId?: string; root?: string } = {},
): MockRunArtifactStore {
  const runId = opts.runId ?? "test-run";
  const moduleId = opts.moduleId ?? "test-module";
  const root = opts.root ?? `/virtual/.kuzushi/v3/runs/${runId}/${moduleId}`;
  const writes: RunArtifactWrite[] = [];

  function resolveSafe(name: string): string {
    if (typeof name !== "string" || name.length === 0) {
      throw new Error("RunArtifactStore: name must be a non-empty string");
    }
    if (name.startsWith("/") || name.includes("..")) {
      throw new Error(`RunArtifactStore: name "${name}" escapes module run dir`);
    }
    return `${root}/${name}`;
  }

  return {
    moduleId,
    runId,
    writes,
    write(name, content) {
      const abs = resolveSafe(name);
      writes.push({ name, content });
      return abs;
    },
    path(name) {
      return resolveSafe(name);
    },
    clear() {
      writes.length = 0;
    },
  };
}
