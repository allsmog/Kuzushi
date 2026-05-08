/**
 * Host implementation of `RunArtifactStore`.
 *
 * Scoped per-(runId, moduleId), writes land under
 * `<dataDir>/runs/<runId>/<moduleId>/<name>`. Names are validated to
 * prevent path traversal — leading slashes, `..` segments, and absolute
 * paths are rejected. Parent directories are created lazily on first write.
 *
 * Modules access this via `ExecutionContext.runArtifacts`. The host wires
 * an instance only when both `dag.runId` and `tool.moduleId` are present
 * (i.e. during scan-mode DAG execution); in shell + run mode the field is
 * `undefined` and modules feature-probe with
 * `ctx.host?.capabilities.has("run-artifacts")`.
 */

import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import type { RunArtifactStore } from "./host-handles.js";

/**
 * Build a run-artifact store rooted at `<dataDir>/runs/<runId>/<moduleId>`.
 * `dataDir` is the host's `.kuzushi` directory (or whatever the operator
 * configured); the runs subdirectory is created on demand.
 */
export function createRunArtifactStore(opts: {
  dataDir: string;
  runId: string;
  moduleId: string;
}): RunArtifactStore {
  const root = path.join(opts.dataDir, "runs", opts.runId, opts.moduleId);

  function resolveSafePath(name: string): string {
    if (typeof name !== "string" || name.length === 0) {
      throw new Error("RunArtifactStore: name must be a non-empty string");
    }
    if (path.isAbsolute(name)) {
      throw new Error(`RunArtifactStore: name "${name}" must be relative`);
    }
    const candidate = path.resolve(root, name);
    const rel = path.relative(root, candidate);
    if (rel.startsWith("..") || path.isAbsolute(rel)) {
      throw new Error(`RunArtifactStore: name "${name}" escapes module run dir`);
    }
    return candidate;
  }

  return {
    moduleId: opts.moduleId,
    runId: opts.runId,
    write(name, content) {
      const abs = resolveSafePath(name);
      mkdirSync(path.dirname(abs), { recursive: true });
      writeFileSync(abs, content);
      return abs;
    },
    path(name) {
      return resolveSafePath(name);
    },
  };
}
