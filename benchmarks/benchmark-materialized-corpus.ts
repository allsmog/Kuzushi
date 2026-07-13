import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { CorpusIdentity, CorpusManifest } from "./benchmark-corpus-contract.js";
import { assertCorpusUnchanged, snapshotCorpus } from "./benchmark-corpus-manifest.js";
import { materializeCorpusTree, prepareKuzushiStateRoot } from "./benchmark-corpus-materializer.js";
import { cleanupCorpus, corpusRootIdentity } from "./benchmark-corpus-removal.js";
import { loadMaterializedTree } from "./benchmark-git-corpus.js";

/**
 * Execute a synchronous callback against a private, read-only materialization
 * of one exact Git commit. The source checkout is never used as the scan root.
 */
export function withMaterializedCorpus<T>(
  sourceRepo: string,
  revision: string,
  callback: (corpusRoot: string) => T,
): T {
  const entries = loadMaterializedTree(sourceRepo, revision);
  const corpusRoot = mkdtempSync(join(tmpdir(), "kuzushi-benchmark-corpus-"));
  const identity = corpusRootIdentity(corpusRoot);
  const baseline = initializeCorpus(corpusRoot, identity, entries);
  return invokeAndVerify(callback, corpusRoot, identity, baseline);
}

function initializeCorpus(
  root: string,
  identity: CorpusIdentity,
  entries: Parameters<typeof materializeCorpusTree>[1],
): CorpusManifest {
  try {
    materializeCorpusTree(root, entries);
    const baseline = snapshotCorpus(root);
    prepareKuzushiStateRoot(root, entries);
    return baseline;
  } catch (error) {
    cleanupCorpus(root, identity);
    throw error;
  }
}

function invokeAndVerify<T>(
  callback: (corpusRoot: string) => T,
  root: string,
  identity: CorpusIdentity,
  baseline: CorpusManifest,
): T {
  let result!: T;
  const failures: unknown[] = [];
  try {
    result = callback(root);
  } catch (error) {
    failures.push(error);
  }
  captureFailure(failures, () => assertCorpusUnchanged(root, identity, baseline));
  captureFailure(failures, () => cleanupCorpus(root, identity));
  throwFailures(failures);
  return result;
}

function captureFailure(failures: unknown[], action: () => void): void {
  try {
    action();
  } catch (error) {
    failures.push(error);
  }
}

function throwFailures(failures: unknown[]): void {
  if (failures.length === 1) throw failures[0];
  if (failures.length > 1) {
    throw new AggregateError(
      failures,
      "Benchmark corpus callback, verification, or cleanup failed",
    );
  }
}
