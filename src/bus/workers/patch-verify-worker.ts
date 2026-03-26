import type Database from "better-sqlite3";
import type { MessageBus } from "../types.js";
import type { PatchVerifyRequestedEvent } from "../events.js";
import { createEvent } from "../helpers.js";
import { toErrorMessage } from "../../utils.js";
import { updatePatchResultStatus, getPatchResultsForFinding } from "../../store/patch-results.js";
import type { ScannerRegistry } from "../../scanners/registry.js";
import type { KuzushiConfig } from "../../types.js";
import { execFileSync } from "node:child_process";

export interface PatchVerifyWorkerDeps {
  bus: MessageBus;
  db: Database.Database;
  config: KuzushiConfig;
  registry: ScannerRegistry;
}

/**
 * Worker that re-verifies patched code by running the scanner on the worktree.
 */
export function registerPatchVerifyWorker(deps: PatchVerifyWorkerDeps): void {
  const { bus, db, config, registry } = deps;

  bus.subscribe<PatchVerifyRequestedEvent>("patch-verify:requested", async (event) => {
    const { context, fingerprint, worktreePath, depth } = event.payload;
    const runId = event.meta.runId;

    await bus.publish(createEvent("patch-verify:start", runId, { context, fingerprint }));

    try {
      const verified = await verifyPatch(fingerprint, worktreePath, config, registry);

      const patchResults = getPatchResultsForFinding(db, fingerprint);
      const latestPatch = patchResults[0];
      if (latestPatch) {
        updatePatchResultStatus(db, latestPatch.patchRunId, verified ? "VERIFIED" : "STILL_VULNERABLE");
      }

      await bus.publish(createEvent("patch-verify:complete", runId, {
        context,
        fingerprint,
        verified,
        depth,
        details: verified
          ? "Finding no longer detected after patch applied"
          : "Finding still present after patch applied",
      }));
    } catch (error) {
      await bus.publish(createEvent("patch-verify:error", runId, {
        context,
        fingerprint,
        error: toErrorMessage(error),
      }));
    } finally {
      cleanupWorktree(worktreePath, context.repoRoot);
    }
  });
}

async function verifyPatch(
  fingerprint: string,
  worktreePath: string,
  config: KuzushiConfig,
  registry: ScannerRegistry,
): Promise<boolean> {
  for (const scannerId of config.scanners) {
    const plugin = registry.get(scannerId);
    if (!plugin) continue;

    const scanOpts = {
      severity: config.severity,
      maxFindings: undefined,
      excludePatterns: config.excludePatterns,
      scanners: [scannerId],
      fresh: true,
    };
    const scannerConfig = config.scannerConfig[scannerId] ?? {};
    const findings = await plugin.scan(worktreePath, scanOpts, scannerConfig);

    for (const finding of findings) {
      if (finding.fingerprint === fingerprint) {
        return false;
      }
    }
  }

  return true;
}

function cleanupWorktree(worktreePath: string, repoRoot: string): void {
  try {
    execFileSync("git", ["worktree", "remove", "--force", worktreePath], {
      cwd: repoRoot,
      stdio: "pipe",
      timeout: 30_000,
    });
  } catch {
    /* best-effort cleanup */
  }
}
