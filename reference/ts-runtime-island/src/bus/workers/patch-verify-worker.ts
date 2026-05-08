import { execFileSync } from "node:child_process";
import type Database from "better-sqlite3";
import type { AgentRuntime } from "../../agent-runtime/types.js";
import { resolveTaskConfig as resolveConfiguredTaskConfig } from "../../capabilities.js";
import type { DagRegistry } from "../../modules/dag-registry.js";
import type { ExecutionContext } from "../../modules/types.js";
import { untrackWorktree } from "../../patch.js";
import { getPatchResultsForFinding, updatePatchResultStatus } from "../../store/patch-results.js";
import { getStoredFinding } from "../../store.js";
import type { KuzushiConfig, ScanOpts } from "../../types.js";
import { toErrorMessage } from "../../utils.js";
import type { PatchVerifyRequestedEvent } from "../events.js";
import { createEvent } from "../helpers.js";
import { extractTaskFindings } from "../task-findings.js";
import type { MessageBus } from "../types.js";

export interface PatchVerifyWorkerDeps {
  bus: MessageBus;
  db: Database.Database;
  config: KuzushiConfig;
  runtime: AgentRuntime;
  dagRegistry: DagRegistry;
}

/**
 * Worker that re-verifies patched code by running configured finding tasks on the worktree.
 */
export function registerPatchVerifyWorker(deps: PatchVerifyWorkerDeps): void {
  const { bus, db, config, runtime, dagRegistry } = deps;

  bus.subscribe<PatchVerifyRequestedEvent>("patch-verify:requested", async (event) => {
    const { context, fingerprint, worktreePath, depth } = event.payload;
    const runId = event.meta.runId;

    await bus.publish(createEvent("patch-verify:start", runId, { context, fingerprint }));

    try {
      const stored = getStoredFinding(db, fingerprint);
      const originatingTaskId = stored?.taskId;
      const verified = await verifyPatch(
        fingerprint,
        worktreePath,
        context.repoRoot,
        context.repoName,
        config,
        runtime,
        dagRegistry,
        originatingTaskId,
      );

      const patchResults = getPatchResultsForFinding(db, fingerprint);
      const latestPatch = patchResults[0];
      if (latestPatch) {
        updatePatchResultStatus(
          db,
          latestPatch.patchRunId,
          verified ? "VERIFIED" : "STILL_VULNERABLE",
        );
      }

      await bus.publish(
        createEvent("patch-verify:complete", runId, {
          context,
          fingerprint,
          verified,
          depth,
          details: verified
            ? "Finding no longer detected after patch applied"
            : "Finding still present after patch applied",
        }),
      );
    } catch (error) {
      await bus.publish(
        createEvent("patch-verify:error", runId, {
          context,
          fingerprint,
          error: toErrorMessage(error),
        }),
      );
    } finally {
      cleanupWorktree(worktreePath, context.repoRoot);
    }
  });
}

async function verifyPatch(
  fingerprint: string,
  worktreePath: string,
  projectRoot: string,
  repoName: string,
  config: KuzushiConfig,
  runtime: AgentRuntime,
  dagRegistry: DagRegistry,
  originatingTaskId?: string,
): Promise<boolean> {
  const silentBus: MessageBus = {
    async publish() {},
    subscribe() {},
    unsubscribe() {},
    async waitFor() {
      throw new Error("waitFor is unavailable in patch verification");
    },
    async close() {},
  };

  const tasksToRun =
    originatingTaskId && dagRegistry.has(originatingTaskId) ? [originatingTaskId] : config.tasks;

  for (const taskId of tasksToRun) {
    if (!dagRegistry.has(taskId)) continue;
    const task = dagRegistry.get(taskId);
    if (task.outputKind !== "findings" && task.outputKind !== "threat-model") {
      continue;
    }

    const scanOpts: ScanOpts = {
      severity: config.severity,
      maxFindings: undefined,
      excludePatterns: config.excludePatterns,
      tasks: [taskId],
      fresh: true,
    };
    const execContext: ExecutionContext = {
      cwd: worktreePath,
      target: worktreePath,
      config,
      runtime,
      bus: silentBus,
      dag: {
        runId: `patch-verify:${fingerprint}`,
        repoRoot: projectRoot,
        workRoot: worktreePath,
        scanPath: worktreePath,
        repoName,
        upstreamOutputs: new Map(),
      },
    };
    const taskConfig = resolveConfiguredTaskConfig(config, taskId);
    if (task.init) {
      await task.init(taskConfig);
    }
    const output = await task.run(scanOpts, execContext);
    const emittedFindings = extractTaskFindings(task.outputKind, output);

    for (const finding of emittedFindings) {
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
  } finally {
    untrackWorktree(worktreePath);
  }
}
