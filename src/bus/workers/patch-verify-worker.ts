import { execFileSync } from "node:child_process";
import type Database from "better-sqlite3";
import type { AgentRuntime } from "../../agent-runtime/types.js";
import type { TaskRegistry } from "../../agents/registry.js";
import type { TaskContext } from "../../agents/types.js";
import { resolveTaskConfig as resolveConfiguredTaskConfig } from "../../capabilities.js";
import { getPatchResultsForFinding, updatePatchResultStatus } from "../../store/patch-results.js";
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
  taskRegistry: TaskRegistry;
}

/**
 * Worker that re-verifies patched code by running configured finding tasks on the worktree.
 */
export function registerPatchVerifyWorker(deps: PatchVerifyWorkerDeps): void {
  const { bus, db, config, runtime, taskRegistry } = deps;

  bus.subscribe<PatchVerifyRequestedEvent>("patch-verify:requested", async (event) => {
    const { context, fingerprint, worktreePath, depth } = event.payload;
    const runId = event.meta.runId;

    await bus.publish(createEvent("patch-verify:start", runId, { context, fingerprint }));

    try {
      const verified = await verifyPatch(
        fingerprint,
        worktreePath,
        context.repoRoot,
        context.repoName,
        config,
        runtime,
        taskRegistry,
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
  taskRegistry: TaskRegistry,
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

  for (const taskId of config.tasks) {
    if (!taskRegistry.has(taskId)) continue;
    const task = taskRegistry.get(taskId);
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
    const taskContext: TaskContext = {
      runId: `patch-verify:${fingerprint}`,
      projectRoot,
      workRoot: worktreePath,
      repoRoot: worktreePath,
      scanPath: worktreePath,
      repoName,
      config,
      runtime,
      bus: silentBus,
      upstreamOutputs: new Map(),
    };
    const taskConfig = resolveConfiguredTaskConfig(config, taskId);
    if (task.init) {
      await task.init(taskConfig);
    }
    const output = await task.run(scanOpts, taskContext);
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
  }
}
