import type Database from "better-sqlite3";
import type { AgentRuntime } from "../../agent-runtime/types.js";
import { runPatchPipeline } from "../../patch.js";
import type { KuzushiConfig } from "../../types.js";
import { toErrorMessage } from "../../utils.js";
import type { PatchRequestedEvent } from "../events.js";
import { createEvent } from "../helpers.js";
import type { MessageBus } from "../types.js";

export interface PatchWorkerDeps {
  bus: MessageBus;
  db: Database.Database;
  runtime: AgentRuntime;
  config: KuzushiConfig;
}

/**
 * Worker that subscribes to patch:requested events, runs patch synthesis,
 * and emits patch:start/complete/error events.
 */
export function registerPatchWorker(deps: PatchWorkerDeps): void {
  const { bus, db, runtime, config } = deps;

  bus.subscribe<PatchRequestedEvent>("patch:requested", async (event) => {
    const { context, fingerprint } = event.payload;
    const runId = event.meta.runId;
    const repoRoot = context.repoRoot;
    const repoName = context.repoName;

    await bus.publish(createEvent("patch:start", runId, { context, fingerprint }));

    try {
      const result = await runPatchPipeline(db, {
        fingerprint,
        repoRoot,
        repoName,
        model: config.model,
        runtime,
        maxIterations: config.patchMaxIterations ?? 3,
        buildCommand: config.patchBuildCommand ?? null,
        testCommand: config.patchTestCommand ?? null,
        skipCleanup: true,
      });

      const patchResult = result.patchResult;

      await bus.publish(
        createEvent("patch:complete", runId, {
          context,
          fingerprint,
          status: patchResult.status,
          worktreePath: patchResult.worktreePath ?? null,
          costUsd: result.costUsd,
          iterations: patchResult.iterations,
        }),
      );
    } catch (error) {
      await bus.publish(
        createEvent("patch:error", runId, {
          context,
          fingerprint,
          error: toErrorMessage(error),
          attempt: 1,
        }),
      );
    }
  });
}
