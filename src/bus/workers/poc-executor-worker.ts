import type { PocExecutor } from "../../poc-executor/types.js";
import { toErrorMessage } from "../../utils.js";
import type { PocExecutionQueuedEvent } from "../events.js";
import { createEvent } from "../helpers.js";
import type { MessageBus } from "../types.js";

/**
 * Worker that subscribes to poc-execution:queued events,
 * executes PoC scripts in a sandbox, and emits results.
 */
export function registerPocExecutorWorker(bus: MessageBus, executor: PocExecutor): void {
  bus.subscribe<PocExecutionQueuedEvent>("poc-execution:queued", async (event) => {
    const { context, fingerprint, scriptPath, language } = event.payload;
    const runId = event.meta.runId;

    try {
      const result = await executor.execute(scriptPath, language, context.repoRoot);

      await bus.publish(
        createEvent("poc-execution:result", runId, {
          context,
          fingerprint,
          exitCode: result.exitCode,
          stdout: result.stdout,
          stderr: result.stderr,
          timedOut: result.timedOut,
          durationMs: result.durationMs,
          verdict: result.verdict,
        }),
      );
    } catch (error) {
      await bus.publish(
        createEvent("poc-execution:error", runId, {
          context,
          fingerprint,
          error: toErrorMessage(error),
        }),
      );
    }
  });
}
