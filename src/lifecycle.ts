import { toErrorMessage } from "./utils.js";

/**
 * Graceful shutdown coordinator.
 *
 * Provides a hook-based shutdown sequence with priority ordering:
 * register named hooks with priority, then drain them in order with a timeout.
 */

const SHUTDOWN_TIMEOUT_MS = 10_000;

interface ShutdownHook {
  name: string;
  fn: () => Promise<void>;
  priority: number;
}

let shuttingDown = false;
const hooks: ShutdownHook[] = [];

/**
 * Register a shutdown hook.
 * Lower priority numbers run first (priority 1 before priority 2, etc.).
 */
export function registerShutdownHook(
  name: string,
  fn: () => Promise<void>,
  priority: number,
): () => void {
  const hook = { name, fn, priority };
  hooks.push(hook);
  return () => {
    const index = hooks.indexOf(hook);
    if (index >= 0) {
      hooks.splice(index, 1);
    }
  };
}

/** Check if the process is currently shutting down. */
export function isShuttingDown(): boolean {
  return shuttingDown;
}

/**
 * Run all registered shutdown hooks in priority order, then exit.
 * Each hook gets a per-hook timeout. If the total shutdown exceeds
 * SHUTDOWN_TIMEOUT_MS, remaining hooks are skipped and the process force-exits.
 */
export async function initiateShutdown(code: number): Promise<never> {
  if (shuttingDown) {
    // Already shutting down — force exit on second signal.
    process.exit(code);
  }

  shuttingDown = true;

  const sorted = [...hooks].sort((a, b) => a.priority - b.priority);

  const deadline = Date.now() + SHUTDOWN_TIMEOUT_MS;

  for (const hook of sorted) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      console.error(`[shutdown] Timeout reached, skipping remaining hooks`);
      break;
    }

    try {
      await Promise.race([
        hook.fn(),
        new Promise<void>((_, reject) =>
          setTimeout(() => reject(new Error("hook timeout")), remaining),
        ),
      ]);
    } catch (err) {
      console.error(`[shutdown] Hook "${hook.name}" failed: ${toErrorMessage(err)}`);
    }
  }

  process.exit(code);
}

/** Clear all registered hooks. Useful for testing. */
export function clearShutdownHooks(): void {
  hooks.length = 0;
  shuttingDown = false;
}

/** Number of currently registered shutdown hooks. Useful for diagnostics and tests. */
export function getShutdownHookCount(): number {
  return hooks.length;
}
