import { createLogger } from "../logger.js";
import type { AgentTask, TaskContext } from "./types.js";

const log = createLogger({ stage: "task-wrappers" });

/**
 * Wrap a task with in-memory caching based on a cache key function.
 */
export function withCache<TInput = unknown, TOutput = unknown>(
  task: AgentTask<TInput, TOutput>,
  options: {
    cacheKey: (input: TInput) => string;
    ttlMs?: number;
  },
): AgentTask<TInput, TOutput> {
  const cache = new Map<string, { value: TOutput; timestamp: number }>();
  const ttl = options.ttlMs ?? 0; // 0 = no expiry

  return {
    ...task,
    id: task.id,
    displayName: task.displayName,
    outputKind: task.outputKind,
    dependsOn: task.dependsOn,
    async run(input: TInput, context: TaskContext): Promise<TOutput> {
      const key = options.cacheKey(input);
      const cached = cache.get(key);

      if (cached && (ttl === 0 || Date.now() - cached.timestamp < ttl)) {
        log.debug({ taskId: task.id, cacheKey: key }, "Cache hit");
        return cached.value;
      }

      const result = await task.run(input, context);
      cache.set(key, { value: result, timestamp: Date.now() });
      log.debug({ taskId: task.id, cacheKey: key }, "Cache miss, stored result");
      return result;
    },
  };
}

/**
 * Wrap a task with retry logic on failure.
 */
export function withRetry<TInput = unknown, TOutput = unknown>(
  task: AgentTask<TInput, TOutput>,
  options?: {
    maxRetries?: number;
    backoffMs?: number;
  },
): AgentTask<TInput, TOutput> {
  const maxRetries = options?.maxRetries ?? 3;
  const backoffMs = options?.backoffMs ?? 1000;

  return {
    ...task,
    id: task.id,
    displayName: task.displayName,
    outputKind: task.outputKind,
    dependsOn: task.dependsOn,
    async run(input: TInput, context: TaskContext): Promise<TOutput> {
      let lastError: Error | undefined;

      for (let attempt = 0; attempt <= maxRetries; attempt++) {
        try {
          return await task.run(input, context);
        } catch (err) {
          lastError = err instanceof Error ? err : new Error(String(err));
          if (attempt < maxRetries) {
            const delay = backoffMs * 2 ** attempt;
            log.warn(
              { taskId: task.id, attempt: attempt + 1, maxRetries, delay },
              "Task failed, retrying",
            );
            await new Promise((resolve) => setTimeout(resolve, delay));
          }
        }
      }

      log.error({ taskId: task.id, maxRetries }, "Task failed after all retries");
      throw lastError;
    },
  };
}

/**
 * Wrap a task with a timeout.
 */
export function withTimeout<TInput = unknown, TOutput = unknown>(
  task: AgentTask<TInput, TOutput>,
  timeoutMs: number,
): AgentTask<TInput, TOutput> {
  return {
    ...task,
    id: task.id,
    displayName: task.displayName,
    outputKind: task.outputKind,
    dependsOn: task.dependsOn,
    async run(input: TInput, context: TaskContext): Promise<TOutput> {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);

      try {
        const result = await Promise.race([
          task.run(input, context),
          new Promise<never>((_, reject) => {
            controller.signal.addEventListener("abort", () => {
              reject(new Error(`Task ${task.id} timed out after ${timeoutMs}ms`));
            });
          }),
        ]);
        return result;
      } finally {
        clearTimeout(timer);
      }
    },
  };
}

/**
 * Wrap a task with structured logging around execution.
 */
export function withLogging<TInput = unknown, TOutput = unknown>(
  task: AgentTask<TInput, TOutput>,
): AgentTask<TInput, TOutput> {
  return {
    ...task,
    id: task.id,
    displayName: task.displayName,
    outputKind: task.outputKind,
    dependsOn: task.dependsOn,
    async run(input: TInput, context: TaskContext): Promise<TOutput> {
      const startTime = Date.now();
      log.info({ taskId: task.id }, "Task execution started");

      try {
        const result = await task.run(input, context);
        const durationMs = Date.now() - startTime;
        log.info({ taskId: task.id, durationMs }, "Task execution completed");
        return result;
      } catch (err) {
        const durationMs = Date.now() - startTime;
        log.error(
          {
            taskId: task.id,
            durationMs,
            error: err instanceof Error ? err.message : String(err),
          },
          "Task execution failed",
        );
        throw err;
      }
    },
  };
}

/**
 * Compose multiple wrappers around a task.
 * Wrappers are applied in order (first wrapper is outermost).
 */
export function compose<TInput = unknown, TOutput = unknown>(
  task: AgentTask<TInput, TOutput>,
  ...wrappers: Array<(task: AgentTask<TInput, TOutput>) => AgentTask<TInput, TOutput>>
): AgentTask<TInput, TOutput> {
  return wrappers.reduce((wrapped, wrapper) => wrapper(wrapped), task);
}
