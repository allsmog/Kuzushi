/**
 * Generic iterative execution loop extracted from the poc-harness-worker pattern.
 *
 * Encapsulates the generate -> execute -> parse errors -> refine cycle used by
 * PoC harness generation, dynamic analysis, and verification workers.
 */
import type { AgentHistoryEntry } from "../../agent-runtime/types.js";

export interface IterativeLoopOptions<TResult> {
  /** Generate or refine the artifact (e.g., PoC script, verification proof). */
  generate: (
    history: AgentHistoryEntry[],
    iteration: number,
  ) => Promise<{ result: TResult; costUsd: number; history: AgentHistoryEntry[] }>;

  /** Execute the generated artifact and return success/failure + error details. */
  execute?: (result: TResult) => Promise<{ success: boolean; output: string; durationMs: number }>;

  /** Build failure history entries to inject into the next iteration. */
  buildFailurePrompt: (result: TResult, executionOutput: string, iteration: number) => string;

  /** Build a reflection prompt at reflection intervals. */
  buildReflectionPrompt: (failureCount: number, totalIterations: number) => string;

  /** Maximum iterations. */
  maxIterations: number;

  /** How often to inject reflection (every N failures). */
  reflectionInterval: number;

  /** Callback for each attempt (e.g., to emit events). */
  onAttempt?: (iteration: number) => void;
}

export interface IterativeLoopResult<TResult> {
  result: TResult;
  totalCostUsd: number;
  iterations: number;
  executionSuccess?: boolean;
  executionOutput?: string;
  executionDurationMs?: number;
  refinementHistory: Array<{ iteration: number; success: boolean; output: string }>;
}

/**
 * Tiered reflection strategy that varies guidance based on the number of attempts.
 *
 * - Attempts 1-3 (standard retry): Returns the failure prompt as-is, no extra reflection.
 * - Attempts 4-6 (reflection checkpoint): Asks the agent to step back, reconsider
 *   assumptions, and identify what it has overlooked.
 * - Attempts 7+ (strategy shift): Instructs the agent to fundamentally change approach,
 *   technique, language, or framework.
 *
 * Callers can use this as their `buildReflectionPrompt` callback to get tiered
 * reflection behavior without custom logic.
 */
export function buildTieredReflectionPrompt(
  failureCount: number,
  _totalIterations: number,
): string {
  if (failureCount <= 3) {
    // Standard retry tier: concise nudge, no heavy reflection.
    return [
      `Attempt ${failureCount} failed.`,
      "Review the error output carefully and correct the specific issue before retrying.",
    ].join("\n");
  }

  if (failureCount <= 6) {
    // Reflection checkpoint tier: step back and reconsider.
    return [
      `You've tried ${failureCount} approaches without success. Step back and reconsider your assumptions.`,
      "",
      "Before your next attempt:",
      "1. What assumptions have you been making that might be wrong?",
      "2. What haven't you considered? Are there alternative APIs, configurations, or entry points?",
      "3. Re-read the error messages from scratch — is there a pattern you missed?",
      "4. Consider whether the vulnerability or behavior manifests differently than you expect.",
    ].join("\n");
  }

  // Strategy shift tier: fundamentally change approach.
  return [
    `You've made ${failureCount} attempts. Your current strategy is not working.`,
    "",
    "IMPORTANT: Fundamentally change your approach. Do NOT iterate on your previous attempts.",
    "",
    "Consider:",
    "1. Try a completely different technique or attack vector.",
    "2. Use a different language, framework, or toolchain if applicable.",
    "3. Target a different code path or entry point entirely.",
    "4. Simplify drastically — the most minimal possible proof may succeed where complex ones fail.",
    "5. Question whether your understanding of the target is correct at all.",
  ].join("\n");
}

/**
 * Run an iterative generate-execute-refine loop.
 *
 * 1. Calls `generate()` on first (and subsequent) iterations.
 * 2. If `execute()` is provided, runs it on the result.
 * 3. If execution fails, calls `buildFailurePrompt()` and injects into history.
 * 4. Every `reflectionInterval` failures, also injects `buildReflectionPrompt()`.
 * 5. Tracks history, cost, and refinement results.
 * 6. Returns the best result (first successful execution, or the last iteration).
 */
export async function iterativeExecutionLoop<TResult>(
  options: IterativeLoopOptions<TResult>,
): Promise<IterativeLoopResult<TResult>> {
  const {
    generate,
    execute,
    buildFailurePrompt,
    buildReflectionPrompt,
    maxIterations,
    reflectionInterval,
    onAttempt,
  } = options;

  const history: AgentHistoryEntry[] = [];
  const refinementHistory: Array<{ iteration: number; success: boolean; output: string }> = [];
  let totalCostUsd = 0;
  let latestResult: TResult | undefined;
  let latestExecutionSuccess: boolean | undefined;
  let latestExecutionOutput: string | undefined;
  let latestExecutionDurationMs: number | undefined;
  let failureCount = 0;

  for (let iteration = 1; iteration <= maxIterations; iteration += 1) {
    onAttempt?.(iteration);

    const generated = await generate(history, iteration);
    totalCostUsd += generated.costUsd;
    latestResult = generated.result;

    // Merge any history entries the generator produced back into our running history.
    // The generator receives the current history and may append to it internally;
    // we use the returned history as-is for the next iteration.
    history.length = 0;
    history.push(...generated.history);

    if (!execute) {
      // No execution step: return result from the first (and only meaningful) generation.
      return {
        result: latestResult,
        totalCostUsd,
        iterations: iteration,
        refinementHistory,
      };
    }

    const execution = await execute(latestResult);
    latestExecutionSuccess = execution.success;
    latestExecutionOutput = execution.output;
    latestExecutionDurationMs = execution.durationMs;

    refinementHistory.push({
      iteration,
      success: execution.success,
      output: execution.output,
    });

    if (execution.success) {
      return {
        result: latestResult,
        totalCostUsd,
        iterations: iteration,
        executionSuccess: true,
        executionOutput: execution.output,
        executionDurationMs: execution.durationMs,
        refinementHistory,
      };
    }

    failureCount += 1;

    // Don't inject failure prompts on the last iteration — there's no next loop.
    if (iteration >= maxIterations) {
      break;
    }

    // Inject failure context for the next iteration.
    const failurePrompt = buildFailurePrompt(latestResult, execution.output, iteration);
    history.push({ role: "user", content: failurePrompt });

    // Inject periodic reflection prompts to help the agent reconsider assumptions.
    if (failureCount % reflectionInterval === 0) {
      const reflectionPrompt = buildReflectionPrompt(failureCount, iteration);
      history.push({ role: "user", content: reflectionPrompt });
    }
  }

  if (!latestResult) {
    throw new Error("iterative execution loop did not produce a result");
  }

  return {
    result: latestResult,
    totalCostUsd,
    iterations: maxIterations,
    executionSuccess: latestExecutionSuccess,
    executionOutput: latestExecutionOutput,
    executionDurationMs: latestExecutionDurationMs,
    refinementHistory,
  };
}
