import type { AgentHistoryEntry } from "../../agent-runtime/types.js";
import type { AgentActivity } from "../../agent-runtime/execution.js";
import type { AgentRuntime } from "../../agent-runtime/types.js";
import { generatePocHarness, PocHarnessExecutionError } from "../../poc-harness.js";
import { createPocExecutor } from "../../poc-executor/index.js";
import { withRetry } from "../../retry.js";
import { coerceRepoContext } from "../../repo-context.js";
import type { KuzushiConfig, PocHarnessResult } from "../../types.js";
import { normalizeCostUsd } from "../../utils.js";
import { toErrorMessage } from "../../utils.js";
import type { PocHarnessFindingQueuedEvent } from "../events.js";
import { createEvent } from "../helpers.js";
import type { MessageBus } from "../types.js";
import { iterativeExecutionLoop } from "./iterative-loop.js";

export interface PocHarnessWorkerDeps {
  config: KuzushiConfig;
  runtime: AgentRuntime;
}

/**
 * PoC harness worker: generates runnable exploit harnesses against verified exploitable findings.
 */
export function registerPocHarnessWorker(
  bus: MessageBus,
  deps: PocHarnessWorkerDeps,
): void {
  bus.subscribe<PocHarnessFindingQueuedEvent>("poc-harness:finding-queued", async (event) => {
    const { context, finding, triageResult, verificationResult, repoContext, index, total } = event.payload;
    const runId = event.meta.runId;
    let attempts = 0;

    try {
      const { result, costUsd } = await generateHarnessWithRefinement(
        deps.config,
        deps.runtime,
        bus,
        runId,
        context,
        finding,
        triageResult,
        verificationResult,
        repoContext,
        index,
        total,
        () => {
          attempts += 1;
        },
      );
      result.costUsd = costUsd;

      await bus.publish(
        createEvent("poc-harness:result", runId, {
          context,
          finding,
          triageResult,
          verificationResult,
          result,
          costUsd,
          attempts,
          index,
          total,
        }),
      );
    } catch (error) {
      const costUsd = error instanceof PocHarnessExecutionError ? error.costUsd : undefined;
      await bus.publish(
        createEvent("poc-harness:error", runId, {
          context,
          finding,
          triageResult,
          verificationResult,
          error: toErrorMessage(error),
          costUsd,
          attempts,
          index,
          total,
        }),
      );
    }
  });
}

/** Intermediate wrapper that holds the PocHarnessResult plus execution metadata. */
interface HarnessIterationResult {
  pocResult: PocHarnessResult;
  /** When true, the result is final and should not be refined further. */
  earlyExit: boolean;
  /** Execution metadata populated when the executor ran. */
  execution?: {
    exitCode: number;
    stdout: string;
    stderr: string;
    verdict: "PASS" | "FAIL" | "ERROR" | "TIMEOUT";
    durationMs: number;
  };
}

async function generateHarnessWithRefinement(
  config: KuzushiConfig,
  runtime: AgentRuntime,
  bus: MessageBus,
  runId: string,
  context: PocHarnessFindingQueuedEvent["payload"]["context"],
  finding: PocHarnessFindingQueuedEvent["payload"]["finding"],
  triageResult: PocHarnessFindingQueuedEvent["payload"]["triageResult"],
  verificationResult: PocHarnessFindingQueuedEvent["payload"]["verificationResult"],
  repoContext: PocHarnessFindingQueuedEvent["payload"]["repoContext"],
  index: number,
  total: number,
  onAttempt: () => void,
): Promise<{ result: PocHarnessResult; costUsd: number }> {
  const repoRoot = context.scanPath ?? context.repoRoot;
  const model = config.pocHarnessModel
    ?? config.verifyModel
    ?? config.triageModel
    ?? config.model;
  const maxIterations = Math.max(1, config.pocRefinementMaxIterations ?? 3);
  const reflectionInterval = Math.max(1, config.pocReflectionInterval ?? 2);
  const retryOptions = {
    maxRetries: config.maxPocHarnessRetries ?? config.maxVerifyRetries ?? 2,
    backoffMs: config.retryBackoffMs ?? 5000,
    multiplier: config.retryBackoffMultiplier ?? 2,
  };
  const activityCallback = async (activity: AgentActivity) => {
    await bus.publish(
      createEvent("poc-harness:agent-activity", runId, {
        context,
        fingerprint: finding.fingerprint,
        kind: activity.kind,
        toolName: activity.toolName,
        toolInput: activity.toolInput,
        summary: activity.summary,
        elapsedSeconds: activity.elapsedSeconds,
        index,
        total,
      }),
    );
  };

  const executor = config.pocExecute === true
    ? await createPocExecutor(config.pocSandbox ?? "docker", config.pocExecTimeoutMs)
    : undefined;

  // Track previous iteration result for assistant summary injection.
  let previousPocResult: PocHarnessResult | undefined;

  // PoC-specific refinement tracking.
  const pocRefinementHistory: NonNullable<PocHarnessResult["refinementHistory"]> = [];

  const loopResult = await iterativeExecutionLoop<HarnessIterationResult>({
    maxIterations,
    reflectionInterval,

    generate: async (history: AgentHistoryEntry[], _iteration: number) => {
      // On subsequent iterations, inject the assistant summary of the previous
      // attempt before the failure prompt that the loop already appended.
      // The original code pushed: assistant_summary, then failure_prompt.
      // The loop appends the failure prompt as the last entry. We insert the
      // assistant summary just before it to maintain the same conversation flow.
      if (previousPocResult && history.length > 0) {
        const assistantEntry: AgentHistoryEntry = {
          role: "assistant",
          content: summarizeHarnessAttempt(previousPocResult),
        };
        // Find where the loop's appended user entries start (from the tail).
        let insertIdx = history.length;
        for (let i = history.length - 1; i >= 0; i--) {
          if (history[i].role === "user") {
            insertIdx = i;
          } else {
            break;
          }
        }
        history.splice(insertIdx, 0, assistantEntry);
      }

      const generated = await withRetry(
        async () => {
          onAttempt();
          return generatePocHarness(
            finding,
            triageResult,
            verificationResult,
            repoRoot,
            context.repoName,
            model,
            config.pocHarnessMaxTurns,
            coerceRepoContext(repoContext),
            {
              runtime,
              history,
              activityCallback,
            },
          );
        },
        retryOptions,
      );

      const pocResult: PocHarnessResult = {
        ...generated.result,
      };

      previousPocResult = pocResult;

      // Determine whether this result should skip execution entirely.
      const earlyExit = pocResult.skipped || !executor;

      return {
        result: { pocResult, earlyExit },
        costUsd: normalizeCostUsd(generated.costUsd),
        history: [...history],
      };
    },

    execute: async (iterResult: HarnessIterationResult) => {
      // Early exit: skipped result or no executor configured.
      if (iterResult.earlyExit) {
        return { success: true, output: "", durationMs: 0 };
      }

      const pocResult = iterResult.pocResult;

      // Parse/syntax validation failure — treat as execution failure without running executor.
      if (!pocResult.scriptPath || !pocResult.language || pocResult.parsed === false) {
        const error = pocResult.parseError ?? "Generated PoC harness was not runnable.";
        return { success: false, output: error, durationMs: 0 };
      }

      // Run the actual executor.
      const execution = await executor!.execute(
        pocResult.scriptPath,
        pocResult.language,
        context.repoRoot,
      );

      // Stash execution metadata on the iteration result so the caller can read it.
      iterResult.execution = {
        exitCode: execution.exitCode,
        stdout: execution.stdout,
        stderr: execution.stderr,
        verdict: execution.verdict,
        durationMs: execution.durationMs,
      };

      if (execution.verdict === "PASS") {
        return { success: true, output: "", durationMs: execution.durationMs };
      }

      const errorDescription = describeExecutionFailure(
        execution.exitCode,
        execution.stdout,
        execution.stderr,
        execution.verdict,
      );
      return { success: false, output: errorDescription, durationMs: execution.durationMs };
    },

    buildFailurePrompt: (iterResult: HarnessIterationResult, executionOutput: string, _iteration: number) => {
      const pocResult = iterResult.pocResult;

      // Record in PoC-specific refinement history.
      pocRefinementHistory.push({
        attempt: pocRefinementHistory.length + 1,
        error: executionOutput,
        approach: describeHarnessApproach(pocResult),
      });

      // Determine if this was a parse failure (no execution) or an execution failure.
      const execution = iterResult.execution;
      return buildPocFailurePrompt(
        execution
          ? { exitCode: execution.exitCode, stdout: execution.stdout, stderr: execution.stderr, verdict: execution.verdict }
          : undefined,
        executionOutput,
      );
    },

    buildReflectionPrompt: (_failureCount: number, totalIterations: number) => {
      return buildReflectionPrompt(totalIterations);
    },
  });

  // Build the final PocHarnessResult from the loop output.
  const finalIterResult = loopResult.result;
  const finalPocResult = finalIterResult.pocResult;
  finalPocResult.iterations = loopResult.iterations;
  finalPocResult.refinementHistory = [...pocRefinementHistory];
  finalPocResult.costUsd = loopResult.totalCostUsd;

  // Populate execution metadata on the final result if the executor ran.
  if (finalIterResult.execution) {
    finalPocResult.pocExecExitCode = finalIterResult.execution.exitCode;
    finalPocResult.pocExecStdout = finalIterResult.execution.stdout;
    finalPocResult.pocExecStderr = finalIterResult.execution.stderr;
    finalPocResult.pocExecVerdict = finalIterResult.execution.verdict;
    finalPocResult.pocExecDurationMs = finalIterResult.execution.durationMs;
  }

  return { result: finalPocResult, costUsd: loopResult.totalCostUsd };
}

function summarizeHarnessAttempt(result: PocHarnessResult): string {
  return JSON.stringify({
    fingerprint: result.fingerprint,
    language: result.language,
    skipped: result.skipped,
    skip_reason: result.skipReason,
    parse_error: result.parseError,
    script_content: result.scriptContent,
  });
}

function describeHarnessApproach(result: PocHarnessResult): string {
  return `Generated ${result.language ?? "unknown"} harness`;
}

function buildPocFailurePrompt(
  execution: {
    exitCode: number;
    stdout: string;
    stderr: string;
    verdict: "PASS" | "FAIL" | "ERROR" | "TIMEOUT";
  } | undefined,
  error: string,
): string {
  return [
    "The PoC harness you generated was executed but did not successfully demonstrate the vulnerability.",
    "Here are the execution results:",
    "",
    `Exit code: ${execution?.exitCode ?? "n/a"}`,
    `Verdict: ${execution?.verdict ?? "ERROR"}`,
    `Stdout: ${execution?.stdout ?? ""}`,
    `Stderr: ${execution?.stderr ?? error}`,
    "",
    "Please analyze what went wrong and generate a refined PoC harness that addresses these issues.",
    "Common problems include: wrong import paths, incorrect API usage, missing setup steps, wrong payload encoding.",
  ].join("\n");
}

function buildReflectionPrompt(iteration: number): string {
  return [
    `You've attempted ${iteration} times without success.`,
    "Before trying again:",
    "1. What assumptions have you been making about the target code?",
    "2. Which of those assumptions might be wrong?",
    "3. What alternative approach could you try?",
  ].join("\n");
}

function describeExecutionFailure(
  exitCode: number,
  stdout: string,
  stderr: string,
  verdict: "PASS" | "FAIL" | "ERROR" | "TIMEOUT",
): string {
  return [
    `verdict=${verdict}`,
    `exit=${exitCode}`,
    stdout.trim() ? `stdout=${stdout.trim()}` : undefined,
    stderr.trim() ? `stderr=${stderr.trim()}` : undefined,
  ].filter(Boolean).join(" | ");
}
