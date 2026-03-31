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

  const history: AgentHistoryEntry[] = [];
  const refinementHistory: NonNullable<PocHarnessResult["refinementHistory"]> = [];
  const executor = config.pocExecute === true
    ? await createPocExecutor(config.pocSandbox ?? "docker", config.pocExecTimeoutMs)
    : undefined;
  let totalCostUsd = 0;
  let latestResult: PocHarnessResult | undefined;

  for (let iteration = 1; iteration <= maxIterations; iteration += 1) {
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

    totalCostUsd += normalizeCostUsd(generated.costUsd);
    latestResult = {
      ...generated.result,
      iterations: iteration,
      refinementHistory: [...refinementHistory],
    };

    if (latestResult.skipped || !executor) {
      latestResult.costUsd = totalCostUsd;
      return { result: latestResult, costUsd: totalCostUsd };
    }

    if (!latestResult.scriptPath || !latestResult.language || latestResult.parsed === false) {
      const error = latestResult.parseError ?? "Generated PoC harness was not runnable.";
      refinementHistory.push({
        attempt: iteration,
        error,
        approach: describeHarnessApproach(latestResult),
      });

      if (iteration >= maxIterations) {
        latestResult.refinementHistory = [...refinementHistory];
        latestResult.costUsd = totalCostUsd;
        return { result: latestResult, costUsd: totalCostUsd };
      }

      history.push({ role: "assistant", content: summarizeHarnessAttempt(latestResult) });
      history.push({ role: "user", content: buildPocFailurePrompt(undefined, error) });
      if (iteration % reflectionInterval === 0) {
        history.push({ role: "user", content: buildReflectionPrompt(iteration) });
      }
      continue;
    }

    const execution = await executor.execute(
      latestResult.scriptPath,
      latestResult.language,
      context.repoRoot,
    );

    latestResult.pocExecExitCode = execution.exitCode;
    latestResult.pocExecStdout = execution.stdout;
    latestResult.pocExecStderr = execution.stderr;
    latestResult.pocExecVerdict = execution.verdict;
    latestResult.pocExecDurationMs = execution.durationMs;
    latestResult.refinementHistory = [...refinementHistory];

    if (execution.verdict === "PASS") {
      latestResult.costUsd = totalCostUsd;
      return { result: latestResult, costUsd: totalCostUsd };
    }

    const error = describeExecutionFailure(execution.exitCode, execution.stdout, execution.stderr, execution.verdict);
    refinementHistory.push({
      attempt: iteration,
      error,
      approach: describeHarnessApproach(latestResult),
    });

    if (iteration >= maxIterations) {
      latestResult.refinementHistory = [...refinementHistory];
      latestResult.costUsd = totalCostUsd;
      return { result: latestResult, costUsd: totalCostUsd };
    }

    history.push({ role: "assistant", content: summarizeHarnessAttempt(latestResult) });
    history.push({ role: "user", content: buildPocFailurePrompt(execution, error) });
    if (iteration % reflectionInterval === 0) {
      history.push({ role: "user", content: buildReflectionPrompt(iteration) });
    }
  }

  if (!latestResult) {
    throw new PocHarnessExecutionError("poc harness generation did not produce a result", totalCostUsd);
  }

  latestResult.costUsd = totalCostUsd;
  latestResult.refinementHistory = [...refinementHistory];
  return { result: latestResult, costUsd: totalCostUsd };
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
