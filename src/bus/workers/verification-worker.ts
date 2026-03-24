import type { AgentHistoryEntry } from "../../agent-runtime/types.js";
import type { AgentActivity } from "../../agent-runtime/execution.js";
import type { AgentRuntime } from "../../agent-runtime/types.js";
import { generatePocHarness } from "../../poc-harness.js";
import { createPocExecutor } from "../../poc-executor/index.js";
import { verifyFindingWithAgent, verifyFindingsBatch, VerificationExecutionError } from "../../verify.js";
import { withRetry } from "../../retry.js";
import { coerceContextEnrichment, coerceRepoContext } from "../../repo-context.js";
import type { KuzushiConfig, VerificationResult } from "../../types.js";
import { normalizeCostUsd, toErrorMessage } from "../../utils.js";
import type { VerificationBatchQueuedEvent, VerificationFindingQueuedEvent } from "../events.js";
import { createEvent } from "../helpers.js";
import type { MessageBus } from "../types.js";
import { resolveTemplates } from "../../prompts/loader.js";
import type Database from "better-sqlite3";
import type { KnowledgeRegistry } from "../../knowledge/types.js";
import { knowledgeInjectionModule } from "../../prompts/modules.js";
import { getBypassKnowledge, formatBypassForPrompt } from "../../bypass-knowledge.js";
import { formatPrecedentsForPrompt, type Precedents } from "../../precedents.js";
import {
  extractScannerSignal,
  extractTriageSignal,
  extractVerificationSignal,
  computeCompositeConfidence,
} from "../../scoring/composite-confidence.js";

export interface VerificationWorkerDeps {
  config: KuzushiConfig;
  runtime: AgentRuntime;
  /** Optional knowledge registry for domain-specific verification prompt enrichment. */
  knowledgeRegistry?: KnowledgeRegistry;
  /** Optional database handle for composite confidence features. */
  db?: Database.Database;
}

/**
 * Verification worker: validates exploitability with concrete source-to-sink analysis.
 */
export function registerVerificationWorker(
  bus: MessageBus,
  deps: VerificationWorkerDeps,
): void {
  const resolvedTemplates = resolveTemplates(deps.config);

  bus.subscribe<VerificationFindingQueuedEvent>("verification:finding-queued", async (event) => {
    const { context, finding, triageResult, repoContext, enrichedContext, index, total } = event.payload;
    const runId = event.meta.runId;
    let attempts = 0;

    try {
      // Build extra prompt context for verification enrichment
      const extraSections: string[] = [];

      // Knowledge registry — inject CWE-specific domain knowledge
      if (deps.knowledgeRegistry) {
        const modules = deps.knowledgeRegistry.query({ cwes: finding.cwe });
        if (modules.length > 0) {
          const sections = deps.knowledgeRegistry.formatForPrompt(modules);
          const knowledgeSection = knowledgeInjectionModule(sections);
          if (knowledgeSection) {
            extraSections.push(knowledgeSection);
          }
        }
      }

      // Precedents — inject org-specific architectural facts
      {
        const precedents = event.payload.precedents as Precedents | undefined;
        if (precedents) {
          const precedentLines = formatPrecedentsForPrompt(precedents);
          if (precedentLines.length > 0) {
            extraSections.push(precedentLines.join("\n"));
          }
        }
      }

      const extraPromptContext = extraSections.length > 0
        ? extraSections.join("\n\n")
        : undefined;

      const { result, costUsd } = await verifyWithRefinement(
        deps.config,
        deps.runtime,
        bus,
        runId,
        context,
        finding,
        triageResult,
        repoContext,
        enrichedContext,
        resolvedTemplates.verify,
        index,
        total,
        () => {
          attempts += 1;
        },
        extraPromptContext,
      );
      result.verifyCostUsd = costUsd;

      // Compute composite confidence from scanner + triage + verification signals
      {
        const scannerSignal = extractScannerSignal(finding);
        const triageSignal = extractTriageSignal(triageResult.confidence);
        const verificationSignal = extractVerificationSignal(result.exploitable);
        const composite = computeCompositeConfidence([scannerSignal, triageSignal, verificationSignal]);
        result.compositeConfidence = composite.composite;
      }

      await bus.publish(
        createEvent("verification:result", runId, {
          context,
          finding,
          triageResult,
          result,
          costUsd,
          attempts,
          index,
          total,
        }),
      );
    } catch (error) {
      const costUsd = error instanceof VerificationExecutionError ? error.costUsd : undefined;
      await bus.publish(
        createEvent("verification:error", runId, {
          context,
          finding,
          triageResult,
          error: toErrorMessage(error),
          costUsd,
          attempts,
          index,
          total,
        }),
      );
    }
  });

  bus.subscribe<VerificationBatchQueuedEvent>("verification:batch-queued", async (event) => {
    const { context, items, repoContext, enrichedContext } = event.payload;
    const runId = event.meta.runId;

    const batchItems = items.map((item) => ({
      finding: item.finding,
      triageResult: item.triageResult,
    }));

    try {
      const { results, costUsd } = await withRetry(
        () =>
          verifyFindingsBatch(
            batchItems,
            context.scanPath ?? context.repoRoot,
            context.repoName,
            deps.config.verifyModel ?? deps.config.triageModel ?? deps.config.model,
            coerceRepoContext(repoContext),
            {
              runtime: deps.runtime,
              enrichedContext: coerceContextEnrichment(enrichedContext),
            },
            deps.config.verifyBatchSize ?? 5,
            deps.config.verifyMaxTurns,
            resolvedTemplates.verify,
          ),
        {
          maxRetries: deps.config.maxVerifyRetries ?? 2,
          backoffMs: deps.config.retryBackoffMs ?? 5000,
          multiplier: deps.config.retryBackoffMultiplier ?? 2,
        },
      );

      const perFindingCost = items.length > 0 ? costUsd / items.length : 0;

      for (const item of items) {
        const result = results.get(item.finding.fingerprint);
        if (result) {
          result.verifyCostUsd = perFindingCost;
          await bus.publish(
            createEvent("verification:result", runId, {
              context,
              finding: item.finding,
              triageResult: item.triageResult,
              result,
              costUsd: perFindingCost,
              attempts: 1,
              index: item.index,
              total: item.total,
            }),
          );
        }
      }
    } catch (error) {
      const costUsd = error instanceof VerificationExecutionError ? error.costUsd : undefined;
      const perFindingCost = costUsd != null && items.length > 0
        ? costUsd / items.length
        : undefined;

      for (const item of items) {
        await bus.publish(
          createEvent("verification:error", runId, {
            context,
            finding: item.finding,
            triageResult: item.triageResult,
            error: toErrorMessage(error),
            costUsd: perFindingCost,
            attempts: 1,
            index: item.index,
            total: item.total,
          }),
        );
      }
    }
  });
}

async function verifyWithRefinement(
  config: KuzushiConfig,
  runtime: AgentRuntime,
  bus: MessageBus,
  runId: string,
  context: VerificationFindingQueuedEvent["payload"]["context"],
  finding: VerificationFindingQueuedEvent["payload"]["finding"],
  triageResult: VerificationFindingQueuedEvent["payload"]["triageResult"],
  repoContext: VerificationFindingQueuedEvent["payload"]["repoContext"],
  enrichedContext: VerificationFindingQueuedEvent["payload"]["enrichedContext"],
  verifyTemplate: string | undefined,
  index: number,
  total: number,
  onAttempt: () => void,
  extraPromptContext?: string,
): Promise<{ result: VerificationResult; costUsd: number }> {
  const repoRoot = context.scanPath ?? context.repoRoot;
  const verifyModel = config.verifyModel ?? config.triageModel ?? config.model;
  const pocModel = config.pocHarnessModel ?? verifyModel;
  const maxIterations = Math.max(1, config.verifyRefinementMaxIterations ?? 3);
  const reflectionInterval = Math.max(1, config.verifyReflectionInterval ?? 2);
  const retryOptions = {
    maxRetries: config.maxVerifyRetries ?? 2,
    backoffMs: config.retryBackoffMs ?? 5000,
    multiplier: config.retryBackoffMultiplier ?? 2,
  };
  const activityCallback = async (activity: AgentActivity) => {
    await bus.publish(
      createEvent("verification:agent-activity", runId, {
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

  const verificationHistory: AgentHistoryEntry[] = [];
  const probeHistory: AgentHistoryEntry[] = [];
  const repoContextValue = coerceRepoContext(repoContext);
  const enrichedContextValue = coerceContextEnrichment(enrichedContext);
  const executor = maxIterations > 1
    ? await createPocExecutor(config.pocSandbox ?? "docker", config.pocExecTimeoutMs)
    : undefined;
  let totalCostUsd = 0;
  let latestResult: VerificationResult | undefined;

  for (let iteration = 1; iteration <= maxIterations; iteration += 1) {
    const verified = await withRetry(
      async () => {
        onAttempt();
        return verifyFindingWithAgent(
          finding,
          triageResult,
          repoRoot,
          context.repoName,
          verifyModel,
          config.verifyMaxTurns,
          repoContextValue,
          {
            runtime,
            enrichedContext: enrichedContextValue,
            history: verificationHistory,
            activityCallback,
            extraPromptContext,
          },
          verifyTemplate,
        );
      },
      retryOptions,
    );

    totalCostUsd += normalizeCostUsd(verified.costUsd);
    latestResult = verified.result;
    const currentResult = latestResult;
    if (isConclusiveVerification(currentResult) || !executor || iteration >= maxIterations) {
      return { result: currentResult, costUsd: totalCostUsd };
    }

    verificationHistory.push({
      role: "assistant",
      content: summarizeVerificationResult(currentResult),
    });

    const probe = await withRetry(
      async () => generatePocHarness(
        finding,
        triageResult,
        currentResult,
        repoRoot,
        context.repoName,
        pocModel,
        config.pocHarnessMaxTurns ?? config.verifyMaxTurns,
        repoContextValue,
        {
          runtime,
          history: probeHistory,
        },
      ),
      retryOptions,
    );

    totalCostUsd += normalizeCostUsd(probe.costUsd);
    probeHistory.push({
      role: "assistant",
      content: JSON.stringify({
        fingerprint: probe.result.fingerprint,
        language: probe.result.language,
        skipped: probe.result.skipped,
        skip_reason: probe.result.skipReason,
        parse_error: probe.result.parseError,
        script_content: probe.result.scriptContent,
      }),
    });

    const feedback = await buildVerificationFeedback(
      executor,
      context.repoRoot,
      probe.result,
    );

    verificationHistory.push({ role: "user", content: feedback });
    probeHistory.push({ role: "user", content: feedback });

    if (iteration % reflectionInterval === 0) {
      const reflection = buildVerificationReflectionPrompt(iteration);
      verificationHistory.push({ role: "user", content: reflection });
      probeHistory.push({ role: "user", content: reflection });
    }
  }

  if (!latestResult) {
    throw new VerificationExecutionError("verification did not produce a result", totalCostUsd);
  }

  return { result: latestResult, costUsd: totalCostUsd };
}

async function buildVerificationFeedback(
  executor: Awaited<ReturnType<typeof createPocExecutor>>,
  repoRoot: string,
  probeResult: Awaited<ReturnType<typeof generatePocHarness>>["result"],
): Promise<string> {
  if (probeResult.skipped) {
    return [
      "The verification probe generator could not produce a runnable probe.",
      `Reason: ${probeResult.skipReason ?? "unknown"}`,
      "Revise your exploitability assessment based on that failed assumption.",
    ].join("\n");
  }

  if (!probeResult.scriptPath || !probeResult.language || probeResult.parsed === false) {
    return [
      "The verification probe was not runnable.",
      `Parse error: ${probeResult.parseError ?? "unknown"}`,
      "Reassess which assumptions about repository imports, APIs, or setup are wrong.",
    ].join("\n");
  }

  const execution = await executor.execute(probeResult.scriptPath, probeResult.language, repoRoot);
  return [
    "The verification probe was executed but the exploitability assessment is still inconclusive.",
    "Here are the execution results:",
    "",
    `Exit code: ${execution.exitCode}`,
    `Verdict: ${execution.verdict}`,
    `Stdout: ${execution.stdout}`,
    `Stderr: ${execution.stderr}`,
    "",
    "Revise the assessment using this concrete execution feedback.",
  ].join("\n");
}

function isConclusiveVerification(result: VerificationResult): boolean {
  return result.proofVerdict !== undefined && result.confidence >= 0.85;
}

function summarizeVerificationResult(result: VerificationResult): string {
  return JSON.stringify({
    fingerprint: result.fingerprint,
    exploitable: result.exploitable,
    poc_payload: result.pocPayload,
    poc_description: result.pocDescription,
    attack_vector: result.attackVector,
    preconditions: result.preconditions,
    confidence: result.confidence,
    proof_verdict: result.proofVerdict,
  });
}

function buildVerificationReflectionPrompt(iteration: number): string {
  return [
    `You've attempted ${iteration} times without success.`,
    "Before trying again:",
    "1. What assumptions have you been making about the target code?",
    "2. Which of those assumptions might be wrong?",
    "3. What alternative approach could you try?",
  ].join("\n");
}
