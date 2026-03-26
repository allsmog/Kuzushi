import type Database from "better-sqlite3";
import { randomUUID } from "node:crypto";
import type { AgentRuntime } from "../../agent-runtime/types.js";
import type { TaskRegistry } from "../../agents/registry.js";
import type { ScannerRegistry } from "../../scanners/registry.js";
import type { Finding, TriageAgentConfig } from "../../scanners/types.js";
import { withRetry } from "../../retry.js";
import { coerceContextEnrichment, coerceRepoContext } from "../../repo-context.js";
import { triageFindingWithAgent, triageFindingsBatch, triageSystemPromptPrefix, BATCH_TRIAGE_FALLBACK_RATIONALE, parseVerdict } from "../../triage.js";
import type { TriageOutput, TriageRuntimeOptions, TriageConfigProvider } from "../../triage.js";
import type { KuzushiConfig, Verdict, RepoContext } from "../../types.js";
import { isRecord, normalizeCostUsd, toErrorMessage } from "../../utils.js";
import type { TriageBatchQueuedEvent, TriageFindingQueuedEvent } from "../events.js";
import { runTriageAssertions, computeTriageQualityScore } from "../../scoring/triage-assertions.js";
import { createEvent } from "../helpers.js";
import type { MessageBus } from "../types.js";
import { triageFindingMultiAgent } from "../../multi-agent-triage.js";
import {
  computeCalibratedConfidence,
  extractRuleFamily,
  formatCalibrationWeightsForPrompt,
  loadCalibrationWeights,
  updateFindingCalibration,
} from "../../confidence-calibration.js";
import { getBypassKnowledge, formatBypassForPrompt } from "../../bypass-knowledge.js";
import { formatPrecedentsForPrompt, type Precedents } from "../../precedents.js";
import type { KnowledgeRegistry } from "../../knowledge/types.js";
import { evidenceChainModule, knowledgeInjectionModule } from "../../prompts/modules.js";
import {
  extractScannerSignal,
  extractTriageSignal,
  computeCompositeConfidence,
  type CompositeConfidenceResult,
} from "../../scoring/composite-confidence.js";
import {
  TrajectoryCollector,
  formatTrajectoriesForPrompt,
  retrieveTrajectories,
  saveTrajectory,
  summarizeTrajectory,
} from "../../trajectory-memory.js";
import type { PipelineHookChain } from "../../hooks/chain.js";
import type { HookContext } from "../../hooks/types.js";
import { resolveTemplates } from "../../prompts/loader.js";

export interface TriageWorkerDeps {
  registry: ScannerRegistry;
  taskRegistry?: TaskRegistry;
  config: KuzushiConfig;
  runtime: AgentRuntime;
  /** Optional database handle for trajectory memory and calibration features. */
  db?: Database.Database;
  /** Optional knowledge registry for domain-specific triage prompt enrichment. */
  knowledgeRegistry?: KnowledgeRegistry;
  /**
   * Optional function that resolves the pipeline hook chain for a given run.
   * Returns undefined if no hooks are configured for this run.
   */
  getRunHooks?: (runId: string) => { hookChain: PipelineHookChain; hookContext: HookContext } | undefined;
}

/**
 * Triage worker: invokes an agentic triage pass per finding.
 */
export function registerTriageWorker(bus: MessageBus, deps: TriageWorkerDeps): void {
  const triageConfigProvider = createTriageConfigProvider(deps.registry, deps.taskRegistry);
  const resolvedTemplates = resolveTemplates(deps.config);
  const useMultiAgent = deps.config.triageStrategy === "multi-agent";
  const useTrajectoryMemory = deps.config.trajectoryMemory === true && deps.db != null;
  const useCalibration = deps.config.confidenceCalibration === true && deps.db != null;
  const ensembleTriageModels = normalizeEnsembleTriageModels(deps.config);
  const useEnsembleTriage = ensembleTriageModels.length > 1;

  // Cache per-run prompt fragments: these are pure functions of (repoContext, enrichedContext)
  // which are fixed for the entire run. Caching maximizes Anthropic API prompt cache hits.
  let cachedSystemPromptPrefix: string | undefined;
  let cachedSystemPromptKey: string | undefined;
  const cachedEvidenceChain = useCalibration ? evidenceChainModule() : undefined;

  bus.subscribe<TriageFindingQueuedEvent>("triage:finding-queued", async (event) => {
    const { context, repoContext, enrichedContext, index, total } = event.payload;
    let finding = event.payload.finding;
    const runId = event.meta.runId;
    let attempts = 0;

    // Invoke beforeTriage hook — allows hooks to modify or skip the finding
    const runHooks = deps.getRunHooks?.(runId);
    if (runHooks) {
      try {
        const hookResult = await runHooks.hookChain.beforeTriage(runHooks.hookContext, finding);
        if (hookResult === null) {
          // Hook requested to skip this finding
          console.error(`[hooks] beforeTriage hook skipped finding ${finding.fingerprint}`);
          await bus.publish(
            createEvent("triage:result", runId, {
              context,
              finding,
              result: {
                fingerprint: finding.fingerprint,
                verdict: "fp" as const,
                confidence: 1,
                rationale: "Skipped by pipeline hook (beforeTriage returned null)",
                verificationSteps: [],
                fixPatch: null,
              },
              costUsd: 0,
              attempts: 0,
              index,
              total,
            }),
          );
          return;
        }
        finding = hookResult;
      } catch (error) {
        console.error(`[hooks] beforeTriage hook error: ${toErrorMessage(error)}`);
      }
    }

    try {
      const { result, costUsd } = await withRetry(
        async () => {
          attempts += 1;

          // Build extra prompt context from enabled features
          const extraSections: string[] = [];

          // Trajectory memory: retrieve exemplars and format for injection
          if (useTrajectoryMemory && deps.db) {
            const maxExemplars = deps.config.trajectoryMaxExemplars ?? 2;
            const exemplars = retrieveTrajectories(
              deps.db,
              finding.ruleId,
              finding.cwe,
              maxExemplars,
            );
            const trajectoryPrompt = formatTrajectoriesForPrompt(exemplars);
            if (trajectoryPrompt) {
              extraSections.push(trajectoryPrompt);
            }
          }

          // Confidence calibration: inject evidence chain instructions (cached)
          if (useCalibration && cachedEvidenceChain) {
            extraSections.push(cachedEvidenceChain);
          }

          // 1A: Knowledge registry — inject CWE-specific domain knowledge
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

          // 1B: Bypass knowledge — inject CWE-specific bypass techniques
          {
            const bypassEntry = getBypassKnowledge(finding.cwe, finding.ruleId);
            if (bypassEntry) {
              const bypassLines = formatBypassForPrompt(bypassEntry);
              extraSections.push(
                bypassLines.join("\n") +
                "\n\nBefore concluding FP, verify that these bypass techniques don't apply.",
              );
            }
          }

          // 1C: Precedents — inject org-specific architectural facts and signal criteria
          {
            const precedents = event.payload.precedents as Precedents | undefined;
            if (precedents) {
              const precedentLines = formatPrecedentsForPrompt(precedents);
              if (precedentLines.length > 0) {
                extraSections.push(precedentLines.join("\n"));
              }
            }
          }

          // 1F: Calibration weights — inject learned investigation priorities
          if (useCalibration && deps.db) {
            try {
              const ruleFamily = extractRuleFamily(finding.ruleId);
              const weights = loadCalibrationWeights(deps.db, ruleFamily);
              const formatted = formatCalibrationWeightsForPrompt(weights);
              if (formatted) {
                extraSections.push(formatted);
              }
            } catch {
              // Non-fatal: calibration weight formatting failure shouldn't break triage
            }
          }

          const extraPromptContext = extraSections.length > 0
            ? extraSections.join("\n\n")
            : undefined;

          // Set up trajectory collector wrapping the activity callback
          const collector = useTrajectoryMemory ? new TrajectoryCollector() : null;
          const baseActivityCallback = async (activity: Parameters<typeof bus.publish>[0] extends never ? never : {
            kind: string;
            toolName?: string;
            toolInput?: Record<string, unknown>;
            summary?: string;
            elapsedSeconds?: number;
          }) => {
            await bus.publish(
              createEvent("triage:agent-activity", runId, {
                context,
                fingerprint: finding.fingerprint,
                kind: activity.kind as "tool-start" | "tool-progress" | "tool-complete" | "reasoning",
                toolName: activity.toolName,
                toolInput: activity.toolInput,
                summary: activity.summary,
                elapsedSeconds: activity.elapsedSeconds,
                index,
                total,
              }),
            );
          };

          const activityCallback = collector
            ? collector.wrapCallback(baseActivityCallback)
            : baseActivityCallback;

          let triageOutput;

          // Cache system prompt prefix on first event (same for all findings in a run).
          // repoContext is invariant per run, so keying on runId alone is stable.
          const coercedRepoContext = coerceRepoContext(repoContext);
          const coercedEnrichedContext = coerceContextEnrichment(enrichedContext);
          if (cachedSystemPromptPrefix === undefined || cachedSystemPromptKey !== runId) {
            cachedSystemPromptPrefix = triageSystemPromptPrefix(coercedRepoContext, coercedEnrichedContext);
            cachedSystemPromptKey = runId;
          }

          if (useMultiAgent) {
            triageOutput = await triageFindingMultiAgent(
              triageConfigProvider,
              finding,
              context.scanPath ?? context.repoRoot,
              context.repoName,
              deps.config.triageModel ?? deps.config.model,
              deps.config.triageSpecialistModel ?? deps.config.triageModel ?? deps.config.model,
              deps.config.triageMaxTurns,
              deps.config.triageSpecialistMaxTurns ?? null,
              coercedRepoContext,
              {
                runtime: deps.runtime,
                activityCallback,
                enrichedContext: coercedEnrichedContext,
              },
              extraPromptContext,
            );
          } else {
            triageOutput = await triageFindingWithAgent(
              triageConfigProvider,
              finding,
              context.scanPath ?? context.repoRoot,
              context.repoName,
              deps.config.triageModel ?? deps.config.model,
              deps.config.triageMaxTurns,
              coercedRepoContext,
              {
                runtime: deps.runtime,
                activityCallback,
                enrichedContext: coercedEnrichedContext,
              },
              extraPromptContext,
              resolvedTemplates.triage,
              cachedSystemPromptPrefix,
            );
          }

          // Ensemble triage: run additional models in parallel and merge via majority vote
          if (useEnsembleTriage && !useMultiAgent) {
            triageOutput = await runEnsembleTriage(
              triageConfigProvider,
              finding,
              context.scanPath ?? context.repoRoot,
              context.repoName,
              ensembleTriageModels,
              deps.config.triageMaxTurns,
              coercedRepoContext,
              {
                runtime: deps.runtime,
                enrichedContext: coercedEnrichedContext,
              },
              extraPromptContext,
              resolvedTemplates.triage,
              cachedSystemPromptPrefix,
              triageOutput,
            );
          }

          // Save trajectory after triage completes
          if (collector && deps.db && collector.length > 0) {
            const steps = collector.getSteps();
            try {
              saveTrajectory(deps.db, {
                id: randomUUID(),
                ruleId: finding.ruleId,
                cwes: finding.cwe,
                scanner: finding.scanner,
                verdict: triageOutput.result.verdict,
                confidence: triageOutput.result.confidence,
                steps,
                summary: summarizeTrajectory(steps, triageOutput.result.verdict),
                repo: context.repoName,
                fingerprint: finding.fingerprint,
              });
            } catch {
              // Non-fatal: trajectory save failure shouldn't break triage
            }
          }

          // Compute calibrated confidence
          if (useCalibration && deps.db && triageOutput.result.evidenceChain?.length) {
            try {
              const ruleFamily = extractRuleFamily(finding.ruleId);
              const weights = loadCalibrationWeights(deps.db, ruleFamily);
              const calibrated = computeCalibratedConfidence(
                triageOutput.result.evidenceChain,
                weights,
              );
              triageOutput.result.calibratedConfidence = calibrated;

              updateFindingCalibration(
                deps.db,
                finding.fingerprint,
                calibrated,
                triageOutput.result.evidenceChain,
              );
            } catch {
              // Non-fatal: calibration failure shouldn't break triage
            }
          }

          // Compute composite confidence from scanner + triage signals
          {
            const scannerSignal = extractScannerSignal(finding);
            const triageSignal = extractTriageSignal(triageOutput.result.confidence);
            const composite = computeCompositeConfidence([scannerSignal, triageSignal]);
            triageOutput.result.compositeConfidence = composite.composite;
          }

          return triageOutput;
        },
        {
          maxRetries: deps.config.maxTriageRetries ?? 2,
          backoffMs: deps.config.retryBackoffMs ?? 5000,
          multiplier: deps.config.retryBackoffMultiplier ?? 2,
        },
      );
      result.triageCostUsd = costUsd;

      // Invoke afterTriage hook — allows hooks to override verdict/confidence
      const afterRunHooks = deps.getRunHooks?.(runId);
      if (afterRunHooks) {
        try {
          const hookResult = await afterRunHooks.hookChain.afterTriage(
            afterRunHooks.hookContext,
            finding,
            { verdict: result.verdict, confidence: result.confidence, rationale: result.rationale },
          );
          result.verdict = hookResult.verdict as typeof result.verdict;
          result.confidence = hookResult.confidence;
          result.rationale = hookResult.rationale;
        } catch (error) {
          console.error(`[hooks] afterTriage hook error: ${toErrorMessage(error)}`);
        }
      }

      await bus.publish(
        createEvent("triage:result", runId, {
          context,
          finding,
          result,
          costUsd,
          attempts,
          index,
          total,
        }),
      );

      // Run triage quality assertions
      if (deps.config.triageAssertions?.enabled !== false) {
        try {
          const assertions = runTriageAssertions(
            {
              verdict: result.verdict,
              confidence: result.confidence,
              rationale: result.rationale,
              verificationSteps: result.verificationSteps,
            },
            deps.config.triageAssertions,
          );
          const qualityScore = computeTriageQualityScore(assertions);
          await bus.publish(
            createEvent("triage:assertions", runId, {
              context,
              fingerprint: finding.fingerprint,
              assertions: assertions.map(a => ({
                name: a.name,
                passed: a.passed,
                score: a.score,
                weight: a.weight,
                reason: a.reason,
              })),
              qualityScore,
            }),
          );
        } catch {
          // Non-fatal: assertion failures shouldn't break triage
        }
      }
    } catch (error) {
      const costUsd = getErrorCostUsd(error);
      await bus.publish(
        createEvent("triage:error", runId, {
          context,
          finding,
          error: toErrorMessage(error),
          costUsd,
          attempts,
          index,
          total,
        }),
      );
    }
  });

  bus.subscribe<TriageBatchQueuedEvent>("triage:batch-queued", async (event) => {
    const { context, findings, repoContext, enrichedContext, total } = event.payload;
    const runId = event.meta.runId;

    try {
      const { results, costUsd } = await triageFindingsBatch(
        findings,
        context.scanPath ?? context.repoRoot,
        context.repoName,
        deps.config.triageBatchModel ?? deps.config.triageModel ?? deps.config.model,
        coerceRepoContext(repoContext),
        {
          runtime: deps.runtime,
          enrichedContext: coerceContextEnrichment(enrichedContext),
          activityCallback: async (activity) => {
            await bus.publish(
              createEvent("triage:agent-activity", runId, {
                context,
                fingerprint: "batch",
                kind: activity.kind,
                toolName: activity.toolName,
                toolInput: activity.toolInput,
                summary: activity.summary,
                elapsedSeconds: activity.elapsedSeconds,
                index: 0,
                total,
              }),
            );
          },
        },
        deps.config.triageBatchSize,
        deps.config.triageMaxTurns,
        resolvedTemplates.triage,
      );

      const perFindingCost = findings.length > 0 ? costUsd / findings.length : 0;

      for (const [idx, finding] of findings.entries()) {
        const result = results.get(finding.fingerprint);
        const isFallback = result?.confidence === 0
          && result?.rationale === BATCH_TRIAGE_FALLBACK_RATIONALE;

        if (result && !isFallback) {
          result.triageCostUsd = perFindingCost;
          await bus.publish(
            createEvent("triage:result", runId, {
              context,
              finding,
              result,
              costUsd: perFindingCost,
              attempts: 1,
              index: idx + 1,
              total,
            }),
          );
        } else {
          await bus.publish(
            createEvent("triage:error", runId, {
              context,
              finding,
              error: isFallback
                ? "Finding omitted from batch triage response"
                : "Finding missing from batch triage response",
              costUsd: perFindingCost,
              attempts: 1,
              index: idx + 1,
              total,
            }),
          );
        }
      }
    } catch (error) {
      const errorCostUsd = getErrorCostUsd(error);
      const perFindingCost = findings.length > 0 && errorCostUsd != null
        ? errorCostUsd / findings.length
        : undefined;

      for (const [idx, finding] of findings.entries()) {
        await bus.publish(
          createEvent("triage:error", runId, {
            context,
            finding,
            error: toErrorMessage(error),
            costUsd: perFindingCost,
            attempts: 1,
            index: idx + 1,
            total,
          }),
        );
      }
    }
  });
}

function createTriageConfigProvider(
  registry: ScannerRegistry,
  taskRegistry?: TaskRegistry,
): {
  has(id: string): boolean;
  get(id: string): { triageAgentConfig(finding: Finding, repoName: string): TriageAgentConfig };
} {
  return {
    has(id: string): boolean {
      if (registry.has(id)) {
        return true;
      }

      if (!taskRegistry || !taskRegistry.has(id)) {
        return false;
      }

      return typeof taskRegistry.get(id).triageAgentConfig === "function";
    },
    get(id: string): { triageAgentConfig(finding: Finding, repoName: string): TriageAgentConfig } {
      if (registry.has(id)) {
        return registry.get(id);
      }

      if (!taskRegistry || !taskRegistry.has(id)) {
        throw new Error(`Unknown triage provider: ${id}`);
      }

      const task = taskRegistry.get(id);
      const triageAgentConfig = task.triageAgentConfig;
      if (typeof triageAgentConfig !== "function") {
        throw new Error(`Task "${id}" does not define triageAgentConfig`);
      }

      return {
        triageAgentConfig: (finding: Finding, repoName: string) => triageAgentConfig(finding, repoName),
      };
    },
  };
}

/**
 * Determine ensemble models for triage. Returns an empty array if ensemble
 * triage is disabled, or the list of unique model identifiers when enabled.
 */
function normalizeEnsembleTriageModels(config: KuzushiConfig): string[] {
  if (config.ensembleTriageEnabled !== true) {
    return [];
  }

  const models = config.ensembleModels;
  if (!Array.isArray(models)) {
    return [];
  }

  const unique = new Set<string>();
  for (const model of models) {
    if (typeof model !== "string") {
      continue;
    }
    const trimmed = model.trim();
    if (trimmed) {
      unique.add(trimmed);
    }
  }

  // Need at least 2 models for meaningful ensemble
  const result = [...unique];
  return result.length >= 2 ? result : [];
}

/**
 * Run ensemble triage: call triage with each ensemble model in parallel,
 * then aggregate results via majority voting.
 *
 * The primary model's result (passed in as `primaryOutput`) is always included.
 * Additional models are called in parallel.
 */
async function runEnsembleTriage(
  triageConfigProvider: TriageConfigProvider,
  finding: Finding,
  repoRoot: string,
  repoName: string,
  ensembleModels: string[],
  maxTurns: number | null,
  repoContext: RepoContext | undefined,
  runtimeOptions: TriageRuntimeOptions,
  extraPromptContext: string | undefined,
  triageTemplate: string | undefined,
  systemPromptPrefix: string | undefined,
  primaryOutput: TriageOutput,
): Promise<TriageOutput> {
  // The primary model already ran — determine which model was used
  const primaryModel = ensembleModels[0] ?? "primary";
  const additionalModels = ensembleModels.slice(1);

  // Run remaining models in parallel
  const additionalResults = await Promise.all(
    additionalModels.map(async (model) => {
      try {
        const result = await triageFindingWithAgent(
          triageConfigProvider,
          finding,
          repoRoot,
          repoName,
          model,
          maxTurns,
          repoContext,
          runtimeOptions,
          extraPromptContext,
          triageTemplate,
          systemPromptPrefix,
        );
        return { kind: "success" as const, model, result };
      } catch {
        return { kind: "error" as const, model };
      }
    }),
  );

  // Collect all votes: primary + successful additional results
  const votes: Array<{ model: string; verdict: Verdict; confidence: number; output: TriageOutput }> = [
    { model: primaryModel, verdict: primaryOutput.result.verdict, confidence: primaryOutput.result.confidence, output: primaryOutput },
  ];
  let totalAdditionalCost = 0;

  for (const lane of additionalResults) {
    if (lane.kind === "success") {
      votes.push({
        model: lane.model,
        verdict: lane.result.result.verdict,
        confidence: lane.result.result.confidence,
        output: lane.result,
      });
      totalAdditionalCost += normalizeCostUsd(lane.result.costUsd);
    }
  }

  // If only the primary succeeded, return it as-is (no ensemble benefit)
  if (votes.length <= 1) {
    return primaryOutput;
  }

  // Majority vote on verdict
  const verdictCounts = new Map<Verdict, number>();
  for (const vote of votes) {
    verdictCounts.set(vote.verdict, (verdictCounts.get(vote.verdict) ?? 0) + 1);
  }

  let winningVerdict: Verdict = primaryOutput.result.verdict;
  let maxCount = 0;
  for (const [verdict, count] of verdictCounts) {
    if (count > maxCount) {
      maxCount = count;
      winningVerdict = verdict;
    }
  }

  // Average confidence across all votes
  const avgConfidence = votes.reduce((sum, v) => sum + v.confidence, 0) / votes.length;

  // Build consensus votes array
  const consensusVotes = votes.map((v) => ({
    model: v.model,
    verdict: v.verdict,
    confidence: v.confidence,
  }));

  // Use the highest-confidence result matching the winning verdict as the base
  const bestMatch = votes
    .filter((v) => v.verdict === winningVerdict)
    .sort((a, b) => b.confidence - a.confidence)[0];

  const baseOutput = bestMatch?.output ?? primaryOutput;

  return {
    result: {
      ...baseOutput.result,
      verdict: winningVerdict,
      confidence: Math.round(avgConfidence * 1000) / 1000,
      consensusVotes,
    },
    costUsd: primaryOutput.costUsd + totalAdditionalCost,
  };
}

function getErrorCostUsd(error: unknown): number | undefined {
  if (!isRecord(error)) {
    return undefined;
  }

  const raw = error["costUsd"];
  if (typeof raw !== "number" || !Number.isFinite(raw) || raw < 0) {
    return undefined;
  }

  return normalizeCostUsd(raw);
}
