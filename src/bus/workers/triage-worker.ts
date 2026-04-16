import { randomUUID } from "node:crypto";
import type Database from "better-sqlite3";
import type { AgentRuntime } from "../../agent-runtime/types.js";
import type { TaskRegistry } from "../../agents/registry.js";
import { resolveStageModel } from "../../agents/tasks/runtime-overrides.js";
import { formatBypassForPrompt, getBypassKnowledge } from "../../bypass-knowledge.js";
import {
  computeCalibratedConfidence,
  extractRuleFamily,
  formatCalibrationWeightsForPrompt,
  loadCalibrationWeights,
  updateFindingCalibration,
} from "../../confidence-calibration.js";
import type { PipelineHookChain } from "../../hooks/chain.js";
import type { HookContext } from "../../hooks/types.js";
import type { KnowledgeRegistry } from "../../knowledge/types.js";
import { triageFindingMultiAgent } from "../../multi-agent-triage.js";
import { formatPrecedentsForPrompt, type Precedents } from "../../precedents.js";
import { resolveTemplates } from "../../prompts/loader.js";
import { evidenceChainModule, knowledgeInjectionModule } from "../../prompts/modules.js";
import { coerceContextEnrichment, coerceRepoContext } from "../../repo-context.js";
import { withRetry } from "../../retry.js";
import type { Finding, TriageAgentConfig } from "../../scanners/types.js";
import {
  computeCompositeConfidence,
  extractScannerSignal,
  extractTriageSignal,
} from "../../scoring/composite-confidence.js";
import { computeTriageQualityScore, runTriageAssertions } from "../../scoring/triage-assertions.js";
import {
  formatTrajectoriesForPrompt,
  retrieveTrajectories,
  saveTrajectory,
  summarizeTrajectory,
  TrajectoryCollector,
} from "../../trajectory-memory.js";
import {
  type FileContentCache,
  preReadForTriage,
  triageFindingsBatch,
  triageFindingWithAgent,
  triageSystemPromptPrefix,
} from "../../triage.js";
import type { KuzushiConfig } from "../../types.js";
import { isRecord, normalizeCostUsd, toErrorMessage } from "../../utils.js";
import type { TriageBatchQueuedEvent, TriageFindingQueuedEvent } from "../events.js";
import { createEvent } from "../helpers.js";
import type { MessageBus } from "../types.js";

export interface TriageWorkerDeps {
  taskRegistry: TaskRegistry;
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
  getRunHooks?: (
    runId: string,
  ) => { hookChain: PipelineHookChain; hookContext: HookContext } | undefined;
  /** Optional REPL state reader for interactive skip/suppress/pause. */
  getReplState?: () =>
    | {
        skippedFingerprints: Set<string>;
        suppressedRules: Set<string>;
        focusPath: string | null;
        paused: boolean;
      }
    | undefined;
}

/**
 * Triage worker: invokes an agentic triage pass per finding.
 */
export function registerTriageWorker(bus: MessageBus, deps: TriageWorkerDeps): void {
  const triageConfigProvider = createTriageConfigProvider(deps.taskRegistry);
  const resolvedTemplates = resolveTemplates(deps.config);
  const useMultiAgent = deps.config.triageStrategy === "multi-agent";
  const useTrajectoryMemory = deps.config.trajectoryMemory === true && deps.db != null;
  const useCalibration = deps.config.confidenceCalibration === true && deps.db != null;

  // Cache per-run prompt fragments: these are pure functions of (repoContext, enrichedContext)
  // which are fixed for the entire run. Caching maximizes Anthropic API prompt cache hits.
  const escalatedFingerprints = new Set<string>();
  let cachedSystemPromptPrefix: string | undefined;
  let cachedSystemPromptKey: string | undefined;
  const cachedEvidenceChain = deps.config.confidenceCalibration ? evidenceChainModule() : "";

  // Per-run file content cache: avoids re-reading the same source file for
  // co-located findings during preReadForTriage.
  const fileContentCache: FileContentCache = new Map();

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

    // REPL interactive skip/suppress/pause check
    const replState = deps.getReplState?.();
    if (replState) {
      // Wait while paused
      while (replState.paused) {
        await new Promise((r) => setTimeout(r, 500));
        const fresh = deps.getReplState?.();
        if (!fresh?.paused) break;
      }

      // Check if finding was skipped or its rule suppressed
      const shouldSkip =
        replState.skippedFingerprints.has(finding.fingerprint) ||
        replState.suppressedRules.has(finding.ruleId);

      if (shouldSkip) {
        await bus.publish(
          createEvent("triage:result", runId, {
            context,
            finding,
            result: {
              fingerprint: finding.fingerprint,
              verdict: "fp" as const,
              confidence: 1,
              rationale: "Skipped via interactive REPL command",
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
    }

    try {
      let { result, costUsd } = await withRetry(
        async () => {
          attempts += 1;

          // Build extra prompt context from enabled features
          const extraSections: string[] = [];

          // Pre-read: load the flagged source file so the LLM has immediate context
          const preRead = await preReadForTriage(
            finding,
            event.payload.context.scanPath ?? event.payload.context.repoRoot,
            50,
            fileContentCache,
          );
          if (preRead) {
            extraSections.push(preRead);
          }

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

          // Evidence chain: always inject structured per-step reasoning instructions
          if (cachedEvidenceChain) {
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

          // 1C-pre: Threat model context — inject application-level context for verdict decisions
          {
            const tmSummary = event.payload.threatModelSummary;
            if (typeof tmSummary === "string" && tmSummary.length > 0) {
              extraSections.push(
                "## Application Threat Model Context\n" +
                  "The following threat model was derived from automated analysis of this application.\n" +
                  "Use it to:\n" +
                  "1. Distinguish between DESIGN CHOICES (by_design) and actual VULNERABILITIES (tp).\n" +
                  "2. Reference specific threat IDs (e.g. [T-01]) in your attack_path narrative when a finding matches a modeled threat.\n" +
                  "3. Identify which trust boundaries are crossed and which attacker-controlled inputs are involved.\n" +
                  "4. Check existing mitigations listed below — if a mitigation covers this finding, it may be a false positive.\n" +
                  "5. Include relevant threat IDs in your source_threat_ids output field.\n\n" +
                  tmSummary,
              );
            }
          }

          // 1C-pre2: Operator-provided context — inject operator-declared trust, scope, architecture
          {
            const opCtx = event.payload.operatorContext;
            if (typeof opCtx === "string" && opCtx.length > 0) {
              extraSections.push(opCtx);
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

          const extraPromptContext =
            extraSections.length > 0 ? extraSections.join("\n\n") : undefined;

          // Set up trajectory collector wrapping the activity callback
          const collector = useTrajectoryMemory ? new TrajectoryCollector() : null;
          const baseActivityCallback = async (
            activity: Parameters<typeof bus.publish>[0] extends never
              ? never
              : {
                  kind: string;
                  toolName?: string;
                  toolInput?: Record<string, unknown>;
                  summary?: string;
                  elapsedSeconds?: number;
                },
          ) => {
            await bus.publish(
              createEvent("triage:agent-activity", runId, {
                context,
                fingerprint: finding.fingerprint,
                kind: activity.kind as
                  | "tool-start"
                  | "tool-progress"
                  | "tool-complete"
                  | "reasoning",
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
            cachedSystemPromptPrefix = triageSystemPromptPrefix(
              coercedRepoContext,
              coercedEnrichedContext,
            );
            cachedSystemPromptKey = runId;
          }

          const triageModel = resolveStageModel(deps.config, "triage");
          const triageSpecialistModel = resolveStageModel(
            deps.config,
            "triage-specialist",
            "triage",
          );

          if (useMultiAgent) {
            triageOutput = await triageFindingMultiAgent(
              triageConfigProvider,
              finding,
              context.scanPath ?? context.repoRoot,
              context.repoName,
              triageModel,
              triageSpecialistModel,
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
              triageModel,
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

          // Save trajectory after triage completes
          if (collector && deps.db && collector.length > 0) {
            const steps = collector.getSteps();
            try {
              saveTrajectory(deps.db, {
                id: randomUUID(),
                ruleId: finding.ruleId,
                cwes: finding.cwe,
                taskId: finding.taskId,
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

      // Auto-escalate: high-severity needs_review with low confidence → multi-agent triage
      if (
        !useMultiAgent &&
        result.verdict === "needs_review" &&
        result.confidence < 0.4 &&
        finding.severity === "ERROR" &&
        !escalatedFingerprints.has(finding.fingerprint)
      ) {
        escalatedFingerprints.add(finding.fingerprint);
        try {
          const coercedRepoContext = coerceRepoContext(repoContext);
          const coercedEnrichedContext = coerceContextEnrichment(enrichedContext);
          const triageModel = resolveStageModel(deps.config, "triage");
          const triageSpecialistModel = resolveStageModel(
            deps.config,
            "triage-specialist",
            "triage",
          );
          const escalatedOutput = await triageFindingMultiAgent(
            triageConfigProvider,
            finding,
            context.scanPath ?? context.repoRoot,
            context.repoName,
            triageModel,
            triageSpecialistModel,
            coercedRepoContext,
            {
              runtime: deps.runtime,
              enrichedContext: coercedEnrichedContext,
            },
          );
          result = escalatedOutput.result;
          result.triageCostUsd = (result.triageCostUsd ?? 0) + escalatedOutput.costUsd;
          costUsd += escalatedOutput.costUsd;
          console.error(
            `[triage] Auto-escalated ${finding.fingerprint} to multi-agent (was needs_review @ ${result.confidence})`,
          );
        } catch (error) {
          console.error(
            `[triage] Multi-agent escalation failed for ${finding.fingerprint}: ${toErrorMessage(error)}`,
          );
        }
      }

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
              assertions: assertions.map((a) => ({
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
      const batchModel = resolveStageModel(deps.config, "triage-batch", "triage");
      const { results, costUsd, missingFingerprints } = await triageFindingsBatch(
        findings,
        context.scanPath ?? context.repoRoot,
        context.repoName,
        batchModel,
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
        resolvedTemplates.triage,
      );

      const perFindingCost = findings.length > 0 ? costUsd / findings.length : 0;
      const missingFingerprintSet = new Set(missingFingerprints);

      for (const [idx, finding] of findings.entries()) {
        const result = results.get(finding.fingerprint);

        if (result && !missingFingerprintSet.has(finding.fingerprint)) {
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
          // Escalate batch-incomplete findings to individual triage instead of
          // accepting a synthesized result — individual triage has pre-read
          // context and can spend more turns investigating.
          await bus.publish(
            createEvent("triage:finding-queued", runId, {
              context,
              finding,
              repoContext,
              enrichedContext,
              index: idx + 1,
              total,
            }),
          );
        }
      }
    } catch (error) {
      const errorCostUsd = getErrorCostUsd(error);
      const perFindingCost =
        findings.length > 0 && errorCostUsd != null ? errorCostUsd / findings.length : undefined;

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

function createTriageConfigProvider(taskRegistry: TaskRegistry): {
  has(id: string): boolean;
  get(id: string): { triageAgentConfig(finding: Finding, repoName: string): TriageAgentConfig };
} {
  return {
    has(id: string): boolean {
      if (!taskRegistry.has(id)) {
        return false;
      }

      return typeof taskRegistry.get(id).triageAgentConfig === "function";
    },
    get(id: string): { triageAgentConfig(finding: Finding, repoName: string): TriageAgentConfig } {
      if (!taskRegistry.has(id)) {
        throw new Error(`Unknown triage provider: ${id}`);
      }

      const task = taskRegistry.get(id);
      const triageAgentConfig = task.triageAgentConfig;
      if (typeof triageAgentConfig !== "function") {
        throw new Error(`Task "${id}" does not define triageAgentConfig`);
      }

      return {
        triageAgentConfig: (finding: Finding, repoName: string) =>
          triageAgentConfig(finding, repoName),
      };
    },
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
