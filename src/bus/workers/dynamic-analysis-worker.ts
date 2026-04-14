import type Database from "better-sqlite3";
import crypto from "node:crypto";
import type { AgentHistoryEntry } from "../../agent-runtime/types.js";
import type { AgentActivity } from "../../agent-runtime/execution.js";
import type { AgentRuntime } from "../../agent-runtime/types.js";
import { resolveStageModel } from "../../agents/tasks/runtime-overrides.js";
import { generatePocHarness, PocHarnessExecutionError } from "../../poc-harness.js";
import { createPocExecutor } from "../../poc-executor/index.js";
import { withRetry } from "../../retry.js";
import { coerceRepoContext } from "../../repo-context.js";
import type {
  DynamicAnalysisRun,
  DynamicAnalysisStatus,
  DynamicCoverageMode,
  KuzushiConfig,
  PocHarnessResult,
  TriageResult,
  VerificationResult,
} from "../../types.js";
import type { Finding } from "../../scanners/types.js";
import { normalizeCostUsd, toErrorMessage } from "../../utils.js";
import {
  insertDynamicAnalysisRun,
  updateFindingMetadata,
  updateFindingProofState,
} from "../../store.js";
import type { DynamicAnalysisFindingQueuedEvent } from "../events.js";
import { createEvent } from "../helpers.js";
import type { MessageBus } from "../types.js";

export interface DynamicAnalysisWorkerDeps {
  config: KuzushiConfig;
  runtime: AgentRuntime;
  db: Database.Database;
}

/**
 * Dynamic analysis worker: executes harnesses to confirm or reject findings
 * through local execution with optional coverage guidance.
 */
export function registerDynamicAnalysisWorker(
  bus: MessageBus,
  deps: DynamicAnalysisWorkerDeps,
): void {
  bus.subscribe<DynamicAnalysisFindingQueuedEvent>("dynamic:finding-queued", async (event) => {
    const {
      context,
      finding,
      triageResult,
      verificationResult,
      pocHarnessResult,
      repoContext,
      index,
      total,
    } = event.payload;
    const runId = event.meta.runId;
    let attempts = 0;

    try {
      const result = await runDynamicAnalysis(
        deps.config,
        deps.runtime,
        deps.db,
        bus,
        runId,
        context,
        finding,
        triageResult,
        verificationResult,
        pocHarnessResult,
        repoContext,
        index,
        total,
        () => { attempts += 1; },
      );

      await bus.publish(
        createEvent("dynamic:result", runId, {
          context,
          finding,
          result,
          costUsd: result.costUsd,
          attempts,
          index,
          total,
        }),
      );
    } catch (error) {
      const costUsd = error instanceof PocHarnessExecutionError ? error.costUsd : undefined;
      await bus.publish(
        createEvent("dynamic:error", runId, {
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
}

function detectCoverageMode(
  language: string | undefined,
  coverageEnabled: boolean,
): DynamicCoverageMode {
  if (!coverageEnabled || !language) return "none";
  const lang = language.toLowerCase();
  if (lang === "javascript" || lang === "typescript" || lang === "node") return "node-v8";
  if (lang === "python") return "python-coverage";
  return "none";
}

function synthesizeSeedInputs(
  finding: Finding,
  triageResult: TriageResult,
  verificationResult?: VerificationResult,
  pocHarnessResult?: PocHarnessResult,
): string[] {
  const seeds: string[] = [];

  // Extract from taint path snippets
  if (finding.taintPath) {
    for (const step of finding.taintPath) {
      if (step.snippet) {
        seeds.push(step.snippet);
      }
    }
  }

  // Extract from verification payloads
  if (verificationResult?.pocPayload) {
    seeds.push(verificationResult.pocPayload);
  }

  // Extract from PoC execution output
  if (pocHarnessResult?.pocExecStdout) {
    seeds.push(pocHarnessResult.pocExecStdout);
  }
  if (pocHarnessResult?.pocExecStderr) {
    seeds.push(pocHarnessResult.pocExecStderr);
  }

  // Extract from triage evidence
  if (triageResult.exploitScenario) {
    seeds.push(triageResult.exploitScenario);
  }

  return seeds.filter(Boolean).slice(0, 20);
}

function classifyDynamicResult(
  verdict: "PASS" | "FAIL" | "ERROR" | "TIMEOUT" | undefined,
  exitCode: number | undefined,
  stdout: string,
): DynamicAnalysisStatus {
  if (verdict === "PASS") return "confirmed";
  if (verdict === "TIMEOUT") return "interesting";

  // Check stdout for explicit vulnerability signals regardless of verdict
  const output = stdout.toLowerCase();
  if (output.includes("vulnerable") || output.includes("exploited") || output.includes("injection successful")) {
    return "confirmed";
  }

  // FAIL verdict = harness ran but did not demonstrate exploitation → rejected
  if (verdict === "FAIL") return "rejected";

  // ERROR verdict with partial signal
  if (output.includes("partial") || output.includes("interesting")) {
    return "interesting";
  }

  return "rejected";
}

async function runDynamicAnalysis(
  config: KuzushiConfig,
  runtime: AgentRuntime,
  db: Database.Database,
  bus: MessageBus,
  runId: string,
  context: DynamicAnalysisFindingQueuedEvent["payload"]["context"],
  finding: Finding,
  triageResult: TriageResult,
  verificationResult: VerificationResult | undefined,
  pocHarnessResult: PocHarnessResult | undefined,
  repoContext: unknown,
  index: number,
  total: number,
  onAttempt: () => void,
): Promise<DynamicAnalysisRun> {
  const repoRoot = context.scanPath ?? context.repoRoot;
  const model = resolveStageModel(config, "dynamic-analysis", "poc-harness", "verify");
  const maxIterations = Math.max(1, config.dynamicMaxIterations ?? 3);
  const budgetUsd = config.dynamicPerFindingBudgetUsd ?? 2;
  const coverageMode = detectCoverageMode(
    finding.subcategory?.[0] ?? pocHarnessResult?.language ?? undefined,
    config.coverageGuidedEnabled === true,
  );
  const retryOptions = {
    maxRetries: config.maxPocHarnessRetries ?? config.maxVerifyRetries ?? 2,
    backoffMs: config.retryBackoffMs ?? 5000,
    multiplier: config.retryBackoffMultiplier ?? 2,
  };

  const dynamicRunId = crypto.randomUUID();
  const seedInputs = synthesizeSeedInputs(finding, triageResult, verificationResult, pocHarnessResult);

  const activityCallback = async (activity: AgentActivity) => {
    await bus.publish(
      createEvent("dynamic:agent-activity", runId, {
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

  const executor = await createPocExecutor(
    config.pocSandbox ?? "docker",
    config.pocExecTimeoutMs,
  );

  const history: AgentHistoryEntry[] = [];
  let totalCostUsd = 0;
  let latestStatus: DynamicAnalysisStatus = "error";
  let latestResult: PocHarnessResult | undefined;
  let executionExitCode: number | null = null;
  let executionStdout = "";
  let executionStderr = "";
  let executionVerdict: DynamicAnalysisRun["executionVerdict"];
  let executionDurationMs: number | null = null;

  // Add seed context to the conversation
  if (seedInputs.length > 0) {
    history.push({
      role: "user",
      content: [
        "Seed inputs extracted from prior analysis (taint paths, verification payloads, PoC output):",
        "",
        ...seedInputs.map((s, i) => `[Seed ${i + 1}] ${s.slice(0, 500)}`),
        "",
        "Use these to inform your harness generation. Focus on confirming the vulnerability through execution.",
      ].join("\n"),
    });
  }

  let actualIterations = 0;
  for (let iteration = 1; iteration <= maxIterations; iteration += 1) {
    actualIterations = iteration;
    // Budget check
    if (totalCostUsd >= budgetUsd) {
      process.stderr.write(
        `[dynamic-analysis] Budget exceeded for ${finding.fingerprint}: $${totalCostUsd.toFixed(4)} >= $${budgetUsd}\n`,
      );
      break;
    }

    const generated = await withRetry(
      async () => {
        onAttempt();
        return generatePocHarness(
          finding,
          triageResult,
          verificationResult ?? {
            fingerprint: finding.fingerprint,
            exploitable: true,
            pocPayload: null,
            pocDescription: "",
            attackVector: null,
            preconditions: [],
            confidence: 0.5,
          },
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
    latestResult = generated.result;

    if (latestResult.skipped || !latestResult.scriptPath || !latestResult.language || latestResult.parsed === false) {
      const error = latestResult.parseError ?? latestResult.skipReason ?? "Harness not runnable";
      history.push({ role: "assistant", content: JSON.stringify({ error, skipped: latestResult.skipped }) });
      history.push({ role: "user", content: buildDynamicRefinementPrompt(undefined, error, coverageMode) });
      continue;
    }

    // Execute the harness
    // NOTE: coverageEnv is not passed to executor.execute() in v1 — the executor
    // interface does not support custom env vars yet. Coverage mode is tracked for
    // future use and included in the refinement prompt for LLM guidance.
    const execution = await executor.execute(
      latestResult.scriptPath,
      latestResult.language,
      repoRoot,
    );

    executionExitCode = execution.exitCode;
    executionStdout = execution.stdout;
    executionStderr = execution.stderr;
    executionVerdict = execution.verdict;
    executionDurationMs = execution.durationMs;

    latestStatus = classifyDynamicResult(
      execution.verdict,
      execution.exitCode,
      execution.stdout,
    );

    // If confirmed or we're at the last iteration, stop
    if (latestStatus === "confirmed" || iteration >= maxIterations) {
      break;
    }

    // Build refinement prompt with execution feedback
    const error = [
      `verdict=${execution.verdict}`,
      `exit=${execution.exitCode}`,
      execution.stdout.trim() ? `stdout=${execution.stdout.trim().slice(0, 1000)}` : undefined,
      execution.stderr.trim() ? `stderr=${execution.stderr.trim().slice(0, 1000)}` : undefined,
    ].filter(Boolean).join(" | ");

    history.push({ role: "assistant", content: JSON.stringify({ scriptPath: latestResult.scriptPath, language: latestResult.language }) });
    history.push({ role: "user", content: buildDynamicRefinementPrompt(execution, error, coverageMode) });
  }

  // Compute proof value: higher for confirmed, lower for rejected
  const proofValue = latestStatus === "confirmed" ? 10
    : latestStatus === "interesting" ? 5
    : latestStatus === "rejected" ? -5
    : 0;

  const run: DynamicAnalysisRun = {
    dynamicRunId,
    pipelineRunId: runId,
    fingerprint: finding.fingerprint,
    repo: context.repoName,
    status: latestStatus,
    score: finding.adjustedScore ?? finding.score,
    proofValue,
    language: latestResult?.language ?? undefined,
    harnessPath: latestResult?.scriptPath ?? null,
    harnessLanguage: latestResult?.language ?? null,
    seedInputs,
    coverageMode,
    executionExitCode,
    executionStdout,
    executionStderr,
    executionVerdict,
    executionDurationMs,
    iterations: actualIterations,
    costUsd: totalCostUsd,
    metadata: {},
  };

  // Persist to DB
  insertDynamicAnalysisRun(db, run);

  // Update finding metadata
  updateFindingMetadata(db, finding.fingerprint, {
    latestDynamicRunId: dynamicRunId,
    latestDynamicStatus: latestStatus,
    dynamicRunIds: [dynamicRunId],
  });

  if (latestStatus === "confirmed") {
    updateFindingProofState(db, finding.fingerprint, "execution_confirmed");
  } else if (latestStatus === "rejected") {
    updateFindingProofState(db, finding.fingerprint, "execution_rejected");
  } else {
    updateFindingProofState(db, finding.fingerprint, "execution_attempted");
  }

  return run;
}

function buildDynamicRefinementPrompt(
  execution: {
    exitCode: number;
    stdout: string;
    stderr: string;
    verdict: "PASS" | "FAIL" | "ERROR" | "TIMEOUT";
  } | undefined,
  error: string,
  coverageMode: DynamicCoverageMode,
): string {
  const lines = [
    "The dynamic analysis harness did not confirm the vulnerability.",
    "",
    `Exit code: ${execution?.exitCode ?? "n/a"}`,
    `Verdict: ${execution?.verdict ?? "ERROR"}`,
    `Stdout: ${(execution?.stdout ?? "").slice(0, 1000)}`,
    `Stderr: ${(execution?.stderr ?? error).slice(0, 1000)}`,
  ];

  if (coverageMode !== "none") {
    lines.push(
      "",
      `Coverage mode: ${coverageMode}`,
      "Consider: Are the vulnerable code paths being reached? Adjust inputs to increase coverage of the target sink.",
    );
  }

  lines.push(
    "",
    "Generate a refined harness that addresses these execution issues.",
    "Focus on: correct import paths, proper setup, realistic payloads that trigger the vulnerability.",
  );

  return lines.join("\n");
}
