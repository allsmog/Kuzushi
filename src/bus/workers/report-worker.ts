import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import type Database from "better-sqlite3";
import {
  printResumeInfo,
  printScanStart,
  printSummary,
  printTriageProgress,
} from "../../report.js";
import { writeCsvReport } from "../../report-csv.js";
import { writeJsonReport } from "../../report-json.js";
import { writeJsonlReport } from "../../report-jsonl.js";
import { generateJunitReport } from "../../report-junit.js";
import { generateMarkdownReport } from "../../report-markdown.js";
import { generateSarifReport } from "../../report-sarif.js";
import { getRateLimitRegistry } from "../../scheduler/index.js";
import type { KuzushiConfig } from "../../types.js";
import { buildScanNotification, sendCompletionNotification } from "../../ui/notify.js";
import { emitOutputNotice } from "../../ui/output.js";
import type { UIStore } from "../../ui/state.js";
import { buildSummaryData } from "../../ui/summary-data.js";
import type {
  BudgetExceededEvent,
  BudgetWarningEvent,
  PipelineErrorEvent,
  PipelineStartEvent,
  PocHarnessErrorEvent,
  PocHarnessResultEvent,
  PocHarnessStartEvent,
  PromptReportEvent,
  ReportRequestedEvent,
  ScanAgentActivityEvent,
  ScanCompleteEvent,
  TaskAgentActivityEvent,
  TaskCompleteEvent,
  TaskErrorEvent,
  TaskProgressEvent,
  TaskStartEvent,
  TriageErrorEvent,
  TriageResultEvent,
  TriageStartEvent,
  VerificationErrorEvent,
  VerificationResultEvent,
  VerificationStartEvent,
} from "../events.js";
import { createEvent } from "../helpers.js";
import type { MessageBus } from "../types.js";

/** Task IDs classified as support/setup work (not primary detectors). */
const SUPPORT_TASK_IDS = new Set([
  "context-gatherer",
  "context-enricher",
  "code-graph-build",
  "code-graph-enrich",
  "app-model-build",
  "reachability-check",
  "call-graph-assist",
]);

interface RunReportState {
  tasks?: string[];
  totalFindings?: number;
  selectedForTriage?: number;
  skippedAlreadyTriaged?: number;
  startPrinted: boolean;
  resumePrinted: boolean;
}

export interface ReportWorkerDeps {
  db: Database.Database;
  config: KuzushiConfig;
}

/**
 * Report worker: handles terminal output and final summary.
 *
 * When a UIStore is provided, all output is written as state updates
 * (consumed by the Ink app or plain-text renderer).
 * When no store is provided (tests, backward compat), falls back
 * to the original console.log behavior.
 */
export function registerReportWorker(
  bus: MessageBus,
  deps: ReportWorkerDeps,
  store?: UIStore,
): void {
  const runState = new Map<string, RunReportState>();
  let triageStartedAt: number | undefined;

  bus.subscribe<PipelineStartEvent>("pipeline:start", (event) => {
    const state = getOrCreateRunState(runState, event.meta.runId);
    const scanOnly = event.payload.context.postProcessMode === "scan-only";
    state.tasks =
      event.payload.scanOpts.tasks !== undefined
        ? [...event.payload.scanOpts.tasks]
        : [...event.payload.config.tasks];

    if (store) {
      // Build pipeline stages from config
      const stageList: Array<{ id: string; label: string }> = [{ id: "scan", label: "Scan" }];
      if (!scanOnly) {
        stageList.push({ id: "triage", label: "Triage" });
        if (event.payload.config.verify) {
          stageList.push({ id: "verify", label: "Verify" });
        }
        if (event.payload.config.pocHarness) {
          stageList.push({ id: "poc", label: "PoC Harness" });
        }
      }
      stageList.push({ id: "report", label: "Report" });

      store.initStages(stageList);
      store.activateStage("scan", state.tasks?.join(", "));
      store.update({
        mode: "running",
        tasks: state.tasks,
        pipelineStartedAt: Date.now(),
        configBanner: {
          model: event.payload.config.model,
          tasks: state.tasks ?? [],
          severity: event.payload.scanOpts.severity,
          concurrency: event.payload.config.triageConcurrency,
          backend: event.payload.config.agentRuntimeBackend,
          scanMode: event.payload.config.scanMode,
        },
      });
      store.clearNotices();

      // Bridge rate limit events to UIStore
      try {
        const registry = getRateLimitRegistry();
        registry.on(
          "concurrency:changed",
          (data: { model: string; from: number; to: number; reason: string }) => {
            store.update({
              throttle: data.to < data.from ? { concurrency: data.to, reason: data.reason } : null,
            });
          },
        );
      } catch {
        // Rate limit registry may not be configured — ignore
      }
    }
  });

  bus.subscribe<TaskStartEvent>("task:start", (event) => {
    if (event.payload.outputKind !== "findings" && event.payload.outputKind !== "threat-model") {
      return;
    }

    const state = getOrCreateRunState(runState, event.meta.runId);
    const tasks = new Set(state.tasks ?? []);
    tasks.add(event.payload.taskId);
    state.tasks = [...tasks];

    if (store) {
      store.update({ tasks: state.tasks, phase: "scanning", mode: "running" });
      // Add scanner as a sub-task branch under the Scan stage
      const role = SUPPORT_TASK_IDS.has(event.payload.taskId)
        ? ("support" as const)
        : ("primary" as const);
      store.upsertSubTask("scan", {
        id: event.payload.taskId,
        label: event.payload.taskId,
        status: "active",
        startedAt: Date.now(),
        detail: scanTaskStartDetail(event.payload.taskId),
        role,
      });
    }
  });

  bus.subscribe<TaskCompleteEvent>("task:complete", (event) => {
    if (store) {
      const existing = store
        .getState()
        .stages.find((stage) => stage.id === "scan")
        ?.subTasks.find((task) => task.id === event.payload.taskId);
      const findingCount = existing?.findingCount ?? 0;
      const lastFinding = existing?.lastFinding;
      const detail =
        findingCount > 0
          ? `${findingCount} finding${findingCount === 1 ? "" : "s"}${lastFinding ? ` · ${truncate(lastFinding, 60)}` : ""}`
          : "complete";
      store.clearScanActivity(event.payload.taskId);
      store.upsertSubTask("scan", {
        id: event.payload.taskId,
        label: event.payload.taskId,
        status: "done",
        elapsedMs: event.payload.durationMs,
        findingCount,
        lastFinding,
        detail,
      });
      updateScanStageDetail(store);
    }
  });

  bus.subscribe<TaskProgressEvent>("task:progress", (event) => {
    if (!store || event.payload.outputKind !== "findings") {
      return;
    }

    const detail = describeTaskProgress(event.payload.progress);
    store.recordSubTaskFinding("scan", event.payload.taskId, detail);
    // Inject the provisional finding as a story beat in the activity lines.
    store.addScanActivity(event.payload.taskId, {
      kind: "finding-preview",
      detail: `Found: ${detail}`,
    });
    updateScanStageDetail(store);
  });

  bus.subscribe<TaskErrorEvent>("task:error", (event) => {
    if (store) {
      const existing = store
        .getState()
        .stages.find((stage) => stage.id === "scan")
        ?.subTasks.find((task) => task.id === event.payload.taskId);
      const prevRetries = existing?.retryCount ?? 0;
      store.clearScanActivity(event.payload.taskId);
      store.upsertSubTask("scan", {
        id: event.payload.taskId,
        label: event.payload.taskId,
        status: "error",
        detail: event.payload.error?.slice(0, 60),
        lastError: event.payload.error?.slice(0, 120),
        retryCount: prevRetries,
      });
      store.addNotice({
        level: "error",
        message: `Task failed: ${event.payload.taskId}`,
        detail: truncate(event.payload.error, 120),
        source: "scan",
      });
      updateScanStageDetail(store);
    }
  });

  bus.subscribe<ScanCompleteEvent>("scan:complete", (event) => {
    const state = getOrCreateRunState(runState, event.meta.runId);
    state.totalFindings = event.payload.totalFindings;

    if (store) {
      store.update({ totalFindings: state.totalFindings });
      // Signal that scan tasks are done but post-processing (dedup, filter, rank) is happening.
      const count = event.payload.totalFindings;
      store.updateStageDetail(
        "scan",
        `${count} finding${count === 1 ? "" : "s"} · deduplicating and ranking`,
      );
      maybeUpdateStartBanner(store, state, event.payload.context.repoName);
    } else {
      maybePrintStartBanner(state, event.payload.context.repoName);
    }
  });

  bus.subscribe<TriageStartEvent>("triage:start", (event) => {
    const state = getOrCreateRunState(runState, event.meta.runId);
    state.selectedForTriage = event.payload.findingCount;
    state.skippedAlreadyTriaged = event.payload.skippedAlreadyTriaged;

    if (store) {
      const total = state.totalFindings ?? 0;
      const selected = event.payload.findingCount;
      const filtered = total - selected - (event.payload.skippedAlreadyTriaged ?? 0);
      const triageDetail =
        filtered > 0
          ? `${selected} of ${total} findings selected · ${filtered} filtered`
          : `${selected} findings via ${event.payload.model}`;
      store.activateStage("triage", triageDetail);
      triageStartedAt = Date.now();

      const skipped = event.payload.skippedAlreadyTriaged ?? 0;
      if (skipped > 0) {
        store.update({
          resumeDiff: {
            previousFindingCount: state.totalFindings ?? 0,
            previousTriagedCount: skipped,
            newFindings: event.payload.findingCount,
            skipped,
            pendingRetriage: 0,
            verdictChanges: [],
          },
        });
      }

      store.update({
        phase: "triaging",
        selectedForTriage: event.payload.findingCount,
        skippedAlreadyTriaged: skipped,
        model: event.payload.model,
        progress: { current: 0, total: event.payload.findingCount },
        mode: "running",
      });
      maybeUpdateStartBanner(store, state, event.payload.context.repoName);
    } else {
      maybePrintStartBanner(state, event.payload.context.repoName);
      if (event.payload.findingCount > 0) {
        console.log(
          `  Triaging ${event.payload.findingCount} findings via ${event.payload.model}...\n`,
        );
      }
    }
  });

  bus.subscribe<TriageResultEvent>("triage:result", (event) => {
    const { result, index, total, attempts } = event.payload;

    if (store) {
      store.addResult({
        kind: "triage",
        verdict: result.verdict,
        confidence: result.confidence,
        costUsd: result.triageCostUsd,
        fingerprint: result.fingerprint,
        index,
        total,
        attempts,
      });
      store.clearAgentActivity(result.fingerprint);

      // Compute ETA from running average (only after 3+ findings for stability)
      if (triageStartedAt && index >= 3 && index < total) {
        const elapsed = Date.now() - triageStartedAt;
        const avgPerFinding = elapsed / index;
        const remaining = (total - index) * avgPerFinding;
        store.update({ etaMs: Math.round(remaining) });
      } else if (index >= total) {
        store.update({ etaMs: undefined });
      }
    } else {
      printTriageProgress(result, index, total, attempts);
    }
  });

  bus.subscribe<TriageErrorEvent>("triage:error", (event) => {
    const { finding, error, index, total, attempts } = event.payload;

    if (store) {
      store.addResult({
        kind: "error",
        errorStage: "triage",
        errorMessage: truncate(error, 160),
        fingerprint: finding.fingerprint,
        index,
        total,
        attempts,
      });
      store.clearAgentActivity(finding.fingerprint);
    } else {
      const retrySuffix = attempts && attempts > 1 ? ` (retry #${attempts})` : "";
      console.log(
        `  [${index}/${total}] TRIAGE ERROR${retrySuffix} ${finding.fingerprint.slice(0, 12)}...`,
      );
      console.log(`    ${truncate(error, 160)}`);
    }
  });

  bus.subscribe<VerificationStartEvent>("verification:start", (event) => {
    if (store) {
      store.activateStage(
        "verify",
        `${event.payload.findingCount} findings via ${event.payload.model}`,
      );
      store.update({
        phase: "verifying",
        model: event.payload.model,
        progress: { current: 0, total: event.payload.findingCount },
        results: [], // clear triage results from live view
        mode: "running",
      });
    } else {
      if (event.payload.findingCount > 0) {
        console.log(
          `  Verifying ${event.payload.findingCount} findings via ${event.payload.model}...\n`,
        );
      }
    }
  });

  bus.subscribe<VerificationResultEvent>("verification:result", (event) => {
    const { result, index, total, attempts } = event.payload;

    if (store) {
      store.addResult({
        kind: "verify",
        exploitable: result.exploitable,
        costUsd: result.verifyCostUsd,
        fingerprint: result.fingerprint,
        index,
        total,
        attempts,
      });
      store.clearAgentActivity(result.fingerprint);
    } else {
      const status = result.exploitable ? "EXPLOITABLE" : "not exploitable";
      const cost =
        result.verifyCostUsd && result.verifyCostUsd > 0
          ? ` $${result.verifyCostUsd.toFixed(4)}`
          : "";
      const retrySuffix = attempts && attempts > 1 ? ` (retry #${attempts})` : "";
      console.log(
        `  [${index}/${total}] ${status}${cost}${retrySuffix} ${result.fingerprint.slice(0, 12)}...`,
      );
    }
  });

  bus.subscribe<VerificationErrorEvent>("verification:error", (event) => {
    const { finding, error, index, total, attempts } = event.payload;

    if (store) {
      store.addResult({
        kind: "error",
        errorStage: "verify",
        errorMessage: truncate(error, 160),
        fingerprint: finding.fingerprint,
        index,
        total,
        attempts,
      });
      store.clearAgentActivity(finding.fingerprint);
    } else {
      const retrySuffix = attempts && attempts > 1 ? ` (retry #${attempts})` : "";
      console.log(
        `  [${index}/${total}] VERIFY ERROR${retrySuffix} ${finding.fingerprint.slice(0, 12)}...`,
      );
      console.log(`    ${truncate(error, 160)}`);
    }
  });

  bus.subscribe<PocHarnessStartEvent>("poc-harness:start", (event) => {
    if (store) {
      store.activateStage(
        "poc",
        `${event.payload.findingCount} harnesses via ${event.payload.model}`,
      );
      store.update({
        phase: "poc",
        model: event.payload.model,
        progress: { current: 0, total: event.payload.findingCount },
        results: [],
        mode: "running",
      });
    } else {
      if (event.payload.findingCount > 0) {
        console.log(
          `  Generating ${event.payload.findingCount} PoC harnesses via ${event.payload.model}...\n`,
        );
      }
    }
  });

  bus.subscribe<PocHarnessResultEvent>("poc-harness:result", (event) => {
    const { result, index, total, attempts } = event.payload;

    if (store) {
      store.addResult({
        kind: "poc",
        skipped: result.skipped,
        parsed: result.parsed,
        costUsd: result.costUsd,
        fingerprint: result.fingerprint,
        index,
        total,
        attempts,
      });
      store.clearAgentActivity(result.fingerprint);
    } else {
      const status = result.skipped ? "SKIPPED" : "GENERATED";
      const parsed = result.skipped ? "" : result.parsed ? " parsed" : " parse-error";
      const cost = result.costUsd && result.costUsd > 0 ? ` $${result.costUsd.toFixed(4)}` : "";
      const retrySuffix = attempts && attempts > 1 ? ` (retry #${attempts})` : "";
      console.log(
        `  [${index}/${total}] ${status}${parsed}${cost}${retrySuffix} ${result.fingerprint.slice(0, 12)}...`,
      );
    }
  });

  bus.subscribe<PocHarnessErrorEvent>("poc-harness:error", (event) => {
    const { finding, error, index, total, attempts } = event.payload;

    if (store) {
      store.addResult({
        kind: "error",
        errorStage: "poc",
        errorMessage: truncate(error, 160),
        fingerprint: finding.fingerprint,
        index,
        total,
        attempts,
      });
      store.clearAgentActivity(finding.fingerprint);
    } else {
      const retrySuffix = attempts && attempts > 1 ? ` (retry #${attempts})` : "";
      console.log(
        `  [${index}/${total}] POC ERROR${retrySuffix} ${finding.fingerprint.slice(0, 12)}...`,
      );
      console.log(`    ${truncate(error, 160)}`);
    }
  });

  // Agent activity — all three stages use the same pattern
  const handleAgentActivity = (event: {
    payload: {
      kind: string;
      index: number;
      total: number;
      toolName?: string;
      toolInput?: Record<string, unknown>;
      elapsedSeconds?: number;
      summary?: string;
      fingerprint?: string;
      /**
       * Only set by `threat-hunt:agent-activity` producers. Signals the actor
       * hunt has finished — drop the fingerprint from the UI's active-agents
       * map so its row disappears from `HeartbeatStrip` as each actor
       * completes, rather than all at once when the whole task ends.
       * Other producers never set this, so their behaviour is unchanged.
       */
      done?: boolean;
    };
  }) => {
    const { kind, index, total, fingerprint } = event.payload;

    if (store && fingerprint && event.payload.done) {
      // Preserve the per-actor line history so the shell can render a
      // post-mortem block after the hunt returns (HeartbeatStrip only
      // lives during the `running` phase; without this archive step the
      // breakdown would be unrecoverable once the tool resolves).
      // Currently only threat-hunt producers set `done: true`, so the
      // other handlers fall through to the no-op branch unchanged.
      store.archiveAgentActivity(fingerprint);
      store.clearAgentActivity(fingerprint);
      return;
    }

    if (store && fingerprint) {
      const detail =
        kind === "tool-start"
          ? summarizeToolInput(event.payload.toolName, event.payload.toolInput)
          : kind === "tool-complete"
            ? (event.payload.summary ?? undefined)
            : kind === "tool-progress"
              ? undefined
              : (event.payload.summary ?? undefined);

      const line = {
        kind: kind as "tool-start" | "tool-progress" | "tool-complete" | "summary",
        toolName: event.payload.toolName,
        detail,
        elapsedSeconds: event.payload.elapsedSeconds,
        index,
        total,
      };
      store.addAgentActivity(fingerprint, line);
      // Mirror into moduleRun.evidenceTail so ModuleRunView's "Evidence"
      // tail fills regardless of which fingerprint owns the event.
      store.pushModuleRunActivity(line);
      return;
    }

    // Fallback: console.log
    const prefix = `  [${index}/${total}]`;

    if (kind === "tool-start") {
      const detail = summarizeToolInput(event.payload.toolName, event.payload.toolInput);
      console.log(`${prefix} -> ${detail}`);
      return;
    }

    if (kind === "tool-progress") {
      const seconds = event.payload.elapsedSeconds ?? 0;
      const toolName = event.payload.toolName ?? "tool";
      console.log(`${prefix} ... ${toolName} (${seconds.toFixed(1)}s)`);
      return;
    }

    if (kind === "tool-complete") {
      if (event.payload.summary) {
        console.log(`${prefix} ✓ ${truncate(event.payload.summary, 140)}`);
      }
      return;
    }

    if (event.payload.summary) {
      console.log(`${prefix} · ${truncate(event.payload.summary, 120)}`);
    }
  };

  bus.subscribe<TaskAgentActivityEvent>("triage:agent-activity", handleAgentActivity);
  bus.subscribe<TaskAgentActivityEvent>("verification:agent-activity", handleAgentActivity);
  bus.subscribe<TaskAgentActivityEvent>("poc-harness:agent-activity", handleAgentActivity);
  bus.subscribe<TaskAgentActivityEvent>("threat-hunt:agent-activity", handleAgentActivity);

  // Scan-time agent activity — keyed by taskId (not fingerprint)
  bus.subscribe<ScanAgentActivityEvent>("scan:agent-activity", (event) => {
    const { kind, taskId, toolName, toolInput, elapsedSeconds, summary } = event.payload;

    if (store) {
      const detail =
        kind === "tool-start"
          ? summarizeToolInput(toolName, toolInput)
          : kind === "tool-complete"
            ? (summary ?? undefined)
            : kind === "tool-progress"
              ? undefined
              : (summary ?? undefined);

      store.addScanActivity(taskId, {
        kind: kind as "tool-start" | "tool-progress" | "tool-complete" | "summary" | "reasoning",
        toolName,
        detail,
        elapsedSeconds,
      });
      // Mirror into moduleRun.evidenceTail. ScanAgentActivity carries no
      // (index,total) — synth zeros so the type matches AgentActivityLine.
      store.pushModuleRunActivity({
        kind: kind as "tool-start" | "tool-progress" | "tool-complete" | "summary" | "reasoning",
        toolName,
        detail,
        elapsedSeconds,
        index: 0,
        total: 0,
      });
      return;
    }

    // Plain-text fallback
    if (kind === "tool-start") {
      const detail = summarizeToolInput(toolName, toolInput);
      console.log(`  [${taskId}] -> ${detail}`);
    } else if (kind === "tool-complete" && summary) {
      console.log(`  [${taskId}] ✓ ${truncate(summary, 140)}`);
    } else if (kind === "reasoning" && summary) {
      console.log(`  [${taskId}] · ${truncate(summary, 120)}`);
    }
  });

  bus.subscribe<PipelineErrorEvent>("pipeline:error", (event) => {
    if (store) {
      store.addNotice({
        level: event.payload.fatal ? "error" : "warning",
        message: event.payload.fatal ? "Pipeline failed" : "Pipeline warning",
        detail: truncate(event.payload.error, 140),
        source: "pipeline",
      });
      return;
    }

    console.log(
      `  ${event.payload.fatal ? "PIPELINE ERROR" : "PIPELINE WARNING"} ${truncate(event.payload.error, 140)}`,
    );
  });

  bus.subscribe<BudgetWarningEvent>("budget:warning", (event) => {
    const detail = `${event.payload.percentUsed.toFixed(0)}% used (${event.payload.currentSpend.toFixed(4)} / ${event.payload.maxBudget.toFixed(4)})`;
    if (store) {
      store.addNotice({
        level: "warning",
        message: "Budget nearing limit",
        detail,
        source: "budget",
      });
      return;
    }

    console.log(`  Budget warning: ${detail}`);
  });

  bus.subscribe<BudgetExceededEvent>("budget:exceeded", (event) => {
    const detail = `${event.payload.totalCostUsd.toFixed(4)} spent against ${event.payload.budgetUsd.toFixed(4)}`;
    if (store) {
      store.addNotice({
        level: "error",
        message: "Budget exceeded",
        detail,
        source: "budget",
      });
      return;
    }

    console.log(`  Budget exceeded: ${detail}`);
  });

  bus.subscribe<PromptReportEvent>("prompt:report", (event) => {
    if (event.payload.warnings.length === 0) {
      return;
    }

    const detail = truncate(event.payload.warnings[0]!, 140);
    if (store) {
      store.addNotice({
        level: "warning",
        message: `Prompt pressure in ${event.payload.taskId}`,
        detail,
        source: "prompt",
      });
      return;
    }

    console.log(`  Prompt warning (${event.payload.taskId}): ${detail}`);
  });

  bus.subscribe<ReportRequestedEvent>("report:requested", async (event) => {
    const state = getOrCreateRunState(runState, event.meta.runId);
    const reportMode = event.payload.reportMode ?? event.payload.context.reportMode ?? "full";
    const scanOnly = event.payload.context.postProcessMode === "scan-only";

    if (store) {
      if (reportMode === "full") {
        maybeUpdateStartBanner(store, state, event.payload.context.repoName);

        if (state.totalFindings === 0) {
          store.addNotice({
            level: "success",
            message: "No findings from tasks",
            detail: "Code looks clean.",
            source: "report",
          });
        } else if (scanOnly) {
          store.addNotice({
            level: "info",
            message: "Scan-only run complete",
            detail: "Findings were saved as needs_review without running triage.",
            source: "report",
          });
        } else if ((state.selectedForTriage ?? 0) === 0) {
          store.addNotice({
            level: "info",
            message: "All findings already triaged",
            detail: "Nothing new to review in this run.",
            source: "report",
          });
        }

        const summaryData = buildSummaryData(deps.db, event.payload.context.repoName, {
          stats: event.payload.stats,
          runId: event.meta.runId,
          repoRoot: event.payload.context.repoRoot,
          auditLog: deps.config.auditLog === true,
          fingerprints: event.payload.fingerprints,
          exploitChains: event.payload.exploitChains,
        });

        const qualityGateResult = event.payload.stats?.qualityGateResult ?? null;

        store.activateStage("report");
        store.completeStage("report");
        store.update({
          mode: "summary",
          phase: "summary",
          summary: summaryData,
          qualityGate: qualityGateResult,
        });

        // Send completion notification
        const { title, message } = buildScanNotification({
          tp: summaryData.verdictCounts.tp,
          needsReview: summaryData.verdictCounts.needs_review,
          totalCostUsd: summaryData.triageCostUsd + summaryData.verificationCostUsd,
          repoName: summaryData.repoName,
        });
        sendCompletionNotification(title, message);
      }
    } else {
      maybePrintStartBanner(state, event.payload.context.repoName);

      if (reportMode === "full") {
        if (state.totalFindings === 0) {
          console.log("  No findings from tasks. Code looks clean.");
        } else if (scanOnly) {
          console.log(
            "  Scan-only run complete. Findings were saved as needs_review without triage.",
          );
        } else if ((state.selectedForTriage ?? 0) === 0) {
          console.log("  All findings already triaged. Nothing to do.");
        }

        printSummary(deps.db, event.payload.context.repoName, {
          stats: event.payload.stats,
          runId: event.meta.runId,
          repoRoot: event.payload.context.repoRoot,
          auditLog: deps.config.auditLog === true,
          fingerprints: event.payload.fingerprints,
          exploitChains: event.payload.exploitChains,
        });
      }
    }

    // File report generation (always happens, store or not)
    if (reportMode === "full") {
      writeFileReports(deps, event, store);
    }

    await bus.publish(
      createEvent("report:complete", event.meta.runId, {
        context: event.payload.context,
      }),
    );

    runState.delete(event.meta.runId);
  });
}

function writeFileReports(
  deps: ReportWorkerDeps,
  event: { payload: ReportRequestedEvent["payload"]; meta: { runId: string } },
  store?: UIStore,
): void {
  if (deps.config.reportOutput) {
    const outputDir = path.dirname(deps.config.reportOutput);
    if (!existsSync(outputDir)) {
      mkdirSync(outputDir, { recursive: true });
    }
    const markdown = generateMarkdownReport(
      deps.db,
      event.payload.context.repoName,
      event.payload.stats ?? {},
      event.meta.runId,
      event.payload.fingerprints,
      event.payload.context.repoRoot,
    );
    writeFileSync(deps.config.reportOutput, markdown, "utf-8");
    notifyReportArtifact(store, "Markdown report written", deps.config.reportOutput);
  }

  if (deps.config.sarifOutput) {
    const outputDir = path.dirname(deps.config.sarifOutput);
    if (!existsSync(outputDir)) {
      mkdirSync(outputDir, { recursive: true });
    }
    const sarif = generateSarifReport(
      deps.db,
      event.payload.context.repoName,
      event.payload.stats ?? {},
      event.meta.runId,
      event.payload.fingerprints,
      event.payload.context.repoRoot,
    );
    writeFileSync(deps.config.sarifOutput, sarif, "utf-8");
    notifyReportArtifact(store, "SARIF report written", deps.config.sarifOutput);
  }

  if (deps.config.junitOutput) {
    const outputDir = path.dirname(deps.config.junitOutput);
    if (!existsSync(outputDir)) {
      mkdirSync(outputDir, { recursive: true });
    }
    const junit = generateJunitReport(deps.db, {
      repo: event.payload.context.repoName,
      stats: event.payload.stats ?? {},
      runId: event.meta.runId,
      repoRoot: event.payload.context.repoRoot,
      fingerprints: event.payload.fingerprints,
    });
    writeFileSync(deps.config.junitOutput, junit, "utf-8");
    notifyReportArtifact(store, "JUnit report written", deps.config.junitOutput);
  }

  if (deps.config.jsonOutput) {
    const outputDir = path.dirname(deps.config.jsonOutput);
    if (!existsSync(outputDir)) {
      mkdirSync(outputDir, { recursive: true });
    }
    writeJsonReport(
      deps.config.jsonOutput,
      deps.db,
      event.payload.context.repoName,
      event.payload.stats ?? {},
      event.payload.exploitChains ?? [],
      deps.config.scanMode,
      event.payload.fingerprints,
      event.payload.context.repoRoot,
      event.meta.runId,
    );
    notifyReportArtifact(store, "JSON report written", deps.config.jsonOutput);
  }

  if (deps.config.csvOutput) {
    const outputDir = path.dirname(deps.config.csvOutput);
    if (!existsSync(outputDir)) {
      mkdirSync(outputDir, { recursive: true });
    }
    writeCsvReport(
      deps.config.csvOutput,
      deps.db,
      event.payload.context.repoName,
      event.payload.fingerprints,
    );
    notifyReportArtifact(store, "CSV report written", deps.config.csvOutput);
  }

  if (deps.config.jsonlOutput) {
    const outputDir = path.dirname(deps.config.jsonlOutput);
    if (!existsSync(outputDir)) {
      mkdirSync(outputDir, { recursive: true });
    }
    writeJsonlReport(
      deps.config.jsonlOutput,
      deps.db,
      event.payload.context.repoName,
      event.payload.fingerprints,
    );
    notifyReportArtifact(store, "JSONL report written", deps.config.jsonlOutput);
  }
}

function notifyReportArtifact(store: UIStore | undefined, message: string, detail: string): void {
  if (store) {
    store.addNotice({
      level: "success",
      message,
      detail,
      source: "report",
    });
    return;
  }

  emitOutputNotice({
    level: "success",
    message,
    detail,
    source: "report",
  });
}

function getOrCreateRunState(map: Map<string, RunReportState>, runId: string): RunReportState {
  const existing = map.get(runId);
  if (existing) {
    return existing;
  }

  const created: RunReportState = { startPrinted: false, resumePrinted: false };
  map.set(runId, created);
  return created;
}

function maybeUpdateStartBanner(store: UIStore, state: RunReportState, repoName: string): void {
  if (state.totalFindings == null || state.selectedForTriage == null || !state.tasks) {
    return;
  }

  if (!store.getState().startBannerShown) {
    store.update({
      startBannerShown: true,
      repoName,
      totalFindings: state.totalFindings,
      selectedForTriage: state.selectedForTriage,
      skippedAlreadyTriaged: state.skippedAlreadyTriaged ?? 0,
      tasks: state.tasks,
    });
  }
}

function maybePrintStartBanner(state: RunReportState, repoName: string): void {
  if (
    !state.resumePrinted &&
    (state.skippedAlreadyTriaged ?? 0) > 0 &&
    state.selectedForTriage != null
  ) {
    printResumeInfo(state.skippedAlreadyTriaged ?? 0, state.selectedForTriage);
    state.resumePrinted = true;
  }

  if (state.startPrinted) {
    return;
  }

  if (state.totalFindings == null || state.selectedForTriage == null || !state.tasks) {
    return;
  }

  printScanStart(repoName, state.selectedForTriage, state.totalFindings, state.tasks);
  state.startPrinted = true;
}

function summarizeToolInput(
  toolName: string | undefined,
  toolInput: Record<string, unknown> | undefined,
): string {
  const name = toolName ?? "Tool";

  if (!toolInput) {
    return name;
  }

  const filePath = asString(toolInput["file_path"]) ?? asString(toolInput["path"]);
  const pattern = asString(toolInput["pattern"]);
  const glob = asString(toolInput["glob"]);

  if (name === "Read" && filePath) {
    return `Inspecting ${filePath}`;
  }

  if (name === "Grep" && pattern) {
    const truncatedPattern = pattern.length > 40 ? `${pattern.slice(0, 37)}...` : pattern;
    return `Searching for "${truncatedPattern}"`;
  }

  if (name === "Glob" && glob) {
    return `Scanning ${glob}`;
  }

  if (filePath) {
    return `${name} ${filePath}`;
  }

  return name;
}

function describeTaskProgress(progress: unknown): string {
  if (!progress || typeof progress !== "object") {
    return "finding emitted";
  }

  const record = progress as Record<string, unknown>;
  const ruleId = asString(record["ruleId"]);
  const filePath = asString(record["filePath"]);
  const startLine = typeof record["startLine"] === "number" ? record["startLine"] : null;

  if (ruleId && filePath && startLine != null) {
    return `${ruleId} · ${filePath}:${startLine}`;
  }
  if (ruleId && filePath) {
    return `${ruleId} · ${filePath}`;
  }
  return ruleId ?? filePath ?? "finding emitted";
}

function updateScanStageDetail(store: UIStore): void {
  const scanStage = store.getState().stages.find((stage) => stage.id === "scan");
  if (!scanStage) {
    return;
  }

  const taskCount = scanStage.subTasks.length;
  const doneCount = scanStage.subTasks.filter((task) => task.status === "done").length;
  const findingCount = scanStage.subTasks.reduce((sum, task) => sum + (task.findingCount ?? 0), 0);
  const parts: string[] = [];

  if (taskCount > 0 && doneCount < taskCount) {
    parts.push(`${doneCount} of ${taskCount} tasks done`);
  } else if (taskCount > 0) {
    parts.push(`${taskCount} task${taskCount === 1 ? "" : "s"} complete`);
  }
  if (findingCount > 0) {
    parts.push(`${findingCount} finding${findingCount === 1 ? "" : "s"}`);
  }

  if (parts.length > 0) {
    store.updateStageDetail("scan", parts.join(" · "));
  }
}

/** Human-readable start detail for scan tasks. */
function scanTaskStartDetail(taskId: string): string {
  switch (taskId) {
    case "agentic":
      return "analyzing codebase";
    case "semgrep":
      return "running rules";
    case "codeql":
      return "building database";
    case "context-gatherer":
      return "mapping attack surface";
    case "context-enricher":
      return "enriching context";
    case "threat-model-randori":
      return "modeling threats";
    case "threat-hunt":
      return "analyzing threats from attack surface";
    default:
      return "preparing task";
  }
}

function truncate(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, max - 3)}...`;
}

function asString(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}
