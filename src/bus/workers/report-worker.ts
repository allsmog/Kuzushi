import type Database from "better-sqlite3";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import {
  printResumeInfo,
  printScanStart,
  printSummary,
  printTriageProgress,
} from "../../report.js";
import { generateMarkdownReport } from "../../report-markdown.js";
import { generateSarifReport } from "../../report-sarif.js";
import { writeJsonReport } from "../../report-json.js";
import { writeCsvReport } from "../../report-csv.js";
import { writeJsonlReport } from "../../report-jsonl.js";
import type { KuzushiConfig } from "../../types.js";
import type {
  PipelineStartEvent,
  PocHarnessAgentActivityEvent,
  PocHarnessResultEvent,
  PocHarnessStartEvent,
  ReportRequestedEvent,
  ScanCompleteEvent,
  TaskStartEvent,
  TaskCompleteEvent,
  TaskErrorEvent,
  TriageAgentActivityEvent,
  TriageErrorEvent,
  TriageResultEvent,
  TriageStartEvent,
  VerificationAgentActivityEvent,
  VerificationErrorEvent,
  VerificationResultEvent,
  VerificationStartEvent,
  PocHarnessErrorEvent,
} from "../events.js";
import { createEvent } from "../helpers.js";
import type { MessageBus } from "../types.js";
import type { UIStore } from "../../ui/state.js";
import { buildSummaryData } from "../../ui/summary-data.js";

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

  bus.subscribe<PipelineStartEvent>("pipeline:start", (event) => {
    const state = getOrCreateRunState(runState, event.meta.runId);
    state.tasks = event.payload.scanOpts.tasks !== undefined
      ? [...event.payload.scanOpts.tasks]
      : [...event.payload.config.tasks];

    if (store) {
      // Build pipeline stages from config
      const stageList: Array<{ id: string; label: string }> = [
        { id: "scan", label: "Scan" },
        { id: "triage", label: "Triage" },
      ];
      if (event.payload.config.verify) {
        stageList.push({ id: "verify", label: "Verify" });
      }
      if (event.payload.config.pocHarness) {
        stageList.push({ id: "poc", label: "PoC Harness" });
      }
      stageList.push({ id: "report", label: "Report" });

      store.initStages(stageList);
      store.activateStage("scan", state.tasks?.join(", "));
      store.update({
        tasks: state.tasks,
        bannerShown: true,
      });
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
      store.update({ tasks: state.tasks, phase: "scanning" });
      // Add scanner as a sub-task branch under the Scan stage
      store.upsertSubTask("scan", {
        id: event.payload.taskId,
        label: event.payload.taskId,
        status: "active",
        startedAt: Date.now(),
      });
    }
  });

  bus.subscribe<TaskCompleteEvent>("task:complete", (event) => {
    if (store) {
      store.upsertSubTask("scan", {
        id: event.payload.taskId,
        label: event.payload.taskId,
        status: "done",
        elapsedMs: event.payload.durationMs,
      });
    }
  });

  bus.subscribe<TaskErrorEvent>("task:error", (event) => {
    if (store) {
      store.upsertSubTask("scan", {
        id: event.payload.taskId,
        label: event.payload.taskId,
        status: "error",
        detail: event.payload.error?.slice(0, 60),
      });
    }
  });

  bus.subscribe<ScanCompleteEvent>("scan:complete", (event) => {
    const state = getOrCreateRunState(runState, event.meta.runId);
    state.totalFindings = event.payload.totalFindings;

    if (store) {
      store.update({ totalFindings: state.totalFindings });
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
      store.activateStage("triage", `${event.payload.findingCount} findings via ${event.payload.model}`);
      store.update({
        phase: "triaging",
        selectedForTriage: event.payload.findingCount,
        skippedAlreadyTriaged: event.payload.skippedAlreadyTriaged ?? 0,
        model: event.payload.model,
        progress: { current: 0, total: event.payload.findingCount },
      });
      maybeUpdateStartBanner(store, state, event.payload.context.repoName);
    } else {
      maybePrintStartBanner(state, event.payload.context.repoName);
      if (event.payload.findingCount > 0) {
        console.log(`  Triaging ${event.payload.findingCount} findings via ${event.payload.model}...\n`);
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
      console.log(`  [${index}/${total}] TRIAGE ERROR${retrySuffix} ${finding.fingerprint.slice(0, 12)}...`);
      console.log(`    ${truncate(error, 160)}`);
    }
  });

  bus.subscribe<VerificationStartEvent>("verification:start", (event) => {
    if (store) {
      store.activateStage("verify", `${event.payload.findingCount} findings via ${event.payload.model}`);
      store.update({
        phase: "verifying",
        model: event.payload.model,
        progress: { current: 0, total: event.payload.findingCount },
        results: [], // clear triage results from live view
      });
    } else {
      if (event.payload.findingCount > 0) {
        console.log(`  Verifying ${event.payload.findingCount} findings via ${event.payload.model}...\n`);
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
      const cost = result.verifyCostUsd && result.verifyCostUsd > 0
        ? ` $${result.verifyCostUsd.toFixed(4)}`
        : "";
      const retrySuffix = attempts && attempts > 1 ? ` (retry #${attempts})` : "";
      console.log(`  [${index}/${total}] ${status}${cost}${retrySuffix} ${result.fingerprint.slice(0, 12)}...`);
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
      console.log(`  [${index}/${total}] VERIFY ERROR${retrySuffix} ${finding.fingerprint.slice(0, 12)}...`);
      console.log(`    ${truncate(error, 160)}`);
    }
  });

  bus.subscribe<PocHarnessStartEvent>("poc-harness:start", (event) => {
    if (store) {
      store.activateStage("poc", `${event.payload.findingCount} harnesses via ${event.payload.model}`);
      store.update({
        phase: "poc",
        model: event.payload.model,
        progress: { current: 0, total: event.payload.findingCount },
        results: [],
      });
    } else {
      if (event.payload.findingCount > 0) {
        console.log(`  Generating ${event.payload.findingCount} PoC harnesses via ${event.payload.model}...\n`);
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
      const parsed = result.skipped ? "" : (result.parsed ? " parsed" : " parse-error");
      const cost = result.costUsd && result.costUsd > 0
        ? ` $${result.costUsd.toFixed(4)}`
        : "";
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
      console.log(`  [${index}/${total}] POC ERROR${retrySuffix} ${finding.fingerprint.slice(0, 12)}...`);
      console.log(`    ${truncate(error, 160)}`);
    }
  });

  // Agent activity — all three stages use the same pattern
  const handleAgentActivity = (
    event: { payload: { kind: string; index: number; total: number; toolName?: string; toolInput?: Record<string, unknown>; elapsedSeconds?: number; summary?: string; fingerprint?: string } },
  ) => {
    const { kind, index, total, fingerprint } = event.payload;

    if (store && fingerprint) {
      const detail = kind === "tool-start"
        ? summarizeToolInput(event.payload.toolName, event.payload.toolInput)
        : kind === "tool-complete"
          ? event.payload.summary ?? undefined
          : kind === "tool-progress"
            ? undefined
            : event.payload.summary ?? undefined;

      store.addAgentActivity(fingerprint, {
        kind: kind as "tool-start" | "tool-progress" | "tool-complete" | "summary",
        toolName: event.payload.toolName,
        detail,
        elapsedSeconds: event.payload.elapsedSeconds,
        index,
        total,
      });
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

  bus.subscribe<TriageAgentActivityEvent>("triage:agent-activity", handleAgentActivity);
  bus.subscribe<VerificationAgentActivityEvent>("verification:agent-activity", handleAgentActivity);
  bus.subscribe<PocHarnessAgentActivityEvent>("poc-harness:agent-activity", handleAgentActivity);

  bus.subscribe<ReportRequestedEvent>("report:requested", async (event) => {
    const state = getOrCreateRunState(runState, event.meta.runId);
    const reportMode = event.payload.reportMode ?? event.payload.context.reportMode ?? "full";

    if (store) {
      if (reportMode === "full") {
        maybeUpdateStartBanner(store, state, event.payload.context.repoName);

        if (state.totalFindings === 0) {
          store.update({ warnings: [...store.getState().warnings, "No findings from tasks. Code looks clean."] });
        } else if ((state.selectedForTriage ?? 0) === 0) {
          store.update({ warnings: [...store.getState().warnings, "All findings already triaged. Nothing to do."] });
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
          phase: "summary",
          summary: summaryData,
          qualityGate: qualityGateResult,
        });
      }
    } else {
      maybePrintStartBanner(state, event.payload.context.repoName);

      if (reportMode === "full") {
        if (state.totalFindings === 0) {
          console.log("  No findings from tasks. Code looks clean.");
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
      writeFileReports(deps, event);
    }

    await bus.publish(
      createEvent("report:complete", event.meta.runId, {
        context: event.payload.context,
      }),
    );

    runState.delete(event.meta.runId);
  });
}

function writeFileReports(deps: ReportWorkerDeps, event: { payload: ReportRequestedEvent["payload"]; meta: { runId: string } }): void {
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
    );
    writeFileSync(deps.config.reportOutput, markdown, "utf-8");
    console.log(`  Report written to ${deps.config.reportOutput}`);
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
    );
    writeFileSync(deps.config.sarifOutput, sarif, "utf-8");
    console.log(`  SARIF report written to ${deps.config.sarifOutput}`);
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
    );
    console.log(`  JSON report written to ${deps.config.jsonOutput}`);
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
    console.log(`  CSV report written to ${deps.config.csvOutput}`);
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
    console.log(`  JSONL report written to ${deps.config.jsonlOutput}`);
  }
}

function getOrCreateRunState(
  map: Map<string, RunReportState>,
  runId: string,
): RunReportState {
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
  if (!state.resumePrinted && (state.skippedAlreadyTriaged ?? 0) > 0 && state.selectedForTriage != null) {
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
    return `Reading ${filePath}`;
  }

  if (name === "Grep" && pattern) {
    return `Grepping "${pattern}"`;
  }

  if (name === "Glob" && glob) {
    return `Globbing "${glob}"`;
  }

  if (filePath) {
    return `${name} ${filePath}`;
  }

  return name;
}

function truncate(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, max - 3)}...`;
}

function asString(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}
