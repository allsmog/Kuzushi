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
  ScanStartEvent,
  TaskStartEvent,
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

interface RunReportState {
  scanners?: string[];
  totalFindings?: number;
  selectedForTriage?: number;
  startPrinted: boolean;
}

export interface ReportWorkerDeps {
  db: Database.Database;
  config: KuzushiConfig;
}

/**
 * Report worker: handles terminal output and final summary.
 */
export function registerReportWorker(bus: MessageBus, deps: ReportWorkerDeps): void {
  const runState = new Map<string, RunReportState>();

  bus.subscribe<PipelineStartEvent>("pipeline:start", (event) => {
    const state = getOrCreateRunState(runState, event.meta.runId);
    state.scanners = event.payload.scanOpts.scanners !== undefined
      ? [...event.payload.scanOpts.scanners]
      : [...event.payload.config.scanners];
  });

  bus.subscribe<ScanStartEvent>("scan:start", (event) => {
    const state = getOrCreateRunState(runState, event.meta.runId);
    state.scanners = [...event.payload.scanners];
  });

  bus.subscribe<TaskStartEvent>("task:start", (event) => {
    if (event.payload.outputKind !== "findings" && event.payload.outputKind !== "threat-model") {
      return;
    }

    const state = getOrCreateRunState(runState, event.meta.runId);
    const scanners = new Set(state.scanners ?? []);
    scanners.add(event.payload.taskId);
    state.scanners = [...scanners];
  });

  bus.subscribe<ScanCompleteEvent>("scan:complete", (event) => {
    const state = getOrCreateRunState(runState, event.meta.runId);
    state.totalFindings = event.payload.totalFindings;
    maybePrintStartBanner(state, event.payload.context.repoName);
  });

  bus.subscribe<TriageStartEvent>("triage:start", (event) => {
    const state = getOrCreateRunState(runState, event.meta.runId);
    state.selectedForTriage = event.payload.findingCount;

    maybePrintStartBanner(state, event.payload.context.repoName);

    if (event.payload.findingCount > 0) {
      console.log(`  Triaging ${event.payload.findingCount} findings via ${event.payload.model}...\n`);
    }
  });

  bus.subscribe<TriageResultEvent>("triage:result", (event) => {
    const { result, index, total, attempts } = event.payload;
    printTriageProgress(result, index, total, attempts);
  });

  bus.subscribe<TriageErrorEvent>("triage:error", (event) => {
    const { finding, error, index, total, attempts } = event.payload;
    const retrySuffix = attempts && attempts > 1 ? ` (retry #${attempts})` : "";
    console.log(`  [${index}/${total}] TRIAGE ERROR${retrySuffix} ${finding.fingerprint.slice(0, 12)}...`);
    console.log(`    ${truncate(error, 160)}`);
  });

  bus.subscribe<VerificationStartEvent>("verification:start", (event) => {
    if (event.payload.findingCount > 0) {
      console.log(`  Verifying ${event.payload.findingCount} findings via ${event.payload.model}...\n`);
    }
  });

  bus.subscribe<VerificationResultEvent>("verification:result", (event) => {
    const { result, index, total, attempts } = event.payload;
    const status = result.exploitable ? "EXPLOITABLE" : "not exploitable";
    const cost = result.verifyCostUsd && result.verifyCostUsd > 0
      ? ` $${result.verifyCostUsd.toFixed(4)}`
      : "";
    const retrySuffix = attempts && attempts > 1 ? ` (retry #${attempts})` : "";
    console.log(`  [${index}/${total}] ${status}${cost}${retrySuffix} ${result.fingerprint.slice(0, 12)}...`);
  });

  bus.subscribe<VerificationErrorEvent>("verification:error", (event) => {
    const { finding, error, index, total, attempts } = event.payload;
    const retrySuffix = attempts && attempts > 1 ? ` (retry #${attempts})` : "";
    console.log(`  [${index}/${total}] VERIFY ERROR${retrySuffix} ${finding.fingerprint.slice(0, 12)}...`);
    console.log(`    ${truncate(error, 160)}`);
  });

  bus.subscribe<PocHarnessStartEvent>("poc-harness:start", (event) => {
    if (event.payload.findingCount > 0) {
      console.log(`  Generating ${event.payload.findingCount} PoC harnesses via ${event.payload.model}...\n`);
    }
  });

  bus.subscribe<PocHarnessResultEvent>("poc-harness:result", (event) => {
    const { result, index, total, attempts } = event.payload;
    const status = result.skipped ? "SKIPPED" : "GENERATED";
    const parsed = result.skipped ? "" : (result.parsed ? " parsed" : " parse-error");
    const cost = result.costUsd && result.costUsd > 0
      ? ` $${result.costUsd.toFixed(4)}`
      : "";
    const retrySuffix = attempts && attempts > 1 ? ` (retry #${attempts})` : "";
    console.log(
      `  [${index}/${total}] ${status}${parsed}${cost}${retrySuffix} ${result.fingerprint.slice(0, 12)}...`,
    );
  });

  bus.subscribe<PocHarnessErrorEvent>("poc-harness:error", (event) => {
    const { finding, error, index, total, attempts } = event.payload;
    const retrySuffix = attempts && attempts > 1 ? ` (retry #${attempts})` : "";
    console.log(`  [${index}/${total}] POC ERROR${retrySuffix} ${finding.fingerprint.slice(0, 12)}...`);
    console.log(`    ${truncate(error, 160)}`);
  });

  bus.subscribe<TriageAgentActivityEvent>("triage:agent-activity", (event) => {
    const prefix = `  [${event.payload.index}/${event.payload.total}]`;

    if (event.payload.kind === "tool-start") {
      const detail = summarizeToolInput(event.payload.toolName, event.payload.toolInput);
      console.log(`${prefix} -> ${detail}`);
      return;
    }

    if (event.payload.kind === "tool-progress") {
      const seconds = event.payload.elapsedSeconds ?? 0;
      const toolName = event.payload.toolName ?? "tool";
      console.log(`${prefix} ... ${toolName} (${seconds.toFixed(1)}s)`);
      return;
    }

    if (event.payload.kind === "tool-complete") {
      if (event.payload.summary) {
        console.log(`${prefix} ✓ ${truncate(event.payload.summary, 140)}`);
      }
      return;
    }

    if (event.payload.summary) {
      console.log(`${prefix} · ${truncate(event.payload.summary, 120)}`);
    }
  });

  bus.subscribe<VerificationAgentActivityEvent>("verification:agent-activity", (event) => {
    const prefix = `  [${event.payload.index}/${event.payload.total}]`;

    if (event.payload.kind === "tool-start") {
      const detail = summarizeToolInput(event.payload.toolName, event.payload.toolInput);
      console.log(`${prefix} -> ${detail}`);
      return;
    }

    if (event.payload.kind === "tool-progress") {
      const seconds = event.payload.elapsedSeconds ?? 0;
      const toolName = event.payload.toolName ?? "tool";
      console.log(`${prefix} ... ${toolName} (${seconds.toFixed(1)}s)`);
      return;
    }

    if (event.payload.kind === "tool-complete") {
      if (event.payload.summary) {
        console.log(`${prefix} ✓ ${truncate(event.payload.summary, 140)}`);
      }
      return;
    }

    if (event.payload.summary) {
      console.log(`${prefix} · ${truncate(event.payload.summary, 120)}`);
    }
  });

  bus.subscribe<PocHarnessAgentActivityEvent>("poc-harness:agent-activity", (event) => {
    const prefix = `  [${event.payload.index}/${event.payload.total}]`;

    if (event.payload.kind === "tool-start") {
      const detail = summarizeToolInput(event.payload.toolName, event.payload.toolInput);
      console.log(`${prefix} -> ${detail}`);
      return;
    }

    if (event.payload.kind === "tool-progress") {
      const seconds = event.payload.elapsedSeconds ?? 0;
      const toolName = event.payload.toolName ?? "tool";
      console.log(`${prefix} ... ${toolName} (${seconds.toFixed(1)}s)`);
      return;
    }

    if (event.payload.kind === "tool-complete") {
      if (event.payload.summary) {
        console.log(`${prefix} ✓ ${truncate(event.payload.summary, 140)}`);
      }
      return;
    }

    if (event.payload.summary) {
      console.log(`${prefix} · ${truncate(event.payload.summary, 120)}`);
    }
  });

  bus.subscribe<ReportRequestedEvent>("report:requested", async (event) => {
    const state = getOrCreateRunState(runState, event.meta.runId);
    maybePrintStartBanner(state, event.payload.context.repoName);

    if (state.totalFindings === 0) {
      console.log("  No findings from scanner. Code looks clean.");
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

    await bus.publish(
      createEvent("report:complete", event.meta.runId, {
        context: event.payload.context,
      }),
    );

    runState.delete(event.meta.runId);
  });
}

function getOrCreateRunState(
  map: Map<string, RunReportState>,
  runId: string,
): RunReportState {
  const existing = map.get(runId);
  if (existing) {
    return existing;
  }

  const created: RunReportState = { startPrinted: false };
  map.set(runId, created);
  return created;
}

function maybePrintStartBanner(state: RunReportState, repoName: string): void {
  if (state.startPrinted) {
    return;
  }

  if (state.totalFindings == null || state.selectedForTriage == null || !state.scanners) {
    return;
  }

  printScanStart(repoName, state.selectedForTriage, state.totalFindings, state.scanners);

  if (state.selectedForTriage < state.totalFindings) {
    printResumeInfo(state.totalFindings - state.selectedForTriage, state.selectedForTriage);
  }

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
