import type Database from "better-sqlite3";
import {
  printResumeInfo,
  printScanStart,
  printSummary,
  printTriageProgress,
} from "../../report.js";
import type {
  PipelineStartEvent,
  ReportRequestedEvent,
  ScanCompleteEvent,
  ScanStartEvent,
  TaskStartEvent,
  TriageAgentActivityEvent,
  TriageResultEvent,
  TriageStartEvent,
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
}

/**
 * Report worker: handles terminal output and final summary.
 */
export function registerReportWorker(bus: MessageBus, deps: ReportWorkerDeps): void {
  const runState = new Map<string, RunReportState>();

  bus.subscribe<PipelineStartEvent>("pipeline:start", (event) => {
    const state = getOrCreateRunState(runState, event.meta.runId);
    state.scanners = event.payload.scanOpts.scanners && event.payload.scanOpts.scanners.length > 0
      ? [...event.payload.scanOpts.scanners]
      : [...event.payload.config.scanners];
  });

  bus.subscribe<ScanStartEvent>("scan:start", (event) => {
    const state = getOrCreateRunState(runState, event.meta.runId);
    state.scanners = [...event.payload.scanners];
  });

  bus.subscribe<TaskStartEvent>("task:start", (event) => {
    if (event.payload.outputKind !== "findings") {
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
    const { result, index, total } = event.payload;
    printTriageProgress(result, index, total);
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

  bus.subscribe<ReportRequestedEvent>("report:requested", async (event) => {
    const state = getOrCreateRunState(runState, event.meta.runId);
    maybePrintStartBanner(state, event.payload.context.repoName);

    if (state.totalFindings === 0) {
      console.log("  No findings from scanner. Code looks clean.");
    } else if ((state.selectedForTriage ?? 0) === 0) {
      console.log("  All findings already triaged. Nothing to do.");
    }

    printSummary(deps.db, event.payload.context.repoName);

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
