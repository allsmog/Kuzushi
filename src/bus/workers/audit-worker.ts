import { appendFileSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import {
  buildReproducibility,
  countFindingsBy,
  RUN_SUMMARY_FILENAME,
  RUN_SUMMARY_SCHEMA_VERSION,
  type RunSummary,
  type RunSummaryFindingCounts,
} from "../../copilot/run-metadata.js";
import type { KuzushiConfig, ScanOpts } from "../../types.js";
import { buildRunMetadata } from "../../utils/run-metadata.js";
import { safeJsonStringify } from "../../utils/safe-json.js";
import type {
  PipelineCompleteEvent,
  PipelineStartEvent,
  ScanAgentActivityEvent,
  TaskAgentActivityEvent,
  TriageErrorEvent,
  TriageResultEvent,
  VerificationErrorEvent,
  VerificationResultEvent,
} from "../events.js";
import type { MessageBus } from "../types.js";

export interface AuditWorkerDeps {
  config: KuzushiConfig;
}

interface RunAuditState {
  runDir: string;
  triageLogPath: string;
  verifyLogPath: string;
  scanLogPath: string;
}

interface SummaryRunState {
  runDir: string;
  startedAt: string;
  config: KuzushiConfig;
  scanOpts: ScanOpts;
  repoRoot: string;
  repoName?: string;
}

const scanRunState = new Map<string, { runDir: string; scanLogPath: string }>();
const summaryRunState = new Map<string, SummaryRunState>();

/**
 * Always-on scan-events writer: subscribes to `pipeline:start` so every
 * run gets a `scan.jsonl` file an operator can `tail -f` to watch
 * detector tool-use, regardless of whether the gated triage/verify
 * audit log is enabled. Cheap (one append per tool event) and
 * orthogonal to the rest of audit-worker, which is gated on
 * `config.auditLog`.
 *
 * This handler also writes the always-on `summary.json` reproducibility
 * record on `pipeline:complete`, so operators get a stable, jq-friendly
 * digest of every run on disk regardless of `--audit-log`.
 */
export function registerScanEventLog(bus: MessageBus): void {
  bus.subscribe<PipelineStartEvent>("pipeline:start", (event) => {
    const runDir = path.join(event.payload.context.repoRoot, ".kuzushi", "runs", event.meta.runId);
    ensureDir(runDir);
    scanRunState.set(event.meta.runId, {
      runDir,
      scanLogPath: path.join(runDir, "scan.jsonl"),
    });
    summaryRunState.set(event.meta.runId, {
      runDir,
      startedAt: event.meta.timestamp,
      config: event.payload.config,
      scanOpts: event.payload.scanOpts,
      repoRoot: event.payload.context.repoRoot,
      repoName: event.payload.context.repoName,
    });
  });

  bus.subscribe<ScanAgentActivityEvent>("scan:agent-activity", (event) => {
    const state = scanRunState.get(event.meta.runId);
    if (!state) return;
    appendFileSync(
      state.scanLogPath,
      `${safeJsonStringify({
        timestamp: event.meta.timestamp,
        eventType: event.type,
        taskId: event.payload.taskId,
        kind: event.payload.kind,
        toolName: event.payload.toolName,
        toolInput: event.payload.toolInput,
        summary: event.payload.summary,
        elapsedSeconds: event.payload.elapsedSeconds,
      })}\n`,
    );
  });

  bus.subscribe<PipelineCompleteEvent>("pipeline:complete", (event) => {
    writeSummaryForRun(event.meta.runId, event.meta.timestamp, event.payload.stats);
    scanRunState.delete(event.meta.runId);
    summaryRunState.delete(event.meta.runId);
  });
}

function writeSummaryForRun(
  runId: string,
  completedAt: string,
  stats: PipelineCompleteEvent["payload"]["stats"],
): void {
  const summaryState = summaryRunState.get(runId);
  if (!summaryState) return;

  let durationMs: number | undefined;
  const startMs = Date.parse(summaryState.startedAt);
  const endMs = Date.parse(completedAt);
  if (Number.isFinite(startMs) && Number.isFinite(endMs) && endMs >= startMs) {
    durationMs = endMs - startMs;
  }

  let totalCostUsd: number | undefined;
  const runMetrics = (stats as { runMetrics?: { costBreakdown?: { total?: number } } })
    .runMetrics;
  if (runMetrics?.costBreakdown?.total != null) {
    totalCostUsd = runMetrics.costBreakdown.total;
  } else if (typeof stats.totalCostUsd === "number") {
    totalCostUsd = stats.totalCostUsd;
  }

  // pipeline:complete carries summary stats but not the full finding list;
  // counts come from the persisted `findings_json` blob via replay paths.
  // `countFindingsBy` is exported from run-metadata.ts for downstream
  // consumers that have full findings in hand.
  void countFindingsBy;
  const findingCounts: RunSummaryFindingCounts | undefined =
    typeof stats.totalFindings === "number"
      ? { total: stats.totalFindings, bySeverity: {}, byVerdict: {} }
      : undefined;

  const reproducibility = buildReproducibility({
    config: summaryState.config,
    scanOpts: summaryState.scanOpts,
    repoRoot: summaryState.repoRoot,
    agentRuntimeBackend: summaryState.config.agentRuntimeBackend,
  });

  const summary: RunSummary = {
    schemaVersion: RUN_SUMMARY_SCHEMA_VERSION,
    runId,
    status: "complete",
    startedAt: summaryState.startedAt,
    completedAt,
    ...(durationMs != null ? { durationMs } : {}),
    ...(totalCostUsd != null ? { totalCostUsd } : {}),
    reproducibility,
    ...(findingCounts ? { findings: findingCounts } : {}),
    repo: {
      root: summaryState.repoRoot,
      ...(summaryState.repoName ? { name: summaryState.repoName } : {}),
    },
  };

  try {
    ensureDir(summaryState.runDir);
    writeFileSync(
      path.join(summaryState.runDir, RUN_SUMMARY_FILENAME),
      safeJsonStringify(summary, 2),
    );
  } catch {
    // Persisting summary.json is best-effort — never crash the bus on FS errors.
  }
}

/**
 * Audit worker: persists per-run triage/verification activity and outcomes as JSONL.
 */
export function registerAuditWorker(bus: MessageBus, deps: AuditWorkerDeps): void {
  if (!deps.config.auditLog) {
    return;
  }

  const runState = new Map<string, RunAuditState>();

  bus.subscribe<PipelineStartEvent>("pipeline:start", (event) => {
    const runDir = path.join(event.payload.context.repoRoot, ".kuzushi", "runs", event.meta.runId);
    ensureDir(runDir);

    const state: RunAuditState = {
      runDir,
      triageLogPath: path.join(runDir, "triage.jsonl"),
      verifyLogPath: path.join(runDir, "verify.jsonl"),
      scanLogPath: path.join(runDir, "scan.jsonl"),
    };

    runState.set(event.meta.runId, state);

    // Reproducibility metadata: a triage analyst three weeks later
    // needs kuzushi version, model, git sha, config hash, node version
    // and platform to repro the run. Computed lazily so a missing git
    // binary / detached worktree never blocks the run.
    let reproducibility: ReturnType<typeof buildRunMetadata> | undefined;
    try {
      reproducibility = buildRunMetadata({
        repoRoot: event.payload.context.repoRoot,
        config: event.payload.config,
        model: event.payload.config?.model,
        scanArgs: event.payload.scanOpts?.tasks,
        startedAt: event.meta.timestamp,
      });
    } catch {
      /* best-effort metadata only — never block the run */
    }

    writeFileSync(
      path.join(runDir, "run.json"),
      safeJsonStringify(
        {
          runId: event.meta.runId,
          timestamp: event.meta.timestamp,
          resumeRunId: event.payload.resumeRunId,
          context: event.payload.context,
          config: event.payload.config,
          scanOpts: event.payload.scanOpts,
          reproducibility,
        },
        2,
      ),
    );
  });

  bus.subscribe<TaskAgentActivityEvent>("triage:agent-activity", (event) => {
    appendAuditLine(runState, event.meta.runId, "triage", event.meta.timestamp, event.type, {
      fingerprint: event.payload.fingerprint,
      payload: event.payload,
    });
  });

  bus.subscribe<TriageResultEvent>("triage:result", (event) => {
    appendAuditLine(runState, event.meta.runId, "triage", event.meta.timestamp, event.type, {
      fingerprint: event.payload.result.fingerprint,
      payload: {
        finding: event.payload.finding,
        result: event.payload.result,
        costUsd: event.payload.costUsd,
        attempts: event.payload.attempts,
        index: event.payload.index,
        total: event.payload.total,
      },
    });
  });

  bus.subscribe<TriageErrorEvent>("triage:error", (event) => {
    appendAuditLine(runState, event.meta.runId, "triage", event.meta.timestamp, event.type, {
      fingerprint: event.payload.finding.fingerprint,
      payload: {
        finding: event.payload.finding,
        error: event.payload.error,
        costUsd: event.payload.costUsd,
        attempts: event.payload.attempts,
        index: event.payload.index,
        total: event.payload.total,
      },
    });
  });

  bus.subscribe<TaskAgentActivityEvent>("verification:agent-activity", (event) => {
    appendAuditLine(runState, event.meta.runId, "verify", event.meta.timestamp, event.type, {
      fingerprint: event.payload.fingerprint,
      payload: event.payload,
    });
  });

  bus.subscribe<VerificationResultEvent>("verification:result", (event) => {
    appendAuditLine(runState, event.meta.runId, "verify", event.meta.timestamp, event.type, {
      fingerprint: event.payload.result.fingerprint,
      payload: {
        finding: event.payload.finding,
        triageResult: event.payload.triageResult,
        result: event.payload.result,
        costUsd: event.payload.costUsd,
        attempts: event.payload.attempts,
        index: event.payload.index,
        total: event.payload.total,
      },
    });
  });

  bus.subscribe<VerificationErrorEvent>("verification:error", (event) => {
    appendAuditLine(runState, event.meta.runId, "verify", event.meta.timestamp, event.type, {
      fingerprint: event.payload.finding.fingerprint,
      payload: {
        finding: event.payload.finding,
        triageResult: event.payload.triageResult,
        error: event.payload.error,
        costUsd: event.payload.costUsd,
        attempts: event.payload.attempts,
        index: event.payload.index,
        total: event.payload.total,
      },
    });
  });

  bus.subscribe<PipelineCompleteEvent>("pipeline:complete", (event) => {
    const state = runState.get(event.meta.runId);
    if (!state) {
      return;
    }

    writeFileSync(
      path.join(state.runDir, "stats.json"),
      safeJsonStringify(
        {
          timestamp: event.meta.timestamp,
          stats: event.payload.stats,
        },
        2,
      ),
    );

    runState.delete(event.meta.runId);
  });
}

function appendAuditLine(
  runState: Map<string, RunAuditState>,
  runId: string,
  stream: "triage" | "verify",
  timestamp: string,
  eventType: string,
  details: {
    fingerprint?: string;
    payload: unknown;
  },
): void {
  const state = runState.get(runId);
  if (!state) {
    return;
  }

  const filePath = stream === "triage" ? state.triageLogPath : state.verifyLogPath;
  appendFileSync(
    filePath,
    `${safeJsonStringify({
      timestamp,
      eventType,
      fingerprint: details.fingerprint,
      payload: details.payload,
    })}\n`,
  );
}

function ensureDir(dirPath: string): void {
  if (!existsSync(dirPath)) {
    mkdirSync(dirPath, { recursive: true });
  }
}
