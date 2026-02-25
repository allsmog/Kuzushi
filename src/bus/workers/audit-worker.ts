import { appendFileSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import type { KuzushiConfig } from "../../types.js";
import type {
  PipelineCompleteEvent,
  PipelineStartEvent,
  TriageAgentActivityEvent,
  TriageErrorEvent,
  TriageResultEvent,
  VerificationAgentActivityEvent,
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
    };

    runState.set(event.meta.runId, state);

    writeFileSync(path.join(runDir, "run.json"), JSON.stringify({
      runId: event.meta.runId,
      timestamp: event.meta.timestamp,
      resumeRunId: event.payload.resumeRunId,
      context: event.payload.context,
      config: event.payload.config,
      scanOpts: event.payload.scanOpts,
    }, null, 2));
  });

  bus.subscribe<TriageAgentActivityEvent>("triage:agent-activity", (event) => {
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

  bus.subscribe<VerificationAgentActivityEvent>("verification:agent-activity", (event) => {
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

    writeFileSync(path.join(state.runDir, "stats.json"), JSON.stringify({
      timestamp: event.meta.timestamp,
      stats: event.payload.stats,
    }, null, 2));

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
  appendFileSync(filePath, `${JSON.stringify({
    timestamp,
    eventType,
    fingerprint: details.fingerprint,
    payload: details.payload,
  })}\n`);
}

function ensureDir(dirPath: string): void {
  if (!existsSync(dirPath)) {
    mkdirSync(dirPath, { recursive: true });
  }
}
