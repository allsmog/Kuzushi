import type Database from "better-sqlite3";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { getTriagedFindingsForRepo } from "../../store.js";
import type { PipelineStartEvent, ReportRequestedEvent } from "../events.js";
import type { MessageBus } from "../types.js";

export interface TaintAnalysisArtifactWorkerDeps {
  db: Database.Database;
}

interface RunState {
  repoRoot: string;
}

/**
 * Writes Taint-analysis-compatible triage artifacts for interoperability workflows.
 */
export function registerTaintAnalysisArtifactWorker(
  bus: MessageBus,
  deps: TaintAnalysisArtifactWorkerDeps,
): void {
  const runs = new Map<string, RunState>();

  bus.subscribe<PipelineStartEvent>("pipeline:start", (event) => {
    runs.set(event.meta.runId, {
      repoRoot: event.payload.context.repoRoot,
    });
  });

  bus.subscribe<ReportRequestedEvent>("report:requested", (event) => {
    try {
      const state = runs.get(event.meta.runId);
      const repoRoot = state?.repoRoot ?? event.payload.context.repoRoot;
      const runDir = path.join(repoRoot, ".kuzushi", "runs", event.meta.runId);
      if (!existsSync(runDir)) {
        mkdirSync(runDir, { recursive: true });
      }

      const rows = getTriagedFindingsForRepo(deps.db, event.payload.context.repoName);
      const findings = rows.map((row) => ({
        id: row.fingerprint,
        scanner: row.scanner,
        rule_id: row.ruleId,
        location: {
          file: row.filePath,
          line: row.startLine,
        },
        severity: row.severity,
        message: row.message,
        verdict: row.verdict,
        confidence: row.confidence,
        rationale: row.rationale,
        verification_steps: row.verificationSteps,
        fix_patch: row.fixPatch,
        ...(row.triageDetails ?? {}),
      }));

      writeFileSync(
        path.join(runDir, "findings.triaged.json"),
        JSON.stringify({
          version: "1.0.0",
          generatedAt: new Date().toISOString(),
          runId: event.meta.runId,
          repo: event.payload.context.repoName,
          findings,
        }, null, 2),
        "utf-8",
      );
    } catch (error) {
      console.error(`[taint-analysis-artifact-worker] Failed to write artifact: ${error}`);
    }

    runs.delete(event.meta.runId);
  });
}
