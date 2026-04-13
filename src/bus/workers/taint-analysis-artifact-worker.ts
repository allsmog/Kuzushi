import type Database from "better-sqlite3";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { buildBoundaryManifest } from "../../monorepo/boundary-manifest.js";
import { getActionableFindings, getTriagedFindingsForRepo } from "../../store.js";
import { isRecord } from "../../utils.js";
import { safeJsonStringify } from "../../utils/safe-json.js";
import type { PipelineStartEvent, ReportRequestedEvent, TaskCompleteEvent } from "../events.js";
import type { MessageBus } from "../types.js";
import type { MonorepoSharedContext } from "../../monorepo/types.js";

export interface TaintAnalysisArtifactWorkerDeps {
  db: Database.Database;
}

interface RunState {
  repoRoot: string;
  monorepoContext?: MonorepoSharedContext;
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
      monorepoContext: event.payload.monorepoContext,
    });
  });

  // Persist ThreatModelDocument when threat-model-randori completes
  bus.subscribe<TaskCompleteEvent>("task:complete", (event) => {
    if (event.payload.taskId !== "threat-model-randori") return;
    const state = runs.get(event.meta.runId);
    if (!state) return;
    const output = event.payload.output;
    if (!isRecord(output) || !isRecord(output["document"])) return;
    try {
      const runDir = path.join(state.repoRoot, ".kuzushi", "runs", event.meta.runId);
      if (!existsSync(runDir)) {
        mkdirSync(runDir, { recursive: true });
      }
      writeFileSync(
        path.join(runDir, "threat-model.json"),
        safeJsonStringify(output["document"], 2),
        "utf-8",
      );
    } catch (error) {
      console.error(`[taint-analysis-artifact-worker] Failed to write threat-model.json: ${error}`);
    }
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
      const findings = rows.map((row) => {
        const details = (row.triageDetails ?? {}) as Record<string, unknown>;
        return {
          id: row.fingerprint,
          scanner: row.scanner,
          rule_id: row.ruleId,
          location: {
            file: row.filePath,
            line: row.startLine,
          },
          severity: row.severity,
          message: row.message,
          title: details.title ?? null,
          attack_narrative: details.attack_narrative ?? null,
          verdict: row.verdict,
          confidence: row.confidence,
          rationale: row.rationale,
          verification_steps: row.verificationSteps,
          fix_patch: row.fixPatch,
          ...details,
        };
      });

      // Include the threat model document if available
      let threatModel: unknown = null;
      const tmPath = path.join(runDir, "threat-model.json");
      if (existsSync(tmPath)) {
        try {
          threatModel = JSON.parse(readFileSync(tmPath, "utf-8"));
        } catch { /* best-effort */ }
      }

      writeFileSync(
        path.join(runDir, "findings.triaged.json"),
        JSON.stringify({
          version: "1.0.0",
          generatedAt: new Date().toISOString(),
          runId: event.meta.runId,
          repo: event.payload.context.repoName,
          findings,
          ...(threatModel ? { threatModel } : {}),
        }, null, 2),
        "utf-8",
      );

      if (state?.monorepoContext?.modulePlan.enabledTasks.includes("taint-iris")) {
        const actionable = getActionableFindings(deps.db, event.payload.context.repoName);
        const boundary = buildBoundaryManifest(
          state.monorepoContext.modulePlan,
          state.monorepoContext.sharedContext,
          actionable,
        );
        writeFileSync(
          path.join(runDir, "boundary.json"),
          safeJsonStringify(boundary, 2),
          "utf-8",
        );
      }
    } catch (error) {
      console.error(`[taint-analysis-artifact-worker] Failed to write artifact: ${error}`);
    }

    runs.delete(event.meta.runId);
  });
}
