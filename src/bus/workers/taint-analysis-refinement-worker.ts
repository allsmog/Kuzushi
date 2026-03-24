import type Database from "better-sqlite3";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import type { AgentRuntime } from "../../agent-runtime/types.js";
import type { TaskRegistry } from "../../agents/registry.js";
import type { TaskContext } from "../../agents/types.js";
import { taintAnalysisRunTask } from "../../agents/tasks/taint-analysis/analyze.js";
import { buildTaintModelDocument } from "../../agents/tasks/taint-analysis/label.js";
import type { TiPriorDocument } from "../../agents/tasks/taint-analysis/ti-prior.js";
import { TAINT_ANALYSIS_PASS_IDS, resolveTaintAnalysisConfig } from "../../agents/tasks/taint-analysis/types.js";
import type { TaintAnalysisLabelOutput, TaintAnalysisLabelsDocument, TaintAnalysisPassEntry, TaintAnalysisPassId } from "../../agents/tasks/taint-analysis/types.js";
import type { ScanOpts, TriageResult, KuzushiConfig, RepoContext } from "../../types.js";
import type { Finding } from "../../scanners/types.js";
import type { ScannerRegistry } from "../../scanners/registry.js";
import { coerceRepoContext } from "../../repo-context.js";
import { triageFindingsBatch } from "../../triage.js";
import {
  deleteFindingsByFingerprints,
  getTriagedFindingsForRepo,
  upsertFinding,
} from "../../store.js";
import { isRecord, normalizeCostUsd, toErrorMessage } from "../../utils.js";
import type { TaintAnalysisRefinementStartEvent } from "../events.js";
import { createEvent } from "../helpers.js";
import type { MessageBus } from "../types.js";

export interface TaintAnalysisRefinementWorkerDeps {
  db: Database.Database;
  registry: ScannerRegistry;
  taskRegistry?: TaskRegistry;
  config: KuzushiConfig;
  runtime: AgentRuntime;
}

interface RefinementSignals {
  sourceFalsePositive: boolean;
  sinkFalsePositive: boolean;
  sourceFpCount: number;
  sinkFpCount: number;
  hints: string[];
}

export function registerTaintAnalysisRefinementWorker(
  bus: MessageBus,
  deps: TaintAnalysisRefinementWorkerDeps,
): void {
  bus.subscribe<TaintAnalysisRefinementStartEvent>("taint-analysis:refinement-start", async (event) => {
    const { context, findings, iteration } = event.payload;
    const labelOutput = asLabelOutput(event.payload.labelOutput);
    if (!labelOutput) {
      await bus.publish(
        createEvent("taint-analysis:refinement-error", event.meta.runId, {
          context,
          iteration,
          error: "Taint analysis label output unavailable; cannot refine.",
        }),
      );
      return;
    }

    try {
      const currentTaintAnalysisFingerprints = new Set(
        findings
          .filter((item) => item.scanner === "taint-analysis-run")
          .map((item) => item.fingerprint),
      );
      const signalsByPass = collectSignalsByPass(
        deps.db,
        context.repoName,
        currentTaintAnalysisFingerprints,
      );
      const allHints: string[] = [];
      for (const [passId, signal] of signalsByPass.entries()) {
        if (signal.hints.length > 0) {
          process.stderr.write(
            `[taint-analysis-refinement] Pass ${passId}: ${signal.hints.length} hint(s): ${signal.hints.join("; ")}\n`,
          );
          allHints.push(...signal.hints);
        }
      }
      const affectedPasses = resolveAffectedPasses(signalsByPass);
      if (affectedPasses.length === 0) {
        await bus.publish(
          createEvent("taint-analysis:refinement-result", event.meta.runId, {
            context,
            iteration,
            affectedPasses: [],
            updatedFindings: findings.filter((item) => item.scanner === "taint-analysis-run"),
            deltaFindings: [],
            deltaTriaged: 0,
            deltaErrors: 0,
            triageCostUsd: 0,
          }),
        );
        return;
      }

      const taintCfg = resolveTaintAnalysisConfig(deps.config);
      const confidenceCap = taintCfg.refinementConfidenceCap ?? 0.3;
      const refinedLabels = applyDeterministicPatch(labelOutput.labels, signalsByPass, confidenceCap);
      const patchPath = path.join(labelOutput.workspaceDir, "labels", `refinement.patch.iter${iteration}.json`);
      await writeFile(
        patchPath,
        JSON.stringify({
          version: "1.0.0",
          iteration,
          affectedPasses,
          signalsByPass: Object.fromEntries([...signalsByPass.entries()]),
        }, null, 2),
        "utf-8",
      );
      if (allHints.length > 0) {
        const hintsPath = path.join(labelOutput.workspaceDir, "labels", `refinement_hints.iter${iteration}.json`);
        await writeFile(hintsPath, JSON.stringify(allHints, null, 2), "utf-8");
      }
      await writeFile(labelOutput.labelsPath, JSON.stringify(refinedLabels, null, 2), "utf-8");
      const tiPrior = await loadTiPriorDocument(labelOutput.tiPriorJsonPath);
      const taintModel = buildTaintModelDocument(refinedLabels, tiPrior);
      await writeFile(labelOutput.taintModelPath, JSON.stringify(taintModel, null, 2), "utf-8");

      const refinedPasses = labelOutput.passes.filter((passId) => affectedPasses.includes(passId));
      const refinedLabelOutput: TaintAnalysisLabelOutput = {
        ...labelOutput,
        passes: refinedPasses as TaintAnalysisLabelOutput["passes"],
        labels: refinedLabels,
      };

      const taskContext: TaskContext = {
        runId: event.meta.runId,
        repoRoot: context.repoRoot,
        scanPath: context.scanPath,
        repoName: context.repoName,
        config: deps.config,
        runtime: deps.runtime,
        bus,
        upstreamOutputs: new Map([["taint-analysis-label", refinedLabelOutput]]),
      };

      const refinedPassFindings = await taintAnalysisRunTask.run(defaultScanOpts(deps.config), taskContext);
      const previousTaintAnalysis = findings.filter((item) => item.scanner === "taint-analysis-run");
      const affectedPassSet = new Set<number>(affectedPasses);
      const previousAffected = previousTaintAnalysis.filter((item) => affectedPassSet.has(extractPassId(item.ruleId) ?? -1));
      const previousAffectedFp = new Set(previousAffected.map((item) => item.fingerprint));
      const updatedTaintAnalysis = [
        ...previousTaintAnalysis.filter((item) => !affectedPassSet.has(extractPassId(item.ruleId) ?? -1)),
        ...refinedPassFindings,
      ];

      const deltaFindings = refinedPassFindings.filter((item) => !previousAffectedFp.has(item.fingerprint));
      const refinedFpSet = new Set(refinedPassFindings.map((item) => item.fingerprint));
      const removedFingerprints = previousAffected
        .filter((item) => !refinedFpSet.has(item.fingerprint))
        .map((item) => item.fingerprint);
      if (removedFingerprints.length > 0) {
        deleteFindingsByFingerprints(deps.db, context.repoName, removedFingerprints);
      }
      const triage = await triageDeltaFindings({
        deps,
        deltaFindings,
        context,
        repoContext: coerceRepoContext(event.payload.repoContext),
      });

      await bus.publish(
        createEvent("taint-analysis:refinement-result", event.meta.runId, {
          context,
          iteration,
          affectedPasses,
          updatedFindings: updatedTaintAnalysis,
          deltaFindings,
          deltaTriaged: triage.triaged,
          deltaErrors: triage.errors,
          triageCostUsd: triage.costUsd,
        }),
      );
    } catch (error) {
      await bus.publish(
        createEvent("taint-analysis:refinement-error", event.meta.runId, {
          context,
          iteration,
          error: toErrorMessage(error),
        }),
      );
    }
  });
}

function collectSignalsByPass(
  db: Database.Database,
  repoName: string,
  currentFingerprints: Set<string>,
): Map<number, RefinementSignals> {
  const rows = getTriagedFindingsForRepo(db, repoName);
  const byPass = new Map<number, RefinementSignals>();

  for (const row of rows) {
    if (currentFingerprints.size > 0 && !currentFingerprints.has(row.fingerprint)) {
      continue;
    }
    if (row.scanner !== "taint-analysis-run") {
      continue;
    }

    const passId = extractPassId(row.ruleId);
    if (!passId) {
      continue;
    }

    const details = row.triageDetails ?? {};
    const source = isRecord(details["source"]) ? details["source"] : undefined;
    const sink = isRecord(details["sink"]) ? details["sink"] : undefined;
    const hint = typeof details["rule_refinement_hint"] === "string"
      ? details["rule_refinement_hint"].trim()
      : "";
    const signal = byPass.get(passId) ?? {
      sourceFalsePositive: false,
      sinkFalsePositive: false,
      sourceFpCount: 0,
      sinkFpCount: 0,
      hints: [],
    };

    if (source && source["is_false_positive"] === true) {
      signal.sourceFalsePositive = true;
      signal.sourceFpCount += 1;
    }
    if (sink && sink["is_false_positive"] === true) {
      signal.sinkFalsePositive = true;
      signal.sinkFpCount += 1;
    }
    if (hint) {
      signal.hints.push(hint);
    }

    byPass.set(passId, signal);
  }

  return byPass;
}

function resolveAffectedPasses(signalsByPass: Map<number, RefinementSignals>): TaintAnalysisPassId[] {
  const out: TaintAnalysisPassId[] = [];
  for (const [passId, signal] of signalsByPass.entries()) {
    if (!isPassId(passId)) {
      continue;
    }
    if (signal.sourceFalsePositive || signal.sinkFalsePositive || signal.hints.length > 0) {
      out.push(passId);
    }
  }
  return out;
}

function applyDeterministicPatch(
  labels: TaintAnalysisLabelsDocument,
  signalsByPass: Map<number, RefinementSignals>,
  confidenceCap: number,
): TaintAnalysisLabelsDocument {
  const cloned = JSON.parse(JSON.stringify(labels)) as TaintAnalysisLabelsDocument;
  for (const pass of cloned.passes) {
    const signal = signalsByPass.get(pass.pass_id);
    if (!signal) {
      continue;
    }
    if (signal.sourceFalsePositive) {
      downgradeEntries(pass.entries, "source", signal.sourceFpCount, confidenceCap);
    }
    if (signal.sinkFalsePositive) {
      downgradeEntries(pass.entries, "sink", signal.sinkFpCount, confidenceCap);
    }
    if (!signal.sourceFalsePositive && !signal.sinkFalsePositive && signal.hints.length > 0) {
      downgradeEntries(pass.entries, "sink", signal.hints.length, confidenceCap);
    }
  }
  return cloned;
}

function downgradeEntries(
  entries: TaintAnalysisPassEntry[],
  role: TaintAnalysisPassEntry["role"],
  signalCount: number,
  confidenceCap: number,
): void {
  const candidates = entries
    .filter((entry) => entry.role === role && entry.classification !== "fp")
    .sort((a, b) => a.confidence - b.confidence);
  const limit = Math.min(signalCount, candidates.length);
  for (const entry of candidates.slice(0, limit)) {
    entry.classification = "fp";
    entry.rationale = `${entry.rationale} [refinement: downgraded due to triage false-positive signals]`;
    entry.confidence = Math.min(entry.confidence, confidenceCap);
  }
}

async function triageDeltaFindings(args: {
  deps: TaintAnalysisRefinementWorkerDeps;
  deltaFindings: Finding[];
  context: TaintAnalysisRefinementStartEvent["payload"]["context"];
  repoContext?: RepoContext;
}): Promise<{ triaged: number; errors: number; costUsd: number }> {
  if (args.deltaFindings.length === 0) {
    return { triaged: 0, errors: 0, costUsd: 0 };
  }

  try {
    const { results, costUsd } = await triageFindingsBatch(
      args.deltaFindings,
      args.context.scanPath ?? args.context.repoRoot,
      args.context.repoName,
      args.deps.config.triageModel ?? args.deps.config.model,
      args.repoContext,
      { runtime: args.deps.runtime },
    );

    let triaged = 0;
    let errors = 0;
    for (const finding of args.deltaFindings) {
      const result = results.get(finding.fingerprint);
      if (!result) {
        errors += 1;
        continue;
      }
      result.triageCostUsd = args.deltaFindings.length > 0 ? normalizeCostUsd(costUsd / args.deltaFindings.length) : 0;
      upsertFinding(args.deps.db, finding, result, args.context.repoName, "HEAD");
      triaged += 1;
    }

    return {
      triaged,
      errors,
      costUsd: normalizeCostUsd(costUsd),
    };
  } catch {
    for (const finding of args.deltaFindings) {
      const fallback: TriageResult = {
        fingerprint: finding.fingerprint,
        verdict: "needs_review",
        confidence: 0,
        rationale: "Refinement delta triage failed; queued as needs_review.",
        verificationSteps: [],
        fixPatch: null,
      };
      upsertFinding(args.deps.db, finding, fallback, args.context.repoName, "HEAD");
    }

    return {
      triaged: 0,
      errors: args.deltaFindings.length,
      costUsd: 0,
    };
  }
}


function isPassId(value: number): value is TaintAnalysisPassId {
  return TAINT_ANALYSIS_PASS_IDS.has(value);
}

function extractPassId(ruleId: string): number | undefined {
  const match = ruleId.match(/taint-analysis\/pass(\d+)\//i);
  if (!match) {
    return undefined;
  }
  const id = Number.parseInt(match[1], 10);
  return isPassId(id) ? id : undefined;
}

function asLabelOutput(value: unknown): TaintAnalysisLabelOutput | null {
  if (!isRecord(value)) {
    return null;
  }
  if (
    !isRecord(value["labels"])
    || typeof value["workspaceDir"] !== "string"
    || typeof value["labelsPath"] !== "string"
    || typeof value["dbPath"] !== "string"
    || typeof value["taintModelPath"] !== "string"
    || !Array.isArray(value["passes"])
    || !Array.isArray((value["labels"] as Record<string, unknown>)["passes"])
  ) {
    return null;
  }
  return value as unknown as TaintAnalysisLabelOutput;
}

function defaultScanOpts(config: KuzushiConfig): ScanOpts {
  return {
    severity: config.severity,
    excludePatterns: config.excludePatterns,
    scanners: config.scanners,
    maxFindings: undefined,
    fresh: false,
  };
}

async function loadTiPriorDocument(tiPriorPath: string): Promise<TiPriorDocument | null> {
  if (!tiPriorPath) {
    return null;
  }

  try {
    const raw = await readFile(tiPriorPath, "utf-8");
    const parsed = JSON.parse(raw);
    if (!isRecord(parsed) || !Array.isArray(parsed["cwes"])) {
      return null;
    }
    return parsed as unknown as TiPriorDocument;
  } catch {
    return null;
  }
}

export const __taintAnalysisRefinementInternals = {
  applyDeterministicPatch,
  resolveAffectedPasses,
  extractPassId,
};
