import type Database from "better-sqlite3";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import type { TaskRegistry } from "../../agents/registry.js";
import type { TaskContext } from "../../agents/types.js";
import { taintAnalysisRunTask } from "../../agents/tasks/taint-analysis/analyze.js";
import { buildTaintModelDocument } from "../../agents/tasks/taint-analysis/label.js";
import type { TiPriorDocument } from "../../agents/tasks/taint-analysis/ti-prior.js";
import type { TaintAnalysisLabelOutput, TaintAnalysisLabelsDocument, TaintAnalysisPassEntry, TaintAnalysisPassId } from "../../agents/tasks/taint-analysis/types.js";
import type { ScanOpts, TriageResult, KuzushiConfig, RepoContext } from "../../types.js";
import type { Finding } from "../../scanners/types.js";
import type { ScannerRegistry } from "../../scanners/registry.js";
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
}

interface RefinementSignals {
  sourceFalsePositive: boolean;
  sinkFalsePositive: boolean;
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

      const refinedLabels = applyDeterministicPatch(labelOutput.labels, signalsByPass);
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
        repoRoot: context.scanPath ?? context.repoRoot,
        scanPath: context.scanPath,
        repoName: context.repoName,
        config: deps.config,
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
        repoContext: asRepoContext(event.payload.repoContext),
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
      hints: [],
    };

    if (source && source["is_false_positive"] === true) {
      signal.sourceFalsePositive = true;
    }
    if (sink && sink["is_false_positive"] === true) {
      signal.sinkFalsePositive = true;
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
): TaintAnalysisLabelsDocument {
  const cloned = JSON.parse(JSON.stringify(labels)) as TaintAnalysisLabelsDocument;
  for (const pass of cloned.passes) {
    const signal = signalsByPass.get(pass.pass_id);
    if (!signal) {
      continue;
    }
    if (signal.sourceFalsePositive) {
      downgradeEntries(pass.entries, "source");
    }
    if (signal.sinkFalsePositive) {
      downgradeEntries(pass.entries, "sink");
    }
    if (!signal.sourceFalsePositive && !signal.sinkFalsePositive && signal.hints.length > 0) {
      downgradeEntries(pass.entries, "sink");
    }
  }
  return cloned;
}

function downgradeEntries(entries: TaintAnalysisPassEntry[], role: TaintAnalysisPassEntry["role"]): void {
  const candidates = entries
    .filter((entry) => entry.role === role && entry.classification !== "fp")
    .sort((a, b) => a.confidence - b.confidence);
  for (const entry of candidates.slice(0, 3)) {
    entry.classification = "fp";
    entry.rationale = `${entry.rationale} [refinement: downgraded due to triage false-positive signals]`;
    entry.confidence = Math.min(entry.confidence, 0.3);
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
    let triaged = 0;
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
      triaged += 1;
    }

    return {
      triaged,
      errors: args.deltaFindings.length,
      costUsd: 0,
    };
  }
}

function asRepoContext(value: unknown): RepoContext | undefined {
  if (!isRecord(value)) {
    return undefined;
  }

  const repoContext: RepoContext = {
    languages: asStringArray(value["languages"]),
    frameworks: asStringArray(value["frameworks"]),
    authPatterns: asStringArray(value["authPatterns"]),
    sanitizationLibs: asStringArray(value["sanitizationLibs"]),
    ormOrDb: asStringArray(value["ormOrDb"]),
    entryPoints: asStringArray(value["entryPoints"]),
  };

  const hasAny = repoContext.languages.length
    || repoContext.frameworks.length
    || repoContext.authPatterns.length
    || repoContext.sanitizationLibs.length
    || repoContext.ormOrDb.length
    || repoContext.entryPoints.length;

  return hasAny ? repoContext : undefined;
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value
    .map((item) => (typeof item === "string" ? item.trim() : ""))
    .filter(Boolean);
}

function isPassId(value: number): value is TaintAnalysisPassId {
  return value >= 1 && value <= 13;
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
  if (!value["labels"] || !value["workspaceDir"] || !value["labelsPath"] || !value["dbPath"]
    || !value["taintModelPath"] || !Array.isArray(value["passes"])) {
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
