/**
 * Extract summary data from the database for the UI.
 *
 * Separates data preparation from rendering — the same data powers
 * both the Ink ScanSummary component and the plain-text fallback.
 */

import path from "node:path";
import type Database from "better-sqlite3";
import type { PipelineStats } from "../bus/events.js";
import { getActionableFindings } from "../store.js";
import { loadThreatModelDocument, renderThreatModelContext } from "../threat-model-renderer.js";
import type { ExploitChain, Verdict } from "../types.js";
import type { ActionableFinding, SummaryData } from "./state.js";

export interface BuildSummaryOptions {
  stats?: Partial<PipelineStats>;
  runId?: string;
  repoRoot?: string;
  auditLog?: boolean;
  fingerprints?: string[];
  exploitChains?: ExploitChain[];
}

export function buildSummaryData(
  db: Database.Database,
  repo: string,
  options: BuildSummaryOptions = {},
): SummaryData {
  const fp = options.fingerprints;
  const allFindings = getActionableFindings(db, repo, {
    includeFalsePositives: true,
    fingerprints: fp,
  });

  const counts: Record<Verdict, number> = { tp: 0, fp: 0, needs_review: 0, by_design: 0 };
  for (const f of allFindings) {
    counts[f.verdict]++;
  }

  const triageCostUsd = options.stats?.totalCostUsd ?? 0;
  const verificationCostUsd =
    options.stats?.verifyCostUsd ?? allFindings.reduce((sum, f) => sum + (f.verifyCostUsd ?? 0), 0);
  const pocHarnessCostUsd =
    options.stats?.pocHarnessCostUsd ??
    allFindings.reduce((sum, f) => sum + (f.pocHarnessCostUsd ?? 0), 0);

  let exploitable = 0;
  let notExploitable = 0;
  let pocGenerated = 0;
  let pocSkipped = 0;
  for (const f of allFindings) {
    if (f.verifyExploitable === 1) exploitable++;
    else if (f.verifyExploitable === 0) notExploitable++;
    if (f.pocHarnessPath && !f.pocHarnessSkipped) pocGenerated++;
    if (f.pocHarnessSkipped === 1) pocSkipped++;
  }

  const actionable = allFindings
    .filter((f) => f.verdict !== "fp")
    .map(
      (f): ActionableFinding => ({
        verdict: f.verdict,
        confidence: f.confidence,
        severity: f.severity,
        taskId: f.taskId,
        filePath: f.filePath,
        startLine: f.startLine,
        ruleId: f.ruleId,
        rationale: f.rationale,
        fingerprint: f.fingerprint,
        verifyExploitable: f.verifyExploitable ?? undefined,
        verifyPocPayload: f.verifyPocPayload ?? undefined,
        verifyAttackVector: f.verifyAttackVector ?? undefined,
        proofState: f.proofState ?? undefined,
        engineProvenance: f.engineProvenance ?? undefined,
        taintPath: f.taintPath,
        corroboratingSignals: f.corroboratingSignals ?? [],
        suppressionReasons: f.suppressionReasons ?? [],
        pocHarnessPath: f.pocHarnessPath ?? undefined,
        pocHarnessSkipped: f.pocHarnessSkipped ?? undefined,
        pocHarnessSkipReason: f.pocHarnessSkipReason ?? undefined,
        pocHarnessParsed: f.pocHarnessParsed ?? undefined,
        pocHarnessParseError: f.pocHarnessParseError ?? undefined,
        pocRunVerdict: f.pocRunVerdict ?? undefined,
        pocRunDurationMs: f.pocRunDurationMs ?? undefined,
        codeCitations: f.codeCitations,
        attackPath: f.attackPath,
        assumptions: f.assumptions,
        controls: f.controls,
        blindspots: f.blindspots,
        sourceThreatIds: f.sourceThreatIds,
        verificationSteps: f.verificationSteps,
        blame: f.blame,
        introducedIn: f.introducedIn,
      }),
    );

  let threatModelSummary: string | undefined;
  if (options.repoRoot && options.runId) {
    const doc = loadThreatModelDocument(options.repoRoot, options.runId);
    if (doc) {
      threatModelSummary = renderThreatModelContext(doc);
    }
  }

  return {
    repoName: repo,
    verdictCounts: counts,
    totalTriaged: counts.tp + counts.fp + counts.needs_review,
    triageCostUsd,
    verificationCostUsd,
    pocHarnessCostUsd,
    variantAnalysisCostUsd: options.stats?.variantAnalysisCostUsd ?? 0,
    exploitable,
    notExploitable,
    pocGenerated,
    pocSkipped,
    triageErrors: options.stats?.triageErrors ?? 0,
    verifyErrors: options.stats?.verifyErrors ?? 0,
    pocHarnessErrors: options.stats?.pocHarnessErrors ?? 0,
    skippedLowConfidence: options.stats?.skippedLowConfidence ?? 0,
    skippedByFpFilter: options.stats?.skippedByFpFilter ?? 0,
    softSuppressedFindings: options.stats?.softSuppressedFindings ?? 0,
    skippedByLlmRescore: options.stats?.skippedByLlmRescore ?? 0,
    corroboratedClusters: options.stats?.corroboratedClusters ?? 0,
    verifyGateAutoAccepted: options.stats?.verifyGateAutoAccepted ?? 0,
    verifyGateSkipped: options.stats?.verifyGateSkipped ?? 0,
    variantFindings: options.stats?.variantFindings ?? 0,
    dynamicConfirmed: options.stats?.dynamicConfirmed ?? 0,
    dynamicInteresting: options.stats?.dynamicInteresting ?? 0,
    dynamicRejected: options.stats?.dynamicRejected ?? 0,
    dynamicErrors: options.stats?.dynamicErrors ?? 0,
    dynamicCostUsd: options.stats?.dynamicCostUsd ?? 0,
    incrementalCachedFiles: options.stats?.incrementalCachedFiles ?? 0,
    incrementalRescannedFiles: options.stats?.incrementalRescannedFiles ?? 0,
    incrementalDepExpandedFiles: options.stats?.incrementalDepExpandedFiles ?? 0,
    patchGenerated: options.stats?.patchGenerated ?? 0,
    patchVerified: options.stats?.patchVerified ?? 0,
    patchFailed: options.stats?.patchFailed ?? 0,
    patchErrors: options.stats?.patchErrors ?? 0,
    patchCostUsd: options.stats?.patchCostUsd ?? 0,
    budgetExceeded: options.stats?.budgetExceeded ?? false,
    failedTasks: options.stats?.failedTasks ?? [],
    extractionDegradation: options.stats?.extractionDegradation,
    stitchDegradation: options.stats?.stitchDegradation,
    tiPriorDegraded: options.stats?.tiPriorDegraded ?? false,
    runMetrics: options.stats?.runMetrics,
    auditLogDir:
      options.auditLog && options.repoRoot && options.runId
        ? path.join(options.repoRoot, ".kuzushi", "runs", options.runId)
        : undefined,
    pocOutputDir:
      (pocGenerated > 0 || pocSkipped > 0) && options.repoRoot
        ? path.join(options.repoRoot, ".kuzushi", "poc")
        : undefined,
    threatModelSummary,
    exploitChains: options.exploitChains ?? [],
    actionableFindings: actionable,
  };
}
