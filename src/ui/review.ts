/**
 * Interactive finding review entry point.
 *
 * Queries the DB for needs_review findings and renders an Ink app
 * where the user can confirm/reject each finding with a keypress.
 */
import type Database from "better-sqlite3";
import { getActionableFindings, updateFindingVerdict } from "../store.js";
import type { Verdict } from "../types.js";
import type { ActionableFinding, UIStore, UIMode } from "./state.js";

export interface ReviewResult {
  reviewed: number;
  tp: number;
  fp: number;
  byDesign: number;
  skipped: number;
}

/**
 * Run interactive review mode.
 *
 * @returns Review result summary, or null if no findings to review.
 */
export async function runInteractiveReview(
  db: Database.Database,
  repo: string,
  store?: UIStore,
  returnMode: UIMode = "summary",
): Promise<ReviewResult | null> {
  if (!process.stdout.isTTY) {
    return null;
  }

  // Query needs_review findings
  const allFindings = getActionableFindings(db, repo, { includeFalsePositives: false });
  const needsReview = allFindings.filter((f) => f.verdict === "needs_review");

  if (needsReview.length === 0) {
    return null;
  }

  // Map StoredFindingRecord to ActionableFinding for the UI
  // Map StoredFindingRecord (null fields) to ActionableFinding (undefined fields)
  const findings: ActionableFinding[] = needsReview.map((f) => ({
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
  }));

  const result: ReviewResult = { reviewed: 0, tp: 0, fp: 0, byDesign: 0, skipped: 0 };

  if (store) {
    return await new Promise<ReviewResult>((resolve) => {
      store.setReview({
        findings,
        onVerdict: (fingerprint: string, verdict: Verdict) => {
          updateFindingVerdict(db, fingerprint, verdict);
          result.reviewed++;
          if (verdict === "tp") result.tp++;
          else if (verdict === "fp") result.fp++;
          else if (verdict === "by_design") result.byDesign++;
        },
        onQuit: () => {
          store.setReview(null);
          resolve(result);
        },
      }, returnMode);
    });
  }

  // Backward-compatible fallback when no shared UI store is present.
  const { render } = await import("ink");
  const { createElement } = await import("react");
  const { InteractiveReview } = await import("./components/InteractiveReview.js");

  await new Promise<void>((resolve) => {
    const instance = render(
      createElement(InteractiveReview, {
        findings,
        onVerdict: (fingerprint: string, verdict: Verdict) => {
          updateFindingVerdict(db, fingerprint, verdict);
          result.reviewed++;
          if (verdict === "tp") result.tp++;
          else if (verdict === "fp") result.fp++;
          else if (verdict === "by_design") result.byDesign++;
        },
        onQuit: () => {
          instance.unmount();
          resolve();
        },
      }),
    );
  });

  return result;
}
