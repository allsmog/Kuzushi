import type { CorroboratingSignal, Finding } from "../scanners/types.js";
import type { GeneratedRule, StrategyEvidence, StrategyResult } from "./types.js";

export interface MergedStrategyResult {
  findings: Finding[];
  evidence: StrategyEvidence[];
  strategyAgreement: "unanimous" | "majority" | "disagreement" | "single";
  confidenceBoost: number;
  flagForReview: boolean;
  generatedRules: GeneratedRule[];
}

interface TaggedFinding {
  finding: Finding;
  strategyKind: string;
  strategyId: string;
}

/** Group findings by location (same file + line within tolerance). */
function groupByLocation(
  tagged: TaggedFinding[],
  tolerance: number = 5,
): Map<string, TaggedFinding[]> {
  const groups = new Map<string, TaggedFinding[]>();
  const sorted = [...tagged].sort(
    (a, b) =>
      a.finding.filePath.localeCompare(b.finding.filePath) ||
      a.finding.startLine - b.finding.startLine,
  );

  for (const item of sorted) {
    let matched = false;
    for (const [key, group] of groups) {
      const ref = group[0]!.finding;
      if (
        ref.filePath === item.finding.filePath &&
        Math.abs(ref.startLine - item.finding.startLine) <= tolerance
      ) {
        group.push(item);
        matched = true;
        break;
      }
    }
    if (!matched) {
      const key = `${item.finding.filePath}:${item.finding.startLine}`;
      groups.set(key, [item]);
    }
  }

  return groups;
}

/** Select the best finding from a group (highest score). */
function selectBestFinding(group: TaggedFinding[]): TaggedFinding {
  return group.reduce((best, current) =>
    (current.finding.adjustedScore ?? current.finding.score) >
    (best.finding.adjustedScore ?? best.finding.score)
      ? current
      : best,
  );
}

/** Merge results from multiple strategies into a unified set of findings. */
export function mergeStrategyResults(results: StrategyResult[]): MergedStrategyResult {
  if (results.length === 0) {
    return {
      findings: [],
      evidence: [],
      strategyAgreement: "single",
      confidenceBoost: 0,
      flagForReview: false,
      generatedRules: [],
    };
  }

  // Collect all findings with their strategy tags
  const allTagged: TaggedFinding[] = results.flatMap((r) =>
    r.findings.map((f) => ({
      finding: f,
      strategyKind: r.strategyKind,
      strategyId: r.strategyId,
    })),
  );

  // Group by location
  const groups = groupByLocation(allTagged);

  const merged: Finding[] = [];
  let overallAgreement: MergedStrategyResult["strategyAgreement"] = "single";
  let flagForReview = false;

  const strategiesThatRan = new Set(results.map((r) => r.strategyKind));

  for (const group of groups.values()) {
    const uniqueStrategies = new Set(group.map((g) => g.strategyKind));
    const best = selectBestFinding(group);

    // Confidence boosting: +5% per additional corroborating strategy, capped at +15%
    const corroborationCount = uniqueStrategies.size;
    const confidenceBoost = Math.min(0.15, (corroborationCount - 1) * 0.05);

    // Check for disagreement
    const strategiesThatFound = uniqueStrategies;
    const strategiesThatMissed = new Set(
      [...strategiesThatRan].filter((s) => !strategiesThatFound.has(s)),
    );

    if (
      strategiesThatFound.size > 0 &&
      strategiesThatMissed.size > 0 &&
      strategiesThatRan.size >= 3
    ) {
      if (strategiesThatFound.size >= strategiesThatMissed.size) {
        overallAgreement = "majority";
      } else {
        overallAgreement = "disagreement";
        flagForReview = true;
      }
    } else if (strategiesThatFound.size === strategiesThatRan.size && strategiesThatRan.size > 1) {
      overallAgreement = "unanimous";
    }

    // Build corroborating signals from other strategies
    const corroboratingSignals: CorroboratingSignal[] = group
      .filter((g) => g.finding.fingerprint !== best.finding.fingerprint)
      .map((g) => ({
        taskId: `strategy:${g.strategyId}`,
        fingerprint: g.finding.fingerprint,
        ruleId: g.finding.ruleId,
        filePath: g.finding.filePath,
        startLine: g.finding.startLine,
        cwe: g.finding.cwe,
        score: g.finding.score,
      }));

    merged.push({
      ...best.finding,
      adjustedScore: Math.min(
        100,
        (best.finding.adjustedScore ?? best.finding.score) + confidenceBoost * 100,
      ),
      corroboratingSignals: [...(best.finding.corroboratingSignals ?? []), ...corroboratingSignals],
      engineProvenance: [
        ...(best.finding.engineProvenance ?? []),
        ...group.map((g) => ({
          kind: "agentic" as const,
          detail: `strategy:${g.strategyId}`,
        })),
      ],
    });
  }

  // Compute overall confidence boost (max across groups)
  let maxBoost = 0;
  for (const group of groups.values()) {
    const uniqueStrategies = new Set(group.map((g) => g.strategyKind));
    const boost = Math.min(0.15, (uniqueStrategies.size - 1) * 0.05);
    if (boost > maxBoost) maxBoost = boost;
  }

  return {
    findings: merged,
    evidence: results.flatMap((r) => r.evidence),
    strategyAgreement: overallAgreement,
    confidenceBoost: maxBoost,
    flagForReview,
    generatedRules: results.flatMap((r) => r.generatedRules ?? []),
  };
}
