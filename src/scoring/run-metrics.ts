import type { Finding } from "../scanners/types.js";
import type { PipelineStats } from "../bus/events.js";

export interface DurationBreakdown {
  scan: number;
  triage: number;
  verify?: number;
  pocHarness?: number;
  dynamicAnalysis?: number;
  total: number;
}

export interface CostBreakdown {
  triage: number;
  verify: number;
  pocHarness: number;
  dynamicAnalysis: number;
  variantAnalysis: number;
  total: number;
}

export interface StructuredEvidenceMetrics {
  findingsWithTaintPath: number;
  proofStateCounts: Record<string, number>;
  engineKindCounts: Record<string, number>;
}

export interface RunMetrics {
  verdictCounts: Record<string, number>;
  severityCounts: Record<string, number>;
  scannerYield: Record<string, number>;
  averageConfidence: number;
  tpRate: number;
  fpRate: number;
  durationBreakdown: DurationBreakdown;
  costBreakdown: CostBreakdown;
  exploitabilityRate?: number;
  structuredEvidence: StructuredEvidenceMetrics;
  classifierDrops?: number;
  corroboratedClusters?: number;
  verificationOutcomes?: {
    exploitable: number;
    notExploitable: number;
    errors: number;
  };
  pocOutcomes?: {
    generated: number;
    skipped: number;
    errors: number;
  };
  assertionSummary?: {
    totalAssertions: number;
    passedAssertions: number;
    averageQualityScore: number;
    perAssertion: Record<string, { passed: number; failed: number; avgScore: number }>;
  };
  promptHash?: string;
}

export interface StageTimestamps {
  pipelineStart: string;
  pipelineEnd: string;
  scanStart?: string;
  scanEnd?: string;
  triageStart?: string;
  triageEnd?: string;
  verifyStart?: string;
  verifyEnd?: string;
  pocStart?: string;
  pocEnd?: string;
  dynamicStart?: string;
  dynamicEnd?: string;
}

export interface StageCosts {
  triage: number;
  verify: number;
  pocHarness: number;
  dynamicAnalysis: number;
  variantAnalysis: number;
}

function msBetween(start: string | undefined, end: string | undefined): number {
  if (!start || !end) {
    return 0;
  }
  const diff = new Date(end).getTime() - new Date(start).getTime();
  return diff > 0 ? diff : 0;
}

export function computeRunMetrics(
  findings: Finding[],
  timestamps: StageTimestamps,
  costs: StageCosts,
  pipelineStats?: Partial<PipelineStats>,
): RunMetrics {
  // Verdict counts
  const verdictCounts: Record<string, number> = {};
  const severityCounts: Record<string, number> = {};
  const scannerYield: Record<string, number> = {};
  const proofStateCounts: Record<string, number> = {};
  const engineKindCounts: Record<string, number> = {};
  let findingsWithTaintPath = 0;
  let totalConfidence = 0;
  let confidenceCount = 0;

  for (const f of findings) {
    // Count verdicts — findings don't carry a verdict directly, but downstream
    // consumers pass triaged findings with a verdict attached.  We handle both
    // the canonical Finding shape (no verdict) and the enriched shape used in
    // pipeline stats.
    const record = f as unknown as Record<string, unknown>;
    const verdict = record["verdict"] as string | undefined;
    if (verdict) {
      verdictCounts[verdict] = (verdictCounts[verdict] ?? 0) + 1;
    }

    // Severity distribution
    const sev = f.severity.toUpperCase();
    severityCounts[sev] = (severityCounts[sev] ?? 0) + 1;

    // Scanner yield
    scannerYield[f.scanner] = (scannerYield[f.scanner] ?? 0) + 1;

    // Confidence accumulation
    const confidence = record["confidence"] as number | undefined;
    if (typeof confidence === "number" && Number.isFinite(confidence)) {
      totalConfidence += confidence;
      confidenceCount += 1;
    }

    if (Array.isArray(f.taintPath) && f.taintPath.length > 0) {
      findingsWithTaintPath += 1;
    }

    if (typeof f.proofState === "string" && f.proofState.length > 0) {
      proofStateCounts[f.proofState] = (proofStateCounts[f.proofState] ?? 0) + 1;
    }

    const engineKinds = new Set(
      (f.engineProvenance ?? [])
        .map((entry) => entry.kind)
        .filter((kind) => typeof kind === "string" && kind.length > 0),
    );
    for (const kind of engineKinds) {
      engineKindCounts[kind] = (engineKindCounts[kind] ?? 0) + 1;
    }
  }

  const total = Object.values(verdictCounts).reduce((s, n) => s + n, 0);
  const tp = verdictCounts["tp"] ?? 0;
  const fp = verdictCounts["fp"] ?? 0;
  const tpRate = total > 0 ? tp / total : 0;
  const fpRate = total > 0 ? fp / total : 0;
  const averageConfidence = confidenceCount > 0 ? totalConfidence / confidenceCount : 0;

  // Duration breakdown
  const scanDuration = msBetween(timestamps.scanStart, timestamps.scanEnd);
  const triageDuration = msBetween(timestamps.triageStart, timestamps.triageEnd);
  const verifyDuration = msBetween(timestamps.verifyStart, timestamps.verifyEnd);
  const pocDuration = msBetween(timestamps.pocStart, timestamps.pocEnd);
  const dynamicDuration = msBetween(timestamps.dynamicStart, timestamps.dynamicEnd);
  const totalDuration = msBetween(timestamps.pipelineStart, timestamps.pipelineEnd);

  const durationBreakdown: DurationBreakdown = {
    scan: scanDuration,
    triage: triageDuration,
    total: totalDuration,
  };
  if (verifyDuration > 0) {
    durationBreakdown.verify = verifyDuration;
  }
  if (pocDuration > 0) {
    durationBreakdown.pocHarness = pocDuration;
  }
  if (dynamicDuration > 0) {
    durationBreakdown.dynamicAnalysis = dynamicDuration;
  }

  // Cost breakdown
  const costTotal = costs.triage + costs.verify + costs.pocHarness + costs.dynamicAnalysis + costs.variantAnalysis;
  const costBreakdown: CostBreakdown = {
    triage: costs.triage,
    verify: costs.verify,
    pocHarness: costs.pocHarness,
    dynamicAnalysis: costs.dynamicAnalysis,
    variantAnalysis: costs.variantAnalysis,
    total: costTotal,
  };

  // Exploitability rate
  let exploitabilityRate: number | undefined;
  const records = findings as unknown as Array<Record<string, unknown>>;
  const exploitable = records.filter(
    (f) => f["verifyExploitable"] === 1 || f["verifyExploitable"] === true,
  ).length;
  const verified = records.filter(
    (f) => f["verifyExploitable"] != null,
  ).length;
  if (verified > 0) {
    exploitabilityRate = exploitable / verified;
  }

  const structuredEvidence: StructuredEvidenceMetrics = {
    findingsWithTaintPath,
    proofStateCounts,
    engineKindCounts,
  };

  // Pipeline stats propagation
  const classifierDrops = pipelineStats?.skippedByClassifier;
  const corroboratedClusters = pipelineStats?.corroboratedClusters;

  const verifiedCount = pipelineStats?.verified ?? 0;
  const verifyErrors = pipelineStats?.verifyErrors ?? 0;
  let verificationOutcomes: RunMetrics["verificationOutcomes"];
  if (verifiedCount > 0 || verifyErrors > 0) {
    verificationOutcomes = {
      exploitable: exploitable,
      notExploitable: verifiedCount - exploitable,
      errors: verifyErrors,
    };
  }

  const pocGenerated = pipelineStats?.pocHarnessGenerated ?? 0;
  const pocSkipped = pipelineStats?.pocHarnessSkipped ?? 0;
  const pocErrors = pipelineStats?.pocHarnessErrors ?? 0;
  let pocOutcomes: RunMetrics["pocOutcomes"];
  if (pocGenerated > 0 || pocSkipped > 0 || pocErrors > 0) {
    pocOutcomes = {
      generated: pocGenerated,
      skipped: pocSkipped,
      errors: pocErrors,
    };
  }

  return {
    verdictCounts,
    severityCounts,
    scannerYield,
    averageConfidence,
    tpRate,
    fpRate,
    durationBreakdown,
    costBreakdown,
    exploitabilityRate,
    structuredEvidence,
    classifierDrops,
    corroboratedClusters,
    verificationOutcomes,
    pocOutcomes,
  };
}

function formatDuration(ms: number): string {
  if (ms < 1000) {
    return `${ms}ms`;
  }
  const seconds = ms / 1000;
  if (seconds < 60) {
    return `${seconds.toFixed(1)}s`;
  }
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  return `${minutes}m ${remainingSeconds.toFixed(0)}s`;
}

export function formatMetricsSummary(metrics: RunMetrics): string {
  const lines: string[] = [];

  lines.push("--- Run Metrics ---");
  lines.push("");

  // Verdict breakdown
  lines.push("Verdict Breakdown:");
  const total = Object.values(metrics.verdictCounts).reduce((s, n) => s + n, 0);
  for (const [verdict, count] of Object.entries(metrics.verdictCounts)) {
    const pct = total > 0 ? ((count / total) * 100).toFixed(1) : "0.0";
    lines.push(`  ${verdict}: ${count} (${pct}%)`);
  }
  lines.push(`  TP Rate: ${(metrics.tpRate * 100).toFixed(1)}%`);
  lines.push(`  FP Rate: ${(metrics.fpRate * 100).toFixed(1)}%`);
  lines.push("");

  // Severity distribution
  lines.push("Severity Distribution:");
  for (const [severity, count] of Object.entries(metrics.severityCounts)) {
    lines.push(`  ${severity}: ${count}`);
  }
  lines.push("");

  // Scanner yield
  lines.push("Scanner Yield:");
  for (const [scanner, count] of Object.entries(metrics.scannerYield)) {
    lines.push(`  ${scanner}: ${count} findings`);
  }
  lines.push("");

  // Average confidence
  lines.push(`Average Confidence: ${(metrics.averageConfidence * 100).toFixed(1)}%`);
  lines.push("");

  // Exploitability rate
  if (metrics.exploitabilityRate != null) {
    lines.push(`Exploitability Rate: ${(metrics.exploitabilityRate * 100).toFixed(1)}%`);
    lines.push("");
  }

  lines.push("Structured Evidence:");
  lines.push(`  Findings With Taint Path: ${metrics.structuredEvidence.findingsWithTaintPath}`);
  const proofEntries = Object.entries(metrics.structuredEvidence.proofStateCounts);
  if (proofEntries.length > 0) {
    lines.push(`  Proof States: ${proofEntries.map(([state, count]) => `${state}=${count}`).join(", ")}`);
  }
  const engineEntries = Object.entries(metrics.structuredEvidence.engineKindCounts);
  if (engineEntries.length > 0) {
    lines.push(`  Engine Provenance: ${engineEntries.map(([kind, count]) => `${kind}=${count}`).join(", ")}`);
  }
  lines.push("");

  // Duration breakdown
  lines.push("Duration Breakdown:");
  lines.push(`  Scan:    ${formatDuration(metrics.durationBreakdown.scan)}`);
  lines.push(`  Triage:  ${formatDuration(metrics.durationBreakdown.triage)}`);
  if (metrics.durationBreakdown.verify != null) {
    lines.push(`  Verify:  ${formatDuration(metrics.durationBreakdown.verify)}`);
  }
  if (metrics.durationBreakdown.pocHarness != null) {
    lines.push(`  PoC:     ${formatDuration(metrics.durationBreakdown.pocHarness)}`);
  }
  lines.push(`  Total:   ${formatDuration(metrics.durationBreakdown.total)}`);
  lines.push("");

  // Pipeline quality
  if (metrics.classifierDrops != null && metrics.classifierDrops > 0) {
    lines.push(`Classifier Drops: ${metrics.classifierDrops}`);
  }
  if (metrics.corroboratedClusters != null && metrics.corroboratedClusters > 0) {
    lines.push(`Corroborated Clusters: ${metrics.corroboratedClusters}`);
  }
  if (metrics.verificationOutcomes) {
    const v = metrics.verificationOutcomes;
    lines.push(`Verification: ${v.exploitable} exploitable, ${v.notExploitable} not exploitable, ${v.errors} errors`);
  }
  if (metrics.pocOutcomes) {
    const p = metrics.pocOutcomes;
    lines.push(`PoC Generation: ${p.generated} generated, ${p.skipped} skipped, ${p.errors} errors`);
  }
  if (metrics.classifierDrops || metrics.corroboratedClusters || metrics.verificationOutcomes || metrics.pocOutcomes) {
    lines.push("");
  }

  // Cost breakdown
  lines.push("Cost Breakdown:");
  lines.push(`  Triage:           $${metrics.costBreakdown.triage.toFixed(4)}`);
  lines.push(`  Verify:           $${metrics.costBreakdown.verify.toFixed(4)}`);
  lines.push(`  PoC Harness:      $${metrics.costBreakdown.pocHarness.toFixed(4)}`);
  lines.push(`  Variant Analysis: $${metrics.costBreakdown.variantAnalysis.toFixed(4)}`);
  lines.push(`  Total:            $${metrics.costBreakdown.total.toFixed(4)}`);

  return lines.join("\n");
}
