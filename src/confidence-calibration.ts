/**
 * Fine-grained confidence calibration system.
 *
 * Instead of relying on a single self-reported confidence value, this module
 * computes a calibrated confidence from per-step evidence weights that are
 * updated post-verification via exponential moving average (EMA).
 */

import type Database from "better-sqlite3";
import type { EvidenceStep } from "./types.js";
import { safeJsonStringify } from "./utils/safe-json.js";

/** Recognized evidence step types for calibration. */
export const EVIDENCE_STEP_TYPES = [
  "source-reachability",
  "sink-danger",
  "sanitization-check",
  "config-review",
  "dataflow-trace",
  "exploit-feasibility",
  "framework-protection",
] as const;

export type EvidenceStepType = (typeof EVIDENCE_STEP_TYPES)[number];

export interface CalibrationWeight {
  stepType: string;
  ruleFamily: string;
  weight: number;
  sampleCount: number;
  updatedAt: string;
}

/** EMA smoothing factor for weight updates. */
const ALPHA = 0.1;

/** Weight bounds to prevent runaway values. */
const WEIGHT_MIN = 0.1;
const WEIGHT_MAX = 3.0;

/** Minimum samples before family-specific weights override global. */
const MIN_FAMILY_SAMPLES = 3;

/**
 * Extract a rule family heuristic from a rule ID.
 * e.g. "express.security.sqli.tainted" → "sqli"
 *      "python.django.security.xss" → "xss"
 */
export function extractRuleFamily(ruleId: string): string {
  const normalized = ruleId.toLowerCase();

  const families = [
    "sqli", "xss", "ssrf", "rce", "lfi", "rfi", "xxe",
    "idor", "csrf", "ssti", "nosqli", "cmdi", "path-traversal",
    "open-redirect", "deserialization", "auth-bypass",
  ];

  for (const family of families) {
    if (normalized.includes(family)) {
      return family;
    }
  }

  // Fall back to segments: pick the most specific-looking one
  const segments = ruleId.split(/[.\-_/]/);
  for (const seg of segments.reverse()) {
    const lower = seg.toLowerCase();
    if (lower.length > 2 && lower !== "security" && lower !== "tainted" && lower !== "audit") {
      return lower;
    }
  }

  return "__unknown__";
}

/**
 * Load calibration weights for a rule family, falling back to __global__.
 */
export function loadCalibrationWeights(
  db: Database.Database,
  ruleFamily: string,
): Map<string, CalibrationWeight> {
  const weights = new Map<string, CalibrationWeight>();

  // Load global weights first
  const globalRows = db.prepare(
    "SELECT step_type, rule_family, weight, sample_count, updated_at FROM calibration_weights WHERE rule_family = ?",
  ).all("__global__") as Array<{
    step_type: string;
    rule_family: string;
    weight: number;
    sample_count: number;
    updated_at: string;
  }>;

  for (const row of globalRows) {
    weights.set(row.step_type, {
      stepType: row.step_type,
      ruleFamily: row.rule_family,
      weight: row.weight,
      sampleCount: row.sample_count,
      updatedAt: row.updated_at,
    });
  }

  // Override with family-specific weights if they have enough samples
  if (ruleFamily !== "__global__") {
    const familyRows = db.prepare(
      "SELECT step_type, rule_family, weight, sample_count, updated_at FROM calibration_weights WHERE rule_family = ?",
    ).all(ruleFamily) as typeof globalRows;

    for (const row of familyRows) {
      if (row.sample_count >= MIN_FAMILY_SAMPLES) {
        weights.set(row.step_type, {
          stepType: row.step_type,
          ruleFamily: row.rule_family,
          weight: row.weight,
          sampleCount: row.sample_count,
          updatedAt: row.updated_at,
        });
      }
    }
  }

  return weights;
}

/**
 * Compute calibrated confidence from evidence steps and calibration weights.
 * Returns the weighted average of step confidences, or a simple average
 * when no weights exist (cold start).
 */
export function computeCalibratedConfidence(
  evidenceChain: EvidenceStep[],
  weights: Map<string, CalibrationWeight>,
): number {
  if (evidenceChain.length === 0) {
    return 0;
  }

  let weightedSum = 0;
  let totalWeight = 0;

  for (const step of evidenceChain) {
    const w = weights.get(step.stepType)?.weight ?? 1.0;
    weightedSum += step.confidence * w;
    totalWeight += w;
  }

  if (totalWeight === 0) {
    return 0;
  }

  return Math.max(0, Math.min(1, weightedSum / totalWeight));
}

/**
 * Update calibration weights after verification determines correctness.
 * Uses EMA to smoothly adjust weights over time.
 */
export function updateCalibrationWeights(
  db: Database.Database,
  evidenceChain: EvidenceStep[],
  ruleFamily: string,
  wasCorrect: boolean,
): void {
  const now = new Date().toISOString();
  const upsertStmt = db.prepare(`
    INSERT INTO calibration_weights (step_type, rule_family, weight, sample_count, updated_at)
    VALUES (?, ?, ?, 1, ?)
    ON CONFLICT(step_type, rule_family) DO UPDATE SET
      weight = ?,
      sample_count = sample_count + 1,
      updated_at = ?
  `);

  // Update both family-specific and global weights
  for (const family of [ruleFamily, "__global__"]) {
    for (const step of evidenceChain) {
      // Load current weight
      const row = db.prepare(
        "SELECT weight FROM calibration_weights WHERE step_type = ? AND rule_family = ?",
      ).get(step.stepType, family) as { weight: number } | undefined;

      const oldWeight = row?.weight ?? 1.0;
      const direction = wasCorrect ? 1.05 : 0.95;
      const newWeight = Math.max(
        WEIGHT_MIN,
        Math.min(WEIGHT_MAX, (1 - ALPHA) * oldWeight + ALPHA * (oldWeight * direction)),
      );

      upsertStmt.run(
        step.stepType,
        family,
        newWeight,
        now,
        newWeight,
        now,
      );
    }
  }
}

/**
 * Ensure the calibration_weights table and findings columns exist.
 */
export function ensureCalibrationSchema(db: Database.Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS calibration_weights (
      step_type     TEXT NOT NULL,
      rule_family   TEXT NOT NULL,
      weight        REAL NOT NULL DEFAULT 1.0,
      sample_count  INTEGER NOT NULL DEFAULT 0,
      updated_at    TEXT NOT NULL,
      PRIMARY KEY (step_type, rule_family)
    )
  `);

  const columns = db.prepare("PRAGMA table_info(findings)").all() as Array<{ name: string }>;
  const names = new Set(columns.map((c) => c.name));

  if (!names.has("calibrated_confidence")) {
    db.exec("ALTER TABLE findings ADD COLUMN calibrated_confidence REAL");
  }
  if (!names.has("evidence_chain_json")) {
    db.exec("ALTER TABLE findings ADD COLUMN evidence_chain_json TEXT");
  }
}

/**
 * Persist calibrated confidence and evidence chain on a finding row.
 */
export function updateFindingCalibration(
  db: Database.Database,
  fingerprint: string,
  calibratedConfidence: number,
  evidenceChain: EvidenceStep[],
): void {
  db.prepare(`
    UPDATE findings
    SET calibrated_confidence = ?, evidence_chain_json = ?, updated_at = datetime('now')
    WHERE fingerprint = ?
  `).run(calibratedConfidence, safeJsonStringify(evidenceChain), fingerprint);
}

/**
 * Format calibration weights into a prompt section showing investigation priorities.
 * Returns empty string if no weights are available.
 */
export function formatCalibrationWeightsForPrompt(
  weights: Map<string, CalibrationWeight>,
): string {
  if (weights.size === 0) {
    return "";
  }

  // Sort by weight descending to show most predictive steps first
  const sorted = [...weights.values()]
    .filter((w) => w.sampleCount >= 2)
    .sort((a, b) => b.weight - a.weight);

  if (sorted.length === 0) {
    return "";
  }

  const lines = [
    "## Investigation Priority (Learned)",
    "Based on historical accuracy, these investigation steps are most predictive for this vulnerability type:",
  ];

  for (const w of sorted) {
    const label = w.stepType.replace(/-/g, " ");
    lines.push(`- ${label} (weight ${w.weight.toFixed(2)}, ${w.sampleCount} samples)`);
  }

  lines.push("", "Prioritize higher-weighted investigation steps for more accurate triage.");

  return lines.join("\n");
}
