import Database from "better-sqlite3";
import { describe, expect, it } from "vitest";
import {
  type CalibrationWeight,
  computeCalibratedConfidence,
  extractRuleFamily,
  loadCalibrationWeights,
  updateCalibrationWeights,
} from "../src/confidence-calibration.js";
import { migration100 } from "../src/migrations/100_schema_reset.js";

function createTestDb(): Database.Database {
  const db = new Database(":memory:");
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = OFF");
  migration100.up(db);
  return db;
}

describe("extractRuleFamily", () => {
  it("extracts sqli from rule id", () => {
    expect(extractRuleFamily("express.security.sqli.tainted")).toBe("sqli");
  });

  it("extracts xss from rule id", () => {
    expect(extractRuleFamily("python.django.security.xss")).toBe("xss");
  });

  it("extracts ssrf from rule id", () => {
    expect(extractRuleFamily("java.spring.ssrf.request")).toBe("ssrf");
  });

  it("falls back to last meaningful segment", () => {
    expect(extractRuleFamily("custom.rule.something")).toBe("something");
  });

  it("returns __unknown__ for very short segments", () => {
    expect(extractRuleFamily("a.b")).toBe("__unknown__");
  });

  it("is case-insensitive", () => {
    expect(extractRuleFamily("Express.Security.SQLI.Tainted")).toBe("sqli");
  });
});

describe("computeCalibratedConfidence", () => {
  it("returns 0 for empty chain", () => {
    expect(computeCalibratedConfidence([], new Map())).toBe(0);
  });

  it("returns simple average with no weights (cold start)", () => {
    const chain: EvidenceStep[] = [
      { stepType: "source-reachability", description: "test", confidence: 0.8, evidence: "e1" },
      { stepType: "sink-danger", description: "test", confidence: 0.4, evidence: "e2" },
    ];
    const result = computeCalibratedConfidence(chain, new Map());
    expect(result).toBeCloseTo(0.6, 5);
  });

  it("applies weights correctly", () => {
    const chain: EvidenceStep[] = [
      { stepType: "source-reachability", description: "test", confidence: 0.8, evidence: "e1" },
      { stepType: "sink-danger", description: "test", confidence: 0.4, evidence: "e2" },
    ];
    const weights = new Map<string, CalibrationWeight>([
      [
        "source-reachability",
        {
          stepType: "source-reachability",
          ruleFamily: "__global__",
          weight: 2.0,
          sampleCount: 5,
          updatedAt: "",
        },
      ],
      [
        "sink-danger",
        {
          stepType: "sink-danger",
          ruleFamily: "__global__",
          weight: 1.0,
          sampleCount: 5,
          updatedAt: "",
        },
      ],
    ]);
    // weighted: (0.8 * 2.0 + 0.4 * 1.0) / (2.0 + 1.0) = 2.0 / 3.0 = 0.6667
    const result = computeCalibratedConfidence(chain, weights);
    expect(result).toBeCloseTo(0.6667, 3);
  });

  it("clamps result to [0, 1]", () => {
    const chain: EvidenceStep[] = [
      { stepType: "source-reachability", description: "test", confidence: 1.0, evidence: "e" },
    ];
    const weights = new Map<string, CalibrationWeight>([
      [
        "source-reachability",
        {
          stepType: "source-reachability",
          ruleFamily: "__global__",
          weight: 3.0,
          sampleCount: 5,
          updatedAt: "",
        },
      ],
    ]);
    expect(computeCalibratedConfidence(chain, weights)).toBe(1);
  });

  it("uses default weight of 1.0 for unknown step types", () => {
    const chain: EvidenceStep[] = [
      { stepType: "unknown-type", description: "test", confidence: 0.5, evidence: "e" },
    ];
    expect(computeCalibratedConfidence(chain, new Map())).toBe(0.5);
  });
});

describe("loadCalibrationWeights", () => {
  it("returns empty map when no weights exist", () => {
    const db = createTestDb();
    const weights = loadCalibrationWeights(db, "sqli");
    expect(weights.size).toBe(0);
    db.close();
  });

  it("loads global weights", () => {
    const db = createTestDb();
    db.prepare(
      "INSERT INTO calibration_weights (step_type, rule_family, weight, sample_count, updated_at) VALUES (?, ?, ?, ?, ?)",
    ).run("source-reachability", "__global__", 1.5, 10, new Date().toISOString());

    const weights = loadCalibrationWeights(db, "sqli");
    expect(weights.get("source-reachability")?.weight).toBe(1.5);
    db.close();
  });

  it("overrides global with family-specific when sample count >= 3", () => {
    const db = createTestDb();
    const now = new Date().toISOString();
    db.prepare(
      "INSERT INTO calibration_weights (step_type, rule_family, weight, sample_count, updated_at) VALUES (?, ?, ?, ?, ?)",
    ).run("source-reachability", "__global__", 1.0, 10, now);
    db.prepare(
      "INSERT INTO calibration_weights (step_type, rule_family, weight, sample_count, updated_at) VALUES (?, ?, ?, ?, ?)",
    ).run("source-reachability", "sqli", 2.5, 3, now);

    const weights = loadCalibrationWeights(db, "sqli");
    expect(weights.get("source-reachability")?.weight).toBe(2.5);
    db.close();
  });

  it("ignores family-specific weights with sample count < 3", () => {
    const db = createTestDb();
    const now = new Date().toISOString();
    db.prepare(
      "INSERT INTO calibration_weights (step_type, rule_family, weight, sample_count, updated_at) VALUES (?, ?, ?, ?, ?)",
    ).run("source-reachability", "__global__", 1.0, 10, now);
    db.prepare(
      "INSERT INTO calibration_weights (step_type, rule_family, weight, sample_count, updated_at) VALUES (?, ?, ?, ?, ?)",
    ).run("source-reachability", "sqli", 2.5, 2, now);

    const weights = loadCalibrationWeights(db, "sqli");
    expect(weights.get("source-reachability")?.weight).toBe(1.0);
    db.close();
  });
});

describe("updateCalibrationWeights", () => {
  it("creates new weights when none exist", () => {
    const db = createTestDb();
    const chain: EvidenceStep[] = [
      { stepType: "source-reachability", description: "test", confidence: 0.8, evidence: "e" },
    ];

    updateCalibrationWeights(db, chain, "sqli", true);

    const row = db
      .prepare(
        "SELECT weight, sample_count FROM calibration_weights WHERE step_type = ? AND rule_family = ?",
      )
      .get("source-reachability", "__global__") as { weight: number; sample_count: number };

    expect(row).toBeDefined();
    expect(row.sample_count).toBe(1);
    // New weight: (1 - 0.1) * 1.0 + 0.1 * (1.0 * 1.05) = 0.9 + 0.105 = 1.005
    expect(row.weight).toBeCloseTo(1.005, 3);
    db.close();
  });

  it("decreases weight when incorrect", () => {
    const db = createTestDb();
    const chain: EvidenceStep[] = [
      { stepType: "source-reachability", description: "test", confidence: 0.8, evidence: "e" },
    ];

    updateCalibrationWeights(db, chain, "sqli", false);

    const row = db
      .prepare("SELECT weight FROM calibration_weights WHERE step_type = ? AND rule_family = ?")
      .get("source-reachability", "__global__") as { weight: number };

    // New weight: (1 - 0.1) * 1.0 + 0.1 * (1.0 * 0.95) = 0.9 + 0.095 = 0.995
    expect(row.weight).toBeCloseTo(0.995, 3);
    db.close();
  });

  it("updates both global and family-specific weights", () => {
    const db = createTestDb();
    const chain: EvidenceStep[] = [
      { stepType: "sink-danger", description: "test", confidence: 0.5, evidence: "e" },
    ];

    updateCalibrationWeights(db, chain, "xss", true);

    const global = db
      .prepare("SELECT weight FROM calibration_weights WHERE step_type = ? AND rule_family = ?")
      .get("sink-danger", "__global__") as { weight: number };
    const family = db
      .prepare("SELECT weight FROM calibration_weights WHERE step_type = ? AND rule_family = ?")
      .get("sink-danger", "xss") as { weight: number };

    expect(global).toBeDefined();
    expect(family).toBeDefined();
    expect(global.weight).toBeCloseTo(family.weight, 5);
    db.close();
  });

  it("clamps weight within [0.1, 3.0]", () => {
    const db = createTestDb();
    const now = new Date().toISOString();
    db.prepare(
      "INSERT INTO calibration_weights (step_type, rule_family, weight, sample_count, updated_at) VALUES (?, ?, ?, ?, ?)",
    ).run("source-reachability", "__global__", 0.1, 50, now);

    const chain: EvidenceStep[] = [
      { stepType: "source-reachability", description: "test", confidence: 0.1, evidence: "e" },
    ];

    for (let i = 0; i < 20; i++) {
      updateCalibrationWeights(db, chain, "sqli", false);
    }

    const row = db
      .prepare("SELECT weight FROM calibration_weights WHERE step_type = ? AND rule_family = ?")
      .get("source-reachability", "__global__") as { weight: number };

    expect(row.weight).toBeGreaterThanOrEqual(0.1);
    db.close();
  });
});
