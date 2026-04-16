import { describe, expect, it } from "vitest";
import { deduplicateFindings } from "../../src/scanners/dedup.js";
import type { Finding } from "../../src/scanners/types.js";

function makeFinding(overrides: Partial<Finding>): Finding {
  return {
    taskId: "semgrep",
    fingerprint: `fp-${Math.random()}`,
    ruleId: "rule",
    filePath: "src/a.ts",
    startLine: 1,
    severity: "WARNING",
    message: "msg",
    evidence: null,
    scannerConfidence: "medium",
    subcategory: ["vuln"],
    likelihood: "MEDIUM",
    impact: "MEDIUM",
    cwe: [],
    score: 1,
    ...overrides,
  };
}

describe("deduplicateFindings", () => {
  it("returns empty for empty input", () => {
    expect(deduplicateFindings([])).toEqual([]);
  });

  it("passes through findings with unique (file, line)", () => {
    const a = makeFinding({ fingerprint: "a", filePath: "x.ts", startLine: 1, cwe: ["CWE-89"] });
    const b = makeFinding({ fingerprint: "b", filePath: "x.ts", startLine: 2, cwe: ["CWE-89"] });
    const result = deduplicateFindings([a, b]);
    expect(result.map((f) => f.fingerprint).sort()).toEqual(["a", "b"]);
  });

  it("collapses CWE-overlapping findings at same location to the highest-scored one", () => {
    const low = makeFinding({ fingerprint: "low", cwe: ["CWE-89"], score: 3 });
    const high = makeFinding({ fingerprint: "high", cwe: ["CWE-89"], score: 7 });
    const result = deduplicateFindings([low, high]);
    expect(result).toHaveLength(1);
    expect(result[0].fingerprint).toBe("high");
  });

  it("keeps CWE-disjoint findings at same location as separate results", () => {
    const sql = makeFinding({ fingerprint: "sql", cwe: ["CWE-89"], score: 5 });
    const xss = makeFinding({ fingerprint: "xss", cwe: ["CWE-79"], score: 6 });
    const result = deduplicateFindings([sql, xss]);
    expect(result).toHaveLength(2);
    expect(result.map((f) => f.fingerprint).sort()).toEqual(["sql", "xss"]);
  });

  it("transitively merges CWE-overlapping clusters", () => {
    // A and B share CWE-89; B and C share CWE-22 — all should collapse to best (C, score 9).
    const a = makeFinding({ fingerprint: "a", cwe: ["CWE-89"], score: 3 });
    const b = makeFinding({ fingerprint: "b", cwe: ["CWE-89", "CWE-22"], score: 5 });
    const c = makeFinding({ fingerprint: "c", cwe: ["CWE-22"], score: 9 });
    const result = deduplicateFindings([a, b, c]);
    expect(result).toHaveLength(1);
    expect(result[0].fingerprint).toBe("c");
  });

  it("treats CWE-less findings as singletons — never merges with CWE-bearing", () => {
    const a = makeFinding({ fingerprint: "a", cwe: [], score: 4 });
    const b = makeFinding({ fingerprint: "b", cwe: ["CWE-89"], score: 3 });
    const c = makeFinding({ fingerprint: "c", cwe: [], score: 2 });
    const result = deduplicateFindings([a, b, c]);
    expect(result).toHaveLength(3);
    expect(new Set(result.map((f) => f.fingerprint))).toEqual(new Set(["a", "b", "c"]));
  });

  it("sorts results by score desc", () => {
    const findings: Finding[] = [
      makeFinding({ fingerprint: "a", filePath: "x.ts", startLine: 1, cwe: ["CWE-89"], score: 3 }),
      makeFinding({ fingerprint: "b", filePath: "y.ts", startLine: 1, cwe: ["CWE-89"], score: 10 }),
      makeFinding({ fingerprint: "c", filePath: "z.ts", startLine: 1, cwe: ["CWE-89"], score: 7 }),
    ];
    const result = deduplicateFindings(findings);
    expect(result.map((f) => f.score)).toEqual([10, 7, 3]);
  });

  it("normalizes CWE ids before matching (case/leading zeros)", () => {
    const a = makeFinding({ fingerprint: "a", cwe: ["cwe-89"], score: 5 });
    const b = makeFinding({ fingerprint: "b", cwe: ["CWE-089"], score: 7 });
    const result = deduplicateFindings([a, b]);
    expect(result).toHaveLength(1);
    expect(result[0].fingerprint).toBe("b");
  });

  it("ignores unparseable CWE entries and treats those findings as CWE-less", () => {
    const a = makeFinding({ fingerprint: "a", cwe: ["garbage"], score: 5 });
    const b = makeFinding({ fingerprint: "b", cwe: ["also-not-a-cwe"], score: 7 });
    const result = deduplicateFindings([a, b]);
    // Both treated as CWE-less → both retained.
    expect(result).toHaveLength(2);
    expect(new Set(result.map((f) => f.fingerprint))).toEqual(new Set(["a", "b"]));
  });

  it("handles large groups without blowing up", () => {
    // 500 findings at the same location, all sharing CWE-89 → one cluster, highest score wins.
    const findings: Finding[] = [];
    for (let i = 0; i < 500; i++) {
      findings.push(makeFinding({ fingerprint: `f-${i}`, cwe: ["CWE-89"], score: i }));
    }
    const result = deduplicateFindings(findings);
    expect(result).toHaveLength(1);
    expect(result[0].score).toBe(499);
  });

  it("ties on score keep a deterministic representative (first-seen within cluster)", () => {
    const a = makeFinding({ fingerprint: "a", cwe: ["CWE-89"], score: 5 });
    const b = makeFinding({ fingerprint: "b", cwe: ["CWE-89"], score: 5 });
    const result = deduplicateFindings([a, b]);
    expect(result).toHaveLength(1);
    // First-seen within the same cluster wins on tie.
    expect(result[0].fingerprint).toBe("a");
  });
});
