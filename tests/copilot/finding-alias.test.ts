import { describe, expect, it } from "vitest";
import {
  computeChainAliases,
  computeFindingAliases,
  formatAliasTable,
  resolveAlias,
} from "../../src/copilot/finding-alias.js";
import type { ExploitChain } from "../../src/types.js";
import type { ActionableFinding } from "../../src/ui/state.js";

function mkFinding(
  partial: Partial<ActionableFinding> & { fingerprint: string; severity?: string },
): ActionableFinding {
  return {
    verdict: "tp",
    confidence: 0.9,
    severity: partial.severity ?? "high",
    taskId: "sast",
    filePath: "src/x.ts",
    startLine: 1,
    ruleId: "rule/x",
    rationale: "",
    corroboratingSignals: [],
    suppressionReasons: [],
    ...partial,
  } as ActionableFinding;
}

function mkChain(partial: Partial<ExploitChain> & { id: string }): ExploitChain {
  return {
    id: partial.id,
    name: partial.name ?? "chain",
    steps: partial.steps ?? [],
    overallSeverity: partial.overallSeverity ?? "HIGH",
    preconditions: partial.preconditions ?? [],
    impactDescription: partial.impactDescription ?? "",
  };
}

describe("computeFindingAliases", () => {
  it("assigns F-0001 / F-0002 in severity-desc then fingerprint-asc order", () => {
    const findings = [
      mkFinding({ fingerprint: "bbb", displaySeverity: "medium" }),
      mkFinding({ fingerprint: "aaa", displaySeverity: "critical" }),
      mkFinding({ fingerprint: "ccc", displaySeverity: "critical" }),
      mkFinding({ fingerprint: "zzz", displaySeverity: "low" }),
    ];
    const aliases = computeFindingAliases(findings);
    expect(aliases).toEqual([
      { alias: "F-0001", target: "aaa" },
      { alias: "F-0002", target: "ccc" },
      { alias: "F-0003", target: "bbb" },
      { alias: "F-0004", target: "zzz" },
    ]);
  });

  it("is deterministic — same input always produces same aliases", () => {
    const findings = [
      mkFinding({ fingerprint: "xyz", displaySeverity: "high" }),
      mkFinding({ fingerprint: "abc", displaySeverity: "high" }),
    ];
    const first = computeFindingAliases(findings);
    const second = computeFindingAliases(findings);
    expect(first).toEqual(second);
  });
});

describe("computeChainAliases", () => {
  it("assigns C-01 / C-02 in severity order", () => {
    const chains = [
      mkChain({ id: "chain-med", overallSeverity: "MEDIUM" }),
      mkChain({ id: "chain-crit", overallSeverity: "CRITICAL" }),
      mkChain({ id: "chain-high", overallSeverity: "HIGH" }),
    ];
    const aliases = computeChainAliases(chains);
    expect(aliases.map((a) => a.alias)).toEqual(["C-01", "C-02", "C-03"]);
    expect(aliases[0]!.target).toBe("chain-crit");
  });
});

describe("resolveAlias", () => {
  const findings = [
    mkFinding({ fingerprint: "aaaaaa1111", displaySeverity: "critical" }),
    mkFinding({ fingerprint: "bbbbbb2222", displaySeverity: "high" }),
  ];
  const aliases = computeFindingAliases(findings);
  const raw = findings.map((f) => f.fingerprint);

  it("resolves F-NNNN to the canonical fingerprint", () => {
    expect(resolveAlias("F-0001", aliases)).toBe("aaaaaa1111");
    expect(resolveAlias("F-0002", aliases)).toBe("bbbbbb2222");
  });

  it("is case-insensitive", () => {
    expect(resolveAlias("f-0001", aliases)).toBe("aaaaaa1111");
  });

  it("canonicalises short aliases (F-1 → F-0001)", () => {
    expect(resolveAlias("F-1", aliases)).toBe("aaaaaa1111");
  });

  it("falls back to raw fingerprint prefix", () => {
    expect(resolveAlias("aaaa", aliases, raw)).toBe("aaaaaa1111");
    expect(resolveAlias("aaaaaa1111", aliases, raw)).toBe("aaaaaa1111");
  });

  it("returns undefined for ambiguous prefix", () => {
    const ambiguous = ["abcd0001", "abcd0002"];
    expect(resolveAlias("abcd", aliases, ambiguous)).toBeUndefined();
  });

  it("returns undefined for unknown alias", () => {
    expect(resolveAlias("F-9999", aliases)).toBeUndefined();
  });

  it("returns undefined for empty input", () => {
    expect(resolveAlias("", aliases, raw)).toBeUndefined();
  });
});

describe("formatAliasTable", () => {
  const findingAliases = [{ alias: "F-0001", target: "aaaaaa1111abcd" }];
  const chainAliases = [{ alias: "C-01", target: "chain-crit" }];

  it("renders a table with both chains and findings by default", () => {
    const out = formatAliasTable(findingAliases, chainAliases);
    expect(out).toContain("F-0001");
    expect(out).toContain("C-01");
  });

  it("filters by prefix", () => {
    const out = formatAliasTable(findingAliases, chainAliases, "F-");
    expect(out).toContain("F-0001");
    expect(out).not.toContain("C-01");
  });

  it("reports empty matches explicitly", () => {
    const out = formatAliasTable([], [], "F-");
    expect(out).toContain('No aliases match "F-"');
  });

  it("reports empty corpus", () => {
    expect(formatAliasTable([], [])).toContain("No aliases for the current run.");
  });

  it("includes optional titles", () => {
    const out = formatAliasTable(findingAliases, chainAliases, undefined, {
      aaaaaa1111abcd: "ssrf on /admin/fetch",
      "chain-crit": "admin auth bypass",
    });
    expect(out).toContain("ssrf on /admin/fetch");
    expect(out).toContain("admin auth bypass");
  });
});
