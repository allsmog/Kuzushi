import { describe, expect, it } from "vitest";
import {
  createRun,
  getActionableFindings,
  initDb,
  updateRunFindings,
  updateRunStatus,
  updateVerificationResult,
  upsertFinding,
} from "../src/store.js";
import { generateSarifReport } from "../src/report-sarif.js";
import type { Finding } from "../src/scanners/types.js";
import type { KuzushiConfig, ScanOpts, TriageResult, VerificationResult } from "../src/types.js";

function makeConfig(): KuzushiConfig {
  return {
    model: "anthropic:claude-sonnet-4-6",
    triageMaxTurns: 10,
    busBackend: "in-process",
    triageBatchSize: 15,
    triageConcurrency: 1,
    scanMode: "sequential",
    scanners: ["semgrep"],
    severity: ["ERROR", "WARNING", "INFO"],
    excludePatterns: [],
    scannerConfig: { semgrep: {} },
  };
}

function makeScanOpts(): ScanOpts {
  return {
    severity: ["ERROR", "WARNING", "INFO"],
    excludePatterns: [],
    scanners: ["semgrep"],
    fresh: false,
  };
}

function makeFinding(overrides: Partial<Finding>): Finding {
  return {
    scanner: "semgrep",
    fingerprint: "fp-default",
    ruleId: "test.rule",
    filePath: "src/app.ts",
    startLine: 8,
    severity: "ERROR",
    message: "Potential SQL injection",
    scannerConfidence: "HIGH",
    subcategory: ["vuln"],
    likelihood: "HIGH",
    impact: "HIGH",
    cwe: ["CWE-89"],
    score: 88,
    ...overrides,
  };
}

function makeTriageResult(
  fingerprint: string,
  verdict: "tp" | "fp" | "needs_review",
  confidence: number,
  rationale: string,
  fixPatch: string | null,
): TriageResult {
  return {
    fingerprint,
    verdict,
    confidence,
    rationale,
    verificationSteps: ["step 1"],
    fixPatch,
  };
}

function makeVerificationResult(fingerprint: string): VerificationResult {
  return {
    fingerprint,
    exploitable: true,
    pocPayload: "' OR 1=1 --",
    pocDescription: "Inject into query param",
    attackVector: "HTTP query",
    preconditions: ["Endpoint reachable"],
    confidence: 0.9,
  };
}

describe("generateSarifReport", () => {
  it("renders valid SARIF v2.1.0 with mapped fields", () => {
    const db = initDb(":memory:");
    const runId = "run-sarif-1";

    createRun(db, runId, "repo", makeConfig(), makeScanOpts());
    updateRunStatus(db, runId, "triaging");

    const finding = makeFinding({
      fingerprint: "fp-sarif-tp",
      filePath: "/workspace/repo/src/app.ts",
      severity: "ERROR",
      cwe: ["CWE-89"],
    });
    const triage = makeTriageResult(
      finding.fingerprint,
      "tp",
      0.95,
      "User-controlled input reaches SQL sink.",
      "Use parameterized query.",
    );

    upsertFinding(db, finding, triage, "repo", "HEAD");
    updateVerificationResult(db, finding.fingerprint, makeVerificationResult(finding.fingerprint));
    updateRunFindings(db, runId, [finding]);

    const sarif = generateSarifReport(
      db,
      "repo",
      {
        totalFindings: 1,
        queuedForTriage: 1,
        skippedAlreadyTriaged: 0,
        skippedLowConfidence: 0,
        startedAt: "2026-01-01T00:00:00.000Z",
        completedAt: "2026-01-01T00:01:00.000Z",
      },
      runId,
    );

    const parsed = JSON.parse(sarif) as {
      $schema: string;
      version: string;
      runs: Array<{
        tool: { driver: { name: string; rules: Array<{ id: string; defaultConfiguration: { level: string }; properties?: { tags?: string[] } }> } };
        results: Array<{
          ruleId: string;
          message: { text: string };
          locations: Array<{ physicalLocation: { artifactLocation: { uri: string }; region: { startLine: number } } }>;
          properties: { exploitable?: boolean };
        }>;
      }>;
    };

    expect(parsed.$schema).toContain("sarif-2.1.0");
    expect(parsed.version).toBe("2.1.0");
    expect(parsed.runs[0].tool.driver.name).toBe("kuzushi");

    const actionable = getActionableFindings(db, "repo", { includeFalsePositives: true });
    expect(parsed.runs[0].results).toHaveLength(actionable.length);

    const result = parsed.runs[0].results[0];
    expect(result.ruleId).toBe("test.rule");
    expect(result.message.text).toBe("Potential SQL injection");
    expect(result.locations[0].physicalLocation.region.startLine).toBe(8);
    expect(result.locations[0].physicalLocation.artifactLocation.uri.startsWith("/")).toBe(false);
    expect(result.properties.exploitable).toBe(true);

    const rule = parsed.runs[0].tool.driver.rules.find((item) => item.id === "test.rule");
    expect(rule?.defaultConfiguration.level).toBe("error");
    expect(rule?.properties?.tags).toContain("external/cwe/cwe-89");

    db.close();
  });

  it("includes pocHarnessCostUsd in totalCostUsd", () => {
    const db = initDb(":memory:");
    const runId = "run-sarif-poc";

    createRun(db, runId, "repo", makeConfig(), makeScanOpts());
    updateRunStatus(db, runId, "triaging");

    const finding = makeFinding({ fingerprint: "fp-poc-cost" });
    const triage = makeTriageResult(finding.fingerprint, "tp", 0.9, "Real", "Fix it.");
    upsertFinding(db, finding, triage, "repo", "HEAD");
    updateRunFindings(db, runId, [finding]);

    const sarif = generateSarifReport(
      db,
      "repo",
      {
        totalFindings: 1,
        totalCostUsd: 0.50,
        verifyCostUsd: 0.10,
        pocHarnessCostUsd: 0.05,
        pocHarnessGenerated: 1,
        pocHarnessSkipped: 0,
        pocHarnessErrors: 0,
      },
      runId,
    );

    const parsed = JSON.parse(sarif) as { runs: Array<{ properties: { summary: Record<string, unknown> } }> };
    const summary = parsed.runs[0].properties.summary;
    expect(summary.pocHarnessCostUsd).toBe(0.05);
    expect(summary.pocHarnessGenerated).toBe(1);
    expect(summary.totalCostUsd).toBeGreaterThan(0.50);

    db.close();
  });

  it("clamps startLine to >= 1 for all file paths", () => {
    const db = initDb(":memory:");
    const runId = "run-sarif-clamp";

    createRun(db, runId, "repo", makeConfig(), makeScanOpts());
    updateRunStatus(db, runId, "triaging");

    const finding = makeFinding({
      fingerprint: "fp-sarif-zero-line",
      filePath: "src/app.ts",
      startLine: 0,
    });
    const triage = makeTriageResult(finding.fingerprint, "tp", 0.9, "Real.", null);
    upsertFinding(db, finding, triage, "repo", "HEAD");
    updateRunFindings(db, runId, [finding]);

    const parsed = JSON.parse(generateSarifReport(db, "repo", {}, runId)) as {
      runs: Array<{
        results: Array<{
          locations: Array<{ physicalLocation: { region: { startLine: number } } }>;
        }>;
      }>;
    };

    expect(parsed.runs[0].results[0].locations[0].physicalLocation.region.startLine).toBe(1);

    db.close();
  });

  it("maps severities and marks false positives with suppressions", () => {
    const db = initDb(":memory:");
    const runId = "run-sarif-2";

    createRun(db, runId, "repo", makeConfig(), makeScanOpts());
    updateRunStatus(db, runId, "triaging");

    const fpFinding = makeFinding({
      fingerprint: "fp-sarif-fp",
      ruleId: "test.warning",
      severity: "WARNING",
      message: "Potential false positive",
      cwe: ["CWE-79"],
    });
    const fpResult = makeTriageResult(
      fpFinding.fingerprint,
      "fp",
      0.91,
      "Sanitization blocks attacker-controlled input.",
      null,
    );

    const noteFinding = makeFinding({
      fingerprint: "fp-sarif-note",
      ruleId: "test.info",
      severity: "INFO",
      message: "Informational finding",
      cwe: [],
    });
    const noteResult = makeTriageResult(
      noteFinding.fingerprint,
      "needs_review",
      0.7,
      "Needs manual validation.",
      null,
    );

    upsertFinding(db, fpFinding, fpResult, "repo", "HEAD");
    upsertFinding(db, noteFinding, noteResult, "repo", "HEAD");
    updateRunFindings(db, runId, [fpFinding, noteFinding]);

    const parsed = JSON.parse(generateSarifReport(db, "repo", {}, runId)) as {
      runs: Array<{
        tool: { driver: { rules: Array<{ id: string; defaultConfiguration: { level: string } }> } };
        results: Array<{ ruleId: string; suppressions?: Array<{ kind: string; justification?: string }> }>;
      }>;
    };

    const warningRule = parsed.runs[0].tool.driver.rules.find((rule) => rule.id === "test.warning");
    const infoRule = parsed.runs[0].tool.driver.rules.find((rule) => rule.id === "test.info");

    expect(warningRule?.defaultConfiguration.level).toBe("warning");
    expect(infoRule?.defaultConfiguration.level).toBe("note");

    const fpSarifResult = parsed.runs[0].results.find((result) => result.ruleId === "test.warning");
    expect(fpSarifResult?.suppressions?.[0]?.kind).toBe("inSource");
    expect(fpSarifResult?.suppressions?.[0]?.justification).toContain("Sanitization blocks");

    db.close();
  });
});
