import { describe, expect, it } from "vitest";
import type { Finding } from "../src/scanners/types.js";
import {
  createRun,
  getActionableFindings,
  initDb,
  updateRunStatus,
  updateVerificationResult,
  upsertFinding,
} from "../src/store.js";
import type { KuzushiConfig, ScanOpts, TriageResult, VerificationResult } from "../src/types.js";

function makeConfig(): KuzushiConfig {
  return {
    model: "anthropic:claude-sonnet-4-6",
    busBackend: "in-process",
    triageBatchSize: 15,
    triageConcurrency: 1,
    scanMode: "sequential",
    tasks: ["semgrep"],
    severity: ["ERROR"],
    excludePatterns: [],
    taskConfig: { semgrep: {} },
  };
}

function makeScanOpts(): ScanOpts {
  return { severity: ["ERROR"], excludePatterns: [], tasks: ["semgrep"], fresh: false };
}

function makeFinding(): Finding {
  return {
    taskId: "semgrep",
    fingerprint: "fp-merge",
    ruleId: "test.rule",
    filePath: "src/app.ts",
    startLine: 8,
    severity: "ERROR",
    message: "test",
    scannerConfidence: "HIGH",
    subcategory: ["vuln"],
    likelihood: "HIGH",
    impact: "HIGH",
    cwe: ["CWE-89"],
    score: 88,
  };
}

function triageWithWeakEvidence(): TriageResult {
  return {
    fingerprint: "fp-merge",
    verdict: "tp",
    confidence: 0.8,
    rationale: "triage rationale",
    verificationSteps: ["check source"],
    fixPatch: null,
    codeCitations: [
      {
        filePath: "src/app.ts",
        startLine: 8,
        endLine: 9,
        snippet: "q(id)",
        description: "triage citation",
      },
    ],
    attackPath: {
      chain: ["entry", "sink"],
      narrative: "triage narrative",
      likelihoodReasoning: "l",
      impactReasoning: "i",
    },
    assumptions: ["Triage assumption"],
    controls: [{ name: "TriageControl", description: "triage control" }],
    blindspots: ["triage blindspot"],
  };
}

function verifyWithStrongerEvidence(): VerificationResult {
  return {
    fingerprint: "fp-merge",
    exploitable: true,
    pocPayload: "' OR 1=1 --",
    pocDescription: "Inject in param",
    attackVector: "HTTP",
    preconditions: ["endpoint reachable"],
    confidence: 0.95,
    codeCitations: [
      {
        filePath: "src/util.ts",
        startLine: 20,
        endLine: 22,
        snippet: "unsafeSanitize(input)",
        description: "verify found a bypass",
      },
    ],
    attackPath: {
      chain: ["entry", "bypass", "sink", "impact"],
      narrative: "verify narrative",
      likelihoodReasoning: "verify likelihood",
      impactReasoning: "verify impact",
    },
    assumptions: ["Verify assumption", "Triage assumption"],
    controls: [{ name: "VerifyControl", description: "verify control" }],
    blindspots: ["verify blindspot"],
  };
}

describe("updateVerificationResult — evidence merge", () => {
  it("appends verify citations to triage citations (deduped)", () => {
    const db = initDb(":memory:");
    createRun(db, "run", "repo", makeConfig(), makeScanOpts());
    updateRunStatus(db, "run", "triaging");

    upsertFinding(db, makeFinding(), triageWithWeakEvidence(), "repo", "HEAD");
    updateVerificationResult(db, "fp-merge", verifyWithStrongerEvidence());

    const [found] = getActionableFindings(db, "repo", { includeFalsePositives: true });
    expect(found.codeCitations).toBeDefined();
    expect(found.codeCitations?.length).toBe(2);
    const paths = found.codeCitations?.map((c) => c.filePath).sort();
    expect(paths).toEqual(["src/app.ts", "src/util.ts"]);

    db.close();
  });

  it("replaces attack_path when verify chain is strictly longer", () => {
    const db = initDb(":memory:");
    createRun(db, "run", "repo", makeConfig(), makeScanOpts());
    updateRunStatus(db, "run", "triaging");

    upsertFinding(db, makeFinding(), triageWithWeakEvidence(), "repo", "HEAD");
    updateVerificationResult(db, "fp-merge", verifyWithStrongerEvidence());

    const [found] = getActionableFindings(db, "repo", { includeFalsePositives: true });
    expect(found.attackPath?.chain.length).toBe(4);
    expect(found.attackPath?.narrative).toBe("verify narrative");

    db.close();
  });

  it("keeps triage attack_path when verify chain is not longer", () => {
    const db = initDb(":memory:");
    createRun(db, "run", "repo", makeConfig(), makeScanOpts());
    updateRunStatus(db, "run", "triaging");

    upsertFinding(db, makeFinding(), triageWithWeakEvidence(), "repo", "HEAD");
    const verify = verifyWithStrongerEvidence();
    verify.attackPath = {
      chain: ["single"],
      narrative: "short",
      likelihoodReasoning: "l",
      impactReasoning: "i",
    };
    updateVerificationResult(db, "fp-merge", verify);

    const [found] = getActionableFindings(db, "repo", { includeFalsePositives: true });
    expect(found.attackPath?.chain.length).toBe(2);
    expect(found.attackPath?.narrative).toBe("triage narrative");

    db.close();
  });

  it("merges assumptions / controls / blindspots without duplicates", () => {
    const db = initDb(":memory:");
    createRun(db, "run", "repo", makeConfig(), makeScanOpts());
    updateRunStatus(db, "run", "triaging");

    upsertFinding(db, makeFinding(), triageWithWeakEvidence(), "repo", "HEAD");
    updateVerificationResult(db, "fp-merge", verifyWithStrongerEvidence());

    const [found] = getActionableFindings(db, "repo", { includeFalsePositives: true });
    // Duplicate "Triage assumption" should not be duplicated
    expect(found.assumptions?.sort()).toEqual(["Triage assumption", "Verify assumption"]);
    expect(found.controls?.map((c) => c.name).sort()).toEqual(["TriageControl", "VerifyControl"]);
    expect(found.blindspots?.sort()).toEqual(["triage blindspot", "verify blindspot"]);

    db.close();
  });

  it("no-op when verify has no extended evidence", () => {
    const db = initDb(":memory:");
    createRun(db, "run", "repo", makeConfig(), makeScanOpts());
    updateRunStatus(db, "run", "triaging");

    upsertFinding(db, makeFinding(), triageWithWeakEvidence(), "repo", "HEAD");
    updateVerificationResult(db, "fp-merge", {
      fingerprint: "fp-merge",
      exploitable: true,
      pocPayload: null,
      pocDescription: "",
      attackVector: null,
      preconditions: [],
      confidence: 0.5,
    });

    const [found] = getActionableFindings(db, "repo", { includeFalsePositives: true });
    expect(found.codeCitations?.length).toBe(1);
    expect(found.attackPath?.chain).toEqual(["entry", "sink"]);
    expect(found.assumptions).toEqual(["Triage assumption"]);

    db.close();
  });
});
