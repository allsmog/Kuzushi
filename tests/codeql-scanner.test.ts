import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { CodeQLPlugin } from "../src/scanners/codeql.js";
import {
  computeCodeQLFingerprint,
  detectCodeQLLanguageFromHeuristics,
  selectFindings,
  type CodeQLSarifOutput,
} from "../src/scanners/run-codeql.js";
import type { Finding } from "../src/scanners/types.js";

function makeFinding(): Finding {
  return {
    scanner: "codeql",
    fingerprint: "fp-codeql",
    ruleId: "codeql.test.rule",
    filePath: "src/app.ts",
    startLine: 10,
    severity: "ERROR",
    message: "Potential SQL injection",
    scannerConfidence: "HIGH",
    subcategory: ["vuln"],
    likelihood: "HIGH",
    impact: "HIGH",
    cwe: ["CWE-89"],
    score: 54,
  };
}

function makeSarifOutput(): CodeQLSarifOutput {
  return {
    runs: [
      {
        tool: {
          driver: {
            rules: [
              {
                id: "codeql.rule.error",
                properties: {
                  problem: { severity: "error" },
                  "security-severity": "8.4",
                  precision: "high",
                  tags: ["security", "external/cwe/cwe-89"],
                },
              },
              {
                id: "codeql.rule.warning",
                properties: {
                  problem: { severity: "warning" },
                  "security-severity": "5.1",
                  precision: "medium",
                  tags: ["correctness"],
                },
              },
              {
                id: "codeql.rule.info",
                properties: {
                  problem: { severity: "recommendation" },
                  "security-severity": "2.0",
                  precision: "low",
                  tags: ["style"],
                },
              },
            ],
          },
        },
        results: [
          {
            ruleId: "codeql.rule.error",
            message: { text: "User input reaches SQL sink" },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: "src/db.ts" },
                  region: { startLine: 42 },
                },
              },
            ],
          },
          {
            ruleId: "codeql.rule.warning",
            message: { text: "Potentially unsafe redirect" },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: "src/redirect.ts" },
                  region: { startLine: 12 },
                },
              },
            ],
          },
          {
            ruleId: "codeql.rule.info",
            message: { text: "Missing strictness" },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: "src/config.ts" },
                  region: { startLine: 3 },
                },
              },
            ],
          },
        ],
      },
    ],
  };
}

describe("selectFindings (CodeQL)", () => {
  it("maps SARIF results to Kuzushi Finding fields", () => {
    const findings = selectFindings(makeSarifOutput(), "repo", "HEAD");
    expect(findings).toHaveLength(3);

    const errorFinding = findings.find((finding) => finding.ruleId === "codeql.rule.error");
    expect(errorFinding).toBeDefined();
    expect(errorFinding?.scanner).toBe("codeql");
    expect(errorFinding?.severity).toBe("ERROR");
    expect(errorFinding?.scannerConfidence).toBe("HIGH");
    expect(errorFinding?.filePath).toBe("src/db.ts");
    expect(errorFinding?.startLine).toBe(42);
    expect(errorFinding?.cwe).toEqual(["CWE-89"]);

    const warningFinding = findings.find((finding) => finding.ruleId === "codeql.rule.warning");
    expect(warningFinding?.severity).toBe("WARNING");
    expect(warningFinding?.scannerConfidence).toBe("MEDIUM");
    expect(warningFinding?.subcategory).toEqual(["audit"]);

    const infoFinding = findings.find((finding) => finding.ruleId === "codeql.rule.info");
    expect(infoFinding?.severity).toBe("INFO");
    expect(infoFinding?.scannerConfidence).toBe("LOW");
  });

  it("deduplicates by fingerprint and keeps the highest score", () => {
    const sarif: CodeQLSarifOutput = {
      runs: [
        {
          tool: {
            driver: {
              rules: [
                {
                  id: "codeql.rule.dup",
                  properties: {
                    problem: { severity: "warning" },
                    "security-severity": "3.0",
                    precision: "low",
                    tags: ["audit"],
                  },
                },
              ],
            },
          },
          results: [
            {
              ruleId: "codeql.rule.dup",
              message: { text: "Duplicate finding" },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: "src/a.ts" },
                    region: { startLine: 10 },
                  },
                },
              ],
            },
          ],
        },
        {
          tool: {
            driver: {
              rules: [
                {
                  id: "codeql.rule.dup",
                  properties: {
                    problem: { severity: "error" },
                    "security-severity": "9.0",
                    precision: "high",
                    tags: ["security", "external/cwe/cwe-79"],
                  },
                },
              ],
            },
          },
          results: [
            {
              ruleId: "codeql.rule.dup",
              message: { text: "Duplicate finding" },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: "src/a.ts" },
                    region: { startLine: 10 },
                  },
                },
              ],
            },
          ],
        },
      ],
    };

    const findings = selectFindings(sarif, "repo", "HEAD");
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("ERROR");
    expect(findings[0].score).toBeGreaterThan(10);
  });

  it("honors maxFindings", () => {
    const findings = selectFindings(makeSarifOutput(), "repo", "HEAD", 2);
    expect(findings).toHaveLength(2);
  });

  it("returns empty array for empty SARIF runs", () => {
    expect(selectFindings({ runs: [] }, "repo", "HEAD")).toEqual([]);
  });
});

describe("computeCodeQLFingerprint", () => {
  it("is deterministic and repo-sensitive", () => {
    const input = {
      ruleId: "codeql.rule",
      filePath: "src/app.ts",
      startLine: 8,
      message: "User input reaches sink",
    };

    const fp1 = computeCodeQLFingerprint("repo-a", "HEAD", input);
    const fp2 = computeCodeQLFingerprint("repo-a", "HEAD", input);
    const fp3 = computeCodeQLFingerprint("repo-b", "HEAD", input);

    expect(fp1).toBe(fp2);
    expect(fp1).not.toBe(fp3);
    expect(fp1).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("detectCodeQLLanguageFromHeuristics", () => {
  it("detects javascript and go markers", async () => {
    const jsRepo = mkdtempSync(path.join(os.tmpdir(), "kuzushi-codeql-js-"));
    const goRepo = mkdtempSync(path.join(os.tmpdir(), "kuzushi-codeql-go-"));

    try {
      writeFileSync(path.join(jsRepo, "package.json"), "{}\n");
      writeFileSync(path.join(goRepo, "go.mod"), "module test\n");

      expect(await detectCodeQLLanguageFromHeuristics(jsRepo)).toBe("javascript");
      expect(await detectCodeQLLanguageFromHeuristics(goRepo)).toBe("go");
    } finally {
      rmSync(jsRepo, { recursive: true, force: true });
      rmSync(goRepo, { recursive: true, force: true });
    }
  });
});

describe("CodeQLPlugin triage prompt", () => {
  it("references semantic dataflow and source-to-sink validation guidance", () => {
    const plugin = new CodeQLPlugin();
    const prompt = plugin.triageAgentConfig(makeFinding(), "repo").prompt;

    expect(prompt.toLowerCase()).toContain("dataflow/taint");
    expect(prompt.toLowerCase()).toContain("source-to-sink");
    expect(prompt.toLowerCase()).toContain("implicit guards");
    expect(prompt.toLowerCase()).toContain("type narrowing");
  });
});
