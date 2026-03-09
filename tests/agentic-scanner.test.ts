import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  computeAgenticFingerprint,
  parseAgenticOutput,
  selectAgenticFindings,
} from "../src/scanners/run-agentic.js";

describe("parseAgenticOutput", () => {
  it("parses structured object output", () => {
    const parsed = parseAgenticOutput({
      findings: [
        {
          ruleId: "agentic.sql.injection",
          filePath: "src/app.ts",
          startLine: 12,
          severity: "ERROR",
          message: "Unsanitized SQL query",
          confidence: "HIGH",
          subcategory: ["vuln"],
          likelihood: "HIGH",
          impact: "HIGH",
          cwe: ["CWE-89"],
          evidence: "db.query(sql + userInput)",
        },
      ],
    });

    expect(parsed.findings).toHaveLength(1);
    expect(parsed.findings[0].ruleId).toBe("agentic.sql.injection");
  });

  it("parses markdown-fenced JSON", () => {
    const parsed = parseAgenticOutput(
      '```json\n{"findings":[{"ruleId":"x","filePath":"a.ts","startLine":1,"severity":"INFO","message":"msg"}]}\n```',
    );

    expect(parsed.findings).toHaveLength(1);
    expect(parsed.findings[0].severity).toBe("INFO");
  });

  it("throws when output is unparseable non-JSON text", () => {
    expect(() =>
      parseAgenticOutput("go\nhasAccess := checkPermission(ctx, user)\nif !hasAccess {\n  return\n}"),
    ).toThrow(/invalid JSON output/i);
  });

  it("normalizes invalid enums to safe defaults", () => {
    const parsed = parseAgenticOutput({
      findings: [
        {
          ruleId: "x",
          filePath: "a.ts",
          startLine: 0,
          severity: "SEVERE",
          message: "msg",
          confidence: "SURE",
          likelihood: "MAYBE",
          impact: "MAYBE",
          subcategory: ["other"],
        },
      ],
    });

    expect(parsed.findings[0].startLine).toBe(1);
    expect(parsed.findings[0].severity).toBe("WARNING");
    expect(parsed.findings[0].confidence).toBe("MEDIUM");
    expect(parsed.findings[0].subcategory).toEqual(["audit"]);
  });
});

describe("selectAgenticFindings", () => {
  it("maps output to Finding with scanner tag", () => {
    const repoRoot = path.resolve("/tmp/repo");
    const selected = selectAgenticFindings(
      {
        findings: [
          {
            ruleId: "agentic.path.traversal",
            filePath: "/tmp/repo/src/server.ts",
            startLine: 44,
            severity: "ERROR",
            message: "Path traversal sink",
            confidence: "HIGH",
            subcategory: ["vuln"],
            likelihood: "HIGH",
            impact: "HIGH",
            cwe: ["CWE-22"],
            evidence: "fs.readFile(userPath)",
          },
        ],
      },
      repoRoot,
      "repo",
      "HEAD",
    );

    expect(selected).toHaveLength(1);
    expect(selected[0].scanner).toBe("agentic");
    expect(selected[0].filePath).toBe("src/server.ts");
  });
});

describe("computeAgenticFingerprint", () => {
  it("is deterministic", () => {
    const finding = {
      ruleId: "x",
      filePath: "src/a.ts",
      startLine: 1,
      severity: "INFO",
      message: "m",
      confidence: "LOW",
      subcategory: ["audit"],
      likelihood: "LOW",
      impact: "LOW",
      cwe: [],
      evidence: "line",
    };

    const a = computeAgenticFingerprint("repo", "HEAD", finding);
    const b = computeAgenticFingerprint("repo", "HEAD", finding);
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });

  it("ignores message/evidence phrasing differences", () => {
    const base = {
      ruleId: "x",
      filePath: "src/a.ts",
      startLine: 1,
      severity: "INFO",
      confidence: "LOW",
      subcategory: ["audit"],
      likelihood: "LOW",
      impact: "LOW",
      cwe: [],
    };

    const a = computeAgenticFingerprint("repo", "HEAD", {
      ...base,
      message: "first phrasing",
      evidence: "first evidence",
    });
    const b = computeAgenticFingerprint("repo", "HEAD", {
      ...base,
      message: "second phrasing",
      evidence: "second evidence",
    });

    expect(a).toBe(b);
  });
});
