import { describe, expect, it } from "vitest";
import {
  __vulnScoutInternals,
  vulnScoutTask,
} from "../../../src/agents/tasks/vuln-scout/vuln-scout.js";

const { buildPrompt, resolveConfig } = __vulnScoutInternals;

describe("vuln-scout", () => {
  describe("buildPrompt", () => {
    it("includes pentesting instructions", () => {
      const prompt = buildPrompt();
      expect(prompt).toContain("whitebox penetration tester");
      expect(prompt).toContain("security analysis skills");
    });

    it("mentions key analysis areas", () => {
      const prompt = buildPrompt();
      expect(prompt).toContain("static analysis");
      expect(prompt).toContain("data flows");
      expect(prompt).toContain("security misconfigurations");
      expect(prompt).toContain("OWASP Top 10");
    });

    it("includes anti-hallucination constraints", () => {
      const prompt = buildPrompt();
      expect(prompt).toContain("Anti-hallucination constraints");
    });
  });

  describe("task definition", () => {
    it("has correct metadata", () => {
      expect(vulnScoutTask.id).toBe("vuln-scout");
      expect(vulnScoutTask.displayName).toBe("Vuln Scout Pentest");
      expect(vulnScoutTask.outputKind).toBe("findings");
      expect(vulnScoutTask.dependsOn).toEqual(["context-gatherer"]);
    });

    it("has triageAgentConfig", () => {
      expect(vulnScoutTask.triageAgentConfig).toBeDefined();

      const config = vulnScoutTask.triageAgentConfig!(
        {
          taskId: "vuln-scout",
          fingerprint: "abc123",
          ruleId: "sql-injection/parameterized-query",
          filePath: "src/db.ts",
          startLine: 42,
          severity: "ERROR",
          message: "User-controlled input interpolated into SQL query",
          evidence: "const sql = `SELECT * FROM users WHERE id = '${req.params.id}'`",
          scannerConfidence: "HIGH",
          subcategory: ["vuln"],
          likelihood: "HIGH",
          impact: "HIGH",
          cwe: ["CWE-89"],
          score: 90,
        },
        "test-repo",
      );

      expect(config.prompt).toContain("Vuln Scout");
      expect(config.prompt).toContain("src/db.ts:42");
      expect(config.prompt).toContain("User-controlled input");
    });
  });
});
