import { describe, expect, it } from "vitest";
import { __tobAuditInternals, tobAuditTask } from "../../../src/agents/tasks/tob-audit/tob-audit.js";

const { buildPrompt, resolveConfig } = __tobAuditInternals;

describe("tob-audit", () => {
  describe("buildPrompt", () => {
    it("includes security audit instructions", () => {
      const prompt = buildPrompt();
      expect(prompt).toContain("senior security auditor");
      expect(prompt).toContain("security analysis skills");
    });

    it("mentions key skill areas", () => {
      const prompt = buildPrompt();
      expect(prompt).toContain("insecure defaults");
      expect(prompt).toContain("sharp edges");
      expect(prompt).toContain("data flows");
      expect(prompt).toContain("variant patterns");
    });

    it("includes anti-hallucination constraints", () => {
      const prompt = buildPrompt();
      expect(prompt).toContain("Anti-hallucination constraints");
    });
  });

  describe("task definition", () => {
    it("has correct metadata", () => {
      expect(tobAuditTask.id).toBe("tob-audit");
      expect(tobAuditTask.displayName).toBe("Trail of Bits Audit");
      expect(tobAuditTask.outputKind).toBe("findings");
      expect(tobAuditTask.dependsOn).toEqual(["context-gatherer"]);
    });

    it("has triageAgentConfig", () => {
      expect(tobAuditTask.triageAgentConfig).toBeDefined();

      const config = tobAuditTask.triageAgentConfig!(
        {
          taskId: "tob-audit",
          fingerprint: "abc123",
          ruleId: "insecure-default/jwt-secret",
          filePath: "src/config.ts",
          startLine: 15,
          severity: "ERROR",
          message: "Hardcoded JWT secret with fallback default",
          evidence: "JWT_SECRET = process.env.SECRET || 'default-secret'",
          scannerConfidence: "HIGH",
          subcategory: ["vuln"],
          likelihood: "HIGH",
          impact: "HIGH",
          cwe: ["CWE-798"],
          score: 85,
        },
        "test-repo",
      );

      expect(config.prompt).toContain("Trail of Bits audit");
      expect(config.prompt).toContain("src/config.ts:15");
      expect(config.prompt).toContain("Hardcoded JWT secret");
    });
  });
});
