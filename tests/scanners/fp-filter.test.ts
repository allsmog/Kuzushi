import { describe, expect, it } from "vitest";
import { HardExclusionFilter } from "../../src/scanners/fp-filter.js";
import type { Finding } from "../../src/scanners/types.js";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    scanner: "test",
    fingerprint: "abc123",
    ruleId: "test/rule",
    filePath: "src/app.ts",
    startLine: 10,
    severity: "WARNING",
    message: "Test finding",
    evidence: null,
    scannerConfidence: "MEDIUM",
    subcategory: ["vuln"],
    likelihood: "MEDIUM",
    impact: "MEDIUM",
    cwe: [],
    score: 50,
    ...overrides,
  };
}

describe("HardExclusionFilter", () => {
  const filter = new HardExclusionFilter();

  describe("keeps legitimate findings", () => {
    it("keeps SQL injection findings", () => {
      const finding = makeFinding({ message: "SQL injection in user query", ruleId: "sql-injection" });
      const { kept, excluded } = filter.filterFindings([finding]);
      expect(kept).toHaveLength(1);
      expect(excluded).toHaveLength(0);
    });

    it("keeps XSS findings", () => {
      const finding = makeFinding({ message: "Cross-site scripting", ruleId: "xss/reflected" });
      const { kept } = filter.filterFindings([finding]);
      expect(kept).toHaveLength(1);
    });

    it("keeps auth bypass findings", () => {
      const finding = makeFinding({ message: "Authentication bypass via IDOR", ruleId: "auth/idor" });
      const { kept } = filter.filterFindings([finding]);
      expect(kept).toHaveLength(1);
    });
  });

  describe("excludes DoS findings", () => {
    it("excludes denial of service", () => {
      const finding = makeFinding({ message: "Denial of service via large payload" });
      const { kept, excluded } = filter.filterFindings([finding]);
      expect(kept).toHaveLength(0);
      expect(excluded).toHaveLength(1);
    });

    it("excludes resource exhaustion", () => {
      const finding = makeFinding({ ruleId: "resource-exhaustion/cpu" });
      const { excluded } = filter.filterFindings([finding]);
      expect(excluded).toHaveLength(1);
    });
  });

  describe("excludes rate limiting findings", () => {
    it("excludes rate limit findings", () => {
      const finding = makeFinding({ message: "Missing rate limiting on login endpoint" });
      const { excluded } = filter.filterFindings([finding]);
      expect(excluded).toHaveLength(1);
    });

    it("excludes brute force lockout", () => {
      const finding = makeFinding({ message: "No brute-force lockout mechanism" });
      const { excluded } = filter.filterFindings([finding]);
      expect(excluded).toHaveLength(1);
    });
  });

  describe("excludes resource leak findings", () => {
    it("excludes memory leak", () => {
      const finding = makeFinding({ message: "Potential memory leak in handler" });
      const { excluded } = filter.filterFindings([finding]);
      expect(excluded).toHaveLength(1);
    });

    it("excludes connection leak", () => {
      const finding = makeFinding({ message: "Database connection leak" });
      const { excluded } = filter.filterFindings([finding]);
      expect(excluded).toHaveLength(1);
    });
  });

  describe("excludes open redirect findings", () => {
    it("excludes open redirect", () => {
      const finding = makeFinding({ message: "Open redirect vulnerability" });
      const { excluded } = filter.filterFindings([finding]);
      expect(excluded).toHaveLength(1);
    });
  });

  describe("excludes memory safety in non-C/C++", () => {
    it("excludes buffer overflow in TypeScript", () => {
      const finding = makeFinding({
        message: "Buffer overflow",
        filePath: "src/handler.ts",
      });
      const { excluded } = filter.filterFindings([finding]);
      expect(excluded).toHaveLength(1);
    });

    it("excludes use after free in Python", () => {
      const finding = makeFinding({
        message: "Use after free detected",
        filePath: "app/views.py",
      });
      const { excluded } = filter.filterFindings([finding]);
      expect(excluded).toHaveLength(1);
    });

    it("keeps buffer overflow in C files", () => {
      const finding = makeFinding({
        message: "Buffer overflow in memcpy",
        filePath: "src/parser.c",
      });
      const { kept } = filter.filterFindings([finding]);
      expect(kept).toHaveLength(1);
    });
  });

  describe("excludes regex injection", () => {
    it("excludes ReDoS", () => {
      const finding = makeFinding({ ruleId: "redos/backtracking" });
      const { excluded } = filter.filterFindings([finding]);
      expect(excluded).toHaveLength(1);
    });
  });

  describe("excludes SSRF in client-side files", () => {
    it("excludes SSRF in public HTML", () => {
      const finding = makeFinding({
        message: "Potential SSRF",
        filePath: "public/index.html",
      });
      const { excluded } = filter.filterFindings([finding]);
      expect(excluded).toHaveLength(1);
    });

    it("keeps SSRF in server code", () => {
      const finding = makeFinding({
        message: "Potential SSRF in API handler",
        filePath: "src/api/proxy.ts",
      });
      const { kept } = filter.filterFindings([finding]);
      expect(kept).toHaveLength(1);
    });
  });

  describe("excludes documentation findings", () => {
    it("excludes findings in markdown", () => {
      const finding = makeFinding({ filePath: "docs/api.md" });
      const { excluded } = filter.filterFindings([finding]);
      expect(excluded).toHaveLength(1);
    });

    it("excludes findings in README", () => {
      const finding = makeFinding({ filePath: "README.md" });
      const { excluded } = filter.filterFindings([finding]);
      expect(excluded).toHaveLength(1);
    });
  });

  describe("excludes test file findings", () => {
    it("excludes findings in test directory", () => {
      const finding = makeFinding({ filePath: "tests/auth.test.ts" });
      const { excluded } = filter.filterFindings([finding]);
      expect(excluded).toHaveLength(1);
    });

    it("excludes findings in __tests__", () => {
      const finding = makeFinding({ filePath: "src/__tests__/handler.test.ts" });
      const { excluded } = filter.filterFindings([finding]);
      expect(excluded).toHaveLength(1);
    });

    it("excludes findings in spec directory", () => {
      const finding = makeFinding({ filePath: "spec/models/user_spec.rb" });
      const { excluded } = filter.filterFindings([finding]);
      expect(excluded).toHaveLength(1);
    });
  });

  describe("custom exclusions", () => {
    it("applies custom regex patterns", () => {
      const customFilter = new HardExclusionFilter(["\\bcustom-ignore\\b"]);
      const finding = makeFinding({ message: "Found custom-ignore issue" });
      const { excluded } = customFilter.filterFindings([finding]);
      expect(excluded).toHaveLength(1);
    });

    it("ignores empty custom patterns", () => {
      const customFilter = new HardExclusionFilter(["", "  "]);
      const finding = makeFinding({ message: "Normal finding" });
      const { kept } = customFilter.filterFindings([finding]);
      expect(kept).toHaveLength(1);
    });
  });

  describe("mixed findings", () => {
    it("correctly separates kept and excluded", () => {
      const findings = [
        makeFinding({ message: "SQL injection", fingerprint: "a" }),
        makeFinding({ message: "Denial of service", fingerprint: "b" }),
        makeFinding({ message: "XSS in handler", fingerprint: "c" }),
        makeFinding({ message: "Memory leak in pool", fingerprint: "d" }),
        makeFinding({ filePath: "tests/auth.test.ts", fingerprint: "e" }),
      ];

      const { kept, excluded } = filter.filterFindings(findings);
      expect(kept).toHaveLength(2);
      expect(excluded).toHaveLength(3);
      expect(kept.map((f) => f.fingerprint)).toEqual(["a", "c"]);
    });
  });
});
