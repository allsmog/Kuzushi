import { describe, expect, it } from "vitest";
import { formatBypassForPrompt, getBypassKnowledge } from "../src/bypass-knowledge.js";

describe("getBypassKnowledge", () => {
  it("returns SQLi bypass techniques for CWE-89", () => {
    const entry = getBypassKnowledge(["CWE-89"], "some-rule");
    expect(entry).toBeDefined();
    expect(entry!.category).toBe("SQL Injection");
    expect(entry!.techniques.length).toBeGreaterThan(0);
  });

  it("returns XSS bypass techniques for CWE-79", () => {
    const entry = getBypassKnowledge(["79"], "some-rule");
    expect(entry).toBeDefined();
    expect(entry!.category).toBe("Cross-Site Scripting (XSS)");
  });

  it("matches SSRF via CWE-918", () => {
    const entry = getBypassKnowledge(["CWE-918"], "some-rule");
    expect(entry).toBeDefined();
    expect(entry!.category).toBe("Server-Side Request Forgery (SSRF)");
  });

  it("falls back to rule ID pattern matching", () => {
    const entry = getBypassKnowledge([], "semgrep.sql-injection.unsafe-query");
    expect(entry).toBeDefined();
    expect(entry!.category).toBe("SQL Injection");
  });

  it("matches path-traversal rule IDs", () => {
    const entry = getBypassKnowledge([], "path-traversal/user-controlled");
    expect(entry).toBeDefined();
    expect(entry!.category).toBe("Path Traversal");
  });

  it("matches auth-bypass via IDOR rule ID", () => {
    const entry = getBypassKnowledge([], "auth-access/idor");
    expect(entry).toBeDefined();
    expect(entry!.category).toBe("Missing Authorization");
  });

  it("returns undefined for unknown CWE and rule ID", () => {
    const entry = getBypassKnowledge(["CWE-999"], "unknown-rule");
    expect(entry).toBeUndefined();
  });

  it("prefers CWE match over rule ID match", () => {
    // CWE says SQLi, but rule ID says XSS — CWE should win
    const entry = getBypassKnowledge(["89"], "xss-related-rule");
    expect(entry).toBeDefined();
    expect(entry!.category).toBe("SQL Injection");
  });
});

describe("formatBypassForPrompt", () => {
  it("formats bypass entry into prompt lines", () => {
    const entry = getBypassKnowledge(["89"], "test")!;
    const lines = formatBypassForPrompt(entry);

    expect(lines[0]).toContain("Category-Specific Bypass Techniques");
    expect(lines[0]).toContain("SQL Injection");
    expect(lines[1]).toContain("not-exploitable");
    expect(lines.length).toBeGreaterThan(3);
  });
});
