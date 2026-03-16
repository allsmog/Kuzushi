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

  it("keeps legitimate server-side findings untouched", () => {
    const finding = makeFinding({ message: "SQL injection in user query", ruleId: "sql-injection" });
    const { kept, hardExcluded, softSuppressed } = filter.filterFindings([finding]);
    expect(kept).toHaveLength(1);
    expect(hardExcluded).toHaveLength(0);
    expect(softSuppressed).toHaveLength(0);
    expect(kept[0].adjustedScore).toBe(50);
  });

  it("hard-excludes low-signal DoS and rate-limiting findings", () => {
    const findings = [
      makeFinding({ fingerprint: "dos", message: "Denial of service via large payload" }),
      makeFinding({ fingerprint: "rate", message: "Missing rate limiting on login endpoint" }),
    ];
    const { kept, hardExcluded, softSuppressed } = filter.filterFindings(findings);
    expect(kept).toHaveLength(0);
    expect(hardExcluded.map((finding) => finding.fingerprint)).toEqual(["dos", "rate"]);
    expect(softSuppressed).toHaveLength(0);
  });

  it("keeps open redirect as a soft suppression with a score penalty", () => {
    const finding = makeFinding({
      fingerprint: "redirect",
      message: "Open redirect vulnerability",
      score: 60,
    });
    const { kept, hardExcluded, softSuppressed } = filter.filterFindings([finding]);
    expect(hardExcluded).toHaveLength(0);
    expect(softSuppressed).toHaveLength(1);
    expect(kept).toHaveLength(1);
    expect(kept[0].fingerprint).toBe("redirect");
    expect(kept[0].adjustedScore).toBe(45);
    expect(kept[0].suppressionReasons?.map((reason) => reason.id)).toEqual(["open-redirect"]);
  });

  it("does not soft-suppress auth-related redirect findings", () => {
    const finding = makeFinding({
      fingerprint: "oauth",
      message: "Open redirect vulnerability in redirect_uri handler",
      filePath: "src/auth/callback.ts",
    });
    const { kept, softSuppressed } = filter.filterFindings([finding]);
    expect(kept).toHaveLength(1);
    expect(softSuppressed).toHaveLength(0);
  });

  it("soft-suppresses client-side SSRF findings but keeps server-side SSRF", () => {
    const clientFinding = makeFinding({
      fingerprint: "client",
      message: "Potential SSRF",
      filePath: "public/index.html",
      score: 40,
    });
    const serverFinding = makeFinding({
      fingerprint: "server",
      message: "Potential SSRF in API handler",
      filePath: "src/api/proxy.ts",
      score: 55,
    });

    const result = filter.filterFindings([clientFinding, serverFinding]);
    expect(result.softSuppressed.map((finding) => finding.fingerprint)).toEqual(["client"]);
    expect(result.hardExcluded).toHaveLength(0);
    expect(result.kept.map((finding) => finding.fingerprint)).toEqual(["client", "server"]);
    expect(result.kept.find((finding) => finding.fingerprint === "client")?.adjustedScore).toBe(25);
    expect(result.kept.find((finding) => finding.fingerprint === "server")?.adjustedScore).toBe(55);
  });

  it("hard-excludes docs, tests, generated output, and custom regex exclusions", () => {
    const customFilter = new HardExclusionFilter(["\\bcustom-ignore\\b"]);
    const findings = [
      makeFinding({ fingerprint: "docs", filePath: "docs/api.md" }),
      makeFinding({ fingerprint: "tests", filePath: "tests/auth.test.ts" }),
      makeFinding({ fingerprint: "generated", filePath: "dist/app.bundle.js" }),
      makeFinding({ fingerprint: "custom", message: "Found custom-ignore issue" }),
    ];

    const { kept, hardExcluded } = customFilter.filterFindings(findings);
    expect(kept).toHaveLength(0);
    expect(hardExcluded.map((finding) => finding.fingerprint)).toEqual([
      "docs",
      "tests",
      "generated",
      "custom",
    ]);
  });
});
