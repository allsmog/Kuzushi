import { describe, expect, it } from "vitest";
import { DesignDecisionClassifier } from "../../src/scanners/design-decision-classifier.js";
import type { Finding } from "../../src/scanners/types.js";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    taskId: "semgrep",
    fingerprint: "test-fp-" + Math.random().toString(36).slice(2, 8),
    ruleId: "test/rule",
    filePath: "src/config.ts",
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

describe("DesignDecisionClassifier", () => {
  const classifier = new DesignDecisionClassifier();

  it("passes real vulnerabilities through to remaining", () => {
    const finding = makeFinding({
      message: "SQL injection in user query parameter",
      ruleId: "sql-injection",
    });
    const { autoClassified, remaining } = classifier.classify([finding]);
    expect(autoClassified).toHaveLength(0);
    expect(remaining).toHaveLength(1);
  });

  it("auto-classifies security toggle flag in config context", () => {
    const finding = makeFinding({
      message: "INSECURE_MODE flag allows disabling TLS verification",
      evidence: "config option INSECURE_MODE = true",
    });
    const { autoClassified, remaining } = classifier.classify([finding]);
    expect(autoClassified).toHaveLength(1);
    expect(remaining).toHaveLength(0);
    expect(autoClassified[0].result.verdict).toBe("by_design");
    expect(autoClassified[0].ruleId).toBe("security-toggle-flags");
  });

  it("does NOT classify security toggle without config context", () => {
    const finding = makeFinding({
      message: "Hardcoded INSECURE_MODE in production code",
      evidence: "const x = doSomething();",
    });
    const { autoClassified, remaining } = classifier.classify([finding]);
    expect(autoClassified).toHaveLength(0);
    expect(remaining).toHaveLength(1);
  });

  it("auto-classifies NODE_TLS_REJECT_UNAUTHORIZED env var", () => {
    const finding = makeFinding({
      message: "TLS certificate verification disabled",
      evidence: "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'",
    });
    const { autoClassified, remaining } = classifier.classify([finding]);
    expect(autoClassified).toHaveLength(1);
    expect(remaining).toHaveLength(0);
    expect(autoClassified[0].ruleId).toBe("env-var-security-toggle");
  });

  it("auto-classifies RFC 7591 dynamic client registration", () => {
    const finding = makeFinding({
      message: "Dynamic client registration allows unauthenticated registration",
      evidence: "RFC 7591 client_registration_endpoint handler",
    });
    const { autoClassified, remaining } = classifier.classify([finding]);
    expect(autoClassified).toHaveLength(1);
    expect(remaining).toHaveLength(0);
    expect(autoClassified[0].ruleId).toBe("rfc-compliant-behavior");
  });

  it("auto-classifies backward-compat legacy support", () => {
    const finding = makeFinding({
      message: "Legacy protocol fallback mode enabled",
      evidence: "backward compatibility for older clients",
      filePath: "src/compat/legacy-handler.ts",
    });
    const { autoClassified, remaining } = classifier.classify([finding]);
    expect(autoClassified).toHaveLength(1);
    expect(remaining).toHaveLength(0);
    expect(autoClassified[0].ruleId).toBe("backward-compat-legacy");
  });

  it("auto-classifies rejectUnauthorized in config context", () => {
    const finding = makeFinding({
      ruleId: "tls-cert-verification",
      message: "rejectUnauthorized set to false",
      evidence: "options.rejectUnauthorized = process.env.SKIP_TLS_VERIFY === '1'",
    });
    const { autoClassified, remaining } = classifier.classify([finding]);
    expect(autoClassified).toHaveLength(1);
    expect(remaining).toHaveLength(0);
    expect(autoClassified[0].ruleId).toBe("intentional-relaxation-config");
  });

  it("does NOT classify when exploit indicators are present", () => {
    const finding = makeFinding({
      message: "INSECURE_MODE config allows SQL injection in query parameter",
      evidence: "config option INSECURE_MODE enables injection",
    });
    const { autoClassified, remaining } = classifier.classify([finding]);
    expect(autoClassified).toHaveLength(0);
    expect(remaining).toHaveLength(1);
  });

  it("handles null evidence gracefully", () => {
    const finding = makeFinding({
      message: "DISABLE_TLS toggle in application config settings",
      evidence: null,
    });
    const { autoClassified, remaining } = classifier.classify([finding]);
    expect(autoClassified).toHaveLength(1);
    expect(remaining).toHaveLength(0);
  });

  it("correctly splits a mixed batch", () => {
    const findings = [
      makeFinding({ fingerprint: "a", message: "SQL injection", ruleId: "sqli" }),
      makeFinding({ fingerprint: "b", message: "NODE_TLS_REJECT_UNAUTHORIZED disabled", evidence: "process.env.NODE_TLS_REJECT_UNAUTHORIZED" }),
      makeFinding({ fingerprint: "c", message: "XSS in template rendering", ruleId: "xss" }),
      makeFinding({ fingerprint: "d", message: "RFC 7591 dynamic client registration endpoint", evidence: "client_registration_endpoint" }),
      makeFinding({ fingerprint: "e", message: "Path traversal in file upload", ruleId: "path-traversal" }),
    ];
    const { autoClassified, remaining } = classifier.classify(findings);
    expect(autoClassified).toHaveLength(2);
    expect(remaining).toHaveLength(3);
    expect(autoClassified.map((c) => c.finding.fingerprint).sort()).toEqual(["b", "d"]);
    expect(remaining.map((f) => f.fingerprint).sort()).toEqual(["a", "c", "e"]);
  });

  it("produces correct TriageResult shape", () => {
    const finding = makeFinding({
      fingerprint: "shape-test",
      message: "GIT_SSL_NO_VERIFY is set",
      evidence: "export GIT_SSL_NO_VERIFY=1",
    });
    const { autoClassified } = classifier.classify([finding]);
    expect(autoClassified).toHaveLength(1);
    const result = autoClassified[0].result;
    expect(result.fingerprint).toBe("shape-test");
    expect(result.verdict).toBe("by_design");
    expect(result.confidence).toBe(0.85);
    expect(result.rationale).toContain("GIT_SSL_NO_VERIFY");
    expect(result.verificationSteps).toEqual([]);
    expect(result.fixPatch).toBeNull();
  });

  it("env var match is case-sensitive", () => {
    const upper = makeFinding({
      fingerprint: "upper",
      message: "NODE_TLS_REJECT_UNAUTHORIZED set to 0",
      evidence: "process.env.NODE_TLS_REJECT_UNAUTHORIZED",
    });
    const lower = makeFinding({
      fingerprint: "lower",
      message: "node_tls_reject_unauthorized set to 0",
      evidence: "process.env.node_tls_reject_unauthorized",
    });
    const { autoClassified, remaining } = classifier.classify([upper, lower]);
    expect(autoClassified).toHaveLength(1);
    expect(autoClassified[0].finding.fingerprint).toBe("upper");
    expect(remaining).toHaveLength(1);
    expect(remaining[0].fingerprint).toBe("lower");
  });
});
