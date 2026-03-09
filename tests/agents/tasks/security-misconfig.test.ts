import { describe, expect, it } from "vitest";
import { securityMisconfigTask, __securityMisconfigInternals } from "../../../src/agents/tasks/security-misconfig.js";
import type { KuzushiConfig } from "../../../src/types.js";
import type { TaskContext } from "../../../src/agents/types.js";

const { resolveConfig, buildPrompt, normalizeFindings, computeFingerprint } = __securityMisconfigInternals;

function makeContext(overrides: Record<string, unknown> = {}): TaskContext {
  return {
    runId: "test-run",
    repoRoot: "/tmp/repo",
    repoName: "test-repo",
    config: makeConfig(overrides),
    bus: {} as TaskContext["bus"],
    upstreamOutputs: new Map(),
  };
}

function makeConfig(overrides: Record<string, unknown> = {}): KuzushiConfig {
  return {
    model: "anthropic:claude-sonnet-4-6",
    triageMaxTurns: 10,
    busBackend: "in-process",
    triageBatchSize: 15,
    triageConcurrency: 1,
    scanMode: "sequential",
    enabledTasks: [],
    scanners: ["semgrep"],
    severity: ["ERROR"],
    excludePatterns: [],
    scannerConfig: overrides.scannerConfig as Record<string, Record<string, unknown>> ?? {},
  };
}

describe("securityMisconfigTask", () => {
  it("has correct metadata", () => {
    expect(securityMisconfigTask.id).toBe("security-misconfig-detect");
    expect(securityMisconfigTask.outputKind).toBe("findings");
    expect(securityMisconfigTask.dependsOn).toEqual(["context-gatherer"]);
  });
});

describe("resolveConfig", () => {
  it("uses defaults when no scanner config", () => {
    const ctx = makeContext();
    const cfg = resolveConfig(ctx);
    expect(cfg.model).toBe("anthropic:claude-sonnet-4-6");
    expect(cfg.maxFindings).toBe(50);
  });

  it("reads overrides from scannerConfig", () => {
    const ctx = makeContext({
      scannerConfig: {
        "security-misconfig-detect": { model: "openai:gpt-4", maxFindings: 10 },
      },
    });
    const cfg = resolveConfig(ctx);
    expect(cfg.model).toBe("openai:gpt-4");
    expect(cfg.maxFindings).toBe(10);
  });
});

describe("buildPrompt", () => {
  it("includes repo context when provided", () => {
    const prompt = buildPrompt(
      { languages: ["Python"], frameworks: ["Django"], authPatterns: [], sanitizationLibs: [], ormOrDb: [], entryPoints: [] },
      25,
    );
    expect(prompt).toContain("Python");
    expect(prompt).toContain("25");
  });

  it("works without repo context", () => {
    const prompt = buildPrompt(undefined, 50);
    expect(prompt).toContain("security hardening");
    expect(prompt).toContain("50");
  });

  it("covers all misconfiguration categories", () => {
    const prompt = buildPrompt(undefined, 50);
    expect(prompt).toContain("debug-mode");
    expect(prompt).toContain("missing-headers");
    expect(prompt).toContain("insecure-cors");
    expect(prompt).toContain("insecure-cookies");
    expect(prompt).toContain("default-credentials");
    expect(prompt).toContain("exposed-admin");
    expect(prompt).toContain("verbose-errors");
  });
});

describe("normalizeFindings", () => {
  it("normalizes valid findings", () => {
    const raw = {
      findings: [
        {
          category: "debug-mode",
          filePath: "settings.py",
          startLine: 10,
          severity: "ERROR",
          description: "DEBUG=True in production config",
          cwe: "CWE-489",
          confidence: "HIGH",
          rationale: "DEBUG is set to True without environment check",
        },
      ],
    };

    const findings = normalizeFindings(raw, "/tmp/repo", "test-repo", 50);
    expect(findings).toHaveLength(1);
    expect(findings[0].scanner).toBe("security-misconfig-detect");
    expect(findings[0].ruleId).toBe("security-misconfig/debug-mode");
    expect(findings[0].filePath).toBe("settings.py");
    expect(findings[0].cwe).toEqual(["CWE-489"]);
  });

  it("deduplicates by fingerprint", () => {
    const raw = {
      findings: [
        { category: "debug-mode", filePath: "settings.py", startLine: 10, severity: "ERROR", description: "Debug on", cwe: "CWE-489", confidence: "HIGH", rationale: "r" },
        { category: "debug-mode", filePath: "settings.py", startLine: 10, severity: "WARNING", description: "Debug on", cwe: "CWE-489", confidence: "MEDIUM", rationale: "r" },
      ],
    };

    const findings = normalizeFindings(raw, "/tmp/repo", "test-repo", 50);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("ERROR");
  });

  it("returns empty for invalid input", () => {
    expect(normalizeFindings(null, "/tmp/repo", "test-repo", 50)).toEqual([]);
    expect(normalizeFindings({ findings: "not-array" }, "/tmp/repo", "test-repo", 50)).toEqual([]);
  });

  it("respects maxFindings", () => {
    const raw = {
      findings: Array.from({ length: 10 }, (_, i) => ({
        category: "debug-mode",
        filePath: `src/file${i}.py`,
        startLine: i + 1,
        severity: "WARNING",
        description: "Debug mode",
        cwe: "CWE-489",
        confidence: "MEDIUM",
        rationale: "r",
      })),
    };

    const findings = normalizeFindings(raw, "/tmp/repo", "test-repo", 3);
    expect(findings).toHaveLength(3);
  });
});

describe("computeFingerprint", () => {
  it("produces stable fingerprints", () => {
    const f = { category: "debug-mode", filePath: "settings.py", startLine: 10, severity: "ERROR", description: "", cwe: "CWE-489", confidence: "HIGH", rationale: "" };
    const fp1 = computeFingerprint("repo", "settings.py", f);
    const fp2 = computeFingerprint("repo", "settings.py", f);
    expect(fp1).toBe(fp2);
    expect(fp1).toHaveLength(64);
  });

  it("produces different fingerprints for different inputs", () => {
    const f1 = { category: "debug-mode", filePath: "settings.py", startLine: 10, severity: "ERROR", description: "", cwe: "", confidence: "", rationale: "" };
    const f2 = { ...f1, startLine: 11 };
    expect(computeFingerprint("repo", "settings.py", f1)).not.toBe(computeFingerprint("repo", "settings.py", f2));
  });
});

describe("triageAgentConfig", () => {
  it("returns a prompt with finding details", () => {
    const finding = {
      scanner: "security-misconfig-detect",
      fingerprint: "abc",
      ruleId: "security-misconfig/debug-mode",
      filePath: "settings.py",
      startLine: 10,
      severity: "ERROR",
      message: "DEBUG=True in production",
      evidence: "No environment check",
      scannerConfidence: "HIGH",
      subcategory: ["vuln"],
      likelihood: "HIGH",
      impact: "HIGH",
      cwe: ["CWE-489"],
      score: 54,
    };

    const config = securityMisconfigTask.triageAgentConfig!(finding, "test-repo");
    expect(config.prompt).toContain("security-misconfig/debug-mode");
    expect(config.prompt).toContain("settings.py:10");
  });
});
