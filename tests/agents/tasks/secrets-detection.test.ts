import { describe, expect, it } from "vitest";
import { secretsDetectionTask, __secretsDetectionInternals } from "../../../src/agents/tasks/secrets-detection.js";
import type { KuzushiConfig } from "../../../src/types.js";
import type { TaskContext } from "../../../src/agents/types.js";

const { resolveConfig, buildPrompt, normalizeFindings, computeFingerprint } = __secretsDetectionInternals;

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

describe("secretsDetectionTask", () => {
  it("has correct metadata", () => {
    expect(secretsDetectionTask.id).toBe("secrets-detect");
    expect(secretsDetectionTask.outputKind).toBe("findings");
    expect(secretsDetectionTask.dependsOn).toEqual([]);
  });
});

describe("resolveConfig", () => {
  it("uses defaults when no scanner config", () => {
    const ctx = makeContext();
    const cfg = resolveConfig(ctx);
    expect(cfg.model).toBe("anthropic:claude-sonnet-4-6");
    expect(cfg.maxFindings).toBe(100);
  });

  it("reads overrides from scannerConfig", () => {
    const ctx = makeContext({
      scannerConfig: {
        "secrets-detect": { model: "openai:gpt-4", maxFindings: 25 },
      },
    });
    const cfg = resolveConfig(ctx);
    expect(cfg.model).toBe("openai:gpt-4");
    expect(cfg.maxFindings).toBe(25);
  });
});

describe("buildPrompt", () => {
  it("includes repo context when provided", () => {
    const prompt = buildPrompt(
      { languages: ["Python"], frameworks: ["Django"], authPatterns: [], sanitizationLibs: [], ormOrDb: [], entryPoints: [] },
      50,
    );
    expect(prompt).toContain("Python");
    expect(prompt).toContain("50");
  });

  it("works without repo context", () => {
    const prompt = buildPrompt(undefined, 100);
    expect(prompt).toContain("secrets detection");
    expect(prompt).toContain("100");
  });

  it("includes anti-hallucination constraints for test fixtures", () => {
    const prompt = buildPrompt(undefined, 100);
    expect(prompt).toContain("test fixture");
    expect(prompt).toContain("placeholder");
  });
});

describe("normalizeFindings", () => {
  it("normalizes valid findings", () => {
    const raw = {
      findings: [
        {
          secretType: "api-key",
          filePath: "src/config.ts",
          startLine: 5,
          severity: "ERROR",
          description: "AWS access key found",
          cwe: "CWE-798",
          confidence: "HIGH",
          rationale: "AKIA prefix detected with valid key format",
        },
      ],
    };

    const findings = normalizeFindings(raw, "/tmp/repo", "test-repo", 100);
    expect(findings).toHaveLength(1);
    expect(findings[0].scanner).toBe("secrets-detect");
    expect(findings[0].ruleId).toBe("secrets/api-key");
    expect(findings[0].filePath).toBe("src/config.ts");
    expect(findings[0].cwe).toEqual(["CWE-798"]);
  });

  it("deduplicates by fingerprint", () => {
    const raw = {
      findings: [
        { secretType: "api-key", filePath: "src/config.ts", startLine: 5, severity: "ERROR", description: "Key", cwe: "CWE-798", confidence: "HIGH", rationale: "r" },
        { secretType: "api-key", filePath: "src/config.ts", startLine: 5, severity: "WARNING", description: "Key", cwe: "CWE-798", confidence: "MEDIUM", rationale: "r" },
      ],
    };

    const findings = normalizeFindings(raw, "/tmp/repo", "test-repo", 100);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("ERROR");
  });

  it("returns empty for invalid input", () => {
    expect(normalizeFindings(null, "/tmp/repo", "test-repo", 100)).toEqual([]);
    expect(normalizeFindings({ findings: "not-array" }, "/tmp/repo", "test-repo", 100)).toEqual([]);
  });

  it("respects maxFindings", () => {
    const raw = {
      findings: Array.from({ length: 10 }, (_, i) => ({
        secretType: "api-key",
        filePath: `src/file${i}.ts`,
        startLine: i + 1,
        severity: "WARNING",
        description: "Key found",
        cwe: "CWE-798",
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
    const f = { secretType: "api-key", filePath: "src/config.ts", startLine: 5, severity: "ERROR", description: "", cwe: "CWE-798", confidence: "HIGH", rationale: "" };
    const fp1 = computeFingerprint("repo", "src/config.ts", f);
    const fp2 = computeFingerprint("repo", "src/config.ts", f);
    expect(fp1).toBe(fp2);
    expect(fp1).toHaveLength(64);
  });

  it("produces different fingerprints for different inputs", () => {
    const f1 = { secretType: "api-key", filePath: "src/config.ts", startLine: 5, severity: "ERROR", description: "", cwe: "", confidence: "", rationale: "" };
    const f2 = { ...f1, startLine: 6 };
    expect(computeFingerprint("repo", "src/config.ts", f1)).not.toBe(computeFingerprint("repo", "src/config.ts", f2));
  });
});

describe("triageAgentConfig", () => {
  it("returns a prompt with finding details", () => {
    const finding = {
      scanner: "secrets-detect",
      fingerprint: "abc",
      ruleId: "secrets/api-key",
      filePath: "src/config.ts",
      startLine: 5,
      severity: "ERROR",
      message: "AWS access key found",
      evidence: "AKIA prefix detected",
      scannerConfidence: "HIGH",
      subcategory: ["vuln"],
      likelihood: "HIGH",
      impact: "HIGH",
      cwe: ["CWE-798"],
      score: 54,
    };

    const config = secretsDetectionTask.triageAgentConfig!(finding, "test-repo");
    expect(config.prompt).toContain("secrets/api-key");
    expect(config.prompt).toContain("src/config.ts:5");
  });
});
