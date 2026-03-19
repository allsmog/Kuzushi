import { describe, expect, it } from "vitest";
import { secretsCryptoDetectTask, __secretsCryptoDetectInternals } from "../../../src/agents/tasks/secrets-crypto-detect.js";
import type { KuzushiConfig } from "../../../src/types.js";
import type { TaskContext } from "../../../src/agents/types.js";

const { resolveConfig, buildPrompt, normalizeFindings, computeFingerprint } = __secretsCryptoDetectInternals;

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
    triageMaxTurns: 7,
    busBackend: "in-process",
    triageBatchSize: 40,
    triageConcurrency: 1,
    scanMode: "sequential",
    enabledTasks: [],
    scanners: ["semgrep"],
    severity: ["ERROR"],
    excludePatterns: [],
    scannerConfig: overrides.scannerConfig as Record<string, Record<string, unknown>> ?? {},
  };
}

describe("secretsCryptoDetectTask", () => {
  it("has correct metadata", () => {
    expect(secretsCryptoDetectTask.id).toBe("secrets-crypto-detect");
    expect(secretsCryptoDetectTask.outputKind).toBe("findings");
    expect(secretsCryptoDetectTask.dependsOn).toEqual(["context-gatherer"]);
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
        "secrets-crypto-detect": { model: "openai:gpt-4", maxFindings: 25 },
      },
    });
    const cfg = resolveConfig(ctx);
    expect(cfg.model).toBe("openai:gpt-4");
    expect(cfg.maxFindings).toBe(25);
  });
});

describe("buildPrompt", () => {
  it("includes both secrets and crypto sections", () => {
    const prompt = buildPrompt(undefined, 50);
    expect(prompt).toContain("Part 1: Secrets Detection");
    expect(prompt).toContain("Part 2: Cryptographic Misuse Detection");
    expect(prompt).toContain("api-key");
    expect(prompt).toContain("hash-for-auth");
  });

  it("includes repo context when provided", () => {
    const prompt = buildPrompt(
      { languages: ["Python"], frameworks: ["Django"], authPatterns: [], sanitizationLibs: [], ormOrDb: [], entryPoints: [] },
      50,
    );
    expect(prompt).toContain("Python");
  });

  it("includes anti-hallucination constraints for test fixtures", () => {
    const prompt = buildPrompt(undefined, 100);
    expect(prompt).toContain("test fixture");
    expect(prompt).toContain("placeholder");
  });
});

describe("normalizeFindings", () => {
  it("normalizes secrets findings with correct scanner and ruleId", () => {
    const raw = {
      findings: [
        {
          detectorId: "secrets-detect",
          category: "api-key",
          filePath: "src/config.ts",
          startLine: 5,
          severity: "ERROR",
          description: "AWS access key found",
          cwe: "CWE-798",
          confidence: "HIGH",
          rationale: "AKIA prefix detected",
        },
      ],
    };

    const findings = normalizeFindings(raw, "/tmp/repo", "test-repo", 100);
    expect(findings).toHaveLength(1);
    expect(findings[0].scanner).toBe("secrets-detect");
    expect(findings[0].ruleId).toBe("secrets/api-key");
    expect(findings[0].cwe).toEqual(["CWE-798"]);
  });

  it("normalizes crypto findings with correct scanner and ruleId", () => {
    const raw = {
      findings: [
        {
          detectorId: "crypto-misuse-detect",
          category: "hash-for-auth",
          filePath: "src/auth.ts",
          startLine: 10,
          severity: "WARNING",
          description: "MD5 used for password hashing",
          cwe: "CWE-328",
          confidence: "HIGH",
          rationale: "MD5 is not suitable for password hashing",
        },
      ],
    };

    const findings = normalizeFindings(raw, "/tmp/repo", "test-repo", 100);
    expect(findings).toHaveLength(1);
    expect(findings[0].scanner).toBe("crypto-misuse-detect");
    expect(findings[0].ruleId).toBe("crypto-misuse/hash-for-auth");
    expect(findings[0].cwe).toEqual(["CWE-328"]);
  });

  it("handles mixed findings from both detectors", () => {
    const raw = {
      findings: [
        {
          detectorId: "secrets-detect",
          category: "api-key",
          filePath: "src/config.ts",
          startLine: 5,
          severity: "ERROR",
          description: "AWS key",
          cwe: "CWE-798",
          confidence: "HIGH",
          rationale: "r",
        },
        {
          detectorId: "crypto-misuse-detect",
          category: "ecb-mode",
          filePath: "src/crypto.ts",
          startLine: 20,
          severity: "WARNING",
          description: "ECB mode",
          cwe: "CWE-327",
          confidence: "MEDIUM",
          rationale: "r",
        },
      ],
    };

    const findings = normalizeFindings(raw, "/tmp/repo", "test-repo", 100);
    expect(findings).toHaveLength(2);
    expect(findings.map(f => f.scanner).sort()).toEqual(["crypto-misuse-detect", "secrets-detect"]);
  });

  it("deduplicates by fingerprint", () => {
    const raw = {
      findings: [
        { detectorId: "secrets-detect", category: "api-key", filePath: "src/config.ts", startLine: 5, severity: "ERROR", description: "Key", cwe: "CWE-798", confidence: "HIGH", rationale: "r" },
        { detectorId: "secrets-detect", category: "api-key", filePath: "src/config.ts", startLine: 5, severity: "WARNING", description: "Key", cwe: "CWE-798", confidence: "MEDIUM", rationale: "r" },
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
        detectorId: "secrets-detect",
        category: "api-key",
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
    const fp1 = computeFingerprint("repo", "secrets-detect", "api-key", "src/config.ts", 5);
    const fp2 = computeFingerprint("repo", "secrets-detect", "api-key", "src/config.ts", 5);
    expect(fp1).toBe(fp2);
    expect(fp1).toHaveLength(64);
  });

  it("produces different fingerprints for different detectors", () => {
    const fp1 = computeFingerprint("repo", "secrets-detect", "api-key", "src/config.ts", 5);
    const fp2 = computeFingerprint("repo", "crypto-misuse", "hash-for-auth", "src/config.ts", 5);
    expect(fp1).not.toBe(fp2);
  });
});

describe("triageAgentConfig", () => {
  it("returns secrets-specific prompt for secrets findings", () => {
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

    const config = secretsCryptoDetectTask.triageAgentConfig!(finding, "test-repo");
    expect(config.prompt).toContain("secrets detection");
    expect(config.prompt).toContain("secrets/api-key");
    expect(config.prompt).toContain("placeholder/test fixture");
  });

  it("returns crypto-specific prompt for crypto findings", () => {
    const finding = {
      scanner: "crypto-misuse-detect",
      fingerprint: "def",
      ruleId: "crypto-misuse/hash-for-auth",
      filePath: "src/auth.ts",
      startLine: 10,
      severity: "WARNING",
      message: "MD5 for password hashing",
      evidence: "Use bcrypt instead",
      scannerConfidence: "HIGH",
      subcategory: ["vuln"],
      likelihood: "HIGH",
      impact: "MEDIUM",
      cwe: ["CWE-328"],
      score: 48,
    };

    const config = secretsCryptoDetectTask.triageAgentConfig!(finding, "test-repo");
    expect(config.prompt).toContain("crypto misuse");
    expect(config.prompt).toContain("crypto-misuse/hash-for-auth");
    expect(config.prompt).toContain("compensating controls");
  });
});
