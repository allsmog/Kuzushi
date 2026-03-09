import { describe, expect, it } from "vitest";
import { cryptoMisuseTask, __cryptoMisuseInternals } from "../../../src/agents/tasks/crypto-misuse.js";
import type { KuzushiConfig } from "../../../src/types.js";
import type { TaskContext } from "../../../src/agents/types.js";

const { resolveConfig, buildPrompt, normalizeFindings, computeFingerprint } = __cryptoMisuseInternals;

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

describe("cryptoMisuseTask", () => {
  it("has correct metadata", () => {
    expect(cryptoMisuseTask.id).toBe("crypto-misuse-detect");
    expect(cryptoMisuseTask.outputKind).toBe("findings");
    expect(cryptoMisuseTask.dependsOn).toEqual(["context-gatherer"]);
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
        "crypto-misuse": { model: "openai:gpt-4", maxFindings: 10 },
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
      { languages: ["TypeScript"], frameworks: ["Express"], authPatterns: [], sanitizationLibs: [], ormOrDb: [], entryPoints: [] },
      25,
    );
    expect(prompt).toContain("TypeScript");
    expect(prompt).toContain("25");
  });

  it("works without repo context", () => {
    const prompt = buildPrompt(undefined, 50);
    expect(prompt).toContain("cryptographic practices");
    expect(prompt).toContain("50");
  });
});

describe("normalizeFindings", () => {
  it("normalizes valid findings", () => {
    const raw = {
      findings: [
        {
          category: "hash-for-auth",
          filePath: "src/auth.ts",
          startLine: 10,
          severity: "ERROR",
          algorithmOrPattern: "MD5",
          recommendation: "Use bcrypt",
          cwe: "328",
          confidence: "HIGH",
          rationale: "MD5 used for password hashing",
        },
      ],
    };

    const findings = normalizeFindings(raw, "/tmp/repo", "test-repo", 50);
    expect(findings).toHaveLength(1);
    expect(findings[0].scanner).toBe("crypto-misuse-detect");
    expect(findings[0].ruleId).toBe("crypto-misuse/hash-for-auth");
    expect(findings[0].filePath).toBe("src/auth.ts");
    expect(findings[0].cwe).toEqual(["328"]);
  });

  it("deduplicates by fingerprint", () => {
    const raw = {
      findings: [
        { category: "hash-for-auth", filePath: "src/auth.ts", startLine: 10, severity: "ERROR", algorithmOrPattern: "MD5", recommendation: "Use bcrypt", cwe: "328", confidence: "HIGH", rationale: "MD5" },
        { category: "hash-for-auth", filePath: "src/auth.ts", startLine: 10, severity: "WARNING", algorithmOrPattern: "MD5", recommendation: "Use bcrypt", cwe: "328", confidence: "MEDIUM", rationale: "MD5" },
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
        category: "hash-for-auth",
        filePath: `src/file${i}.ts`,
        startLine: i + 1,
        severity: "WARNING",
        algorithmOrPattern: "MD5",
        recommendation: "Use bcrypt",
        cwe: "328",
        confidence: "MEDIUM",
        rationale: "MD5",
      })),
    };

    const findings = normalizeFindings(raw, "/tmp/repo", "test-repo", 3);
    expect(findings).toHaveLength(3);
  });
});

describe("computeFingerprint", () => {
  it("produces stable fingerprints", () => {
    const f = { category: "hash-for-auth", filePath: "src/auth.ts", startLine: 10, severity: "ERROR", algorithmOrPattern: "MD5", recommendation: "", cwe: "328", confidence: "HIGH", rationale: "" };
    const fp1 = computeFingerprint("repo", "src/auth.ts", f);
    const fp2 = computeFingerprint("repo", "src/auth.ts", f);
    expect(fp1).toBe(fp2);
    expect(fp1).toHaveLength(64);
  });

  it("produces different fingerprints for different inputs", () => {
    const f1 = { category: "hash-for-auth", filePath: "src/auth.ts", startLine: 10, severity: "ERROR", algorithmOrPattern: "", recommendation: "", cwe: "", confidence: "", rationale: "" };
    const f2 = { ...f1, startLine: 11 };
    expect(computeFingerprint("repo", "src/auth.ts", f1)).not.toBe(computeFingerprint("repo", "src/auth.ts", f2));
  });
});

describe("triageAgentConfig", () => {
  it("returns a prompt with finding details", () => {
    const finding = {
      scanner: "crypto-misuse-detect",
      fingerprint: "abc",
      ruleId: "crypto-misuse/hash-for-auth",
      filePath: "src/auth.ts",
      startLine: 10,
      severity: "ERROR",
      message: "MD5 used for auth",
      evidence: "Use bcrypt",
      scannerConfidence: "HIGH",
      subcategory: ["vuln"],
      likelihood: "HIGH",
      impact: "HIGH",
      cwe: ["328"],
      score: 54,
    };

    const config = cryptoMisuseTask.triageAgentConfig!(finding, "test-repo");
    expect(config.prompt).toContain("crypto-misuse/hash-for-auth");
    expect(config.prompt).toContain("src/auth.ts:10");
  });
});
