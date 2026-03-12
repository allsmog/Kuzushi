import { describe, expect, it } from "vitest";
import { dangerousApiTask, __dangerousApiInternals } from "../../../src/agents/tasks/dangerous-api.js";
import type { KuzushiConfig } from "../../../src/types.js";
import type { TaskContext } from "../../../src/agents/types.js";

const { resolveConfig, buildPrompt, normalizeFindings, computeFingerprint } = __dangerousApiInternals;

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

describe("dangerousApiTask", () => {
  it("has correct metadata", () => {
    expect(dangerousApiTask.id).toBe("dangerous-api-detect");
    expect(dangerousApiTask.outputKind).toBe("findings");
    expect(dangerousApiTask.dependsOn).toEqual(["context-gatherer"]);
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
        "dangerous-api": { model: "openai:gpt-4", maxFindings: 20 },
      },
    });
    const cfg = resolveConfig(ctx);
    expect(cfg.model).toBe("openai:gpt-4");
    expect(cfg.maxFindings).toBe(20);
  });
});

describe("buildPrompt", () => {
  it("includes expert persona", () => {
    const prompt = buildPrompt(undefined, 25);
    expect(prompt).toContain("senior application security engineer");
    expect(prompt).toContain("10+ years");
  });

  it("includes all categories", () => {
    const prompt = buildPrompt(undefined, 25);
    expect(prompt).toContain("unsafe-deserialization");
    expect(prompt).toContain("unsafe-subprocess");
    expect(prompt).toContain("unsafe-file-ops");
    expect(prompt).toContain("insecure-defaults");
    expect(prompt).toContain("unsafe-regex");
  });

  it("includes anti-hallucination constraints", () => {
    const prompt = buildPrompt(undefined, 25);
    expect(prompt).toContain("Anti-hallucination constraints");
  });

  it("includes framework guidance when context provided", () => {
    const prompt = buildPrompt(
      { languages: ["TypeScript"], frameworks: ["Express"], authPatterns: [], sanitizationLibs: ["helmet"], ormOrDb: [], entryPoints: [] },
      25,
    );
    expect(prompt).toContain("Express");
    expect(prompt).toContain("helmet");
    expect(prompt).toContain("Framework-specific guidance");
  });

  it("omits framework guidance when no frameworks", () => {
    const prompt = buildPrompt(
      { languages: ["TypeScript"], frameworks: [], authPatterns: [], sanitizationLibs: [], ormOrDb: [], entryPoints: [] },
      25,
    );
    expect(prompt).not.toContain("Framework-specific guidance");
  });
});

describe("normalizeFindings", () => {
  it("normalizes valid findings", () => {
    const raw = {
      findings: [
        {
          category: "unsafe-deserialization",
          filePath: "src/handler.ts",
          startLine: 42,
          severity: "ERROR",
          description: "Unsafe deserialization with user input",
          cwe: "502",
          confidence: "HIGH",
          rationale: "Request body passed to deserializer",
          apiOrFunction: "yaml.load()",
          inputSource: "req.body.data",
        },
      ],
    };

    const findings = normalizeFindings(raw, "/tmp/repo", "test-repo", 50);
    expect(findings).toHaveLength(1);
    expect(findings[0].scanner).toBe("dangerous-api-detect");
    expect(findings[0].ruleId).toBe("dangerous-api/unsafe-deserialization");
    expect(findings[0].message).toContain("yaml.load()");
  });

  it("handles missing optional fields", () => {
    const raw = {
      findings: [
        {
          category: "insecure-defaults",
          filePath: "src/config.ts",
          startLine: 10,
          severity: "WARNING",
          description: "Debug mode enabled",
          cwe: "16",
          confidence: "MEDIUM",
          rationale: "DEBUG=true in production config",
        },
      ],
    };

    const findings = normalizeFindings(raw, "/tmp/repo", "test-repo", 50);
    expect(findings).toHaveLength(1);
    expect(findings[0].message).not.toContain("undefined");
  });

  it("returns empty for invalid input", () => {
    expect(normalizeFindings(null, "/tmp/repo", "test-repo", 50)).toEqual([]);
  });

  it("deduplicates by fingerprint", () => {
    const raw = {
      findings: [
        { category: "unsafe-subprocess", filePath: "src/a.ts", startLine: 1, severity: "ERROR", description: "cmd injection", cwe: "78", confidence: "HIGH", rationale: "r" },
        { category: "unsafe-subprocess", filePath: "src/a.ts", startLine: 1, severity: "WARNING", description: "cmd injection", cwe: "78", confidence: "MEDIUM", rationale: "r" },
      ],
    };

    const findings = normalizeFindings(raw, "/tmp/repo", "test-repo", 50);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("ERROR");
  });

  it("respects maxFindings", () => {
    const raw = {
      findings: Array.from({ length: 10 }, (_, i) => ({
        category: "unsafe-subprocess",
        filePath: `src/file${i}.ts`,
        startLine: 1,
        severity: "ERROR",
        description: `Finding ${i}`,
        cwe: "78",
        confidence: "HIGH",
        rationale: "r",
      })),
    };

    const findings = normalizeFindings(raw, "/tmp/repo", "test-repo", 3);
    expect(findings).toHaveLength(3);
  });
});

describe("computeFingerprint", () => {
  it("produces stable fingerprints", () => {
    const f = { category: "unsafe-subprocess", filePath: "src/a.ts", startLine: 1, severity: "ERROR", description: "", cwe: "78", confidence: "HIGH", rationale: "" };
    const fp1 = computeFingerprint("repo", "src/a.ts", f);
    const fp2 = computeFingerprint("repo", "src/a.ts", f);
    expect(fp1).toBe(fp2);
  });
});

describe("triageAgentConfig", () => {
  it("returns a prompt with finding details", () => {
    const finding = {
      scanner: "dangerous-api-detect",
      fingerprint: "abc",
      ruleId: "dangerous-api/unsafe-subprocess",
      filePath: "src/handler.ts",
      startLine: 42,
      severity: "ERROR",
      message: "Command injection with user input",
      evidence: "Request body passed to shell command",
      scannerConfidence: "HIGH",
      subcategory: ["vuln"],
      likelihood: "HIGH",
      impact: "HIGH",
      cwe: ["78"],
      score: 54,
    };

    const config = dangerousApiTask.triageAgentConfig!(finding, "test-repo");
    expect(config.prompt).toContain("dangerous-api/unsafe-subprocess");
    expect(config.prompt).toContain("src/handler.ts:42");
  });
});
