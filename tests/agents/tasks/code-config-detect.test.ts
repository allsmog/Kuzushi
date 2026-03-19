import { describe, expect, it } from "vitest";
import { codeConfigDetectTask, __codeConfigDetectInternals } from "../../../src/agents/tasks/code-config-detect.js";
import type { KuzushiConfig } from "../../../src/types.js";
import type { TaskContext } from "../../../src/agents/types.js";

const { resolveConfig, buildPrompt, normalizeFindings, computeFingerprint } = __codeConfigDetectInternals;

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

describe("codeConfigDetectTask", () => {
  it("has correct metadata", () => {
    expect(codeConfigDetectTask.id).toBe("code-config-detect");
    expect(codeConfigDetectTask.outputKind).toBe("findings");
    expect(codeConfigDetectTask.dependsOn).toEqual(["context-gatherer"]);
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
        "code-config-detect": { model: "openai:gpt-4", maxFindings: 20 },
      },
    });
    const cfg = resolveConfig(ctx);
    expect(cfg.model).toBe("openai:gpt-4");
    expect(cfg.maxFindings).toBe(20);
  });
});

describe("buildPrompt", () => {
  it("includes all three detection sections", () => {
    const prompt = buildPrompt(undefined, 50);
    expect(prompt).toContain("Part 1: Dangerous API Detection");
    expect(prompt).toContain("Part 2: Auth/Access Control Detection");
    expect(prompt).toContain("Part 3: Security Misconfiguration Detection");
  });

  it("includes dangerous API categories", () => {
    const prompt = buildPrompt(undefined, 50);
    expect(prompt).toContain("unsafe-deserialization");
    expect(prompt).toContain("unsafe-subprocess");
    expect(prompt).toContain("unsafe-file-ops");
  });

  it("includes auth categories", () => {
    const prompt = buildPrompt(undefined, 50);
    expect(prompt).toContain("unprotected-endpoint");
    expect(prompt).toContain("missing-role-check");
    expect(prompt).toContain("idor");
  });

  it("includes misconfig categories", () => {
    const prompt = buildPrompt(undefined, 50);
    expect(prompt).toContain("debug-mode");
    expect(prompt).toContain("insecure-cors");
    expect(prompt).toContain("container-misconfig");
  });

  it("includes framework guidance when context provided", () => {
    const prompt = buildPrompt(
      { languages: ["TypeScript"], frameworks: ["Express"], authPatterns: [], sanitizationLibs: ["helmet"], ormOrDb: [], entryPoints: [] },
      25,
    );
    expect(prompt).toContain("Express");
    expect(prompt).toContain("Framework-specific guidance");
  });

  it("includes anti-hallucination constraints", () => {
    const prompt = buildPrompt(undefined, 25);
    expect(prompt).toContain("Anti-hallucination constraints");
  });
});

describe("normalizeFindings", () => {
  it("normalizes dangerous-api findings", () => {
    const raw = {
      findings: [
        {
          detectorId: "dangerous-api-detect",
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

  it("normalizes auth-access findings with endpoint info", () => {
    const raw = {
      findings: [
        {
          detectorId: "auth-access-detect",
          category: "unprotected-endpoint",
          filePath: "src/routes.ts",
          startLine: 15,
          severity: "ERROR",
          description: "POST endpoint without auth middleware",
          cwe: "CWE-862",
          confidence: "HIGH",
          rationale: "No auth check",
          endpoint: "/api/admin/users",
          httpMethod: "POST",
        },
      ],
    };

    const findings = normalizeFindings(raw, "/tmp/repo", "test-repo", 50);
    expect(findings).toHaveLength(1);
    expect(findings[0].scanner).toBe("auth-access-detect");
    expect(findings[0].ruleId).toBe("auth-access/unprotected-endpoint");
    expect(findings[0].message).toContain("POST /api/admin/users");
  });

  it("normalizes security-misconfig findings", () => {
    const raw = {
      findings: [
        {
          detectorId: "security-misconfig-detect",
          category: "debug-mode",
          filePath: "src/app.ts",
          startLine: 3,
          severity: "WARNING",
          description: "Debug mode enabled in production",
          cwe: "CWE-489",
          confidence: "HIGH",
          rationale: "DEBUG=true in config",
        },
      ],
    };

    const findings = normalizeFindings(raw, "/tmp/repo", "test-repo", 50);
    expect(findings).toHaveLength(1);
    expect(findings[0].scanner).toBe("security-misconfig-detect");
    expect(findings[0].ruleId).toBe("security-misconfig/debug-mode");
  });

  it("handles mixed findings from all three detectors", () => {
    const raw = {
      findings: [
        { detectorId: "dangerous-api-detect", category: "unsafe-eval", filePath: "src/a.ts", startLine: 1, severity: "ERROR", description: "eval", cwe: "94", confidence: "HIGH", rationale: "r" },
        { detectorId: "auth-access-detect", category: "idor", filePath: "src/b.ts", startLine: 2, severity: "WARNING", description: "idor", cwe: "639", confidence: "MEDIUM", rationale: "r" },
        { detectorId: "security-misconfig-detect", category: "insecure-cors", filePath: "src/c.ts", startLine: 3, severity: "WARNING", description: "cors", cwe: "942", confidence: "HIGH", rationale: "r" },
      ],
    };

    const findings = normalizeFindings(raw, "/tmp/repo", "test-repo", 50);
    expect(findings).toHaveLength(3);
    expect(findings.map(f => f.scanner).sort()).toEqual(["auth-access-detect", "dangerous-api-detect", "security-misconfig-detect"]);
  });

  it("deduplicates by fingerprint", () => {
    const raw = {
      findings: [
        { detectorId: "dangerous-api-detect", category: "unsafe-subprocess", filePath: "src/a.ts", startLine: 1, severity: "ERROR", description: "cmd injection", cwe: "78", confidence: "HIGH", rationale: "r" },
        { detectorId: "dangerous-api-detect", category: "unsafe-subprocess", filePath: "src/a.ts", startLine: 1, severity: "WARNING", description: "cmd injection", cwe: "78", confidence: "MEDIUM", rationale: "r" },
      ],
    };

    const findings = normalizeFindings(raw, "/tmp/repo", "test-repo", 50);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("ERROR");
  });

  it("returns empty for invalid input", () => {
    expect(normalizeFindings(null, "/tmp/repo", "test-repo", 50)).toEqual([]);
  });

  it("respects maxFindings", () => {
    const raw = {
      findings: Array.from({ length: 10 }, (_, i) => ({
        detectorId: "dangerous-api-detect",
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
    const fp1 = computeFingerprint("repo", "dangerous-api", "unsafe-subprocess", "src/a.ts", 1);
    const fp2 = computeFingerprint("repo", "dangerous-api", "unsafe-subprocess", "src/a.ts", 1);
    expect(fp1).toBe(fp2);
  });

  it("produces different fingerprints for different detectors", () => {
    const fp1 = computeFingerprint("repo", "dangerous-api", "unsafe-eval", "src/a.ts", 1);
    const fp2 = computeFingerprint("repo", "auth-access", "idor", "src/a.ts", 1);
    expect(fp1).not.toBe(fp2);
  });
});

describe("triageAgentConfig", () => {
  it("returns dangerous-api-specific prompt for dangerous-api findings", () => {
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

    const config = codeConfigDetectTask.triageAgentConfig!(finding, "test-repo");
    expect(config.prompt).toContain("dangerous API usage");
    expect(config.prompt).toContain("dangerous-api/unsafe-subprocess");
  });

  it("returns auth-specific prompt for auth findings", () => {
    const finding = {
      scanner: "auth-access-detect",
      fingerprint: "def",
      ruleId: "auth-access/unprotected-endpoint",
      filePath: "src/routes.ts",
      startLine: 15,
      severity: "ERROR",
      message: "Unprotected POST endpoint",
      evidence: null,
      scannerConfidence: "HIGH",
      subcategory: ["vuln"],
      likelihood: "HIGH",
      impact: "HIGH",
      cwe: ["CWE-862"],
      score: 54,
    };

    const config = codeConfigDetectTask.triageAgentConfig!(finding, "test-repo");
    expect(config.prompt).toContain("auth/access control");
    expect(config.prompt).toContain("middleware");
  });

  it("returns misconfig-specific prompt for security-misconfig findings", () => {
    const finding = {
      scanner: "security-misconfig-detect",
      fingerprint: "ghi",
      ruleId: "security-misconfig/debug-mode",
      filePath: "src/app.ts",
      startLine: 3,
      severity: "WARNING",
      message: "Debug mode enabled",
      evidence: "DEBUG=true in config",
      scannerConfidence: "HIGH",
      subcategory: ["vuln"],
      likelihood: "HIGH",
      impact: "MEDIUM",
      cwe: ["CWE-489"],
      score: 48,
    };

    const config = codeConfigDetectTask.triageAgentConfig!(finding, "test-repo");
    expect(config.prompt).toContain("security misconfiguration");
    expect(config.prompt).toContain("production environments");
  });
});
