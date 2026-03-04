import { describe, expect, it } from "vitest";
import { authAccessTask, __authAccessInternals } from "../../../src/agents/tasks/auth-access.js";
import type { KuzushiConfig } from "../../../src/types.js";
import type { TaskContext } from "../../../src/agents/types.js";

const { resolveConfig, buildPrompt, normalizeFindings, computeFingerprint } = __authAccessInternals;

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

describe("authAccessTask", () => {
  it("has correct metadata", () => {
    expect(authAccessTask.id).toBe("auth-access-detect");
    expect(authAccessTask.outputKind).toBe("findings");
    expect(authAccessTask.dependsOn).toEqual(["context-gatherer"]);
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
        "auth-access": { model: "openai:gpt-4", maxFindings: 20 },
      },
    });
    const cfg = resolveConfig(ctx);
    expect(cfg.model).toBe("openai:gpt-4");
    expect(cfg.maxFindings).toBe(20);
  });
});

describe("buildPrompt", () => {
  it("includes auth patterns context when provided", () => {
    const prompt = buildPrompt(
      { languages: ["TypeScript"], frameworks: ["Express"], authPatterns: ["JWT"], sanitizationLibs: [], ormOrDb: [], entryPoints: ["src/index.ts"] },
      25,
    );
    expect(prompt).toContain("JWT");
    expect(prompt).toContain("src/index.ts");
    expect(prompt).toContain("25");
  });
});

describe("normalizeFindings", () => {
  it("normalizes valid findings", () => {
    const raw = {
      findings: [
        {
          pattern: "unprotected-endpoint",
          filePath: "src/routes/admin.ts",
          startLine: 15,
          severity: "ERROR",
          description: "Admin endpoint without auth",
          cwe: "862",
          confidence: "HIGH",
          rationale: "POST /admin/delete has no middleware",
          endpoint: "/admin/delete",
          httpMethod: "POST",
        },
      ],
    };

    const findings = normalizeFindings(raw, "/tmp/repo", "test-repo", 50);
    expect(findings).toHaveLength(1);
    expect(findings[0].scanner).toBe("auth-access-detect");
    expect(findings[0].ruleId).toBe("auth-access/unprotected-endpoint");
    expect(findings[0].message).toContain("POST /admin/delete");
  });

  it("handles missing endpoint info", () => {
    const raw = {
      findings: [
        {
          pattern: "idor",
          filePath: "src/api.ts",
          startLine: 5,
          severity: "WARNING",
          description: "No ownership check",
          cwe: "639",
          confidence: "MEDIUM",
          rationale: "User ID from URL param",
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
});

describe("computeFingerprint", () => {
  it("produces stable fingerprints", () => {
    const f = { pattern: "idor", filePath: "src/api.ts", startLine: 5, severity: "WARNING", description: "", cwe: "639", confidence: "MEDIUM", rationale: "" };
    const fp1 = computeFingerprint("repo", "src/api.ts", f);
    const fp2 = computeFingerprint("repo", "src/api.ts", f);
    expect(fp1).toBe(fp2);
  });
});

describe("triageAgentConfig", () => {
  it("returns a prompt with finding details", () => {
    const finding = {
      scanner: "auth-access-detect",
      fingerprint: "abc",
      ruleId: "auth-access/unprotected-endpoint",
      filePath: "src/routes/admin.ts",
      startLine: 15,
      severity: "ERROR",
      message: "Admin endpoint without auth",
      evidence: "POST /admin/delete has no middleware",
      scannerConfidence: "HIGH",
      subcategory: ["vuln"],
      likelihood: "HIGH",
      impact: "HIGH",
      cwe: ["862"],
      score: 54,
    };

    const config = authAccessTask.triageAgentConfig!(finding, "test-repo");
    expect(config.prompt).toContain("auth-access/unprotected-endpoint");
    expect(config.prompt).toContain("src/routes/admin.ts:15");
  });
});
