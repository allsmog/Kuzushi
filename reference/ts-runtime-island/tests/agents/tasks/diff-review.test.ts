import { describe, expect, it } from "vitest";
import { __diffReviewInternals, diffReviewTask } from "../../../src/agents/tasks/diff-review.js";
import type { DagRunContext } from "../../../src/agents/types.js";
import type { KuzushiConfig } from "../../../src/types.js";

const { resolveConfig, buildPrompt, normalizeFindings, computeFingerprint } = __diffReviewInternals;

function makeContext(overrides: Record<string, unknown> = {}): DagRunContext {
  return {
    runId: "test-run",
    repoRoot: "/tmp/repo",
    repoName: "test-repo",
    config: makeConfig(overrides),
    bus: {} as DagRunContext["bus"],
    upstreamOutputs: new Map(),
  };
}

function makeConfig(overrides: Record<string, unknown> = {}): KuzushiConfig {
  return {
    model: "anthropic:claude-sonnet-4-6",
    busBackend: "in-process",
    triageBatchSize: 15,
    triageConcurrency: 1,
    scanMode: "sequential",
    tasks: ["semgrep"],
    severity: ["ERROR"],
    excludePatterns: [],
    taskConfig: {},
    ...overrides,
  };
}

describe("diffReviewTask", () => {
  it("has correct metadata", () => {
    expect(diffReviewTask.id).toBe("diff-review");
    expect(diffReviewTask.outputKind).toBe("findings");
    expect(diffReviewTask.dependsOn).toEqual(["context-gatherer"]);
  });
});

describe("resolveConfig", () => {
  it("uses defaults", () => {
    const ctx = makeContext();
    const cfg = resolveConfig(ctx);
    expect(cfg.model).toBe("anthropic:claude-sonnet-4-6");
    expect(cfg.maxFindings).toBe(30);
    expect(cfg.diffBase).toBe("main");
  });

  it("reads overrides from taskConfig", () => {
    const ctx = makeContext({
      taskConfig: {
        "diff-review": { model: "openai:gpt-4", maxFindings: 10 },
      },
    });
    const cfg = resolveConfig(ctx);
    expect(cfg.model).toBe("openai:gpt-4");
    expect(cfg.maxFindings).toBe(10);
  });

  it("uses diffBase from config", () => {
    const ctx = makeContext({ diffBase: "develop" });
    const cfg = resolveConfig(ctx);
    expect(cfg.diffBase).toBe("develop");
  });
});

describe("buildPrompt", () => {
  it("includes three-phase methodology", () => {
    const prompt = buildPrompt(undefined, ["src/app.ts"], "diff content", "main", 10);
    expect(prompt).toContain("Phase 1: Context research");
    expect(prompt).toContain("Phase 2: Comparative analysis");
    expect(prompt).toContain("Phase 3: Vulnerability assessment");
  });

  it("includes changed files", () => {
    const prompt = buildPrompt(undefined, ["src/api.ts", "src/auth.ts"], "diff", "main", 10);
    expect(prompt).toContain("src/api.ts");
    expect(prompt).toContain("src/auth.ts");
    expect(prompt).toContain("2");
  });

  it("includes confidence threshold", () => {
    const prompt = buildPrompt(undefined, ["src/app.ts"], "diff", "main", 10);
    expect(prompt).toContain("0.7");
  });

  it("truncates large diffs", () => {
    const largeDiff = "x".repeat(200_000);
    const prompt = buildPrompt(undefined, ["src/app.ts"], largeDiff, "main", 10);
    expect(prompt).toContain("[diff truncated]");
    expect(prompt.length).toBeLessThan(200_000);
  });
});

describe("normalizeFindings", () => {
  it("normalizes valid findings", () => {
    const raw = {
      findings: [
        {
          ruleId: "sql-injection",
          filePath: "src/api.ts",
          startLine: 15,
          severity: "ERROR",
          message: "SQL injection in new endpoint",
          confidence: 0.9,
          rationale: "User input concatenated into query",
          cwe: ["89"],
        },
      ],
    };

    const findings = normalizeFindings(raw, "/tmp/repo", "test-repo", "main", 30);
    expect(findings).toHaveLength(1);
    expect(findings[0].taskId).toBe("diff-review");
    expect(findings[0].scannerConfidence).toBe("HIGH");
  });

  it("filters low confidence findings", () => {
    const raw = {
      findings: [
        {
          ruleId: "xss",
          filePath: "src/view.ts",
          startLine: 5,
          severity: "WARNING",
          message: "Possible XSS",
          confidence: 0.5,
          rationale: "Maybe unsafe",
        },
      ],
    };

    const findings = normalizeFindings(raw, "/tmp/repo", "test-repo", "main", 30);
    expect(findings).toHaveLength(0);
  });

  it("maps confidence to levels correctly", () => {
    const raw = {
      findings: [
        {
          ruleId: "a",
          filePath: "src/a.ts",
          startLine: 1,
          severity: "ERROR",
          message: "a",
          confidence: 0.95,
          rationale: "r",
        },
        {
          ruleId: "b",
          filePath: "src/b.ts",
          startLine: 1,
          severity: "ERROR",
          message: "b",
          confidence: 0.75,
          rationale: "r",
        },
      ],
    };

    const findings = normalizeFindings(raw, "/tmp/repo", "test-repo", "main", 30);
    expect(findings[0].scannerConfidence).toBe("HIGH");
    expect(findings[1].scannerConfidence).toBe("MEDIUM");
  });

  it("returns empty for invalid input", () => {
    expect(normalizeFindings(null, "/tmp/repo", "test-repo", "main", 30)).toEqual([]);
  });
});

describe("computeFingerprint", () => {
  it("produces stable fingerprints", () => {
    const f = {
      ruleId: "xss",
      filePath: "src/a.ts",
      startLine: 1,
      severity: "ERROR",
      message: "",
      confidence: 0.9,
      rationale: "",
    };
    const fp1 = computeFingerprint("repo", "main", "src/a.ts", f);
    const fp2 = computeFingerprint("repo", "main", "src/a.ts", f);
    expect(fp1).toBe(fp2);
  });

  it("differs by diffBase", () => {
    const f = {
      ruleId: "xss",
      filePath: "src/a.ts",
      startLine: 1,
      severity: "ERROR",
      message: "",
      confidence: 0.9,
      rationale: "",
    };
    const fp1 = computeFingerprint("repo", "main", "src/a.ts", f);
    const fp2 = computeFingerprint("repo", "develop", "src/a.ts", f);
    expect(fp1).not.toBe(fp2);
  });
});

describe("triageAgentConfig", () => {
  it("returns a prompt with finding details", () => {
    const finding = {
      taskId: "diff-review",
      fingerprint: "abc",
      ruleId: "sql-injection",
      filePath: "src/api.ts",
      startLine: 15,
      severity: "ERROR",
      message: "SQL injection",
      evidence: "User input in query",
      scannerConfidence: "HIGH",
      subcategory: ["vuln"],
      likelihood: "HIGH",
      impact: "HIGH",
      cwe: ["89"],
      score: 54,
    };

    const config = diffReviewTask.triageAgentConfig!(finding, "test-repo");
    expect(config.prompt).toContain("diff-review");
    expect(config.prompt).toContain("src/api.ts:15");
    expect(config.prompt).toContain("recently changed code");
  });
});
