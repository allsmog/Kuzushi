import { describe, expect, it } from "vitest";
import { raceConditionTask, __raceConditionInternals } from "../../../src/agents/tasks/race-condition.js";
import type { KuzushiConfig } from "../../../src/types.js";
import type { TaskContext } from "../../../src/agents/types.js";

const { resolveConfig, buildPrompt, normalizeFindings, computeFingerprint } = __raceConditionInternals;

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
    busBackend: "in-process",
    triageBatchSize: 15,
    triageConcurrency: 1,
    scanMode: "sequential",
    tasks: [],
    tasks: ["semgrep"],
    severity: ["ERROR"],
    excludePatterns: [],
    taskConfig: overrides.taskConfig as Record<string, Record<string, unknown>> ?? {},
  };
}

describe("raceConditionTask", () => {
  it("has correct metadata", () => {
    expect(raceConditionTask.id).toBe("race-condition-detect");
    expect(raceConditionTask.outputKind).toBe("findings");
    expect(raceConditionTask.dependsOn).toEqual(["context-gatherer"]);
  });
});

describe("resolveConfig", () => {
  it("uses defaults when no scanner config", () => {
    const ctx = makeContext();
    const cfg = resolveConfig(ctx);
    expect(cfg.model).toBe("anthropic:claude-sonnet-4-6");
    expect(cfg.maxFindings).toBe(50);
  });

  it("reads overrides from taskConfig", () => {
    const ctx = makeContext({
      taskConfig: {
        "race-condition": { model: "openai:gpt-4", maxFindings: 30 },
      },
    });
    const cfg = resolveConfig(ctx);
    expect(cfg.model).toBe("openai:gpt-4");
    expect(cfg.maxFindings).toBe(30);
  });
});

describe("buildPrompt", () => {
  it("includes repo context when provided", () => {
    const prompt = buildPrompt(
      { languages: ["Go"], frameworks: ["Gin"], authPatterns: [], sanitizationLibs: [], ormOrDb: [], entryPoints: [] },
      25,
    );
    expect(prompt).toContain("Go");
    expect(prompt).toContain("25");
  });

  it("works without repo context", () => {
    const prompt = buildPrompt(undefined, 50);
    expect(prompt).toContain("race condition");
  });
});

describe("normalizeFindings", () => {
  it("normalizes valid findings", () => {
    const raw = {
      findings: [
        {
          pattern: "toctou",
          filePath: "src/upload.go",
          startLine: 42,
          severity: "ERROR",
          description: "File existence check followed by open",
          cwe: "367",
          confidence: "HIGH",
          rationale: "os.Stat then os.Open without lock",
          sharedResource: "/tmp/upload",
          concurrencyMechanism: "goroutine",
        },
      ],
    };

    const findings = normalizeFindings(raw, "/tmp/repo", "test-repo", 50);
    expect(findings).toHaveLength(1);
    expect(findings[0].taskId).toBe("race-condition-detect");
    expect(findings[0].ruleId).toBe("race-condition/toctou");
    expect(findings[0].message).toContain("/tmp/upload");
    expect(findings[0].cwe).toEqual(["367"]);
  });

  it("deduplicates by fingerprint", () => {
    const raw = {
      findings: [
        { pattern: "toctou", filePath: "src/upload.go", startLine: 42, severity: "ERROR", description: "TOCTOU", cwe: "367", confidence: "HIGH", rationale: "x" },
        { pattern: "toctou", filePath: "src/upload.go", startLine: 42, severity: "WARNING", description: "TOCTOU", cwe: "367", confidence: "MEDIUM", rationale: "y" },
      ],
    };

    const findings = normalizeFindings(raw, "/tmp/repo", "test-repo", 50);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("ERROR");
  });

  it("returns empty for invalid input", () => {
    expect(normalizeFindings(null, "/tmp/repo", "test-repo", 50)).toEqual([]);
    expect(normalizeFindings("not-an-object", "/tmp/repo", "test-repo", 50)).toEqual([]);
  });

  it("respects maxFindings", () => {
    const raw = {
      findings: Array.from({ length: 10 }, (_, i) => ({
        pattern: "unprotected-shared-state",
        filePath: `src/handler${i}.go`,
        startLine: i + 1,
        severity: "WARNING",
        description: "Shared state",
        cwe: "362",
        confidence: "MEDIUM",
        rationale: "No lock",
      })),
    };

    const findings = normalizeFindings(raw, "/tmp/repo", "test-repo", 5);
    expect(findings).toHaveLength(5);
  });
});

describe("computeFingerprint", () => {
  it("produces stable fingerprints", () => {
    const f = { pattern: "toctou", filePath: "src/upload.go", startLine: 42, severity: "ERROR", description: "", cwe: "367", confidence: "HIGH", rationale: "" };
    const fp1 = computeFingerprint("repo", "src/upload.go", f);
    const fp2 = computeFingerprint("repo", "src/upload.go", f);
    expect(fp1).toBe(fp2);
    expect(fp1).toHaveLength(64);
  });
});

describe("triageAgentConfig", () => {
  it("returns a prompt with finding details", () => {
    const finding = {
      taskId: "race-condition-detect",
      fingerprint: "abc",
      ruleId: "race-condition/toctou",
      filePath: "src/upload.go",
      startLine: 42,
      severity: "ERROR",
      message: "TOCTOU file access",
      evidence: "os.Stat then os.Open",
      scannerConfidence: "HIGH",
      subcategory: ["vuln"],
      likelihood: "HIGH",
      impact: "HIGH",
      cwe: ["367"],
      score: 54,
    };

    const config = raceConditionTask.triageAgentConfig!(finding, "test-repo");
    expect(config.prompt).toContain("race-condition/toctou");
    expect(config.prompt).toContain("src/upload.go:42");
  });
});
