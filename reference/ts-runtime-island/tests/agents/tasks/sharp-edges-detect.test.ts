import { describe, expect, it } from "vitest";
import {
  __sharpEdgesDetectInternals,
  sharpEdgesDetectTask,
} from "../../../src/agents/tasks/sharp-edges-detect.js";
import type { DagRunContext } from "../../../src/agents/types.js";
import type { KuzushiConfig } from "../../../src/types.js";

const {
  resolveConfig,
  buildScoundrelPrompt,
  buildLazyDeveloperPrompt,
  buildConfusedDeveloperPrompt,
  normalizeFindings,
  computeFingerprint,
} = __sharpEdgesDetectInternals;

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
    taskConfig: (overrides.taskConfig as Record<string, Record<string, unknown>>) ?? {},
  };
}

describe("sharpEdgesDetectTask", () => {
  it("has correct metadata", () => {
    expect(sharpEdgesDetectTask.id).toBe("sharp-edges-detect");
    expect(sharpEdgesDetectTask.outputKind).toBe("findings");
    expect(sharpEdgesDetectTask.dependsOn).toEqual([
      "context-gatherer",
      "app-model-build",
      "threat-scenario-build",
    ]);
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
        "sharp-edges-detect": { model: "openai:gpt-4", maxFindings: 20 },
      },
    });
    const cfg = resolveConfig(ctx);
    expect(cfg.model).toBe("openai:gpt-4");
    expect(cfg.maxFindings).toBe(20);
  });
});

describe("buildScoundrelPrompt", () => {
  it("includes scoundrel persona framing", () => {
    const prompt = buildScoundrelPrompt(undefined, 50);
    expect(prompt).toContain("Scoundrel");
    expect(prompt).toContain("malicious insider");
  });

  it("includes repo context when provided", () => {
    const prompt = buildScoundrelPrompt(
      {
        languages: ["Java"],
        frameworks: ["Spring"],
        authPatterns: [],
        sanitizationLibs: [],
        ormOrDb: [],
        entryPoints: [],
      },
      25,
    );
    expect(prompt).toContain("Java");
    expect(prompt).toContain("25");
  });

  it("covers scoundrel categories", () => {
    const prompt = buildScoundrelPrompt(undefined, 50);
    expect(prompt).toContain("algorithm-selection");
    expect(prompt).toContain("dangerous-defaults");
    expect(prompt).toContain("configuration-cliff");
  });
});

describe("buildLazyDeveloperPrompt", () => {
  it("includes lazy developer persona framing", () => {
    const prompt = buildLazyDeveloperPrompt(undefined, 50);
    expect(prompt).toContain("Lazy Developer");
    expect(prompt).toContain("copy-paste");
  });

  it("covers lazy developer categories", () => {
    const prompt = buildLazyDeveloperPrompt(undefined, 50);
    expect(prompt).toContain("dangerous-defaults");
    expect(prompt).toContain("primitive-vs-semantic");
    expect(prompt).toContain("silent-failure");
  });
});

describe("buildConfusedDeveloperPrompt", () => {
  it("includes confused developer persona framing", () => {
    const prompt = buildConfusedDeveloperPrompt(undefined, 50);
    expect(prompt).toContain("Confused Developer");
    expect(prompt).toContain("confuse similar-looking parameters");
  });

  it("covers confused developer categories", () => {
    const prompt = buildConfusedDeveloperPrompt(undefined, 50);
    expect(prompt).toContain("stringly-typed-security");
    expect(prompt).toContain("configuration-cliff");
    expect(prompt).toContain("silent-failure");
  });
});

describe("normalizeFindings", () => {
  it("normalizes valid findings", () => {
    const raw = {
      findings: [
        {
          category: "dangerous-defaults",
          filePath: "src/auth/session.ts",
          startLine: 42,
          severity: "ERROR",
          description: "Session cookie defaults to httpOnly: false",
          cwe: "CWE-1188",
          confidence: "HIGH",
          rationale: "createSession() sets httpOnly: false by default",
          persona: "lazy-developer",
        },
      ],
    };

    const findings = normalizeFindings(raw, "/tmp/repo", "test-repo", 50);
    expect(findings).toHaveLength(1);
    expect(findings[0].taskId).toBe("sharp-edges-detect");
    expect(findings[0].ruleId).toBe("sharp-edges/dangerous-defaults");
    expect(findings[0].filePath).toBe("src/auth/session.ts");
    expect(findings[0].cwe).toEqual(["CWE-1188"]);
    expect(findings[0].message).toContain("[lazy-developer]");
  });

  it("deduplicates by fingerprint", () => {
    const raw = {
      findings: [
        {
          category: "dangerous-defaults",
          filePath: "src/auth.ts",
          startLine: 10,
          severity: "ERROR",
          description: "d",
          cwe: "CWE-1188",
          confidence: "HIGH",
          rationale: "r",
          persona: "scoundrel",
        },
        {
          category: "dangerous-defaults",
          filePath: "src/auth.ts",
          startLine: 10,
          severity: "WARNING",
          description: "d",
          cwe: "CWE-1188",
          confidence: "MEDIUM",
          rationale: "r",
          persona: "lazy-developer",
        },
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
        category: "silent-failure",
        filePath: `src/file${i}.ts`,
        startLine: i + 1,
        severity: "WARNING",
        description: "Silent auth failure",
        cwe: "CWE-755",
        confidence: "MEDIUM",
        rationale: "r",
        persona: "confused-developer",
      })),
    };

    const findings = normalizeFindings(raw, "/tmp/repo", "test-repo", 3);
    expect(findings).toHaveLength(3);
  });

  it("maps categories to correct CWEs", () => {
    const categories = [
      ["algorithm-selection", "CWE-327"],
      ["dangerous-defaults", "CWE-1188"],
      ["primitive-vs-semantic", "CWE-676"],
      ["configuration-cliff", "CWE-16"],
      ["silent-failure", "CWE-755"],
      ["stringly-typed-security", "CWE-697"],
    ] as const;

    for (const [category, expectedCwe] of categories) {
      const raw = {
        findings: [
          {
            category,
            filePath: "src/test.ts",
            startLine: 1,
            severity: "WARNING",
            description: "test",
            cwe: expectedCwe,
            confidence: "MEDIUM",
            rationale: "r",
            persona: "scoundrel",
          },
        ],
      };
      const findings = normalizeFindings(raw, "/tmp/repo", "test-repo", 50);
      expect(findings[0].cwe).toEqual([expectedCwe]);
    }
  });
});

describe("computeFingerprint", () => {
  it("produces stable fingerprints", () => {
    const f = {
      category: "dangerous-defaults" as const,
      filePath: "src/auth.ts",
      startLine: 42,
      severity: "ERROR",
      description: "",
      cwe: "CWE-1188",
      confidence: "HIGH",
      rationale: "",
      persona: "scoundrel" as const,
    };
    const fp1 = computeFingerprint("repo", "src/auth.ts", f);
    const fp2 = computeFingerprint("repo", "src/auth.ts", f);
    expect(fp1).toBe(fp2);
    expect(fp1).toHaveLength(64);
  });

  it("produces different fingerprints for different inputs", () => {
    const f1 = {
      category: "dangerous-defaults" as const,
      filePath: "src/auth.ts",
      startLine: 42,
      severity: "ERROR",
      description: "",
      cwe: "",
      confidence: "",
      rationale: "",
      persona: "scoundrel" as const,
    };
    const f2 = { ...f1, startLine: 43 };
    expect(computeFingerprint("repo", "src/auth.ts", f1)).not.toBe(
      computeFingerprint("repo", "src/auth.ts", f2),
    );
  });
});

describe("triageAgentConfig", () => {
  it("returns a prompt with finding details", () => {
    const finding = {
      taskId: "sharp-edges-detect",
      fingerprint: "abc",
      ruleId: "sharp-edges/dangerous-defaults",
      filePath: "src/auth/session.ts",
      startLine: 42,
      severity: "ERROR",
      message: "[scoundrel] Session cookie insecure by default",
      evidence: "httpOnly defaults to false",
      scannerConfidence: "HIGH",
      subcategory: ["vuln"],
      likelihood: "HIGH",
      impact: "HIGH",
      cwe: ["CWE-1188"],
      score: 54,
    };

    const config = sharpEdgesDetectTask.triageAgentConfig!(finding, "test-repo");
    expect(config.prompt).toContain("sharp-edges/dangerous-defaults");
    expect(config.prompt).toContain("src/auth/session.ts:42");
    expect(config.prompt).toContain("API design footgun");
  });
});
