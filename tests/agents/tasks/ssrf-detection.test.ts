import { describe, expect, it } from "vitest";
import {
  __ssrfDetectionInternals,
  ssrfDetectionTask,
} from "../../../src/agents/tasks/ssrf-detection.js";
import type { DagRunContext } from "../../../src/agents/types.js";
import type { KuzushiConfig } from "../../../src/types.js";

const { resolveConfig, buildPrompt, normalizeFindings, computeFingerprint } =
  __ssrfDetectionInternals;

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

describe("ssrfDetectionTask", () => {
  it("has correct metadata", () => {
    expect(ssrfDetectionTask.id).toBe("ssrf-detect");
    expect(ssrfDetectionTask.outputKind).toBe("findings");
    expect(ssrfDetectionTask.dependsOn).toEqual([
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
        "ssrf-detect": { model: "openai:gpt-4", maxFindings: 20 },
      },
    });
    const cfg = resolveConfig(ctx);
    expect(cfg.model).toBe("openai:gpt-4");
    expect(cfg.maxFindings).toBe(20);
  });
});

describe("buildPrompt", () => {
  it("includes repo context when provided", () => {
    const prompt = buildPrompt(
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

  it("works without repo context", () => {
    const prompt = buildPrompt(undefined, 50);
    expect(prompt).toContain("SSRF");
    expect(prompt).toContain("50");
  });

  it("includes bypass patterns", () => {
    const prompt = buildPrompt(undefined, 50);
    expect(prompt).toContain("DNS rebinding");
    expect(prompt).toContain("IPv6-mapped");
    expect(prompt).toContain("Decimal IP");
    expect(prompt).toContain("Octal IP");
  });

  it("covers all categories", () => {
    const prompt = buildPrompt(undefined, 50);
    expect(prompt).toContain("url-from-user-input");
    expect(prompt).toContain("missing-allowlist");
    expect(prompt).toContain("redirect-following");
    expect(prompt).toContain("internal-service-url");
  });

  it("inserts threat-model guidance when provided", () => {
    const prompt = buildPrompt(
      undefined,
      50,
      [],
      undefined,
      undefined,
      "## Threat model leads from STRIDE\n- lead",
    );
    expect(prompt).toContain("## Threat model leads from STRIDE");
    expect(prompt.indexOf("## Threat model leads from STRIDE")).toBeLessThan(
      prompt.indexOf("## Categories to check"),
    );
  });
});

describe("normalizeFindings", () => {
  it("normalizes valid findings", () => {
    const raw = {
      findings: [
        {
          category: "url-from-user-input",
          filePath: "src/api/proxy.ts",
          startLine: 42,
          severity: "ERROR",
          description: "User-controlled URL passed to fetch()",
          cwe: "CWE-918",
          confidence: "HIGH",
          rationale: "Request parameter used directly in fetch call",
          sinkFunction: "fetch",
          inputSource: "req.query.url",
        },
      ],
    };

    const findings = normalizeFindings(raw, "/tmp/repo", "test-repo", 50);
    expect(findings).toHaveLength(1);
    expect(findings[0].taskId).toBe("ssrf-detect");
    expect(findings[0].ruleId).toBe("ssrf/url-from-user-input");
    expect(findings[0].filePath).toBe("src/api/proxy.ts");
    expect(findings[0].cwe).toEqual(["CWE-918"]);
  });

  it("deduplicates by fingerprint", () => {
    const raw = {
      findings: [
        {
          category: "url-from-user-input",
          filePath: "src/api/proxy.ts",
          startLine: 42,
          severity: "ERROR",
          description: "SSRF",
          cwe: "CWE-918",
          confidence: "HIGH",
          rationale: "r",
        },
        {
          category: "url-from-user-input",
          filePath: "src/api/proxy.ts",
          startLine: 42,
          severity: "WARNING",
          description: "SSRF",
          cwe: "CWE-918",
          confidence: "MEDIUM",
          rationale: "r",
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
        category: "url-from-user-input",
        filePath: `src/file${i}.ts`,
        startLine: i + 1,
        severity: "WARNING",
        description: "SSRF",
        cwe: "CWE-918",
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
    const f = {
      category: "url-from-user-input",
      filePath: "src/proxy.ts",
      startLine: 42,
      severity: "ERROR",
      description: "",
      cwe: "CWE-918",
      confidence: "HIGH",
      rationale: "",
    };
    const fp1 = computeFingerprint("repo", "src/proxy.ts", f);
    const fp2 = computeFingerprint("repo", "src/proxy.ts", f);
    expect(fp1).toBe(fp2);
    expect(fp1).toHaveLength(64);
  });

  it("produces different fingerprints for different inputs", () => {
    const f1 = {
      category: "url-from-user-input",
      filePath: "src/proxy.ts",
      startLine: 42,
      severity: "ERROR",
      description: "",
      cwe: "",
      confidence: "",
      rationale: "",
    };
    const f2 = { ...f1, startLine: 43 };
    expect(computeFingerprint("repo", "src/proxy.ts", f1)).not.toBe(
      computeFingerprint("repo", "src/proxy.ts", f2),
    );
  });
});

describe("triageAgentConfig", () => {
  it("returns a prompt with finding details", () => {
    const finding = {
      taskId: "ssrf-detect",
      fingerprint: "abc",
      ruleId: "ssrf/url-from-user-input",
      filePath: "src/api/proxy.ts",
      startLine: 42,
      severity: "ERROR",
      message: "User-controlled URL passed to fetch()",
      evidence: "Request parameter used directly",
      scannerConfidence: "HIGH",
      subcategory: ["vuln"],
      likelihood: "HIGH",
      impact: "HIGH",
      cwe: ["CWE-918"],
      score: 54,
    };

    const config = ssrfDetectionTask.triageAgentConfig!(finding, "test-repo");
    expect(config.prompt).toContain("ssrf/url-from-user-input");
    expect(config.prompt).toContain("src/api/proxy.ts:42");
  });
});
