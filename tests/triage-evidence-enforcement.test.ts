import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";
import type { AgentMessage, AgentRuntime } from "../src/agent-runtime/types.js";
import type { Finding, TriageAgentConfig } from "../src/scanners/types.js";
import {
  buildEvidenceReinforcementPrompt,
  triageFindingWithEvidenceEnforcement,
  validateTriageEvidence,
} from "../src/triage.js";
import type { TriageResult } from "../src/types.js";

function makeFinding(): Finding {
  return {
    taskId: "semgrep",
    fingerprint: "fp-enforce",
    ruleId: "test.rule",
    filePath: "src/app.ts",
    startLine: 10,
    severity: "ERROR",
    message: "test",
    scannerConfidence: "HIGH",
    subcategory: ["vuln"],
    likelihood: "HIGH",
    impact: "HIGH",
    cwe: ["CWE-89"],
    score: 70,
  };
}

function registryWithConfig(config: TriageAgentConfig) {
  return {
    has: () => true,
    get: () => ({
      id: "semgrep",
      displayName: "Semgrep",
      triageAgentConfig: () => config,
      scan: async () => [],
    }),
  };
}

function makeMockRuntime(responses: Array<Record<string, unknown>>): AgentRuntime {
  let call = 0;
  const queryFn = vi.fn().mockImplementation(function* (): Generator<AgentMessage> {
    const structuredOutput = responses[call] ?? responses[responses.length - 1];
    call += 1;
    yield {
      type: "result",
      subtype: "success",
      result: "{}",
      structuredOutput,
      durationMs: 10,
      numTurns: 1,
      totalCostUsd: 0.01,
    } as AgentMessage;
  });
  return { id: "mock-runtime", query: queryFn };
}

function makeRepoRoot(): string {
  const root = mkdtempSync(path.join(tmpdir(), "kuzushi-enforce-"));
  mkdirSync(path.join(root, "src"), { recursive: true });
  writeFileSync(path.join(root, "src", "app.ts"), "export const x = 1;\n");
  writeFileSync(path.join(root, "src", "util.ts"), "export const y = 2;\n");
  return root;
}

function baseTriage(overrides: Partial<TriageResult>): TriageResult {
  return {
    fingerprint: "fp-enforce",
    verdict: "tp",
    confidence: 0.9,
    rationale: "ok",
    verificationSteps: ["s1"],
    fixPatch: null,
    ...overrides,
  };
}

describe("validateTriageEvidence", () => {
  const repoRoot = makeRepoRoot();

  it("accepts fp verdicts without citations", () => {
    const r = validateTriageEvidence(baseTriage({ verdict: "fp", codeCitations: [] }), repoRoot);
    expect(r.ok).toBe(true);
  });

  it("accepts by_design verdicts without citations", () => {
    const r = validateTriageEvidence(
      baseTriage({ verdict: "by_design", codeCitations: [] }),
      repoRoot,
    );
    expect(r.ok).toBe(true);
  });

  it("rejects tp verdicts with no citations", () => {
    const r = validateTriageEvidence(baseTriage({ verdict: "tp", codeCitations: [] }), repoRoot);
    expect(r.ok).toBe(false);
    expect(r.reasons.some((m) => m.includes("at least 2 code_citations"))).toBe(true);
  });

  it("rejects needs_review with only one citation", () => {
    const r = validateTriageEvidence(
      baseTriage({
        verdict: "needs_review",
        codeCitations: [
          {
            filePath: "src/app.ts",
            startLine: 1,
            endLine: 1,
            snippet: "x",
            description: "d",
          },
        ],
      }),
      repoRoot,
    );
    expect(r.ok).toBe(false);
  });

  it("rejects tp when citation files don't exist", () => {
    const r = validateTriageEvidence(
      baseTriage({
        codeCitations: [
          {
            filePath: "src/ghost.ts",
            startLine: 1,
            endLine: 1,
            snippet: "x",
            description: "d",
          },
          {
            filePath: "src/phantom.ts",
            startLine: 1,
            endLine: 1,
            snippet: "x",
            description: "d",
          },
        ],
        attackPath: {
          chain: ["a", "b"],
          narrative: "n",
          likelihoodReasoning: "l",
          impactReasoning: "i",
        },
      }),
      repoRoot,
    );
    expect(r.ok).toBe(false);
    expect(r.reasons.some((m) => m.includes("must reference files that exist"))).toBe(true);
  });

  it("rejects tp with valid citations but empty chain", () => {
    const r = validateTriageEvidence(
      baseTriage({
        codeCitations: [
          {
            filePath: "src/app.ts",
            startLine: 1,
            endLine: 1,
            snippet: "x",
            description: "d",
          },
          {
            filePath: "src/util.ts",
            startLine: 1,
            endLine: 1,
            snippet: "y",
            description: "d",
          },
        ],
      }),
      repoRoot,
    );
    expect(r.ok).toBe(false);
    expect(r.reasons.some((m) => m.includes("attack_path.chain"))).toBe(true);
  });

  it("accepts tp with 2 real citations + 2-step chain", () => {
    const r = validateTriageEvidence(
      baseTriage({
        codeCitations: [
          {
            filePath: "src/app.ts",
            startLine: 1,
            endLine: 1,
            snippet: "x",
            description: "d",
          },
          {
            filePath: "src/util.ts",
            startLine: 1,
            endLine: 1,
            snippet: "y",
            description: "d",
          },
        ],
        attackPath: {
          chain: ["entry", "sink"],
          narrative: "n",
          likelihoodReasoning: "l",
          impactReasoning: "i",
        },
      }),
      repoRoot,
    );
    expect(r.ok).toBe(true);
  });

  it("accepts needs_review with 2 real citations (no chain required)", () => {
    const r = validateTriageEvidence(
      baseTriage({
        verdict: "needs_review",
        codeCitations: [
          {
            filePath: "src/app.ts",
            startLine: 1,
            endLine: 1,
            snippet: "x",
            description: "d",
          },
          {
            filePath: "src/util.ts",
            startLine: 1,
            endLine: 1,
            snippet: "y",
            description: "d",
          },
        ],
      }),
      repoRoot,
    );
    expect(r.ok).toBe(true);
  });
});

describe("buildEvidenceReinforcementPrompt", () => {
  it("lists reasons and instructs agent to use semantic tools", () => {
    const out = buildEvidenceReinforcementPrompt([
      'verdict="tp" requires at least 2 code_citations (got 0)',
    ]);
    expect(out).toContain("Your previous response does not meet the evidence requirements");
    expect(out).toContain('verdict="tp" requires at least 2 code_citations');
    expect(out).toContain("GetCallers");
    expect(out).toContain("GetFunctionBody");
    expect(out).toContain("GetCallees");
    expect(out).toContain("do not fabricate");
  });
});

describe("triageFindingWithEvidenceEnforcement", () => {
  it("passes through strong first response unchanged", async () => {
    const repoRoot = makeRepoRoot();
    const runtime = makeMockRuntime([
      {
        fingerprint: "fp-enforce",
        verdict: "tp",
        confidence: 0.9,
        rationale: "ok",
        verification_steps: ["s1"],
        fix_patch: null,
        code_citations: [
          {
            file_path: "src/app.ts",
            start_line: 1,
            end_line: 1,
            snippet: "x",
            description: "d",
          },
          {
            file_path: "src/util.ts",
            start_line: 1,
            end_line: 1,
            snippet: "y",
            description: "d",
          },
        ],
        attack_path: {
          chain: ["entry", "sink"],
          narrative: "n",
          likelihood_reasoning: "l",
          impact_reasoning: "i",
        },
      },
    ]);

    const out = await triageFindingWithEvidenceEnforcement(
      registryWithConfig({ prompt: "p" }) as any,
      makeFinding(),
      repoRoot,
      "repo",
      "anthropic:claude-sonnet-4-6",
      { runtime },
    );

    expect(out.result.verdict).toBe("tp");
    expect(runtime.query).toHaveBeenCalledTimes(1);
    expect(out.costUsd).toBeCloseTo(0.01);
  });

  it("re-invokes when first tp response has no citations; accepts strong second response", async () => {
    const repoRoot = makeRepoRoot();
    const runtime = makeMockRuntime([
      {
        fingerprint: "fp-enforce",
        verdict: "tp",
        confidence: 0.9,
        rationale: "weak",
        verification_steps: [],
        fix_patch: null,
      },
      {
        fingerprint: "fp-enforce",
        verdict: "tp",
        confidence: 0.85,
        rationale: "stronger",
        verification_steps: ["s1"],
        fix_patch: null,
        code_citations: [
          {
            file_path: "src/app.ts",
            start_line: 1,
            end_line: 1,
            snippet: "x",
            description: "d",
          },
          {
            file_path: "src/util.ts",
            start_line: 1,
            end_line: 1,
            snippet: "y",
            description: "d",
          },
        ],
        attack_path: {
          chain: ["entry", "sink"],
          narrative: "n",
          likelihood_reasoning: "l",
          impact_reasoning: "i",
        },
      },
    ]);

    const out = await triageFindingWithEvidenceEnforcement(
      registryWithConfig({ prompt: "p" }) as any,
      makeFinding(),
      repoRoot,
      "repo",
      "anthropic:claude-sonnet-4-6",
      { runtime },
    );

    expect(out.result.verdict).toBe("tp");
    expect(out.result.rationale).toBe("stronger");
    expect(runtime.query).toHaveBeenCalledTimes(2);
    expect(out.costUsd).toBeCloseTo(0.02);
    // Second call's prompt should contain the reinforcement language
    const secondCall = (runtime.query as ReturnType<typeof vi.fn>).mock.calls[1];
    expect(secondCall[0].prompt).toContain("does not meet the evidence requirements");
    expect(secondCall[0].prompt).toContain("GetCallers");
  });

  it("downgrades to needs_review when second response is still insufficient", async () => {
    const repoRoot = makeRepoRoot();
    const runtime = makeMockRuntime([
      {
        fingerprint: "fp-enforce",
        verdict: "tp",
        confidence: 0.9,
        rationale: "r1",
        verification_steps: [],
        fix_patch: null,
      },
      {
        fingerprint: "fp-enforce",
        verdict: "tp",
        confidence: 0.85,
        rationale: "r2",
        verification_steps: [],
        fix_patch: null,
      },
    ]);

    const out = await triageFindingWithEvidenceEnforcement(
      registryWithConfig({ prompt: "p" }) as any,
      makeFinding(),
      repoRoot,
      "repo",
      "anthropic:claude-sonnet-4-6",
      { runtime },
    );

    expect(out.result.verdict).toBe("needs_review");
    expect(out.result.confidence).toBeLessThanOrEqual(0.5);
    expect(out.result.blindspots?.some((b) => b.startsWith("Evidence-enforcement:"))).toBe(true);
    expect(runtime.query).toHaveBeenCalledTimes(2);
    expect(out.costUsd).toBeCloseTo(0.02);
  });

  it("skips enforcement for fp verdicts (single call)", async () => {
    const repoRoot = makeRepoRoot();
    const runtime = makeMockRuntime([
      {
        fingerprint: "fp-enforce",
        verdict: "fp",
        confidence: 0.95,
        rationale: "safe",
        verification_steps: ["s1"],
        fix_patch: null,
      },
    ]);

    const out = await triageFindingWithEvidenceEnforcement(
      registryWithConfig({ prompt: "p" }) as any,
      makeFinding(),
      repoRoot,
      "repo",
      "anthropic:claude-sonnet-4-6",
      { runtime },
    );

    expect(out.result.verdict).toBe("fp");
    expect(runtime.query).toHaveBeenCalledTimes(1);
  });

  it("respects maxEnforcementAttempts=0 (disabled)", async () => {
    const repoRoot = makeRepoRoot();
    const runtime = makeMockRuntime([
      {
        fingerprint: "fp-enforce",
        verdict: "tp",
        confidence: 0.9,
        rationale: "weak",
        verification_steps: [],
        fix_patch: null,
      },
    ]);

    const out = await triageFindingWithEvidenceEnforcement(
      registryWithConfig({ prompt: "p" }) as any,
      makeFinding(),
      repoRoot,
      "repo",
      "anthropic:claude-sonnet-4-6",
      { runtime },
      {},
      undefined,
      undefined,
      undefined,
      0,
    );

    expect(out.result.verdict).toBe("tp");
    expect(runtime.query).toHaveBeenCalledTimes(1);
  });
});
