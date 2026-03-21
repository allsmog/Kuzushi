import { describe, expect, it, vi } from "vitest";
import {
  BATCH_TRIAGE_FALLBACK_RATIONALE,
  buildDefaultTriageAgentConfig,
  DEFAULT_BATCH_SIZE,
  extractJson,
  parseAgentOutput,
  parseTriageResponse,
  parseVerdict,
  TriageExecutionError,
  triageFindingsBatch,
  triageFindingWithAgent,
  triageSystemPromptPrefix,
} from "../src/triage.js";
import type { Finding, TriageAgentConfig } from "../src/scanners/types.js";
import type { AgentMessage, AgentRuntime } from "../src/agent-runtime/types.js";

function makeFinding(): Finding {
  return {
    scanner: "semgrep",
    fingerprint: "test-fp",
    ruleId: "test.rule",
    filePath: "src/test.ts",
    startLine: 10,
    severity: "ERROR",
    message: "test finding",
    scannerConfidence: "HIGH",
    subcategory: ["vuln"],
    likelihood: "HIGH",
    impact: "HIGH",
    cwe: ["CWE-79"],
    score: 54,
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

function missingRegistry() {
  return {
    has: () => false,
    get: () => {
      throw new Error("missing");
    },
  };
}

function makeMockRuntime(messages: AgentMessage[], id = "mock-runtime"): AgentRuntime {
  const queryFn = vi.fn().mockImplementation(function* () {
    for (const message of messages) {
      yield message;
    }
  });

  return {
    id,
    query: queryFn,
  };
}

describe("parseVerdict", () => {
  it("accepts tp", () => expect(parseVerdict("tp")).toBe("tp"));
  it("accepts fp", () => expect(parseVerdict("fp")).toBe("fp"));
  it("accepts needs_review", () => expect(parseVerdict("needs_review")).toBe("needs_review"));
  it("defaults unknown to needs_review", () => expect(parseVerdict("bogus")).toBe("needs_review"));
});

describe("extractJson", () => {
  it("extracts from markdown fence", () => {
    const text = 'Some text\n```json\n{"a":1}\n```\nmore text';
    expect(extractJson(text)).toBe('{"a":1}');
  });

  it("extracts bare JSON object", () => {
    const text = 'Here is the result: {"verdict":"fp"}';
    expect(extractJson(text)).toBe('{"verdict":"fp"}');
  });

  it("returns trimmed text when no JSON found", () => {
    expect(extractJson("  just text  ")).toBe("just text");
  });

  it("handles nested code fences inside JSON values", () => {
    const text = [
      "Here is the result:",
      "```json",
      '{"verdict":"tp","fix_patch":"```python\\nprint(1)\\n```"}',
      "```",
      "",
    ].join("\n");
    const extracted = extractJson(text);
    expect(extracted).toContain('"verdict":"tp"');
  });
});

describe("parseTriageResponse", () => {
  it("parses a valid JSON response", () => {
    const json = JSON.stringify({
      verdict: "fp",
      confidence: 0.95,
      rationale: "safe",
      verification_steps: ["step 1"],
      fix_patch: null,
    });
    const result = parseTriageResponse(json, "fp123");
    expect(result.fingerprint).toBe("fp123");
    expect(result.verdict).toBe("fp");
    expect(result.confidence).toBe(0.95);
    expect(result.verificationSteps).toEqual(["step 1"]);
  });

  it("clamps confidence above 1", () => {
    const json = JSON.stringify({ verdict: "tp", confidence: 1.5, rationale: "x", verification_steps: [] });
    expect(parseTriageResponse(json, "x").confidence).toBe(1);
  });

  it("clamps confidence below 0", () => {
    const json = JSON.stringify({ verdict: "tp", confidence: -0.5, rationale: "x", verification_steps: [] });
    expect(parseTriageResponse(json, "x").confidence).toBe(0);
  });

  it("handles missing verification_steps", () => {
    const json = JSON.stringify({ verdict: "fp", confidence: 0.9, rationale: "ok" });
    expect(parseTriageResponse(json, "x").verificationSteps).toEqual([]);
  });

  it("throws a clear error for malformed JSON", () => {
    expect(() => parseTriageResponse("not-json", "x"))
      .toThrow("Invalid triage JSON response");
  });
});

describe("parseAgentOutput", () => {
  it("parses structured object output", () => {
    const result = parseAgentOutput({
      fingerprint: "fp-obj",
      verdict: "tp",
      confidence: 0.88,
      rationale: "confirmed",
      verification_steps: ["step"],
      fix_patch: null,
    }, "fallback");

    expect(result.fingerprint).toBe("fp-obj");
    expect(result.verdict).toBe("tp");
    expect(result.confidence).toBe(0.88);
  });

  it("falls back to text parser for string output", () => {
    const result = parseAgentOutput(
      JSON.stringify({
        verdict: "fp",
        confidence: 0.91,
        rationale: "safe",
        verification_steps: ["step"],
      }),
      "fallback-fp",
    );

    expect(result.fingerprint).toBe("fallback-fp");
    expect(result.verdict).toBe("fp");
  });

  it("parses evidence_trail from structured output", () => {
    const result = parseAgentOutput({
      fingerprint: "fp-trail",
      verdict: "tp",
      confidence: 0.75,
      rationale: "confirmed",
      verification_steps: ["step"],
      fix_patch: null,
      evidence_trail: [
        { level: "0.3", evidence: "Traced source to sink" },
        { level: "0.75", evidence: "Verified guards absent" },
      ],
    }, "fallback");

    expect(result.evidenceTrail).toBeDefined();
    expect(result.evidenceTrail).toHaveLength(2);
    expect(result.evidenceTrail![0].level).toBe("0.3");
    expect(result.evidenceTrail![1].evidence).toBe("Verified guards absent");
  });

  it("parses extended Taint-analysis source/sink triage fields", () => {
    const result = parseAgentOutput({
      fingerprint: "fp-ext",
      verdict: "fp",
      confidence: 0.72,
      rationale: "source is not attacker-controlled",
      verification_steps: ["trace input origin", "inspect sink usage"],
      fix_patch: null,
      source: {
        why: "Input originates from constant config",
        is_false_positive: true,
        evidence: "hardcoded value in config.ts",
      },
      sink: {
        why: "sink requires validated tokenized args",
        is_false_positive: false,
        evidence: "wrapper enforces allowlist",
      },
      is_vulnerable: false,
      exploit_scenario: "Not exploitable due to fixed source",
      recommended_fix: "Tighten source pattern matching",
      rule_refinement_hint: "constrain source to request-bound values",
      triage_schema_version: "1.0.0",
    }, "fallback");

    expect(result.source?.isFalsePositive).toBe(true);
    expect(result.source?.why).toContain("constant");
    expect(result.sink?.isFalsePositive).toBe(false);
    expect(result.isVulnerable).toBe(false);
    expect(result.ruleRefinementHint).toContain("constrain source");
    expect(result.triageSchemaVersion).toBe("1.0.0");
  });
});

describe("buildDefaultTriageAgentConfig", () => {
  it("builds a fallback prompt with finding metadata", () => {
    const config = buildDefaultTriageAgentConfig(makeFinding(), "repo");
    expect(config.prompt).toContain("security engineer");
    expect(config.prompt).toContain("test.rule");
    expect(config.prompt).toContain("test-fp");
  });

  it("does not include False-Dismissal Patterns in user prompt (moved to system prompt)", () => {
    const config = buildDefaultTriageAgentConfig(makeFinding(), "repo");
    expect(config.prompt).not.toContain("Common False-Dismissal Patterns");
  });

  it("does not include Confidence Escalation Protocol in user prompt (moved to system prompt)", () => {
    const config = buildDefaultTriageAgentConfig(makeFinding(), "repo");
    expect(config.prompt).not.toContain("Confidence Escalation Protocol");
  });

  it("triageSystemPromptPrefix includes False-Dismissal Patterns and Confidence Escalation Protocol", () => {
    const prefix = triageSystemPromptPrefix();
    expect(prefix).toContain("Common False-Dismissal Patterns");
    expect(prefix).toContain("WAF will catch it");
    expect(prefix).toContain("parameterized queries");
    expect(prefix).toContain("framework handles XSS");
    expect(prefix).toContain("Confidence Escalation Protocol");
    expect(prefix).toContain("Start at 0.1");
  });

  it("does not include repository context in user prompt (moved to system prompt)", () => {
    const config = buildDefaultTriageAgentConfig(makeFinding(), "repo");

    expect(config.prompt).not.toContain("## Repository Context");
  });

  it("triageSystemPromptPrefix includes repository context when provided", () => {
    const prefix = triageSystemPromptPrefix({
      languages: ["TypeScript"],
      frameworks: ["Next.js"],
      authPatterns: ["JWT"],
      sanitizationLibs: ["helmet"],
      ormOrDb: ["Prisma"],
      entryPoints: ["src/pages/api/*"],
    });

    expect(prefix).toContain("## Repository Context");
    expect(prefix).toContain("TypeScript");
    expect(prefix).toContain("Prisma");
  });
});

describe("triageFindingWithAgent", () => {
  it("uses structured_output when available", async () => {
    const runtime = makeMockRuntime([
      {
        type: "result",
        subtype: "success",
        result: "{}",
        structuredOutput: {
          fingerprint: "test-fp",
          verdict: "fp",
          confidence: 0.95,
          rationale: "hardcoded input",
          verification_steps: ["check source"],
          fix_patch: null,
        },
        durationMs: 100,
        numTurns: 1,
        totalCostUsd: 0,
      },
    ]);

    const output = await triageFindingWithAgent(
      registryWithConfig({ prompt: "custom triage" }) as any,
      makeFinding(),
      "/tmp/repo",
      "repo",
      "anthropic:claude-sonnet-4-6",
      12,
      { runtime },
    );

    expect(output.result.verdict).toBe("fp");
    expect(output.result.confidence).toBe(0.95);
    expect(output.costUsd).toBe(0);
    expect(runtime.query).toHaveBeenCalledTimes(1);
  });

  it("uses semantic navigation tools for pi-ai runtime defaults", async () => {
    const runtime = makeMockRuntime([
      {
        type: "result",
        subtype: "success",
        result: "{}",
        structuredOutput: {
          fingerprint: "test-fp",
          verdict: "fp",
          confidence: 0.95,
          rationale: "hardcoded input",
          verification_steps: ["check source"],
          fix_patch: null,
        },
      },
    ], "pi-ai");

    await triageFindingWithAgent(
      registryWithConfig({ prompt: "custom triage" }) as any,
      makeFinding(),
      "/tmp/repo",
      "repo",
      "anthropic:claude-sonnet-4-6",
      12,
      { runtime },
    );

    expect(runtime.query).toHaveBeenCalledWith(expect.objectContaining({
      options: expect.objectContaining({
        allowedTools: [
          "Read",
          "Glob",
          "Grep",
          "GetCallers",
          "GetCallees",
          "GetFunctionBody",
          "GoToDefinition",
          "FindReferences",
          "TypeAtPosition",
        ],
      }),
    }));
  });

  it("falls back to result text parsing when structured_output is missing", async () => {
    const runtime = makeMockRuntime([
      {
        type: "result",
        subtype: "success",
        result: JSON.stringify({
          verdict: "tp",
          confidence: 0.8,
          rationale: "real vulnerability",
          verification_steps: ["follow taint"],
          fix_patch: "diff",
        }),
        durationMs: 100,
        numTurns: 1,
        totalCostUsd: 0,
      },
    ]);

    const output = await triageFindingWithAgent(
      registryWithConfig({ prompt: "custom triage" }) as any,
      makeFinding(),
      "/tmp/repo",
      "repo",
      "anthropic:claude-sonnet-4-6",
      7,
      { runtime },
    );

    expect(output.result.verdict).toBe("tp");
    expect(output.result.fixPatch).toBe("diff");
  });

  it("uses default agent config when scanner plugin is missing", async () => {
    const runtime = makeMockRuntime([
      {
        type: "result",
        subtype: "success",
        result: JSON.stringify({
          verdict: "needs_review",
          confidence: 0.5,
          rationale: "insufficient evidence",
          verification_steps: ["inspect runtime path"],
          fix_patch: null,
        }),
        durationMs: 100,
        numTurns: 1,
        totalCostUsd: 0,
      },
    ]);

    const output = await triageFindingWithAgent(
      missingRegistry() as any,
      makeFinding(),
      "/tmp/repo",
      "repo",
      "anthropic:claude-sonnet-4-6",
      9,
      { runtime },
    );

    expect(output.result.verdict).toBe("needs_review");
  });

  it("captures total_cost_usd from result messages", async () => {
    const runtime = makeMockRuntime([
      {
        type: "result",
        subtype: "success",
        result: JSON.stringify({
          verdict: "fp",
          confidence: 0.9,
          rationale: "safe",
          verification_steps: ["step"],
          fix_patch: null,
        }),
        durationMs: 100,
        numTurns: 1,
        totalCostUsd: 0.0123,
      },
    ]);

    const output = await triageFindingWithAgent(
      registryWithConfig({ prompt: "custom triage" }) as any,
      makeFinding(),
      "/tmp/repo",
      "repo",
      "anthropic:claude-sonnet-4-6",
      9,
      { runtime },
    );

    expect(output.result.verdict).toBe("fp");
    expect(output.costUsd).toBe(0.0123);
  });

  it("throws when agent run fails", async () => {
    const runtime = makeMockRuntime([
      {
        type: "result",
        subtype: "error_max_turns",
        errors: ["max turns exceeded"],
        durationMs: 100,
        numTurns: 10,
        totalCostUsd: 0,
      },
    ]);

    await expect(
      triageFindingWithAgent(
        registryWithConfig({ prompt: "custom triage" }) as any,
        makeFinding(),
        "/tmp/repo",
        "repo",
        "anthropic:claude-sonnet-4-6",
        9,
        { runtime },
      ),
    ).rejects.toThrow("triage agent failed");
  });

  it("throws TriageExecutionError with cost on failed runs", async () => {
    const runtime = makeMockRuntime([
      {
        type: "result",
        subtype: "error_max_turns",
        errors: ["max turns exceeded"],
        durationMs: 100,
        numTurns: 10,
        totalCostUsd: 0.021,
      },
    ]);

    try {
      await triageFindingWithAgent(
        registryWithConfig({ prompt: "custom triage" }) as any,
        makeFinding(),
        "/tmp/repo",
        "repo",
        "anthropic:claude-sonnet-4-6",
        9,
        { runtime },
      );
      expect.unreachable("Expected triage run to throw");
    } catch (error) {
      expect(error).toBeInstanceOf(TriageExecutionError);
      expect((error as TriageExecutionError).costUsd).toBe(0.021);
    }
  });

  it("throws TriageExecutionError with cost when output parsing fails", async () => {
    const runtime = makeMockRuntime([
      {
        type: "result",
        subtype: "success",
        result: "not-json",
        durationMs: 100,
        numTurns: 1,
        totalCostUsd: 0.017,
      },
    ]);

    try {
      await triageFindingWithAgent(
        registryWithConfig({ prompt: "custom triage" }) as any,
        makeFinding(),
        "/tmp/repo",
        "repo",
        "anthropic:claude-sonnet-4-6",
        9,
        { runtime },
      );
      expect.unreachable("Expected triage run to throw");
    } catch (error) {
      expect(error).toBeInstanceOf(TriageExecutionError);
      expect((error as TriageExecutionError).costUsd).toBe(0.017);
      expect((error as Error).message).toContain("triage output parse failed");
    }
  });

  it("emits activity callbacks for assistant/tool progress/summary messages", async () => {
    const runtime = makeMockRuntime([
      {
        type: "assistant",
        content: [
          { type: "tool_use", name: "Read", input: { file_path: "src/test.ts" } },
          { type: "text", text: "Investigating dataflow path." },
        ],
      },
      {
        type: "tool-progress",
        toolUseId: "tool-1",
        toolName: "Read",
        elapsedSeconds: 1.2,
      },
      {
        type: "tool-summary",
        summary: "Verified sanitization before sink.",
        precedingToolUseIds: ["tool-1"],
      },
      {
        type: "result",
        subtype: "success",
        result: JSON.stringify({
          verdict: "fp",
          confidence: 0.9,
          rationale: "sanitized",
          verification_steps: ["trace data flow"],
          fix_patch: null,
        }),
        durationMs: 100,
        numTurns: 1,
        totalCostUsd: 0,
      },
    ]);

    const activities: Array<Record<string, unknown>> = [];

    await triageFindingWithAgent(
      registryWithConfig({ prompt: "custom triage" }) as any,
      makeFinding(),
      "/tmp/repo",
      "repo",
      "anthropic:claude-sonnet-4-6",
      10,
      {
        runtime,
        activityCallback: (activity) => {
          activities.push(activity as unknown as Record<string, unknown>);
        },
      },
    );

    expect(activities.some((a) => a["kind"] === "tool-start")).toBe(true);
    expect(activities.some((a) => a["kind"] === "reasoning")).toBe(true);
    expect(activities.some((a) => a["kind"] === "tool-progress")).toBe(true);
    expect(activities.some((a) => a["kind"] === "tool-complete")).toBe(true);
  });
});

function makeFindingWithFp(fp: string): Finding {
  return {
    ...makeFinding(),
    fingerprint: fp,
  };
}

function makeBatchRuntime(respondTo: Finding[]): AgentRuntime {
  const queryFn = vi.fn().mockImplementation(function* () {
    yield {
      type: "result",
      subtype: "success",
      result: "{}",
      structuredOutput: {
        results: respondTo.map((f) => ({
          fingerprint: f.fingerprint,
          verdict: "tp",
          confidence: 0.85,
          rationale: "confirmed vulnerability",
          verification_steps: ["step"],
          fix_patch: null,
        })),
      },
      durationMs: 100,
      numTurns: 1,
      totalCostUsd: 0.01,
    };
  });
  return { id: "mock-batch-runtime", query: queryFn };
}

describe("triageFindingsBatch", () => {
  it("returns empty results for empty findings", async () => {
    const runtime = makeBatchRuntime([]);
    const output = await triageFindingsBatch([], "/tmp", "repo", "model", undefined, { runtime });
    expect(output.results.size).toBe(0);
    expect(output.costUsd).toBe(0);
    expect(runtime.query).not.toHaveBeenCalled();
  });

  it("processes small batch in a single LLM call", async () => {
    const findings = Array.from({ length: 5 }, (_, i) => makeFindingWithFp(`fp-${i}`));
    const runtime = makeBatchRuntime(findings);

    const output = await triageFindingsBatch(findings, "/tmp", "repo", "model", undefined, { runtime });
    expect(output.results.size).toBe(5);
    expect(runtime.query).toHaveBeenCalledTimes(1);
    for (const f of findings) {
      expect(output.results.get(f.fingerprint)?.verdict).toBe("tp");
    }
  });

  it("chunks large batches into multiple LLM calls", async () => {
    const batchSize = 5;
    const findings = Array.from({ length: 13 }, (_, i) => makeFindingWithFp(`fp-${i}`));

    // The runtime will be called multiple times (once per chunk)
    let callCount = 0;
    const queryFn = vi.fn().mockImplementation(function* (_opts: unknown) {
      callCount++;
      // Extract findings from the prompt to respond with correct fingerprints
      const chunkStart = (callCount - 1) * batchSize;
      const chunkEnd = Math.min(callCount * batchSize, findings.length);
      const chunkFindings = findings.slice(chunkStart, chunkEnd);

      yield {
        type: "result",
        subtype: "success",
        result: "{}",
        structuredOutput: {
          results: chunkFindings.map((f) => ({
            fingerprint: f.fingerprint,
            verdict: "fp",
            confidence: 0.9,
            rationale: "safe",
            verification_steps: ["check"],
            fix_patch: null,
          })),
        },
        durationMs: 100,
        numTurns: 1,
        totalCostUsd: 0.01,
      };
    });
    const runtime: AgentRuntime = { id: "mock-chunked", query: queryFn };

    const output = await triageFindingsBatch(
      findings, "/tmp", "repo", "model", undefined, { runtime }, batchSize,
    );

    // 13 findings / 5 per chunk = 3 chunks
    expect(runtime.query).toHaveBeenCalledTimes(3);
    expect(output.results.size).toBe(13);
    expect(output.costUsd).toBeCloseTo(0.03, 4);
    for (const f of findings) {
      expect(output.results.get(f.fingerprint)?.verdict).toBe("fp");
    }
  });

  it("uses DEFAULT_BATCH_SIZE when no maxBatchSize provided", () => {
    expect(DEFAULT_BATCH_SIZE).toBe(15);
  });

  it("fills missing findings with needs_review fallback", async () => {
    const findings = Array.from({ length: 3 }, (_, i) => makeFindingWithFp(`fp-${i}`));
    // Runtime only returns result for fp-0, missing fp-1 and fp-2
    const queryFn = vi.fn().mockImplementation(function* () {
      yield {
        type: "result",
        subtype: "success",
        result: "{}",
        structuredOutput: {
          results: [{
            fingerprint: "fp-0",
            verdict: "tp",
            confidence: 0.9,
            rationale: "real",
            verification_steps: ["check"],
            fix_patch: null,
          }],
        },
        durationMs: 100,
        numTurns: 1,
        totalCostUsd: 0.01,
      };
    });
    const runtime: AgentRuntime = { id: "mock-partial", query: queryFn };

    const output = await triageFindingsBatch(findings, "/tmp", "repo", "model", undefined, { runtime });
    expect(output.results.size).toBe(3);
    expect(output.results.get("fp-0")?.verdict).toBe("tp");
    expect(output.results.get("fp-1")?.verdict).toBe("needs_review");
    expect(output.results.get("fp-1")?.confidence).toBe(0);
    expect(output.results.get("fp-1")?.rationale).toBe(BATCH_TRIAGE_FALLBACK_RATIONALE);
    expect(output.results.get("fp-2")?.verdict).toBe("needs_review");
    expect(output.results.get("fp-2")?.rationale).toBe(BATCH_TRIAGE_FALLBACK_RATIONALE);
  });
});
