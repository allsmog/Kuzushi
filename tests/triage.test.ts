import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  buildDefaultTriageAgentConfig,
  extractJson,
  parseAgentOutput,
  parseTriageResponse,
  parseVerdict,
  TriageExecutionError,
  triageFindingWithAgent,
} from "../src/triage.js";
import type { Finding, TriageAgentConfig } from "../src/scanners/types.js";

const { queryMock } = vi.hoisted(() => ({
  queryMock: vi.fn(),
}));

vi.mock("@anthropic-ai/claude-agent-sdk", () => ({
  query: queryMock,
}));

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

function streamResult(messages: Array<Record<string, unknown>>) {
  return (async function* () {
    for (const message of messages) {
      yield message;
    }
  })();
}

beforeEach(() => {
  queryMock.mockReset();
});

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
});

describe("buildDefaultTriageAgentConfig", () => {
  it("builds a fallback prompt with finding metadata", () => {
    const config = buildDefaultTriageAgentConfig(makeFinding(), "repo");
    expect(config.prompt).toContain("security triage agent");
    expect(config.prompt).toContain("test.rule");
    expect(config.prompt).toContain("test-fp");
  });

  it("includes repository context when provided", () => {
    const config = buildDefaultTriageAgentConfig(makeFinding(), "repo", {
      languages: ["TypeScript"],
      frameworks: ["Next.js"],
      authPatterns: ["JWT"],
      sanitizationLibs: ["helmet"],
      ormOrDb: ["Prisma"],
      entryPoints: ["src/pages/api/*"],
    });

    expect(config.prompt).toContain("## Repository Context");
    expect(config.prompt).toContain("TypeScript");
    expect(config.prompt).toContain("Prisma");
  });
});

describe("triageFindingWithAgent", () => {
  it("uses structured_output when available", async () => {
    queryMock.mockReturnValue(streamResult([
      {
        type: "result",
        subtype: "success",
        result: "{}",
        structured_output: {
          fingerprint: "test-fp",
          verdict: "fp",
          confidence: 0.95,
          rationale: "hardcoded input",
          verification_steps: ["check source"],
          fix_patch: null,
        },
      },
    ]));

    const output = await triageFindingWithAgent(
      registryWithConfig({ prompt: "custom triage" }) as any,
      makeFinding(),
      "/tmp/repo",
      "repo",
      "claude-sonnet-4-20250514",
      12,
    );

    expect(output.result.verdict).toBe("fp");
    expect(output.result.confidence).toBe(0.95);
    expect(output.costUsd).toBe(0);
    expect(queryMock).toHaveBeenCalledTimes(1);
    expect(queryMock.mock.calls[0][0]?.options?.maxTurns).toBe(12);
  });

  it("falls back to result text parsing when structured_output is missing", async () => {
    queryMock.mockReturnValue(streamResult([
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
      },
    ]));

    const output = await triageFindingWithAgent(
      registryWithConfig({ prompt: "custom triage" }) as any,
      makeFinding(),
      "/tmp/repo",
      "repo",
      "claude-sonnet-4-20250514",
      7,
    );

    expect(output.result.verdict).toBe("tp");
    expect(output.result.fixPatch).toBe("diff");
  });

  it("uses default agent config when scanner plugin is missing", async () => {
    queryMock.mockReturnValue(streamResult([
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
      },
    ]));

    const output = await triageFindingWithAgent(
      missingRegistry() as any,
      makeFinding(),
      "/tmp/repo",
      "repo",
      "claude-sonnet-4-20250514",
      9,
    );

    expect(output.result.verdict).toBe("needs_review");
    expect(queryMock.mock.calls[0][0]?.prompt).toContain("security triage agent");
  });

  it("captures total_cost_usd from SDK result messages", async () => {
    queryMock.mockReturnValue(streamResult([
      {
        type: "result",
        subtype: "success",
        total_cost_usd: 0.0123,
        result: JSON.stringify({
          verdict: "fp",
          confidence: 0.9,
          rationale: "safe",
          verification_steps: ["step"],
          fix_patch: null,
        }),
      },
    ]));

    const output = await triageFindingWithAgent(
      registryWithConfig({ prompt: "custom triage" }) as any,
      makeFinding(),
      "/tmp/repo",
      "repo",
      "claude-sonnet-4-20250514",
      9,
    );

    expect(output.result.verdict).toBe("fp");
    expect(output.costUsd).toBe(0.0123);
  });

  it("throws when agent run fails", async () => {
    queryMock.mockReturnValue(streamResult([
      {
        type: "result",
        subtype: "error_max_turns",
        errors: ["max turns exceeded"],
      },
    ]));

    await expect(
      triageFindingWithAgent(
        registryWithConfig({ prompt: "custom triage" }) as any,
        makeFinding(),
        "/tmp/repo",
        "repo",
        "claude-sonnet-4-20250514",
        9,
      ),
    ).rejects.toThrow("triage agent failed");
  });

  it("throws TriageExecutionError with cost on failed runs", async () => {
    queryMock.mockReturnValue(streamResult([
      {
        type: "result",
        subtype: "error_max_turns",
        errors: ["max turns exceeded"],
        total_cost_usd: 0.021,
      },
    ]));

    try {
      await triageFindingWithAgent(
        registryWithConfig({ prompt: "custom triage" }) as any,
        makeFinding(),
        "/tmp/repo",
        "repo",
        "claude-sonnet-4-20250514",
        9,
      );
      expect.unreachable("Expected triage run to throw");
    } catch (error) {
      expect(error).toBeInstanceOf(TriageExecutionError);
      expect((error as TriageExecutionError).costUsd).toBe(0.021);
    }
  });

  it("throws TriageExecutionError with cost when output parsing fails", async () => {
    queryMock.mockReturnValue(streamResult([
      {
        type: "result",
        subtype: "success",
        total_cost_usd: 0.017,
        result: "not-json",
      },
    ]));

    try {
      await triageFindingWithAgent(
        registryWithConfig({ prompt: "custom triage" }) as any,
        makeFinding(),
        "/tmp/repo",
        "repo",
        "claude-sonnet-4-20250514",
        9,
      );
      expect.unreachable("Expected triage run to throw");
    } catch (error) {
      expect(error).toBeInstanceOf(TriageExecutionError);
      expect((error as TriageExecutionError).costUsd).toBe(0.017);
      expect((error as Error).message).toContain("triage output parse failed");
    }
  });

  it("emits activity callbacks for assistant/tool progress/summary messages", async () => {
    queryMock.mockReturnValue(streamResult([
      {
        type: "assistant",
        message: {
          content: [
            { type: "tool_use", name: "Read", input: { file_path: "src/test.ts" } },
            { type: "text", text: "Investigating dataflow path." },
          ],
        },
      },
      {
        type: "tool_progress",
        tool_use_id: "tool-1",
        tool_name: "Read",
        elapsed_time_seconds: 1.2,
      },
      {
        type: "tool_use_summary",
        summary: "Verified sanitization before sink.",
        preceding_tool_use_ids: ["tool-1"],
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
      },
    ]));

    const activities: Array<Record<string, unknown>> = [];

    await triageFindingWithAgent(
      registryWithConfig({ prompt: "custom triage" }) as any,
      makeFinding(),
      "/tmp/repo",
      "repo",
      "claude-sonnet-4-20250514",
      10,
      {
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
