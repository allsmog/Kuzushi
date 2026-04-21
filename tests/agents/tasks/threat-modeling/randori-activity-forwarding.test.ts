import { describe, expect, it, vi } from "vitest";
import type { AgentMessage, AgentRuntime } from "../../../../src/agent-runtime/types.js";
import {
  describeRuntimeMessage,
  runRandoriPasta,
} from "../../../../src/agents/tasks/threat-modeling/randori-runner.js";

vi.mock("../../../../src/agents/tasks/threat-modeling/randori-artifacts.js", () => ({
  readRandoriArtifacts: vi.fn(() => ({})),
  mergeRandoriStageOutputs: vi.fn(() => null),
}));

vi.mock("../../../../src/agents/tasks/threat-modeling/randori-adapter.js", () => ({
  convertRandoriToThreatModel: vi.fn(),
}));

function asMsg<T extends AgentMessage>(m: T): AgentMessage {
  return m;
}

describe("describeRuntimeMessage", () => {
  it("returns one entry per tool_use block on assistant messages", () => {
    const out = describeRuntimeMessage(
      asMsg({
        type: "assistant",
        content: [
          { type: "text", text: "thinking about next step" },
          { type: "tool_use", name: "Glob", input: { pattern: "src/**/*.ts" } },
          { type: "tool_use", name: "Read", input: { path: "/repo/src/index.ts" } },
        ],
      }),
    );
    expect(out).toEqual(["Glob · src/**/*.ts", "Read · /repo/src/index.ts"]);
  });

  it("falls back to the tool name when no hint input is present", () => {
    const out = describeRuntimeMessage(
      asMsg({
        type: "assistant",
        content: [{ type: "tool_use", name: "Bash" }],
      }),
    );
    expect(out).toEqual(["Bash"]);
  });

  it("recognizes file_path and filePath aliases for Read-style tools", () => {
    // Regression: earlier versions only checked `path`; LLM variants using
    // `file_path` / `filePath` surfaced as bare "Read" in the progress rail.
    const out = describeRuntimeMessage(
      asMsg({
        type: "assistant",
        content: [
          { type: "tool_use", name: "Read", input: { file_path: "/repo/a.go" } },
          { type: "tool_use", name: "Read", input: { filePath: "/repo/b.go" } },
          { type: "tool_use", name: "Bash", input: { command: "pnpm test" } },
        ],
      }),
    );
    expect(out).toEqual(["Read · /repo/a.go", "Read · /repo/b.go", "Bash · pnpm test"]);
  });

  it("truncates long hints to 40 chars with an ellipsis", () => {
    const long = "/very-deep".repeat(10);
    const [line] = describeRuntimeMessage(
      asMsg({
        type: "assistant",
        content: [{ type: "tool_use", name: "Read", input: { path: long } }],
      }),
    );
    expect(line).toBeDefined();
    const hint = line!.split(" · ")[1]!;
    expect(hint.length).toBeLessThanOrEqual(40);
    expect(hint.endsWith("…")).toBe(true);
  });

  it("surfaces the first line of a tool-summary", () => {
    const out = describeRuntimeMessage(
      asMsg({
        type: "tool-summary",
        summary: "Found 14 routes under src/routes\n- /foo\n- /bar",
        precedingToolUseIds: [],
      }),
    );
    expect(out).toEqual(["Found 14 routes under src/routes"]);
  });

  it("returns nothing for text-only assistant messages", () => {
    const out = describeRuntimeMessage(
      asMsg({
        type: "assistant",
        content: [{ type: "text", text: "ok let me plan this out" }],
      }),
    );
    expect(out).toEqual([]);
  });

  it("returns nothing for tool-progress ticks (too noisy)", () => {
    const out = describeRuntimeMessage(
      asMsg({
        type: "tool-progress",
        toolUseId: "tu-1",
        toolName: "Grep",
        elapsedSeconds: 3,
      }),
    );
    expect(out).toEqual([]);
  });

  it("returns nothing for result envelopes", () => {
    const out = describeRuntimeMessage(
      asMsg({
        type: "result",
        subtype: "success",
        result: "done",
        totalCostUsd: 0.01,
      }),
    );
    expect(out).toEqual([]);
  });
});

describe("runRandoriPasta — activity forwarding", () => {
  it("calls onActivity for each tool_use block while a phase query streams", async () => {
    const scripted: AgentMessage[] = [
      {
        type: "assistant",
        content: [
          { type: "text", text: "starting" },
          { type: "tool_use", name: "Glob", input: { pattern: "**/*.ts" } },
        ],
      },
      {
        type: "assistant",
        content: [{ type: "tool_use", name: "Read", input: { path: "/repo/src/app.ts" } }],
      },
      {
        type: "tool-summary",
        summary: "Summarised the routing layer",
        precedingToolUseIds: ["tu-1"],
      },
      {
        type: "result",
        subtype: "success",
        result: "ok",
        totalCostUsd: 0.02,
      },
    ];

    const runtime: AgentRuntime = {
      id: "test-runtime",
      async *query() {
        for (const m of scripted) yield m;
      },
    };

    const activity: string[] = [];
    const phases: string[] = [];
    const result = await runRandoriPasta({
      runtime,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      pluginPath: "/plugin",
      model: "test-model",
      allowedTools: ["Read", "Grep"],
      stages: ["s1", "s2", "s3"],
      artifactDir: ".kuzushi/randori",
      maxElements: 40,
      maxThreats: 30,
      emitFindings: false,
      findingThreshold: "medium",
      logTag: "[test]",
      onPhase: (p) => phases.push(p),
      onActivity: (a) => activity.push(a),
    });

    // The seed activity plus one entry per tool_use plus the tool-summary.
    expect(phases).toEqual(["phase 1 (S1/S2/S3 scope)"]);
    expect(activity).toEqual([
      "scoping s1, s2, s3",
      "Glob · **/*.ts",
      "Read · /repo/src/app.ts",
      "Summarised the routing layer",
    ]);
    // Cost accumulates from the result envelope even with forwarding enabled.
    expect(result.costUsd).toBeCloseTo(0.02);
  });

  it("still accumulates cost and completes when onActivity is not provided", async () => {
    const scripted: AgentMessage[] = [
      {
        type: "assistant",
        content: [{ type: "tool_use", name: "Grep", input: { query: "foo" } }],
      },
      { type: "result", subtype: "success", result: "ok", totalCostUsd: 0.05 },
    ];

    const runtime: AgentRuntime = {
      id: "test-runtime",
      async *query() {
        for (const m of scripted) yield m;
      },
    };

    const result = await runRandoriPasta({
      runtime,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      pluginPath: "/plugin",
      model: "test-model",
      allowedTools: [],
      stages: ["s1"],
      artifactDir: ".kuzushi/randori",
      maxElements: 40,
      maxThreats: 30,
      emitFindings: false,
      findingThreshold: "medium",
    });

    expect(result.costUsd).toBeCloseTo(0.05);
    expect(result.empty).toBe(true); // no artifacts produced by the mocks
  });

  it("swallows runtime errors from a phase without aborting the runner", async () => {
    const runtime: AgentRuntime = {
      id: "test-runtime",
      query() {
        return {
          [Symbol.asyncIterator]() {
            return {
              next() {
                return Promise.reject(new Error("runtime boom"));
              },
            };
          },
        };
      },
    };

    const activity: string[] = [];
    const result = await runRandoriPasta({
      runtime,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      pluginPath: "/plugin",
      model: "test-model",
      allowedTools: [],
      stages: ["s1"],
      artifactDir: ".kuzushi/randori",
      maxElements: 40,
      maxThreats: 30,
      emitFindings: false,
      findingThreshold: "medium",
      onActivity: (a) => activity.push(a),
    });

    expect(result.empty).toBe(true);
    expect(result.costUsd).toBe(0);
    // The seed "scoping …" pulse still lands even though the query threw.
    expect(activity).toContain("scoping s1");
  });
});
