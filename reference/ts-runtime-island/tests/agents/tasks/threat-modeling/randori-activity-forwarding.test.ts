import { describe, expect, it, vi } from "vitest";
import type { AgentMessage, AgentRuntime } from "../../../../src/agent-runtime/types.js";
import {
  createRandoriToolGuard,
  describeRuntimeMessage,
  runRandoriPasta,
} from "../../../../src/agents/tasks/threat-modeling/randori-runner.js";

vi.mock("../../../../src/agents/tasks/threat-modeling/randori-artifacts.js", () => ({
  readRandoriArtifacts: vi.fn(() => ({})),
  mergeRandoriStageOutputs: vi.fn(() => null),
  ensureFallbackS4Artifact: vi.fn(() => ({ written: false, path: "", threats: [] })),
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

  it("surfaces the tool name for pi-ai tool-call-start events", () => {
    // pi-ai streaming yields this the moment the model commits to a tool
    // — before any JSON args stream in. Matters for Opus + max thinking
    // where the first full assistant turn can take 5+ minutes; without
    // this signal the activity rail is silent the whole way.
    const out = describeRuntimeMessage(
      asMsg({
        type: "tool-call-start",
        toolUseId: "tu-1",
        toolName: "Read",
      }),
    );
    expect(out).toEqual(["Read"]);
  });

  it("falls back to 'tool' when tool-call-start lacks a name", () => {
    const out = describeRuntimeMessage(
      asMsg({
        type: "tool-call-start",
        toolUseId: "tu-2",
      } as unknown as AgentMessage),
    );
    expect(out).toEqual(["tool"]);
  });

  it("returns nothing for text-delta and thinking-delta (too noisy)", () => {
    expect(describeRuntimeMessage(asMsg({ type: "text-delta", delta: "hello" }))).toEqual([]);
    expect(describeRuntimeMessage(asMsg({ type: "thinking-delta", delta: "thinking..." }))).toEqual(
      [],
    );
  });
});

describe("createRandoriToolGuard", () => {
  const options = { signal: new AbortController().signal, toolUseId: "tu-1" };

  it("denies absolute Read paths outside a targeted .github directory", async () => {
    const guard = createRandoriToolGuard("/tmp/repo/.github");
    const decision = await guard("Read", { file_path: "/tmp/repo/actions/x.yml" }, options);

    expect(decision).toMatchObject({
      behavior: "deny",
      message: expect.stringContaining('escapes the Randori analysis root "/tmp/repo/.github"'),
    });
  });

  it("allows absolute Read paths inside a targeted .github directory", async () => {
    const guard = createRandoriToolGuard("/tmp/repo/.github");
    const decision = await guard("Read", { file_path: "/tmp/repo/.github/actions/x.yml" }, options);

    expect(decision).toEqual({ behavior: "allow" });
  });

  it("allows relative Read paths that resolve inside the active target", async () => {
    const guard = createRandoriToolGuard("/tmp/repo/.github");
    const decision = await guard("Read", { file_path: "actions/x.yml" }, options);

    expect(decision).toEqual({ behavior: "allow" });
  });

  it("denies relative Read paths that escape the active target", async () => {
    const guard = createRandoriToolGuard("/tmp/repo/.github");
    const decision = await guard("Read", { file_path: "../actions/x.yml" }, options);

    expect(decision).toMatchObject({
      behavior: "deny",
      message: expect.stringContaining('file_path "../actions/x.yml" escapes'),
    });
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

describe("runRandoriPasta — tool-failure retry cap", () => {
  // When the sub-Claude retries the same tool on validation errors, we
  // cap at 3 consecutive failures and abort the phase. Without this,
  // context:build was observed wedged for 20+ minutes on an S4 Write
  // retry loop that never converged.

  const makeRuntime = (messages: AgentMessage[]): AgentRuntime => ({
    id: "test",
    async *query() {
      for (const m of messages) yield m;
    },
  });

  it("emits a pulse for each failed tool_result with the failure count", async () => {
    const scripted: AgentMessage[] = [
      {
        type: "assistant",
        content: [{ type: "tool_use", id: "tu-1", name: "Write", input: { file_path: "/x" } }],
      },
      {
        type: "tool-result",
        toolUseId: "tu-1",
        isError: true,
        content: "Validation failed for tool Write",
      },
      {
        type: "assistant",
        content: [{ type: "tool_use", id: "tu-2", name: "Write", input: { file_path: "/x" } }],
      },
      {
        type: "tool-result",
        toolUseId: "tu-2",
        isError: true,
        content: "Validation failed for tool Write",
      },
      { type: "result", subtype: "success", result: "ok", totalCostUsd: 0.01 },
    ];

    const activity: string[] = [];
    await runRandoriPasta({
      runtime: makeRuntime(scripted),
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

    expect(activity).toContain("Write failed (1/3): Validation failed for tool Write");
    expect(activity).toContain("Write failed (2/3): Validation failed for tool Write");
    // Only two failures — under the cap, no abort pulse.
    expect(activity.some((l) => l.startsWith("aborting phase"))).toBe(false);
  });

  it("aborts the phase after 3 consecutive failures from the same tool", async () => {
    const scripted: AgentMessage[] = [];
    for (let i = 0; i < 4; i++) {
      scripted.push({
        type: "assistant",
        content: [{ type: "tool_use", id: `tu-${i}`, name: "Write", input: { file_path: "/x" } }],
      });
      scripted.push({
        type: "tool-result",
        toolUseId: `tu-${i}`,
        isError: true,
        content: "Validation failed for tool Write",
      });
    }
    scripted.push({ type: "result", subtype: "success", result: "ok", totalCostUsd: 0.01 });

    const activity: string[] = [];
    await runRandoriPasta({
      runtime: makeRuntime(scripted),
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

    expect(activity).toContain("Write failed (3/3): Validation failed for tool Write");
    expect(activity).toContain("aborting phase after 3 Write failures");
    // The cap fires at the 3rd failure, so the 4th scripted failure is
    // never consumed. We don't assert the exact index of the abort pulse,
    // just that it was emitted.
    const abortIndex = activity.findIndex((l) => l.startsWith("aborting"));
    expect(abortIndex).toBeGreaterThan(-1);
    // No pulse after the abort — we break out of the loop.
    expect(activity.slice(abortIndex + 1)).toEqual([]);
  });

  it("clears THIS tool's counter only when THAT tool succeeds (not other tools)", async () => {
    // Write fail → Read success → Write fail: the Read success does NOT
    // reset Write's counter. This is the real-world pattern from the
    // PASTA S4 retry loop.
    const scripted: AgentMessage[] = [
      {
        type: "assistant",
        content: [{ type: "tool_use", id: "w1", name: "Write", input: { file_path: "/x" } }],
      },
      { type: "tool-result", toolUseId: "w1", isError: true, content: "fail 1" },
      {
        type: "assistant",
        content: [{ type: "tool_use", id: "r1", name: "Read", input: { file_path: "/x" } }],
      },
      { type: "tool-result", toolUseId: "r1", isError: false, content: "ok" },
      {
        type: "assistant",
        content: [{ type: "tool_use", id: "w2", name: "Write", input: { file_path: "/y" } }],
      },
      { type: "tool-result", toolUseId: "w2", isError: true, content: "fail 2" },
      {
        type: "assistant",
        content: [{ type: "tool_use", id: "r2", name: "Read", input: { file_path: "/y" } }],
      },
      { type: "tool-result", toolUseId: "r2", isError: false, content: "ok" },
      {
        type: "assistant",
        content: [{ type: "tool_use", id: "w3", name: "Write", input: { file_path: "/z" } }],
      },
      { type: "tool-result", toolUseId: "w3", isError: true, content: "fail 3" },
      { type: "result", subtype: "success", result: "ok", totalCostUsd: 0 },
    ];

    const activity: string[] = [];
    await runRandoriPasta({
      runtime: makeRuntime(scripted),
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

    // Write counter climbs 1→2→3 despite the Reads succeeding in between.
    // The cap fires on the 3rd Write failure — which is the whole point
    // of the per-tool tracking over the old cross-tool-reset behavior.
    expect(activity).toContain("Write failed (1/3): fail 1");
    expect(activity).toContain("Write failed (2/3): fail 2");
    expect(activity).toContain("Write failed (3/3): fail 3");
    expect(activity).toContain("aborting phase after 3 Write failures");
  });

  it("a tool's success clears ONLY its own counter", async () => {
    // Write fail → Write success → Write fail: the Write success resets
    // Write's own counter, so the final count is 1.
    const scripted: AgentMessage[] = [
      {
        type: "assistant",
        content: [{ type: "tool_use", id: "w1", name: "Write", input: { file_path: "/x" } }],
      },
      { type: "tool-result", toolUseId: "w1", isError: true, content: "fail 1" },
      {
        type: "assistant",
        content: [{ type: "tool_use", id: "w2", name: "Write", input: { file_path: "/y" } }],
      },
      { type: "tool-result", toolUseId: "w2", isError: false, content: "ok" },
      {
        type: "assistant",
        content: [{ type: "tool_use", id: "w3", name: "Write", input: { file_path: "/z" } }],
      },
      { type: "tool-result", toolUseId: "w3", isError: true, content: "fail 2" },
      { type: "result", subtype: "success", result: "ok", totalCostUsd: 0 },
    ];

    const activity: string[] = [];
    await runRandoriPasta({
      runtime: makeRuntime(scripted),
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

    const failurePulses = activity.filter((l) => l.startsWith("Write failed"));
    expect(failurePulses).toEqual(["Write failed (1/3): fail 1", "Write failed (1/3): fail 2"]);
    expect(activity.some((l) => l.startsWith("aborting phase"))).toBe(false);
  });

  it("different tools each have independent counters", async () => {
    // Write fails twice and Read fails twice — neither trips the cap in
    // isolation. Interleaved.
    const scripted: AgentMessage[] = [
      {
        type: "assistant",
        content: [{ type: "tool_use", id: "w1", name: "Write", input: {} }],
      },
      { type: "tool-result", toolUseId: "w1", isError: true, content: "w1" },
      {
        type: "assistant",
        content: [{ type: "tool_use", id: "r1", name: "Read", input: {} }],
      },
      { type: "tool-result", toolUseId: "r1", isError: true, content: "r1" },
      {
        type: "assistant",
        content: [{ type: "tool_use", id: "w2", name: "Write", input: {} }],
      },
      { type: "tool-result", toolUseId: "w2", isError: true, content: "w2" },
      {
        type: "assistant",
        content: [{ type: "tool_use", id: "r2", name: "Read", input: {} }],
      },
      { type: "tool-result", toolUseId: "r2", isError: true, content: "r2" },
      { type: "result", subtype: "success", result: "ok", totalCostUsd: 0 },
    ];

    const activity: string[] = [];
    await runRandoriPasta({
      runtime: makeRuntime(scripted),
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

    // Independent counters: Write 1/3, 2/3 and Read 1/3, 2/3. Neither trips.
    expect(activity).toContain("Write failed (1/3): w1");
    expect(activity).toContain("Read failed (1/3): r1");
    expect(activity).toContain("Write failed (2/3): w2");
    expect(activity).toContain("Read failed (2/3): r2");
    expect(activity.some((l) => l.startsWith("aborting phase"))).toBe(false);
  });
});
