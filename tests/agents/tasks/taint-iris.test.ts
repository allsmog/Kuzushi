import { describe, expect, it } from "vitest";
import type { AgentQueryRequest, AgentRuntime } from "../../../src/agent-runtime/types.js";
import { taintIrisTask } from "../../../src/agents/tasks/taint-iris/iris.js";
import type { PipelineContext } from "../../../src/agents/types.js";
import type { KuzushiConfig, ScanOpts } from "../../../src/types.js";

function cwe(id: string) {
  return { id, name: `${id} name`, reason: `${id} reason` };
}

function makeRuntime(capture: (request: AgentQueryRequest) => void): AgentRuntime {
  return {
    id: "test",
    async *query(request) {
      capture(request);
      yield {
        type: "result",
        subtype: "success",
        result: '{"findings":[]}',
        structuredOutput: { findings: [] },
        totalCostUsd: 0.02,
      };
    },
  };
}

function makeConfig(taskConfig: KuzushiConfig["taskConfig"]): KuzushiConfig {
  return {
    model: "test-model",
    taskConfig,
    tasks: [],
  } as unknown as KuzushiConfig;
}

function makeContext(
  runtime: AgentRuntime,
  taskConfig: KuzushiConfig["taskConfig"],
  signal?: AbortSignal,
): PipelineContext {
  return {
    runId: "run-1",
    repoRoot: "/repo",
    repoName: "repo",
    config: makeConfig(taskConfig),
    runtime,
    bus: {} as PipelineContext["bus"],
    upstreamOutputs: new Map([
      ["context-gatherer", { languages: ["TypeScript"], frameworks: ["Express"] }],
      ["taint-cwe-select", { cwes: [cwe("CWE-89"), cwe("CWE-78"), cwe("CWE-22")] }],
    ]),
    ...(signal ? { signal } : {}),
  };
}

describe("taint-iris task", () => {
  it("threads TAINT_IRIS_PROMPT into the agent prompt", async () => {
    let captured: AgentQueryRequest | undefined;
    const runtime = makeRuntime((request) => {
      captured = request;
    });

    await taintIrisTask.run(
      {
        target: ".",
        TAINT_IRIS_PROMPT: "Operator override: focus on sql sinks only.",
      } as unknown as ScanOpts,
      makeContext(runtime, { "taint-iris": { codeqlMode: "off" } }),
    );

    expect(captured?.prompt).toContain("## Operator Prompt Override");
    expect(captured?.prompt).toContain("Operator override: focus on sql sinks only.");
    expect(captured?.prompt).toContain("CWE-89");
  });

  it("caps selected CWEs while keeping one agent session", async () => {
    let captured: AgentQueryRequest | undefined;
    const runtime = makeRuntime((request) => {
      captured = request;
    });

    await taintIrisTask.run(
      { target: ".", maxCwes: 2 } as unknown as ScanOpts,
      makeContext(runtime, { "taint-iris": { codeqlMode: "off" } }),
    );

    expect(captured?.prompt).toContain("Analyzing first 2 of 3 selected CWE classes.");
    expect(captured?.prompt).toContain("CWE-89");
    expect(captured?.prompt).toContain("CWE-78");
    expect(captured?.prompt).not.toContain("CWE-22");
  });

  it("forwards abort and budget controls to the runtime query", async () => {
    let captured: AgentQueryRequest | undefined;
    const runtime = makeRuntime((request) => {
      captured = request;
    });
    const controller = new AbortController();

    await taintIrisTask.run(
      { target: "." },
      makeContext(
        runtime,
        { "taint-iris": { codeqlMode: "off", maxBudgetUsd: 0.5 } },
        controller.signal,
      ),
    );

    expect(captured?.options.maxBudgetUsd).toBe(0.5);
    expect(captured?.options.abortController).toBeDefined();
    expect(captured?.options.abortController?.signal.aborted).toBe(false);

    controller.abort();
    expect(captured?.options.abortController?.signal.aborted).toBe(true);
  });
});
