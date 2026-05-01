import { describe, expect, it } from "vitest";
import type { AgentQueryRequest, AgentRuntime } from "../../src/agent-runtime/types.js";
import { InProcessBus } from "../../src/bus/adapters/in-process.js";
import { createAgenticSastModule } from "../../src/modules/agentic-sast/agentic-sast.js";
import type { DagTool, ExecutionContext } from "../../src/modules/types.js";
import { isDagTool } from "../../src/modules/types.js";
import type { KuzushiConfig } from "../../src/types.js";

function agenticScanTool(): DagTool {
  const tool = createAgenticSastModule().tools.find((candidate) => {
    return candidate.name === "agentic-sast:scan";
  });
  if (!tool || !isDagTool(tool)) {
    throw new Error("agentic-sast:scan DagTool not found");
  }
  return tool;
}

function makeConfig(overrides: Partial<KuzushiConfig> = {}): KuzushiConfig {
  return {
    model: "anthropic:operator-model",
    busBackend: "in-process",
    triageBatchSize: 1,
    triageConcurrency: 1,
    scanMode: "sequential",
    tasks: ["agentic-sast:scan"],
    severity: ["ERROR"],
    excludePatterns: [],
    taskConfig: {},
    ...overrides,
  } as KuzushiConfig;
}

async function runAgenticScan(
  config: KuzushiConfig,
  ctxOverrides: Partial<ExecutionContext> = {},
  tool: DagTool = agenticScanTool(),
) {
  const seenModels: string[] = [];
  const runtime: AgentRuntime = {
    id: "test-runtime",
    async *query(request: AgentQueryRequest) {
      seenModels.push(request.options.model);
      yield {
        type: "result",
        subtype: "success",
        result: "{}",
        structuredOutput: { findings: [] },
        durationMs: 1,
        numTurns: 1,
        totalCostUsd: 0,
      };
    },
  };
  await tool.init?.({});
  await tool.run({ target: "/tmp/repo", severity: ["ERROR"], excludePatterns: [] }, {
    cwd: "/tmp/repo",
    target: "/tmp/repo",
    runtime,
    bus: new InProcessBus(),
    config,
    dag: {
      runId: "test-run",
      repoRoot: "/tmp/repo",
      repoName: "repo",
      upstreamOutputs: new Map(),
    },
    ...ctxOverrides,
  } as ExecutionContext);
  return seenModels;
}

describe("agentic-sast runtime config", () => {
  it("does not require a model during module-load init", async () => {
    await expect(agenticScanTool().init?.({})).resolves.toBeUndefined();
  });

  it("uses the operator's configured model at scan time", async () => {
    await expect(runAgenticScan(makeConfig())).resolves.toEqual(["anthropic:operator-model"]);
  });

  it("lets taskConfig.agentic.model override config.model", async () => {
    const config = makeConfig({
      taskConfig: {
        agentic: { model: "anthropic:task-model" },
      },
    });

    await expect(runAgenticScan(config)).resolves.toEqual(["anthropic:task-model"]);
  });

  it("lets ctx.modelOverride override persisted config", async () => {
    const config = makeConfig({
      taskConfig: {
        agentic: { model: "anthropic:task-model" },
      },
    });

    await expect(
      runAgenticScan(config, { modelOverride: "anthropic:lane-model" }),
    ).resolves.toEqual(["anthropic:lane-model"]);
  });

  it("uses the current config.model rather than a cached prior fallback", async () => {
    const tool = agenticScanTool();

    await expect(
      runAgenticScan(makeConfig({ model: "anthropic:first-model" }), {}, tool),
    ).resolves.toEqual(["anthropic:first-model"]);
    await expect(
      runAgenticScan(makeConfig({ model: "anthropic:second-model" }), {}, tool),
    ).resolves.toEqual(["anthropic:second-model"]);
  });
});
