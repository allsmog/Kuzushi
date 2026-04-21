import { afterEach, describe, expect, it, vi } from "vitest";
import { createCoreSastModule } from "../../src/modules/core-sast.js";
import { createSemgrepModule } from "../../src/modules/sast/core-semgrep.js";
import { createTaintIrisModule } from "../../src/modules/sast/core-taint-iris.js";
import { createThreatHuntModule } from "../../src/modules/sast/core-threat-hunt.js";
import type { ToolExecutionContext } from "../../src/modules/types.js";
import type { KuzushiConfig } from "../../src/types.js";

const {
  runPipelineMock,
  resolveRepoMock,
  resolveScanSeverityMock,
  configureTerminalOutputMock,
  resetTerminalOutputMock,
} = vi.hoisted(() => ({
  runPipelineMock: vi.fn(),
  resolveRepoMock: vi.fn(() => ({ root: "/tmp/repo", name: "repo" })),
  resolveScanSeverityMock: vi.fn((_config: unknown, opts: { severity?: string }) =>
    opts.severity ? opts.severity.split(",") : ["ERROR"],
  ),
  configureTerminalOutputMock: vi.fn(),
  resetTerminalOutputMock: vi.fn(),
}));

vi.mock("../../src/cli/commands/scan-pipeline.js", () => ({
  runPipeline: runPipelineMock,
}));

vi.mock("../../src/cli/shared.js", () => ({
  resolveRepo: resolveRepoMock,
}));

vi.mock("../../src/cli/scan-config.js", () => ({
  resolveScanSeverity: resolveScanSeverityMock,
}));

vi.mock("../../src/ui/output.js", () => ({
  configureTerminalOutput: configureTerminalOutputMock,
  resetTerminalOutput: resetTerminalOutputMock,
}));

function createConfig(): KuzushiConfig {
  return {
    model: "anthropic:claude-sonnet-4-6",
    busBackend: "in-process",
    triageBatchSize: 5,
    triageConcurrency: 2,
    scanMode: "parallel",
    tasks: ["semgrep"],
    severity: ["ERROR"],
    excludePatterns: [],
    taskConfig: {
      semgrep: {},
      "threat-hunt": { maxActors: 5 },
    },
  };
}

function createContext(config = createConfig()): ToolExecutionContext {
  return {
    cwd: "/tmp/repo",
    runtime: { id: "test", async *query() {} },
    bus: {} as ToolExecutionContext["bus"],
    config,
    target: "/tmp/repo",
  };
}

afterEach(() => {
  vi.clearAllMocks();
});

describe("createCoreSastModule tool execution", () => {
  it("keeps sast:scan on full post-processing", async () => {
    runPipelineMock.mockResolvedValue({
      runId: "run-1",
      status: "complete",
      stats: {
        totalFindings: 3,
        triaged: 2,
        totalCostUsd: 1.25,
      },
    });

    const module = createCoreSastModule();
    const tool = module.tools.find((entry) => entry.name === "sast:scan");
    const ctx = createContext();

    const result = await tool!.execute({ target: "/tmp/repo", severity: ["critical"] }, ctx);

    expect(runPipelineMock).toHaveBeenCalledWith(
      expect.objectContaining({
        postProcessMode: "full",
        scanOpts: expect.objectContaining({
          tasks: undefined,
          severity: ["critical"],
        }),
      }),
    );
    expect(result.output).toContain("3 findings, 2 triaged");
  });

  it("runs standalone task tools in scan-only mode and injects task config overrides", async () => {
    runPipelineMock.mockResolvedValue({
      runId: "run-2",
      status: "complete",
      stats: {
        totalFindings: 2,
        triaged: 0,
        totalCostUsd: 0.75,
      },
    });

    const ctx = createContext();

    const semgrepTool = createSemgrepModule().tools.find((e) => e.name === "semgrep:scan");
    const threatHuntTool = createThreatHuntModule().tools.find((e) => e.name === "threat-hunt:run");
    const taintIrisTool = createTaintIrisModule().tools.find((e) => e.name === "taint-iris:hunt");

    await semgrepTool!.execute({ target: "/tmp/repo", severity: ["high"] }, ctx);
    expect(runPipelineMock).toHaveBeenLastCalledWith(
      expect.objectContaining({
        postProcessMode: "scan-only",
        scanOpts: expect.objectContaining({
          tasks: ["semgrep"],
        }),
      }),
    );

    await threatHuntTool!.execute({ target: "/tmp/repo", maxActors: 7, maxFindings: 12 }, ctx);
    expect(runPipelineMock).toHaveBeenLastCalledWith(
      expect.objectContaining({
        postProcessMode: "scan-only",
        scanOpts: expect.objectContaining({
          tasks: ["threat-hunt"],
        }),
        config: expect.objectContaining({
          taskConfig: expect.objectContaining({
            "threat-hunt": expect.objectContaining({
              maxActors: 7,
              maxFindings: 12,
            }),
          }),
        }),
      }),
    );

    await taintIrisTool!.execute({ target: "/tmp/repo" }, ctx);
    expect(runPipelineMock).toHaveBeenLastCalledWith(
      expect.objectContaining({
        postProcessMode: "scan-only",
        scanOpts: expect.objectContaining({
          tasks: ["taint-cwe-select", "taint-iris"],
        }),
      }),
    );
  });
});
