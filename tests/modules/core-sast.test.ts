import { afterEach, describe, expect, it, vi } from "vitest";
import { createCoreSastModule } from "../../src/modules/core-sast.js";
import { wrapDagToolExecute } from "../../src/modules/dag-bridge.js";
import { createSemgrepModule } from "../../src/modules/semgrep/semgrep.js";
import { createTaintIrisModule } from "../../src/modules/taint-iris/taint-iris.js";
import type { CopilotModule, DagTool, ExecutionContext } from "../../src/modules/types.js";
import { isDagTool } from "../../src/modules/types.js";
import type { KuzushiConfig } from "../../src/types.js";

// threat-hunt is no longer a task-wrapping module — it now runs its agent
// fan-out directly via the DagTool contract (see
// `src/modules/threat-hunt/threat-hunt.ts`). The `runPipeline` assertions
// that used to live here moved to
// `tests/modules/threat-hunt/threat-hunt.test.ts`.

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

function createContext(config = createConfig()): ExecutionContext {
  return {
    cwd: "/tmp/repo",
    runtime: { id: "test", async *query() {} },
    bus: {} as ExecutionContext["bus"],
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

    // The semgrep module ships a DagTool — its shell-mode `execute()` is
    // installed by the registry bridge at `loadModule` time. This test
    // exercises tools directly, so install the wrapper ourselves.
    const semgrepTool = pickDagToolWithExecute(createSemgrepModule(), "semgrep:scan");
    const taintIrisTool = pickDagToolWithExecute(createTaintIrisModule(), "taint-iris:hunt");

    await semgrepTool.execute({ target: "/tmp/repo", severity: ["high"] }, ctx);
    expect(runPipelineMock).toHaveBeenLastCalledWith(
      expect.objectContaining({
        postProcessMode: "scan-only",
        scanOpts: expect.objectContaining({
          tasks: ["semgrep"],
        }),
      }),
    );

    await taintIrisTool.execute({ target: "/tmp/repo" }, ctx);
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

/**
 * Resolve a DagTool by name and ensure it has a working `execute()`
 * installed (the registry bridge normally does this at load time). Returns
 * the tool typed as the underlying `DagTool` so callers can invoke
 * `.execute()` without navigating the undiscriminated union.
 */
function pickDagToolWithExecute(mod: CopilotModule, name: string): DagTool {
  const tool = mod.tools.find((t) => t.name === name);
  if (!tool || !isDagTool(tool)) {
    throw new Error(`Expected DagTool "${name}" on module "${mod.id}".`);
  }
  wrapDagToolExecute(mod, tool);
  return tool;
}
