import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

// Mock the scan pipeline so we can inspect what taskConfig makes it through.
const runPipelineMock = vi.hoisted(() => vi.fn());
vi.mock("../../src/cli/commands/scan.js", () => ({ runPipeline: runPipelineMock }));
vi.mock("../../src/cli/shared.js", () => ({
  resolveRepo: () => ({ root: "/tmp/repo", name: "repo" }),
}));
vi.mock("../../src/cli/scan-config.js", () => ({
  resolveScanSeverity: () => ["ERROR"],
}));
vi.mock("../../src/ui/output.js", () => ({
  configureTerminalOutput: vi.fn(),
  resetTerminalOutput: vi.fn(),
}));

import { createThreatHuntModule } from "../../src/modules/sast/core-threat-hunt.js";
import type { ToolExecutionContext } from "../../src/modules/types.js";
import type { KuzushiConfig } from "../../src/types.js";

const tempDirs: string[] = [];
afterEach(() => {
  runPipelineMock.mockReset();
  while (tempDirs.length > 0) rmSync(tempDirs.pop()!, { recursive: true, force: true });
});

function mkCtx(): ToolExecutionContext {
  return {
    cwd: "/tmp/repo",
    runtime: { id: "test", async *query() {} },
    bus: {} as ToolExecutionContext["bus"],
    config: {
      model: "anthropic:claude-sonnet-4-6",
      busBackend: "in-process",
      triageBatchSize: 5,
      triageConcurrency: 2,
      scanMode: "parallel",
      tasks: ["threat-hunt"],
      severity: ["ERROR"],
      excludePatterns: [],
      taskConfig: {},
    } as KuzushiConfig,
    target: "/tmp/repo",
  };
}

describe("threat-hunt sub-module forwards THREAT_HUNT_PROMPT", () => {
  it("reads an inline override and threads it through taskConfig", async () => {
    runPipelineMock.mockResolvedValue({
      runId: "r",
      status: "complete",
      stats: { totalFindings: 0, triaged: 0 },
    });
    const mod = createThreatHuntModule();
    const tool = mod.tools.find((t) => t.name === "threat-hunt:run");
    await tool!.execute({ target: "/tmp/repo", THREAT_HUNT_PROMPT: "be extra careful" }, mkCtx());
    expect(runPipelineMock).toHaveBeenCalledWith(
      expect.objectContaining({
        config: expect.objectContaining({
          taskConfig: expect.objectContaining({
            "threat-hunt": expect.objectContaining({ promptOverride: "be extra careful" }),
          }),
        }),
      }),
    );
  });

  it("reads a file path and forwards the file contents", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "kz-prompt-"));
    tempDirs.push(dir);
    const file = path.join(dir, "hunt.md");
    writeFileSync(file, "# file-backed prompt\n", "utf8");

    runPipelineMock.mockResolvedValue({
      runId: "r",
      status: "complete",
      stats: { totalFindings: 0, triaged: 0 },
    });
    const mod = createThreatHuntModule();
    const tool = mod.tools.find((t) => t.name === "threat-hunt:run");
    await tool!.execute({ target: "/tmp/repo", THREAT_HUNT_PROMPT: file }, mkCtx());
    const call = runPipelineMock.mock.calls.at(-1)?.[0];
    const override = call?.config?.taskConfig?.["threat-hunt"]?.promptOverride;
    expect(override).toContain("file-backed prompt");
  });

  it("omits promptOverride when no value is set", async () => {
    runPipelineMock.mockResolvedValue({
      runId: "r",
      status: "complete",
      stats: { totalFindings: 0, triaged: 0 },
    });
    const mod = createThreatHuntModule();
    const tool = mod.tools.find((t) => t.name === "threat-hunt:run");
    await tool!.execute({ target: "/tmp/repo" }, mkCtx());
    const call = runPipelineMock.mock.calls.at(-1)?.[0];
    expect(call?.config?.taskConfig?.["threat-hunt"]?.promptOverride).toBeUndefined();
  });
});
