import { beforeEach, describe, expect, it, vi } from "vitest";
import { createCoreRandoriModule } from "../../src/modules/randori/randori.js";
import type { ToolExecutionContext } from "../../src/modules/types.js";
import type { KuzushiConfig } from "../../src/types.js";

const {
  resolveRepoMock,
  resolveRandoriPluginPathMock,
  runRandoriPastaMock,
  loadPersistentThreatModelMock,
  readRandoriArtifactsMock,
  mergeRandoriStageOutputsMock,
  convertRandoriToThreatModelMock,
} = vi.hoisted(() => ({
  resolveRepoMock: vi.fn(() => ({ root: "/tmp/repo", name: "repo" })),
  resolveRandoriPluginPathMock: vi.fn(() => "/randori-plugin"),
  runRandoriPastaMock: vi.fn(),
  loadPersistentThreatModelMock: vi.fn(() => null),
  readRandoriArtifactsMock: vi.fn(),
  mergeRandoriStageOutputsMock: vi.fn(),
  convertRandoriToThreatModelMock: vi.fn(),
}));

vi.mock("../../src/cli/shared.js", () => ({
  resolveRepo: resolveRepoMock,
}));

vi.mock("../../src/agents/tasks/threat-modeling/resolve-randori.js", () => ({
  resolveRandoriPluginPath: resolveRandoriPluginPathMock,
}));

vi.mock("../../src/agents/tasks/threat-modeling/randori-runner.js", () => ({
  runRandoriPasta: runRandoriPastaMock,
}));

vi.mock("../../src/threat-model-renderer.js", () => ({
  loadPersistentThreatModel: loadPersistentThreatModelMock,
}));

vi.mock("../../src/agents/tasks/threat-modeling/randori-artifacts.js", () => ({
  readRandoriArtifacts: readRandoriArtifactsMock,
  mergeRandoriStageOutputs: mergeRandoriStageOutputsMock,
}));

vi.mock("../../src/agents/tasks/threat-modeling/randori-adapter.js", () => ({
  convertRandoriToThreatModel: convertRandoriToThreatModelMock,
}));

function createConfig(): KuzushiConfig {
  return {
    model: "anthropic:claude-sonnet-4-6",
    busBackend: "in-process",
    triageBatchSize: 5,
    triageConcurrency: 2,
    scanMode: "parallel",
    tasks: [],
    severity: ["ERROR"],
    excludePatterns: [],
    taskConfig: {},
  } as KuzushiConfig;
}

function createCtx(overrides: Partial<ToolExecutionContext> = {}): ToolExecutionContext {
  return {
    cwd: "/tmp/repo",
    runtime: {} as ToolExecutionContext["runtime"],
    bus: {} as ToolExecutionContext["bus"],
    config: createConfig(),
    ...overrides,
  };
}

function emptyThreatModel() {
  return {
    version: "1.0",
    dfd: { elements: [], trustBoundaries: [] },
    threats: [],
    summary: { total: 0, bySeverity: {}, byCategory: {} },
  };
}

describe("core-randori module", () => {
  beforeEach(() => {
    runRandoriPastaMock.mockClear();
    resolveRandoriPluginPathMock.mockClear();
    readRandoriArtifactsMock.mockReset();
    mergeRandoriStageOutputsMock.mockReset();
    convertRandoriToThreatModelMock.mockReset();
  });

  it("exposes the expected metadata and tools", () => {
    const mod = createCoreRandoriModule();
    expect(mod.id).toBe("randori");
    expect(mod.category).toBe("intel");
    expect(mod.tools.map((t) => t.name).sort()).toEqual(["randori:pasta", "randori:threat-model"]);
  });

  it("randori:pasta returns a helpful error when the plugin is missing", async () => {
    resolveRandoriPluginPathMock.mockImplementationOnce(() => {
      throw new Error("missing .claude-plugin/plugin.json");
    });
    const pasta = createCoreRandoriModule().tools.find((t) => t.name === "randori:pasta")!;
    const result = await pasta.execute({}, createCtx());
    expect(result.ok).toBe(false);
    expect(result.output).toContain("@kuzushi/randori-plugin is not installed");
    expect(runRandoriPastaMock).not.toHaveBeenCalled();
  });

  it("randori:pasta rejects unknown stages", async () => {
    const pasta = createCoreRandoriModule().tools.find((t) => t.name === "randori:pasta")!;
    const result = await pasta.execute({ stages: ["s9"] }, createCtx());
    expect(result.ok).toBe(false);
    expect(result.output).toContain("unknown stage(s): s9");
    expect(runRandoriPastaMock).not.toHaveBeenCalled();
  });

  it("randori:pasta dispatches to the runner with sensible defaults", async () => {
    runRandoriPastaMock.mockResolvedValueOnce({
      document: emptyThreatModel(),
      findings: [],
      artifacts: {},
      costUsd: 0.05,
      empty: true,
    });
    const pasta = createCoreRandoriModule().tools.find((t) => t.name === "randori:pasta")!;
    const result = await pasta.execute(
      { target: "/some/repo", outputDir: ".kuzushi/custom" },
      createCtx({ workspaceId: "ws-123" }),
    );
    expect(result.ok).toBe(false); // empty → ok=false
    const call = runRandoriPastaMock.mock.calls[0][0];
    expect(call.stages).toEqual(["s1", "s2", "s3", "s4"]);
    expect(call.artifactDir).toBe(".kuzushi/custom");
    expect(call.maxElements).toBe(40);
    expect(call.maxThreats).toBe(30);
    expect(call.emitFindings).toBe(false);
    expect(call.findingThreshold).toBe("medium");
  });

  it("randori:threat-model requires outputDir", async () => {
    const tm = createCoreRandoriModule().tools.find((t) => t.name === "randori:threat-model")!;
    const result = await tm.execute({}, createCtx());
    expect(result.ok).toBe(false);
    expect(result.output).toContain("requires an outputDir");
  });

  it("randori:threat-model errors when no artifacts exist", async () => {
    readRandoriArtifactsMock.mockReturnValueOnce({});
    const tm = createCoreRandoriModule().tools.find((t) => t.name === "randori:threat-model")!;
    const result = await tm.execute({ outputDir: ".kuzushi/randori" }, createCtx());
    expect(result.ok).toBe(false);
    expect(result.output).toContain("No pasta-*.json artifacts found");
  });

  it("randori:threat-model returns the parsed document on success", async () => {
    readRandoriArtifactsMock.mockReturnValueOnce({ s1Objectives: { mock: true } });
    mergeRandoriStageOutputsMock.mockReturnValueOnce({ merged: true });
    convertRandoriToThreatModelMock.mockReturnValueOnce(emptyThreatModel());

    const tm = createCoreRandoriModule().tools.find((t) => t.name === "randori:threat-model")!;
    const result = await tm.execute({ outputDir: ".kuzushi/randori" }, createCtx());
    expect(result.ok).toBe(true);
    const data = result.data as { document: { threats: unknown[] } };
    expect(Array.isArray(data.document.threats)).toBe(true);
  });
});
