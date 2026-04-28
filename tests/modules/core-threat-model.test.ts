import { beforeEach, describe, expect, it, vi } from "vitest";
import { createThreatModelModule } from "../../src/modules/threat-model/threat-model.js";
import type { ExecutionContext } from "../../src/modules/types.js";
import type { KuzushiConfig } from "../../src/types.js";

const {
  resolveRepoMock,
  resolveRandoriPluginPathMock,
  runRandoriPastaMock,
  loadPersistentThreatModelMock,
  savePersistentThreatModelMock,
  readRandoriArtifactsMock,
  mergeRandoriStageOutputsMock,
  convertRandoriToThreatModelMock,
} = vi.hoisted(() => ({
  resolveRepoMock: vi.fn(() => ({ root: "/tmp/repo", name: "repo" })),
  resolveRandoriPluginPathMock: vi.fn(() => "/randori-plugin"),
  runRandoriPastaMock: vi.fn(),
  loadPersistentThreatModelMock: vi.fn(() => null),
  savePersistentThreatModelMock: vi.fn(() => true),
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
  savePersistentThreatModel: savePersistentThreatModelMock,
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

function createCtx(overrides: Partial<ExecutionContext> = {}): ExecutionContext {
  return {
    cwd: "/tmp/repo",
    runtime: {} as ExecutionContext["runtime"],
    bus: {} as ExecutionContext["bus"],
    config: createConfig(),
    ...overrides,
  };
}

function threatModelWithThreat() {
  return {
    version: "1.0",
    dfd: { elements: [], trustBoundaries: [] },
    threats: [
      {
        id: "T-1",
        elementId: "boundary",
        category: "elevation-of-privilege",
        title: "Privileged workflow trigger",
        description: "A comment-triggered workflow can run privileged automation.",
        attackVector: "pull_request_target",
        preconditions: ["Attacker can open a pull request"],
        impact: "critical",
        likelihood: "high",
        existingMitigations: [],
        missingMitigations: ["Require approval before privileged commands"],
        relatedCwe: ["OWASP-A01"],
        affectedFiles: [{ filePath: "workflows/ci.yml", startLine: 10 }],
        evidenceAnchors: [
          {
            filePath: "workflows/ci.yml",
            startLine: 10,
            description: "Privileged job trigger",
          },
        ],
      },
    ],
    summary: { total: 1, bySeverity: { critical: 1 }, byCategory: { "elevation-of-privilege": 1 } },
  };
}

describe("threat-model module", () => {
  beforeEach(() => {
    runRandoriPastaMock.mockReset();
    resolveRandoriPluginPathMock.mockReset();
    resolveRandoriPluginPathMock.mockReturnValue("/randori-plugin");
    readRandoriArtifactsMock.mockReset();
    mergeRandoriStageOutputsMock.mockReset();
    convertRandoriToThreatModelMock.mockReset();
    savePersistentThreatModelMock.mockReset();
    savePersistentThreatModelMock.mockReturnValue(true);
  });

  it("exposes selectable threat model tools", () => {
    const mod = createThreatModelModule();
    expect(mod.id).toBe("threat-model");
    expect(mod.category).toBe("intel");
    const names = mod.tools.map((t) => t.name).sort();
    expect(names).toEqual(
      expect.arrayContaining([
        "threat-model:attach",
        "threat-model:attachments",
        "threat-model:build",
        "threat-model:detach",
        "threat-model:methodologies",
        "threat-model:read",
        "threat-model:reparse",
        "threat-model:threat-model-randori",
        "threat-model:threat-scenario-build",
      ]),
    );
  });

  it("lists PASTA, STRIDE, and DREAD methodologies", async () => {
    const tool = createThreatModelModule().tools.find(
      (t) => t.name === "threat-model:methodologies",
    )!;
    const result = await tool.execute({}, createCtx());
    expect(result.ok).toBe(true);
    expect(result.output).toContain("pasta");
    expect(result.output).toContain("stride");
    expect(result.output).toContain("dread");
  });

  it("builds with the configured methodology and applies DREAD scoring", async () => {
    runRandoriPastaMock.mockResolvedValueOnce({
      document: threatModelWithThreat(),
      findings: [],
      artifacts: {},
      costUsd: 0.05,
      empty: false,
    });
    const config = createConfig();
    config.taskConfig["threat-model"] = {
      methodology: "dread",
      maxElements: 12,
      maxThreats: 4,
      randoriStages: ["s1", "s2", "s3", "s4"],
    };
    const build = createThreatModelModule().tools.find((t) => t.name === "threat-model:build")!;
    const result = await build.execute({ target: "/some/repo" }, createCtx({ config }));

    expect(result.ok).toBe(true);
    expect(result.output).toContain("Method:   DREAD");
    const call = runRandoriPastaMock.mock.calls[0][0];
    expect(call.maxElements).toBe(12);
    expect(call.maxThreats).toBe(4);
    expect(savePersistentThreatModelMock).toHaveBeenCalledWith(
      "/tmp/repo",
      expect.objectContaining({ methodology: "dread" }),
      false,
    );
    const data = result.data as {
      methodology: string;
      persisted: boolean;
      slice: string;
      document: { riskScores?: { threats: unknown[] } };
    };
    expect(data.methodology).toBe("dread");
    expect(data.slice).toBe("all");
    expect(data.persisted).toBe(true);
    expect(data.document.riskScores?.threats).toHaveLength(1);
  });

  it("reads existing artifacts and applies the requested methodology overlay", async () => {
    readRandoriArtifactsMock.mockReturnValueOnce({ s4Threats: { threats: [] } });
    mergeRandoriStageOutputsMock.mockReturnValueOnce({ merged: true });
    convertRandoriToThreatModelMock.mockReturnValueOnce(threatModelWithThreat());

    const read = createThreatModelModule().tools.find((t) => t.name === "threat-model:read")!;
    const result = await read.execute(
      { outputDir: ".kuzushi/randori", methodology: "stride" },
      createCtx(),
    );

    expect(result.ok).toBe(true);
    expect(result.output).toContain("Loaded STRIDE threat model");
    const data = result.data as { methodology: string; document: { methodology?: string } };
    expect(data.methodology).toBe("stride");
    expect(data.document.methodology).toBe("stride");
  });
});
