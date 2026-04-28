/**
 * threat-model KB integration: verifies that operator-staged attachments
 * are loaded from disk by `threat-model:build` and reach `runRandoriPasta`
 * as the `systemPromptAddendum` field.
 */

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ExecutionContext } from "../../../src/modules/types.js";
import type { KuzushiConfig } from "../../../src/types.js";

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

vi.mock("../../../src/cli/shared.js", () => ({ resolveRepo: resolveRepoMock }));
vi.mock("../../../src/agents/tasks/threat-modeling/resolve-randori.js", () => ({
  resolveRandoriPluginPath: resolveRandoriPluginPathMock,
}));
vi.mock("../../../src/agents/tasks/threat-modeling/randori-runner.js", () => ({
  runRandoriPasta: runRandoriPastaMock,
}));
vi.mock("../../../src/threat-model-renderer.js", () => ({
  loadPersistentThreatModel: loadPersistentThreatModelMock,
  savePersistentThreatModel: savePersistentThreatModelMock,
}));
vi.mock("../../../src/agents/tasks/threat-modeling/randori-artifacts.js", () => ({
  readRandoriArtifacts: readRandoriArtifactsMock,
  mergeRandoriStageOutputs: mergeRandoriStageOutputsMock,
}));
vi.mock("../../../src/agents/tasks/threat-modeling/randori-adapter.js", () => ({
  convertRandoriToThreatModel: convertRandoriToThreatModelMock,
}));

const tempDirs: string[] = [];

function tempRoot(): string {
  const dir = mkdtempSync(path.join(tmpdir(), "tm-attachments-"));
  tempDirs.push(dir);
  return dir;
}

function emptyConfig(): KuzushiConfig {
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

function createCtx(cwd: string, overrides: Partial<ExecutionContext> = {}): ExecutionContext {
  return {
    cwd,
    runtime: {} as ExecutionContext["runtime"],
    bus: {} as ExecutionContext["bus"],
    config: emptyConfig(),
    ...overrides,
  };
}

beforeEach(() => {
  runRandoriPastaMock.mockReset();
  savePersistentThreatModelMock.mockReset();
  savePersistentThreatModelMock.mockReturnValue(true);
  runRandoriPastaMock.mockResolvedValue({
    document: {
      version: "1",
      dfd: { elements: [], trustBoundaries: [] },
      threats: [],
      summary: {},
    },
    findings: [],
    artifacts: {},
    costUsd: 0,
    empty: false,
  });
});

afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("threat-model attachments integration", () => {
  it("loads attachments from .kuzushi/threat-model/attachments.json and forwards them as systemPromptAddendum", async () => {
    const root = tempRoot();
    resolveRepoMock.mockReturnValueOnce({ root, name: "fixture" });
    // Stage a parsed attachment via the shared adapter — not the tool — so
    // this test isn't entangled with the attach tool's argument plumbing.
    const { defaultAttachmentAdapter } = await import(
      "../../../src/modules/_shared/attachments/index.js"
    );
    const adapter = defaultAttachmentAdapter("threat-model");
    adapter.write(root, [
      {
        id: "abc1234567",
        source: path.join(root, "rfc-checkout.md"),
        sourceType: "local",
        kind: "design-doc",
        title: "rfc-checkout.md",
        status: "parsed",
        extracted: {
          text: "Checkout uses a 30-second timeout for downstream payment auth",
          charCount: 60,
          parser: "text",
        },
        parseWarnings: [],
        attachedAt: "2026-04-27T00:00:00.000Z",
      },
    ]);
    // Pretend artifact reads return at least one stage so the build
    // doesn't short-circuit; the runner is mocked so the merger is bypassed
    // entirely — what we care about is the parameters passed to runRandoriPasta.
    readRandoriArtifactsMock.mockReturnValue({
      s2Scope: { foo: 1 },
      s3Decomposition: null,
      s4Threats: null,
      narrative: null,
    });
    mergeRandoriStageOutputsMock.mockReturnValue({ threats: [] });
    convertRandoriToThreatModelMock.mockReturnValue({
      version: "1",
      dfd: { elements: [], trustBoundaries: [] },
      threats: [],
      summary: {},
    });

    const { createThreatModelModule } = await import(
      "../../../src/modules/threat-model/threat-model.js"
    );
    const tool = createThreatModelModule().tools.find((t) => t.name === "threat-model:build")!;
    const ctx = createCtx(root, { target: root });
    await tool.execute({ target: root }, ctx);

    expect(runRandoriPastaMock).toHaveBeenCalledTimes(1);
    const params = runRandoriPastaMock.mock.calls[0]?.[0];
    expect(params.systemPromptAddendum).toBeDefined();
    expect(params.systemPromptAddendum).toContain('<untrusted_attachment moduleId="threat-model"');
    expect(params.systemPromptAddendum).toContain("rfc-checkout.md");
    expect(params.systemPromptAddendum).toContain("30-second timeout");
  });

  it("omits systemPromptAddendum entirely when no attachments are staged", async () => {
    const root = tempRoot();
    resolveRepoMock.mockReturnValueOnce({ root, name: "fixture" });
    mkdirSync(path.join(root, ".kuzushi"), { recursive: true });
    readRandoriArtifactsMock.mockReturnValue({
      s2Scope: { foo: 1 },
      s3Decomposition: null,
      s4Threats: null,
      narrative: null,
    });
    mergeRandoriStageOutputsMock.mockReturnValue({ threats: [] });
    convertRandoriToThreatModelMock.mockReturnValue({
      version: "1",
      dfd: { elements: [], trustBoundaries: [] },
      threats: [],
      summary: {},
    });

    const { createThreatModelModule } = await import(
      "../../../src/modules/threat-model/threat-model.js"
    );
    const tool = createThreatModelModule().tools.find((t) => t.name === "threat-model:build")!;
    const ctx = createCtx(root, { target: root });
    await tool.execute({ target: root }, ctx);

    const params = runRandoriPastaMock.mock.calls[0]?.[0];
    expect(params.systemPromptAddendum).toBeUndefined();
  });

  it("registers all four attachment tools under the threat-model module", async () => {
    const { createThreatModelModule } = await import(
      "../../../src/modules/threat-model/threat-model.js"
    );
    const names = createThreatModelModule()
      .tools.map((t) => t.name)
      .sort();
    expect(names).toContain("threat-model:attach");
    expect(names).toContain("threat-model:attachments");
    expect(names).toContain("threat-model:detach");
    expect(names).toContain("threat-model:reparse");
  });

  it("threat-model:attach end-to-end persists a doc the build path then reads", async () => {
    const root = tempRoot();
    const file = path.join(root, "design.md");
    writeFileSync(file, "system uses STRIDE-shaped attack-surface analysis end-to-end");
    resolveRepoMock.mockReturnValueOnce({ root, name: "fixture" });
    readRandoriArtifactsMock.mockReturnValue({
      s2Scope: { foo: 1 },
      s3Decomposition: null,
      s4Threats: null,
      narrative: null,
    });
    mergeRandoriStageOutputsMock.mockReturnValue({ threats: [] });
    convertRandoriToThreatModelMock.mockReturnValue({
      version: "1",
      dfd: { elements: [], trustBoundaries: [] },
      threats: [],
      summary: {},
    });

    const { createThreatModelModule } = await import(
      "../../../src/modules/threat-model/threat-model.js"
    );
    const mod = createThreatModelModule();
    const attach = mod.tools.find((t) => t.name === "threat-model:attach")!;
    const build = mod.tools.find((t) => t.name === "threat-model:build")!;
    const ctx = createCtx(root, { target: root });

    const attachResult = await attach.execute({ source: file }, ctx);
    expect(attachResult.ok).toBe(true);
    await build.execute({ target: root }, ctx);

    const params = runRandoriPastaMock.mock.calls[0]?.[0];
    expect(params.systemPromptAddendum).toContain("attack-surface analysis end-to-end");
  });
});
