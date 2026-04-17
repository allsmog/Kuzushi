import { beforeEach, describe, expect, it, vi } from "vitest";
import { createCorePromptArmorModule } from "../../src/modules/core-prompt-armor.js";
import type { ToolExecutionContext } from "../../src/modules/types.js";
import type { KuzushiConfig } from "../../src/types.js";

const { resolveRepoMock, resolvePromptArmorPluginPathMock, runtimeQueryMock, existsSyncMock } =
  vi.hoisted(() => ({
    resolveRepoMock: vi.fn(() => ({ root: "/tmp/repo", name: "repo" })),
    resolvePromptArmorPluginPathMock: vi.fn(() => "/plugins/prompt-armor"),
    runtimeQueryMock: vi.fn(),
    existsSyncMock: vi.fn(() => true),
  }));

vi.mock("../../src/cli/shared.js", () => ({
  resolveRepo: resolveRepoMock,
}));

vi.mock("../../src/agents/tasks/prompt-armor/resolve-promptarmor-plugin.js", () => ({
  resolvePromptArmorPluginPath: resolvePromptArmorPluginPathMock,
}));

vi.mock("node:fs", async () => {
  const actual = await vi.importActual<typeof import("node:fs")>("node:fs");
  return {
    ...actual,
    existsSync: existsSyncMock,
  };
});

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

function createCtx(): ToolExecutionContext {
  return {
    cwd: "/tmp/repo",
    runtime: { query: runtimeQueryMock } as unknown as ToolExecutionContext["runtime"],
    bus: {} as ToolExecutionContext["bus"],
    config: createConfig(),
  };
}

async function mockQueryResult(costUsd: number): Promise<void> {
  runtimeQueryMock.mockImplementationOnce(async function* () {
    yield { type: "result", totalCostUsd: costUsd };
  });
}

describe("core-prompt-armor module", () => {
  beforeEach(() => {
    runtimeQueryMock.mockReset();
    resolvePromptArmorPluginPathMock.mockClear();
  });

  it("exposes the expected metadata and six tools", () => {
    const mod = createCorePromptArmorModule();
    expect(mod.id).toBe("prompt-armor");
    expect(mod.category).toBe("offense");
    expect(mod.tools.map((t) => t.name).sort()).toEqual([
      "prompt-armor:analyze",
      "prompt-armor:attack",
      "prompt-armor:config",
      "prompt-armor:diff",
      "prompt-armor:report",
      "prompt-armor:scan",
    ]);
    for (const tool of mod.tools) expect(tool.headless).toBe(true);
  });

  it("refuses network commands without authorized: true", async () => {
    const scan = createCorePromptArmorModule().tools.find((t) => t.name === "prompt-armor:scan")!;
    const result = await scan.execute({ endpoint: "https://example/chat" }, createCtx());
    expect(result.ok).toBe(false);
    expect(result.output).toContain("authorized: true");
    expect(runtimeQueryMock).not.toHaveBeenCalled();
  });

  it("runs network commands when authorized: true is passed", async () => {
    await mockQueryResult(0.13);
    const scan = createCorePromptArmorModule().tools.find((t) => t.name === "prompt-armor:scan")!;
    const result = await scan.execute(
      { authorized: true, endpoint: "https://example/chat", suites: ["jailbreak"] },
      createCtx(),
    );
    expect(result.ok).toBe(true);
    expect(result.costUsd).toBeCloseTo(0.13);
    const [args] = runtimeQueryMock.mock.calls[0];
    expect(args.options.plugins).toEqual([{ type: "local", path: "/plugins/prompt-armor" }]);
    expect(args.prompt).toContain("/scan");
    expect(args.prompt).toContain("endpoint: https://example/chat");
    expect(args.prompt).toContain("suites: jailbreak");
  });

  it("runs read-only commands without the authorized flag", async () => {
    await mockQueryResult(0.02);
    const analyze = createCorePromptArmorModule().tools.find(
      (t) => t.name === "prompt-armor:analyze",
    )!;
    const result = await analyze.execute({ focus: "system-prompt" }, createCtx());
    expect(result.ok).toBe(true);
    const [args] = runtimeQueryMock.mock.calls[0];
    expect(args.prompt).toContain("/analyze");
    expect(args.prompt).toContain("focus: system-prompt");
  });

  it("prompt-armor:attack also requires authorization", async () => {
    const attack = createCorePromptArmorModule().tools.find(
      (t) => t.name === "prompt-armor:attack",
    )!;
    const result = await attack.execute({ attack: "dan" }, createCtx());
    expect(result.ok).toBe(false);
    expect(result.output).toContain("authorized: true");
  });

  it("returns a graceful error when the plugin is not installed", async () => {
    resolvePromptArmorPluginPathMock.mockImplementationOnce(() => {
      throw new Error("missing plugin/.claude-plugin");
    });
    const report = createCorePromptArmorModule().tools.find(
      (t) => t.name === "prompt-armor:report",
    )!;
    const result = await report.execute({}, createCtx());
    expect(result.ok).toBe(false);
    expect(result.output).toContain("promptarmor-plugin not resolvable");
    expect(runtimeQueryMock).not.toHaveBeenCalled();
  });
});
