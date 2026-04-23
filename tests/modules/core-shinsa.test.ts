import { beforeEach, describe, expect, it, vi } from "vitest";
import { createCoreShinsaModule } from "../../src/modules/shinsa/shinsa.js";
import type { ToolExecutionContext } from "../../src/modules/types.js";
import type { KuzushiConfig } from "../../src/types.js";

const {
  resolveRepoMock,
  resolveShinsaPluginPathMock,
  runtimeQueryMock,
  readdirSyncMock,
  existsSyncMock,
} = vi.hoisted(() => ({
  resolveRepoMock: vi.fn(() => ({ root: "/tmp/repo", name: "repo" })),
  resolveShinsaPluginPathMock: vi.fn(() => "/plugins/shinsa"),
  runtimeQueryMock: vi.fn(),
  readdirSyncMock: vi.fn(() => [
    { name: "iso-27001-annex-a", isDirectory: () => true },
    { name: "nist-800-53", isDirectory: () => true },
    { name: "control-mapping", isDirectory: () => true },
  ]),
  existsSyncMock: vi.fn(() => true),
}));

vi.mock("../../src/cli/shared.js", () => ({
  resolveRepo: resolveRepoMock,
}));

vi.mock("../../src/agents/tasks/shinsa/resolve-shinsa-plugin.js", () => ({
  resolveShinsaPluginPath: resolveShinsaPluginPathMock,
}));

vi.mock("node:fs", async () => {
  const actual = await vi.importActual<typeof import("node:fs")>("node:fs");
  return {
    ...actual,
    existsSync: existsSyncMock,
    readdirSync: readdirSyncMock,
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

describe("core-shinsa module", () => {
  beforeEach(() => {
    runtimeQueryMock.mockReset();
    resolveShinsaPluginPathMock.mockClear();
    existsSyncMock.mockClear();
    existsSyncMock.mockReturnValue(true);
  });

  it("exposes the expected metadata and tools", () => {
    const mod = createCoreShinsaModule();
    expect(mod.id).toBe("shinsa");
    expect(mod.category).toBe("governance");
    expect(mod.tools.map((t) => t.name).sort()).toEqual([
      "shinsa:frameworks",
      "shinsa:nist-quick-check",
      "shinsa:nist-scan",
      "shinsa:quick-check",
      "shinsa:scan",
    ]);
    for (const tool of mod.tools) expect(tool.headless).toBe(true);
  });

  it("returns graceful error when the plugin is not installed", async () => {
    resolveShinsaPluginPathMock.mockImplementationOnce(() => {
      throw new Error("missing .claude-plugin");
    });
    const scan = createCoreShinsaModule().tools.find((t) => t.name === "shinsa:scan")!;
    const result = await scan.execute({}, createCtx());
    expect(result.ok).toBe(false);
    expect(result.output).toContain("shinsa-plugin not resolvable");
    expect(runtimeQueryMock).not.toHaveBeenCalled();
  });

  it("shinsa:scan dispatches to the runtime with the plugin loaded", async () => {
    await mockQueryResult(0.42);
    const scan = createCoreShinsaModule().tools.find((t) => t.name === "shinsa:scan")!;
    const result = await scan.execute({ target: "/some/repo" }, createCtx());

    expect(result.ok).toBe(true);
    expect(result.costUsd).toBeCloseTo(0.42);
    expect(runtimeQueryMock).toHaveBeenCalledTimes(1);
    const [args] = runtimeQueryMock.mock.calls[0];
    expect(args.options.plugins).toEqual([{ type: "local", path: "/plugins/shinsa" }]);
    expect(args.prompt).toContain("/compliance-scan");
  });

  it("shinsa:nist-scan invokes the nist-scan command", async () => {
    await mockQueryResult(0.1);
    const nist = createCoreShinsaModule().tools.find((t) => t.name === "shinsa:nist-scan")!;
    await nist.execute({}, createCtx());
    const [args] = runtimeQueryMock.mock.calls[0];
    expect(args.prompt).toContain("/nist-scan");
    expect(args.prompt).toContain("NIST SP 800-53");
  });

  it("shinsa:frameworks lists the plugin's skills directory", async () => {
    const frameworks = createCoreShinsaModule().tools.find((t) => t.name === "shinsa:frameworks")!;
    const result = await frameworks.execute({}, createCtx());
    expect(result.ok).toBe(true);
    const data = result.data as { skills: string[] };
    expect(data.skills).toEqual(["control-mapping", "iso-27001-annex-a", "nist-800-53"]);
    expect(runtimeQueryMock).not.toHaveBeenCalled();
  });

  it("scan tools propagate control / family / severity filters into the prompt", async () => {
    await mockQueryResult(0.05);
    const scan = createCoreShinsaModule().tools.find((t) => t.name === "shinsa:scan")!;
    await scan.execute(
      {
        controls: ["A.8.5", "A.8.24"],
        family: "A.8",
        severity: ["critical", "high"],
      },
      createCtx(),
    );
    const [args] = runtimeQueryMock.mock.calls[0];
    expect(args.prompt).toContain("A.8.5, A.8.24");
    expect(args.prompt).toContain("control family: A.8");
    expect(args.prompt).toContain("critical, high");
  });
});
