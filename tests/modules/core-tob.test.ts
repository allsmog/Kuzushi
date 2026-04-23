import { beforeEach, describe, expect, it, vi } from "vitest";
import { createCoreTobModule } from "../../src/modules/tob/tob.js";
import type { ToolExecutionContext } from "../../src/modules/types.js";
import type { KuzushiConfig } from "../../src/types.js";

const {
  resolveRepoMock,
  resolveTobPluginsMock,
  runPluginFindingScannerMock,
  SECURITY_PLUGINS_MOCK,
} = vi.hoisted(() => ({
  resolveRepoMock: vi.fn(() => ({ root: "/tmp/repo", name: "repo" })),
  resolveTobPluginsMock: vi.fn(() => [
    { type: "local", path: "/tob/plugins/fp-check" },
    { type: "local", path: "/tob/plugins/sharp-edges" },
    { type: "local", path: "/tob/plugins/insecure-defaults" },
  ]),
  runPluginFindingScannerMock: vi.fn(),
  SECURITY_PLUGINS_MOCK: [
    "fp-check",
    "sharp-edges",
    "insecure-defaults",
    "variant-analysis",
    "static-analysis",
  ],
}));

vi.mock("../../src/cli/shared.js", () => ({
  resolveRepo: resolveRepoMock,
}));

vi.mock("../../src/agents/tasks/tob-audit/resolve-tob-plugin.js", () => ({
  resolveTobPlugins: resolveTobPluginsMock,
  SECURITY_PLUGINS: SECURITY_PLUGINS_MOCK,
}));

vi.mock("../../src/agents/tasks/plugin-finding-scanner.js", () => ({
  runPluginFindingScanner: runPluginFindingScannerMock,
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

function createCtx(): ToolExecutionContext {
  return {
    cwd: "/tmp/repo",
    runtime: {} as ToolExecutionContext["runtime"],
    bus: {} as ToolExecutionContext["bus"],
    config: createConfig(),
  };
}

describe("core-tob module", () => {
  beforeEach(() => {
    runPluginFindingScannerMock.mockClear();
    resolveTobPluginsMock.mockClear();
  });

  it("exposes the expected metadata and tools", () => {
    const mod = createCoreTobModule();
    expect(mod.id).toBe("tob");
    expect(mod.tools.map((t) => t.name).sort()).toEqual(["tob:audit", "tob:skills"]);
  });

  it("tob:skills lists resolvable plugins and declared-but-missing", async () => {
    const skills = createCoreTobModule().tools.find((t) => t.name === "tob:skills")!;
    const result = await skills.execute({}, createCtx());
    expect(result.ok).toBe(true);
    const data = result.data as {
      resolvable: Array<{ id: string }>;
      unresolved: string[];
      declared: string[];
    };
    expect(data.resolvable.map((r) => r.id).sort()).toEqual([
      "fp-check",
      "insecure-defaults",
      "sharp-edges",
    ]);
    expect(data.unresolved.sort()).toEqual(["static-analysis", "variant-analysis"]);
  });

  it("tob:audit filters by requested skills", async () => {
    runPluginFindingScannerMock.mockResolvedValueOnce({ findings: [], costUsd: 0 });

    const audit = createCoreTobModule().tools.find((t) => t.name === "tob:audit")!;
    const result = await audit.execute({ skills: ["sharp-edges"] }, createCtx());
    expect(result.ok).toBe(true);
    const call = runPluginFindingScannerMock.mock.calls[0][0];
    expect(call.plugins).toEqual([{ type: "local", path: "/tob/plugins/sharp-edges" }]);
  });

  it("tob:audit rejects unknown skill names", async () => {
    const audit = createCoreTobModule().tools.find((t) => t.name === "tob:audit")!;
    const result = await audit.execute({ skills: ["not-a-real-skill"] }, createCtx());
    expect(result.ok).toBe(false);
    expect(result.output).toContain("unknown skill(s): not-a-real-skill");
    expect(runPluginFindingScannerMock).not.toHaveBeenCalled();
  });

  it("tob:audit returns graceful error when plugins cannot be resolved", async () => {
    resolveTobPluginsMock.mockImplementationOnce(() => {
      throw new Error("plugin dir missing");
    });
    const audit = createCoreTobModule().tools.find((t) => t.name === "tob:audit")!;
    const result = await audit.execute({}, createCtx());
    expect(result.ok).toBe(false);
    expect(result.output).toContain("@kuzushi/tob-skills is not installed");
  });
});
