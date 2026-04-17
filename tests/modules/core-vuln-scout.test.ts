import { beforeEach, describe, expect, it, vi } from "vitest";
import { createCoreVulnScoutModule } from "../../src/modules/core-vuln-scout.js";
import type { ToolExecutionContext } from "../../src/modules/types.js";
import type { KuzushiConfig } from "../../src/types.js";

const { resolveRepoMock, resolveVulnScoutPluginMock, runPluginFindingScannerMock } = vi.hoisted(
  () => ({
    resolveRepoMock: vi.fn(() => ({ root: "/tmp/repo", name: "repo" })),
    resolveVulnScoutPluginMock: vi.fn(() => ({ type: "local", path: "/plugin" })),
    runPluginFindingScannerMock: vi.fn(),
  }),
);

vi.mock("../../src/cli/shared.js", () => ({
  resolveRepo: resolveRepoMock,
}));

vi.mock("../../src/agents/tasks/vuln-scout/resolve-vuln-scout.js", () => ({
  resolveVulnScoutPlugin: resolveVulnScoutPluginMock,
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

function createCtx(overrides: Partial<ToolExecutionContext> = {}): ToolExecutionContext {
  return {
    cwd: "/tmp/repo",
    runtime: {} as ToolExecutionContext["runtime"],
    bus: {} as ToolExecutionContext["bus"],
    config: createConfig(),
    ...overrides,
  };
}

describe("core-vuln-scout module", () => {
  beforeEach(() => {
    runPluginFindingScannerMock.mockClear();
    resolveVulnScoutPluginMock.mockClear();
  });

  it("exposes the expected metadata and tools", () => {
    const mod = createCoreVulnScoutModule();
    expect(mod.id).toBe("vuln-scout");
    expect(mod.category).toBe("offense");
    expect(mod.tools.map((t) => t.name)).toEqual(["vuln-scout:audit"]);
    expect(mod.tools[0].headless).toBe(true);
  });

  it("returns a helpful error when the plugin is not installed", async () => {
    resolveVulnScoutPluginMock.mockImplementationOnce(() => {
      throw new Error("missing whitebox-pentest/.claude-plugin/plugin.json");
    });
    const [audit] = createCoreVulnScoutModule().tools;
    const result = await audit.execute({}, createCtx());
    expect(result.ok).toBe(false);
    expect(result.output).toContain("@kuzushi/vuln-scout is not installed");
    expect(result.output).toContain("missing whitebox-pentest");
    expect(runPluginFindingScannerMock).not.toHaveBeenCalled();
  });

  it("dispatches to the shared scanner and returns normalized output", async () => {
    runPluginFindingScannerMock.mockResolvedValueOnce({
      findings: [
        {
          taskId: "vuln-scout",
          fingerprint: "fp1",
          ruleId: "sqli/raw",
          filePath: "src/db.ts",
          startLine: 42,
          severity: "ERROR",
          message: "raw SQL",
          evidence: null,
          scannerConfidence: "HIGH",
          subcategory: ["vuln"],
          likelihood: "HIGH",
          impact: "HIGH",
          cwe: ["CWE-89"],
          score: 90,
        },
      ],
      costUsd: 0.12,
    });

    const [audit] = createCoreVulnScoutModule().tools;
    const result = await audit.execute(
      { target: "/some/repo", maxFindings: 10, model: "anthropic:claude-opus-4-7" },
      createCtx(),
    );

    expect(result.ok).toBe(true);
    expect(result.costUsd).toBeCloseTo(0.12);
    expect(result.output).toContain("vuln-scout:audit complete");
    expect(result.output).toContain("src/db.ts:42");
    const data = result.data as { findings: unknown[] };
    expect(data.findings).toHaveLength(1);

    const call = runPluginFindingScannerMock.mock.calls[0][0];
    expect(call.scannerId).toBe("vuln-scout");
    expect(call.model).toBe("anthropic:claude-opus-4-7");
    expect(call.maxFindings).toBe(10);
    expect(call.plugins).toEqual([{ type: "local", path: "/plugin" }]);
  });

  it("wraps runner errors as ToolResult instead of throwing", async () => {
    runPluginFindingScannerMock.mockRejectedValueOnce(new Error("boom"));
    const [audit] = createCoreVulnScoutModule().tools;
    const result = await audit.execute({}, createCtx());
    expect(result.ok).toBe(false);
    expect(result.output).toContain("vuln-scout:audit error: boom");
  });
});
