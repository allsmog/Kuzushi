import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AgentRuntime } from "../../src/agent-runtime/types.js";
import type { MessageBus } from "../../src/bus/types.js";
import { CopilotCore } from "../../src/copilot/core.js";
import { AuditTrail } from "../../src/governance/audit.js";
import { GovernanceEnforcer } from "../../src/governance/enforcer.js";
import { defaultScopePolicy } from "../../src/governance/types.js";
import type { CopilotModule, ModuleTool, ToolResult } from "../../src/modules/types.js";
import type { KuzushiConfig } from "../../src/types.js";

function tool(name: string, impl: () => Promise<ToolResult> | ToolResult): ModuleTool {
  return {
    name,
    description: `fake ${name}`,
    inputSchema: { type: "object" },
    headless: true,
    async execute() {
      return impl();
    },
  };
}

function module(id: string, tools: ModuleTool[]): CopilotModule {
  return {
    id,
    displayName: id,
    category: "offense",
    version: "0.0.1",
    description: id,
    tools,
  };
}

function fakeConfig(): KuzushiConfig {
  return {
    model: "anthropic:claude-sonnet-4-6",
    busBackend: "in-process",
    triageBatchSize: 1,
    triageConcurrency: 1,
    scanMode: "parallel",
    tasks: [],
    severity: ["ERROR"],
    excludePatterns: [],
    taskConfig: {},
  } as KuzushiConfig;
}

const fakeRuntime = {} as AgentRuntime;
const fakeBus = {
  subscribe: () => {},
  emit: async () => {},
  close: async () => {},
} as unknown as MessageBus;

let tmp: string;
beforeEach(() => {
  tmp = mkdtempSync(path.join(tmpdir(), "kuzushi-core-"));
});
afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

describe("CopilotCore.executeTool", () => {
  it("returns a graceful error for unknown tools", async () => {
    const core = new CopilotCore({
      runtime: fakeRuntime,
      bus: fakeBus,
      config: fakeConfig(),
      dataDir: tmp,
      loadCoreSast: false,
    });
    await core.init();
    const result = await core.executeTool("no-such:tool", {});
    expect(result.ok).toBe(false);
    expect(result.output).toContain('Unknown tool: "no-such:tool"');
  });

  it("dispatches to the module's tool and passes through its result + cost", async () => {
    const core = new CopilotCore({
      runtime: fakeRuntime,
      bus: fakeBus,
      config: fakeConfig(),
      dataDir: tmp,
      loadCoreSast: false,
    });
    core.registry.register(
      module("demo", [
        tool("demo:add", () => ({ ok: true, output: "2+2=4", data: { x: 4 }, costUsd: 0.01 })),
      ]),
    );
    const result = await core.executeTool("demo:add", {});
    expect(result.ok).toBe(true);
    expect(result.output).toBe("2+2=4");
    expect(result.costUsd).toBe(0.01);
  });

  it("blocks execution when the governance enforcer denies", async () => {
    const enforcer = new GovernanceEnforcer({
      ...defaultScopePolicy(),
      deniedTargets: ["production-db"],
    });
    const auditTrail = new AuditTrail(tmp);
    const recordSpy = vi.spyOn(auditTrail, "record");

    const core = new CopilotCore({
      runtime: fakeRuntime,
      bus: fakeBus,
      config: fakeConfig(),
      dataDir: tmp,
      loadCoreSast: false,
      enforcer,
      auditTrail,
    });
    const executeSpy = vi.fn(() => Promise.resolve({ ok: true, output: "unreachable" }));
    core.registry.register(
      module("demo", [
        { ...tool("demo:scan", () => ({ ok: true, output: "x" })), execute: executeSpy },
      ]),
    );

    const result = await core.executeTool("demo:scan", { target: "production-db" });
    expect(result.ok).toBe(false);
    expect(result.output).toContain("Blocked by governance");
    expect(executeSpy).not.toHaveBeenCalled();
    expect(recordSpy).toHaveBeenCalled();
  });

  it("records audit + propagates cost to the enforcer on success", async () => {
    const enforcer = new GovernanceEnforcer(defaultScopePolicy());
    const auditTrail = new AuditTrail(tmp);
    const recordSpy = vi.spyOn(auditTrail, "record");

    const core = new CopilotCore({
      runtime: fakeRuntime,
      bus: fakeBus,
      config: fakeConfig(),
      dataDir: tmp,
      loadCoreSast: false,
      enforcer,
      auditTrail,
    });
    core.registry.register(
      module("demo", [tool("demo:run", () => ({ ok: true, output: "x", costUsd: 0.25 }))]),
    );
    await core.executeTool("demo:run", {});

    expect(enforcer.getCumulativeCost()).toBeCloseTo(0.25);
    expect(recordSpy).toHaveBeenCalledTimes(1);
  });
});
