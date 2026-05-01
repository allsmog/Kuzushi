import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CopilotCore } from "../../src/copilot/core.js";
import { defineModule, defineTool } from "../../src/modules/define.js";
import type {
  CopilotModule,
  ModuleContext,
  ModuleReadyContext,
  ToolResult,
} from "../../src/modules/types.js";
import { createMockBus, noopRuntime } from "../../src/testing/index.js";
import type { KuzushiConfig } from "../../src/types.js";

const tempDirs: string[] = [];
afterEach(() => {
  while (tempDirs.length > 0) rmSync(tempDirs.pop()!, { recursive: true, force: true });
});

function mkConfig(): KuzushiConfig {
  return {
    model: "anthropic:claude-sonnet-4-6",
    busBackend: "in-process",
    triageBatchSize: 5,
    triageConcurrency: 2,
    scanMode: "concurrent",
    tasks: [],
    severity: ["ERROR"],
    excludePatterns: [],
    taskConfig: {},
  } as unknown as KuzushiConfig;
}

function mkDataDir(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-ready-"));
  tempDirs.push(dir);
  return dir;
}

function buildPing(id: string): CopilotModule {
  return defineModule({
    id,
    displayName: id,
    category: "offense",
    version: "0.0.1",
    description: `${id} test module`,
    tools: [
      defineTool<typeof id extends infer S extends string ? S : string>({
        name: `${id}:ping`,
        description: "ping",
        inputSchema: { type: "object" },
        headless: true,
        async execute(): Promise<ToolResult> {
          return { ok: true, output: "pong" };
        },
      }) as never,
    ],
  });
}

describe("CopilotModule.ready lifecycle hook", () => {
  it("runs after init for every module in the load batch", async () => {
    const order: string[] = [];
    const peerSeenBy: Record<string, string[]> = {};

    const a: CopilotModule = {
      ...buildPing("mod-a"),
      async init(_c: Record<string, unknown>, _ctx: ModuleContext) {
        order.push("a:init");
      },
      async ready(ctx: ModuleReadyContext) {
        order.push("a:ready");
        peerSeenBy["mod-a"] = ctx.peers.map((p) => p.id);
      },
    };
    const b: CopilotModule = {
      ...buildPing("mod-b"),
      async init(_c: Record<string, unknown>, _ctx: ModuleContext) {
        order.push("b:init");
      },
      async ready(ctx: ModuleReadyContext) {
        order.push("b:ready");
        peerSeenBy["mod-b"] = ctx.peers.map((p) => p.id);
      },
    };

    const core = new CopilotCore({
      runtime: noopRuntime,
      bus: createMockBus(),
      config: mkConfig(),
      dataDir: mkDataDir(),
      loadCoreSast: false,
    });
    // Drive ready explicitly via the same private path the host uses on init.
    await core.registry.loadModule(a, {
      runtime: noopRuntime,
      bus: createMockBus(),
      config: mkConfig(),
      dataDir: "/tmp",
    } as ModuleContext);
    await core.registry.loadModule(b, {
      runtime: noopRuntime,
      bus: createMockBus(),
      config: mkConfig(),
      dataDir: "/tmp",
    } as ModuleContext);
    // The above already ran each module's init+ready? No — registry.loadModule
    // doesn't call ready (it's a CopilotCore-level hook). Drive ready
    // explicitly via the same private path the host uses on init.
    await (core as unknown as { runReadyHooks(): Promise<void> }).runReadyHooks();

    expect(order).toEqual(["a:init", "b:init", "a:ready", "b:ready"]);
    expect(peerSeenBy["mod-a"]).toEqual(["mod-b"]);
    expect(peerSeenBy["mod-b"]).toEqual(["mod-a"]);
  });

  it("swallows errors thrown from ready (init is the rollback boundary)", async () => {
    const a: CopilotModule = {
      ...buildPing("err-mod"),
      async ready() {
        throw new Error("boom");
      },
    };

    const core = new CopilotCore({
      runtime: noopRuntime,
      bus: createMockBus(),
      config: mkConfig(),
      dataDir: mkDataDir(),
      loadCoreSast: false,
    });
    await core.registry.loadModule(a, {
      runtime: noopRuntime,
      bus: createMockBus(),
      config: mkConfig(),
      dataDir: "/tmp",
    } as ModuleContext);

    // Should not throw.
    await expect(
      (core as unknown as { runReadyHooks(): Promise<void> }).runReadyHooks(),
    ).resolves.toBeUndefined();
  });

  it("modules without ready are skipped silently", async () => {
    const a = buildPing("plain-mod"); // no ready hook
    const core = new CopilotCore({
      runtime: noopRuntime,
      bus: createMockBus(),
      config: mkConfig(),
      dataDir: mkDataDir(),
      loadCoreSast: false,
    });
    await core.registry.loadModule(a, {
      runtime: noopRuntime,
      bus: createMockBus(),
      config: mkConfig(),
      dataDir: "/tmp",
    } as ModuleContext);
    await expect(
      (core as unknown as { runReadyHooks(): Promise<void> }).runReadyHooks(),
    ).resolves.toBeUndefined();
  });

  it("ctx.peers excludes the module itself", async () => {
    let observed: string[] = [];
    const a: CopilotModule = {
      ...buildPing("self-mod"),
      async ready(ctx: ModuleReadyContext) {
        observed = ctx.peers.map((p) => p.id);
      },
    };
    const core = new CopilotCore({
      runtime: noopRuntime,
      bus: createMockBus(),
      config: mkConfig(),
      dataDir: mkDataDir(),
      loadCoreSast: false,
    });
    await core.registry.loadModule(a, {
      runtime: noopRuntime,
      bus: createMockBus(),
      config: mkConfig(),
      dataDir: "/tmp",
    } as ModuleContext);
    await (core as unknown as { runReadyHooks(): Promise<void> }).runReadyHooks();
    expect(observed).not.toContain("self-mod");
  });

  it("ctx.peers includes id, displayName, category, version", async () => {
    let snapshot: ReadonlyArray<{
      id: string;
      displayName: string;
      category: string;
      version: string;
    }> = [];
    const a: CopilotModule = {
      ...buildPing("watcher"),
      async ready(ctx: ModuleReadyContext) {
        snapshot = [...ctx.peers];
      },
    };
    const b = buildPing("subject");
    const core = new CopilotCore({
      runtime: noopRuntime,
      bus: createMockBus(),
      config: mkConfig(),
      dataDir: mkDataDir(),
      loadCoreSast: false,
    });
    await core.registry.loadModule(b, {
      runtime: noopRuntime,
      bus: createMockBus(),
      config: mkConfig(),
      dataDir: "/tmp",
    } as ModuleContext);
    await core.registry.loadModule(a, {
      runtime: noopRuntime,
      bus: createMockBus(),
      config: mkConfig(),
      dataDir: "/tmp",
    } as ModuleContext);
    await (core as unknown as { runReadyHooks(): Promise<void> }).runReadyHooks();
    const subjectEntry = snapshot.find((p) => p.id === "subject");
    expect(subjectEntry).toBeDefined();
    expect(subjectEntry?.displayName).toBe("subject");
    expect(subjectEntry?.category).toBe("offense");
    expect(subjectEntry?.version).toBe("0.0.1");
  });
});

// Quiet vi import warning when no spies are used in this file.
void vi;
