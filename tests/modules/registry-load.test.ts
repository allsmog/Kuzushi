import { describe, expect, it } from "vitest";
import { ModuleEventBus } from "../../src/bus/module-events.js";
import { ModuleLoadError } from "../../src/modules/errors.js";
import { ModuleRegistry } from "../../src/modules/registry.js";
import type { CopilotModule, ModuleContext, ModuleManifest } from "../../src/modules/types.js";

function makeCtx(bus: ModuleEventBus): ModuleContext {
  return {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    runtime: {} as any,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    bus: {} as any,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    config: {} as any,
    dataDir: "/tmp",
    events: bus.scope("test"),
  };
}

function makeModule(id: string, init?: CopilotModule["init"]): CopilotModule {
  const mod: CopilotModule = {
    id,
    displayName: id,
    category: "offense",
    version: "0.0.1",
    description: "",
    tools: [],
  };
  if (init) {
    (mod as { init?: CopilotModule["init"] }).init = init;
  }
  return mod;
}

describe("ModuleRegistry config schema enforcement (SCHEMA-3)", () => {
  it("accepts a valid moduleConfig against configSchema", async () => {
    const reg = new ModuleRegistry();
    const bus = new ModuleEventBus();
    const mod = makeModule("x");
    const manifest: ModuleManifest = {
      id: "x",
      displayName: "X",
      version: "1.0.0",
      entry: "./x.js",
      category: "offense",
      description: "",
      configSchema: {
        type: "object",
        properties: { apiKey: { type: "string" } },
        required: ["apiKey"],
      },
    };
    await expect(
      reg.loadModule(mod, makeCtx(bus), {
        manifest,
        moduleConfig: { apiKey: "secret" },
      }),
    ).resolves.toBeUndefined();
    expect(reg.has("x")).toBe(true);
  });

  it("rejects a moduleConfig that violates configSchema", async () => {
    const reg = new ModuleRegistry();
    const bus = new ModuleEventBus();
    const mod = makeModule("y");
    const manifest: ModuleManifest = {
      id: "y",
      displayName: "Y",
      version: "1.0.0",
      entry: "./y.js",
      category: "offense",
      description: "",
      configSchema: {
        type: "object",
        required: ["apiKey"],
      },
    };
    try {
      await reg.loadModule(mod, makeCtx(bus), {
        manifest,
        moduleConfig: {},
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(ModuleLoadError);
      expect((err as ModuleLoadError).code).toBe("CONFIG_INVALID");
    }
    // Rollback semantics — the failed load should leave no trace.
    expect(reg.has("y")).toBe(false);
  });

  it("skips validation when manifest has no configSchema", async () => {
    const reg = new ModuleRegistry();
    const bus = new ModuleEventBus();
    const mod = makeModule("z");
    const manifest: ModuleManifest = {
      id: "z",
      displayName: "Z",
      version: "1.0.0",
      entry: "./z.js",
      category: "offense",
      description: "",
    };
    await expect(
      reg.loadModule(mod, makeCtx(bus), {
        manifest,
        moduleConfig: { foo: "bar" },
      }),
    ).resolves.toBeUndefined();
  });

  it("preserves ModuleLoadError codes through init-failure rollback", async () => {
    const reg = new ModuleRegistry();
    const bus = new ModuleEventBus();
    const mod = makeModule("w", async () => {
      throw new ModuleLoadError("SDK_INCOMPATIBLE", "nope");
    });
    try {
      await reg.loadModule(mod, makeCtx(bus));
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(ModuleLoadError);
      expect((err as ModuleLoadError).code).toBe("SDK_INCOMPATIBLE");
    }
    expect(reg.has("w")).toBe(false);
  });
});
