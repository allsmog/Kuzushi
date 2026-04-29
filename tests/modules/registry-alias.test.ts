/**
 * Regression test for v0.21 followup M1 — module-id legacy alias layer.
 * The `threat-hunt` → `carlini-threat-hunt` rename must keep old ids
 * resolvable so taskConfig keys, `/use threat-hunt`, and persisted
 * resume metadata all continue to work.
 */

import { describe, expect, it } from "vitest";
import { defineModule } from "../../src/modules/define.js";
import { ModuleRegistry } from "../../src/modules/registry.js";
import type { CopilotModule } from "../../src/modules/types.js";

function makeModule(id: string, legacyIds?: string[]): CopilotModule {
  return defineModule({
    id,
    legacyIds,
    displayName: id,
    category: "offense",
    version: "0.0.0",
    description: `${id} module`,
    tools: [],
  });
}

describe("ModuleRegistry — module-id legacy aliases (M1)", () => {
  it("resolves a legacy id to the canonical module via has()/get()", () => {
    const registry = new ModuleRegistry();
    registry.register(makeModule("carlini-threat-hunt", ["threat-hunt"]));
    expect(registry.has("threat-hunt")).toBe(true);
    expect(registry.has("carlini-threat-hunt")).toBe(true);
    expect(registry.get("threat-hunt").id).toBe("carlini-threat-hunt");
  });

  it("resolveModuleId returns the canonical id for a legacy alias", () => {
    const registry = new ModuleRegistry();
    registry.register(makeModule("carlini-threat-hunt", ["threat-hunt"]));
    expect(registry.resolveModuleId("threat-hunt")).toBe("carlini-threat-hunt");
    expect(registry.resolveModuleId("carlini-threat-hunt")).toBe("carlini-threat-hunt");
  });

  it("returns the input unchanged when no alias is mapped", () => {
    const registry = new ModuleRegistry();
    registry.register(makeModule("sast"));
    expect(registry.resolveModuleId("sast")).toBe("sast");
    expect(registry.resolveModuleId("nonexistent")).toBe("nonexistent");
  });

  it("listModuleIdAliases reports the populated aliases", () => {
    const registry = new ModuleRegistry();
    registry.register(makeModule("carlini-threat-hunt", ["threat-hunt", "th"]));
    registry.register(makeModule("sast"));
    const aliases = registry.listModuleIdAliases();
    expect(aliases).toEqual(
      expect.arrayContaining([
        { from: "threat-hunt", to: "carlini-threat-hunt" },
        { from: "th", to: "carlini-threat-hunt" },
      ]),
    );
    expect(aliases).toHaveLength(2);
  });

  it("does NOT shadow a real module that owns the legacy id", () => {
    const registry = new ModuleRegistry();
    registry.register(makeModule("threat-hunt"));
    registry.register(makeModule("carlini-threat-hunt", ["threat-hunt"]));
    expect(registry.get("threat-hunt").id).toBe("threat-hunt");
    expect(registry.resolveModuleId("threat-hunt")).toBe("threat-hunt");
  });

  it("ignores empty / self-referential legacy ids", () => {
    const registry = new ModuleRegistry();
    registry.register(makeModule("carlini-threat-hunt", ["", "carlini-threat-hunt"]));
    expect(registry.listModuleIdAliases()).toEqual([]);
  });

  it("clears legacy aliases when the canonical module is unloaded", async () => {
    const registry = new ModuleRegistry();
    registry.register(makeModule("carlini-threat-hunt", ["threat-hunt"]));
    expect(registry.has("threat-hunt")).toBe(true);
    await registry.unloadModule("carlini-threat-hunt");
    expect(registry.has("threat-hunt")).toBe(false);
    expect(registry.has("carlini-threat-hunt")).toBe(false);
  });

  it("unloadModule accepts a legacy id and removes the canonical entry", async () => {
    const registry = new ModuleRegistry();
    registry.register(makeModule("carlini-threat-hunt", ["threat-hunt"]));
    await registry.unloadModule("threat-hunt");
    expect(registry.has("carlini-threat-hunt")).toBe(false);
    expect(registry.has("threat-hunt")).toBe(false);
  });
});
