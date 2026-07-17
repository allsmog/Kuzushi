import { describe, expect, expectTypeOf, it } from "vitest";
import { PatchResultSchema } from "../../src/index.js";
import type { KwpExecutionContext, KwpRuntimeHandle } from "../../src/modules/index.js";
import * as moduleSdk from "../../src/modules/index.js";
// Import exactly through the public-surface barrel to assert that the
// `kuzushi/modules` re-exports are wired. Everything asserted here must
// remain stable across minor releases (see docs/devex/06-module-sdk-assessment.md §6).
import {
  createCoreSastModule,
  defineModule,
  defineTool,
  ModuleLoadError,
  ModuleRegistry,
  parseModuleSpecifier,
} from "../../src/modules/index.js";

describe("kuzushi/modules public barrel", () => {
  it("re-exports defineModule / defineTool", () => {
    expect(typeof defineModule).toBe("function");
    expect(typeof defineTool).toBe("function");
  });

  it("re-exports ModuleLoadError as a constructor", () => {
    const err = new ModuleLoadError("SHAPE_INVALID", "x");
    expect(err).toBeInstanceOf(Error);
    expect(err.code).toBe("SHAPE_INVALID");
  });

  it("re-exports ModuleRegistry", () => {
    const reg = new ModuleRegistry();
    expect(reg.ids()).toEqual([]);
  });

  it("re-exports parseModuleSpecifier", () => {
    expect(parseModuleSpecifier("builtin:sast")).toEqual({ type: "builtin", id: "sast" });
    expect(parseModuleSpecifier("package:@kuzushi/x")).toEqual({
      type: "package",
      name: "@kuzushi/x",
    });
  });

  it("keeps KWP process ownership in the native host", () => {
    expect(moduleSdk).not.toHaveProperty("runWorker");
    expect(moduleSdk).not.toHaveProperty("KwpWorkerHarness");
    expectTypeOf<KwpExecutionContext["runtime"]>().toEqualTypeOf<KwpRuntimeHandle>();
  });

  it("keeps retired built-in factory symbols as migration stubs", () => {
    expect(typeof createCoreSastModule).toBe("function");
    expect(() => createCoreSastModule()).toThrow(/retired from the public SDK/);
  });

  it("preserves unresolved patch spend in the public PatchResult schema", () => {
    const result = PatchResultSchema.parse({
      patchRunId: "patch-1",
      fingerprint: "fp-1",
      repo: "/repo",
      diff: null,
      status: "UNKNOWN",
      iterations: 1,
      costUsd: 0.25,
      providerSpendUnresolved: true,
      history: [],
    });

    expect(result.costUsd).toBe(0.25);
    expect(result.providerSpendUnresolved).toBe(true);
    expect(
      PatchResultSchema.safeParse({ ...result, costUsd: Number.POSITIVE_INFINITY }).success,
    ).toBe(false);
  });
});
