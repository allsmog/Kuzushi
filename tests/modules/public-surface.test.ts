import { describe, expect, it } from "vitest";
// Import exactly through the public-surface barrel to assert that the
// `kuzushi/modules` re-exports are wired. Everything asserted here must
// remain stable across minor releases (see docs/devex/06-module-sdk-assessment.md §6).
import {
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
});
