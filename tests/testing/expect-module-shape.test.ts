import { describe, expect, it } from "vitest";
import { defineModule, defineTool } from "../../src/modules/define.js";
import { expectModuleShape, ModuleShapeError } from "../../src/testing/index.js";

const okTool = () =>
  defineTool<"foo">({
    name: "foo:ping",
    description: "x",
    inputSchema: {},
    headless: true,
    async execute() {
      return { ok: true, output: "pong" };
    },
  });

describe("expectModuleShape", () => {
  it("accepts a well-formed CopilotModule", () => {
    const mod = defineModule({
      id: "foo",
      displayName: "Foo",
      version: "0.0.1",
      description: "x",
      category: "offense",
      tools: [okTool()],
    });
    expect(() => expectModuleShape(mod)).not.toThrow();
  });

  it("rejects missing required fields with issues list", () => {
    let caught: ModuleShapeError | undefined;
    try {
      expectModuleShape({ id: "foo", tools: [] });
    } catch (err) {
      if (err instanceof ModuleShapeError) caught = err;
    }
    expect(caught).toBeInstanceOf(ModuleShapeError);
    expect(caught?.issues.length).toBeGreaterThan(0);
    expect(caught?.issues.some((i) => /displayName/.test(i))).toBe(true);
  });

  it("rejects tool names that don't start with the module id", () => {
    const mod = {
      id: "foo",
      displayName: "Foo",
      version: "0.0.1",
      description: "x",
      category: "offense" as const,
      tools: [
        {
          name: "sast:scan", // wrong prefix for id="foo"
          description: "",
          inputSchema: {},
          headless: true,
          async execute() {
            return { ok: true, output: "" };
          },
        },
      ],
    };
    let caught: ModuleShapeError | undefined;
    try {
      expectModuleShape(mod);
    } catch (err) {
      if (err instanceof ModuleShapeError) caught = err;
    }
    expect(caught).toBeInstanceOf(ModuleShapeError);
    expect(caught?.issues.some((i) => i.includes('must start with "foo:"'))).toBe(true);
  });

  it("rejects duplicate tool names within a module", () => {
    const mod = {
      id: "foo",
      displayName: "Foo",
      version: "0.0.1",
      description: "x",
      category: "offense" as const,
      tools: [
        {
          name: "foo:ping",
          description: "",
          inputSchema: {},
          headless: true,
          async execute() {
            return { ok: true, output: "" };
          },
        },
        {
          name: "foo:ping", // duplicate
          description: "",
          inputSchema: {},
          headless: true,
          async execute() {
            return { ok: true, output: "" };
          },
        },
      ],
    };
    let caught: ModuleShapeError | undefined;
    try {
      expectModuleShape(mod);
    } catch (err) {
      if (err instanceof ModuleShapeError) caught = err;
    }
    expect(caught).toBeInstanceOf(ModuleShapeError);
    expect(caught?.issues.some((i) => /duplicate tool name/.test(i))).toBe(true);
  });

  it("rejects non-object inputs", () => {
    expect(() => expectModuleShape(null)).toThrowError(ModuleShapeError);
    expect(() => expectModuleShape("not a module")).toThrowError(ModuleShapeError);
  });

  it("narrows the type after the assertion passes", () => {
    const raw: unknown = defineModule({
      id: "foo",
      displayName: "Foo",
      version: "0.0.1",
      description: "x",
      category: "offense",
      tools: [okTool()],
    });
    expectModuleShape(raw);
    // Type narrowed to CopilotModule — accessing .id is well-typed.
    expect(raw.id).toBe("foo");
  });
});
