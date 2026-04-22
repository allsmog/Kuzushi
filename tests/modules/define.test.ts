import { describe, expect, it } from "vitest";
import { defineModule, defineTool } from "../../src/modules/define.js";
import { ModuleLoadError } from "../../src/modules/errors.js";

describe("defineTool", () => {
  it("returns its input unchanged (identity helper)", () => {
    const tool = defineTool<"foo">({
      name: "foo:ping",
      description: "x",
      inputSchema: {},
      headless: true,
      async execute() {
        return { ok: true, output: "pong" };
      },
    });
    expect(tool.name).toBe("foo:ping");
    expect(tool.headless).toBe(true);
  });
});

describe("defineModule", () => {
  it("assembles a valid CopilotModule", () => {
    const mod = defineModule({
      id: "foo",
      displayName: "Foo",
      version: "0.0.1",
      description: "x",
      category: "offense",
      tools: [
        defineTool<"foo">({
          name: "foo:ping",
          description: "",
          inputSchema: {},
          headless: true,
          async execute() {
            return { ok: true, output: "ok" };
          },
        }),
      ],
    });
    expect(mod.id).toBe("foo");
    expect(mod.tools).toHaveLength(1);
    expect(mod.tools[0]!.name).toBe("foo:ping");
  });

  it("throws ModuleLoadError{SHAPE_INVALID} when a tool prefix mismatches id", () => {
    expect(() =>
      defineModule({
        id: "foo",
        displayName: "Foo",
        version: "0.0.1",
        description: "x",
        category: "offense",
        tools: [
          // Cast escapes the compile-time check so we can test the runtime guard.
          {
            name: "bar:ping",
            description: "",
            inputSchema: {},
            headless: true,
            async execute() {
              return { ok: true, output: "" };
            },
          } as never,
        ],
      }),
    ).toThrow(ModuleLoadError);
  });

  it("reports the offending tool index in details", () => {
    try {
      defineModule({
        id: "foo",
        displayName: "Foo",
        version: "0.0.1",
        description: "x",
        category: "offense",
        tools: [
          defineTool<"foo">({
            name: "foo:ok",
            description: "",
            inputSchema: {},
            headless: true,
            async execute() {
              return { ok: true, output: "" };
            },
          }),
          {
            name: "wrong:ping",
            description: "",
            inputSchema: {},
            headless: true,
            async execute() {
              return { ok: true, output: "" };
            },
          } as never,
        ],
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(ModuleLoadError);
      const e = err as ModuleLoadError;
      expect(e.code).toBe("SHAPE_INVALID");
      expect(e.details?.["toolIndex"]).toBe(1);
    }
  });

  it("tolerates modules with zero tools", () => {
    const mod = defineModule({
      id: "empty",
      displayName: "Empty",
      version: "0.0.1",
      description: "",
      category: "intel",
      tools: [],
    });
    expect(mod.tools).toHaveLength(0);
  });
});
