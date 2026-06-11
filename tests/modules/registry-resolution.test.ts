import { describe, expect, it } from "vitest";
import { DagRegistry } from "../../src/modules/dag-registry.js";
import { parseModuleSpecifier, validateConfigAgainstSchema } from "../../src/modules/registry.js";
import type { OutputKind } from "../../src/modules/types.js";

// A minimal hidden DAG node. `DagRegistry.register` accepts the `DagNodeImpl`
// shape (id/dependsOn/run) directly, so tests don't need a full DagTool.
function node(id: string, dependsOn: string[] = []) {
  return {
    id,
    displayName: id,
    outputKind: "report" as OutputKind,
    dependsOn,
    async run() {
      return {};
    },
  };
}

function registryOf(...nodes: ReturnType<typeof node>[]): DagRegistry {
  const registry = new DagRegistry();
  for (const n of nodes) registry.register(n);
  return registry;
}

describe("parseModuleSpecifier", () => {
  it("parses each explicit scheme", () => {
    expect(parseModuleSpecifier("builtin:core-sast")).toEqual({
      type: "builtin",
      id: "core-sast",
    });
    expect(parseModuleSpecifier("file:///abs/path/index.js")).toEqual({
      type: "local",
      path: "/abs/path/index.js",
    });
    expect(parseModuleSpecifier("package:@scope/mod")).toEqual({
      type: "package",
      name: "@scope/mod",
    });
    expect(parseModuleSpecifier("mcp:http://localhost:3000")).toEqual({
      type: "mcp",
      serverUrl: "http://localhost:3000",
    });
  });

  it("treats a bare string as a builtin id", () => {
    expect(parseModuleSpecifier("triage")).toEqual({ type: "builtin", id: "triage" });
  });

  it("does not confuse a bare id containing a colon with the mcp scheme", () => {
    // Only the exact "mcp:" prefix selects mcp; "semgrep:scan" stays builtin.
    expect(parseModuleSpecifier("semgrep:scan")).toEqual({
      type: "builtin",
      id: "semgrep:scan",
    });
  });
});

describe("validateConfigAgainstSchema", () => {
  const schema = {
    type: "object",
    required: ["token"],
    properties: {
      token: { type: "string" },
      retries: { type: "integer" },
      mode: { type: "string", enum: ["fast", "deep"] },
    },
  };

  it("accepts a config that satisfies the schema", () => {
    expect(
      validateConfigAgainstSchema({ token: "abc", retries: 3, mode: "deep" }, schema),
    ).toBeNull();
  });

  it("rejects non-object configs", () => {
    expect(validateConfigAgainstSchema(null, schema)).toMatch(/plain object/);
    expect(validateConfigAgainstSchema(["a"], schema)).toMatch(/plain object/);
    expect(validateConfigAgainstSchema("nope", schema)).toMatch(/plain object/);
  });

  it("reports a missing required field", () => {
    expect(validateConfigAgainstSchema({ retries: 1 }, schema)).toMatch(
      /missing required config field "token"/,
    );
  });

  it("reports a type mismatch with the offending field", () => {
    expect(validateConfigAgainstSchema({ token: 42 }, schema)).toMatch(
      /config field "token" expected type string, got integer/,
    );
  });

  it("accepts an integer where the schema asks for number", () => {
    const numberSchema = { properties: { n: { type: "number" } } };
    expect(validateConfigAgainstSchema({ n: 7 }, numberSchema)).toBeNull();
  });

  it("enforces enum membership", () => {
    expect(validateConfigAgainstSchema({ token: "x", mode: "slow" }, schema)).toMatch(
      /config field "mode" must be one of fast\|deep/,
    );
  });

  it("ignores absent optional properties", () => {
    expect(validateConfigAgainstSchema({ token: "x" }, schema)).toBeNull();
  });

  it("rejects a non-object schema type", () => {
    expect(validateConfigAgainstSchema({}, { type: "array" })).toMatch(
      /configSchema.type "array" is unsupported/,
    );
  });
});

describe("DagRegistry.resolveOrder", () => {
  it("returns empty for an empty enabled set", () => {
    expect(registryOf(node("a:run")).resolveOrder([])).toEqual([]);
  });

  it("orders a linear dependency chain into single-node groups", () => {
    const registry = registryOf(node("a:run"), node("b:run", ["a:run"]), node("c:run", ["b:run"]));
    expect(registry.resolveOrder(["c:run", "b:run", "a:run"])).toEqual([
      ["a:run"],
      ["b:run"],
      ["c:run"],
    ]);
  });

  it("groups independent nodes into one parallel wave, preserving enabled priority", () => {
    const registry = registryOf(node("a:run"), node("b:run"), node("c:run", ["a:run", "b:run"]));
    // Enabled order is the tie-break within a wave: b before a.
    expect(registry.resolveOrder(["b:run", "a:run", "c:run"])).toEqual([
      ["b:run", "a:run"],
      ["c:run"],
    ]);
  });

  it("detects a dependency cycle", () => {
    const registry = registryOf(node("a:run", ["b:run"]), node("b:run", ["a:run"]));
    expect(() => registry.resolveOrder(["a:run", "b:run"])).toThrow(/cycle detected/);
  });

  it("rejects an enabled node whose dependency is not enabled", () => {
    const registry = registryOf(node("a:run"), node("b:run", ["a:run"]));
    expect(() => registry.resolveOrder(["b:run"])).toThrow(
      /depends on "a:run" but it is not enabled/,
    );
  });

  it("rejects an unknown enabled node", () => {
    expect(() => registryOf(node("a:run")).resolveOrder(["ghost:run"])).toThrow(
      /Unknown enabled DAG tool: ghost:run/,
    );
  });
});

describe("DagRegistry.validate", () => {
  it("passes when every dependency is registered", () => {
    expect(() => registryOf(node("a:run"), node("b:run", ["a:run"])).validate()).not.toThrow();
  });

  it("flags a dependency on an unregistered tool", () => {
    expect(() => registryOf(node("b:run", ["a:run"])).validate()).toThrow(
      /depends on unknown DAG tool "a:run"/,
    );
  });
});
