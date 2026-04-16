import { describe, expect, it } from "vitest";
import {
  ALL_TOOLS,
  buildPolicyLayers,
  expandToolGroups,
  resolveToolPolicy,
  TOOL_GROUPS,
  type ToolPolicy,
  type ToolPolicyLayer,
} from "../../src/prompts/tool-policy.js";

describe("expandToolGroups", () => {
  it("expands group:readonly", () => {
    const expanded = expandToolGroups(["group:readonly"]);
    expect(expanded).toEqual(expect.arrayContaining(["Read", "Glob", "Grep"]));
    expect(expanded).toHaveLength(3);
  });

  it("expands group:analysis", () => {
    const expanded = expandToolGroups(["group:analysis"]);
    expect(expanded).toEqual(
      expect.arrayContaining(["GetCallers", "GetCallees", "GetFunctionBody"]),
    );
  });

  it("passes through non-group names", () => {
    const expanded = expandToolGroups(["Read", "Bash"]);
    expect(expanded).toEqual(["Read", "Bash"]);
  });

  it("deduplicates when mixing groups and individual tools", () => {
    const expanded = expandToolGroups(["group:readonly", "Read", "Bash"]);
    expect(expanded.filter((t) => t === "Read")).toHaveLength(1);
    expect(expanded).toContain("Bash");
  });

  it("ignores unknown groups", () => {
    const expanded = expandToolGroups(["group:unknown", "Read"]);
    expect(expanded).toEqual(["Read"]);
  });
});

describe("resolveToolPolicy", () => {
  it("returns all available tools with no layers", () => {
    const result = resolveToolPolicy(ALL_TOOLS, []);
    expect(result).toEqual(ALL_TOOLS);
  });

  it("filters to allowed tools", () => {
    const layers: ToolPolicyLayer[] = [{ name: "task", policy: { allow: ["Read", "Grep"] } }];
    const result = resolveToolPolicy(ALL_TOOLS, layers);
    expect(result).toEqual(["Read", "Grep"]);
  });

  it("removes denied tools", () => {
    const layers: ToolPolicyLayer[] = [{ name: "task", policy: { deny: ["Bash", "Write"] } }];
    const result = resolveToolPolicy(ALL_TOOLS, layers);
    expect(result).not.toContain("Bash");
    expect(result).not.toContain("Write");
    expect(result).toContain("Read");
  });

  it("deny always wins over allow", () => {
    const layers: ToolPolicyLayer[] = [
      { name: "task", policy: { allow: ["Read", "Bash"] } },
      { name: "config", policy: { deny: ["Bash"] } },
    ];
    const result = resolveToolPolicy(ALL_TOOLS, layers);
    expect(result).toContain("Read");
    expect(result).not.toContain("Bash");
  });

  it("deny in earlier layer blocks allow in later layer", () => {
    const layers: ToolPolicyLayer[] = [
      { name: "global", policy: { deny: ["Write"] } },
      { name: "task", policy: { allow: ["Write", "Read"] } },
    ];
    const result = resolveToolPolicy(ALL_TOOLS, layers);
    expect(result).not.toContain("Write");
  });

  it("supports group references in allow", () => {
    const layers: ToolPolicyLayer[] = [{ name: "task", policy: { allow: ["group:readonly"] } }];
    const result = resolveToolPolicy(ALL_TOOLS, layers);
    expect(result).toEqual(expect.arrayContaining(["Read", "Glob", "Grep"]));
    expect(result).not.toContain("Bash");
  });

  it("supports group references in deny", () => {
    const layers: ToolPolicyLayer[] = [{ name: "task", policy: { deny: ["group:analysis"] } }];
    const result = resolveToolPolicy(ALL_TOOLS, layers);
    expect(result).not.toContain("GetCallers");
    expect(result).not.toContain("GetCallees");
    expect(result).not.toContain("GetFunctionBody");
    expect(result).toContain("Read");
  });

  it("intersects allow across multiple layers", () => {
    const layers: ToolPolicyLayer[] = [
      { name: "global", policy: { allow: ["Read", "Grep", "Bash"] } },
      { name: "task", policy: { allow: ["Read", "Grep"] } },
    ];
    const result = resolveToolPolicy(ALL_TOOLS, layers);
    expect(result).toEqual(["Read", "Grep"]);
  });

  it("returns empty array when all tools are denied", () => {
    const layers: ToolPolicyLayer[] = [{ name: "task", policy: { deny: ["group:all"] } }];
    const result = resolveToolPolicy(ALL_TOOLS, layers);
    expect(result).toEqual([]);
  });
});

describe("buildPolicyLayers", () => {
  it("creates default layer when no overrides", () => {
    const layers = buildPolicyLayers();
    expect(layers).toHaveLength(1);
    expect(layers[0].name).toBe("global-defaults");
  });

  it("includes task policy layer", () => {
    const taskPolicy: ToolPolicy = { allow: ["Read"], deny: ["Bash"] };
    const layers = buildPolicyLayers(taskPolicy);
    expect(layers).toHaveLength(2);
    expect(layers[1].name).toBe("task");
    expect(layers[1].policy).toEqual(taskPolicy);
  });

  it("includes config policy layers", () => {
    const configPolicies = {
      security: { deny: ["Bash", "Write"] },
      readonly: { allow: ["group:readonly"] },
    };
    const layers = buildPolicyLayers(undefined, configPolicies);
    expect(layers).toHaveLength(3);
    expect(layers[1].name).toBe("config:security");
    expect(layers[2].name).toBe("config:readonly");
  });
});
