import { describe, expect, it, vi } from "vitest";
import type { RawDiscoveryNode } from "../../src/discovery/adapters/types.js";
import type { DiscoveredProduct } from "../../src/discovery/types.js";

// Mock the manifest parsers before importing the module under test
vi.mock("../../src/monorepo/dependency-graph.js", () => ({
  readPackageName: vi.fn(async (_dir: string) => null),
  parsePackageJsonDeps: vi.fn(async (_dir: string) => []),
  parseGoModDeps: vi.fn(async (_dir: string) => []),
  parseCargoDeps: vi.fn(async (_dir: string) => []),
}));

import {
  buildWorkspaceDependencyMap,
  clusterWorkspaceMembers,
} from "../../src/discovery/workspace-clustering.js";
import {
  readPackageName,
  parsePackageJsonDeps,
} from "../../src/monorepo/dependency-graph.js";

function makeNode(overrides: Partial<RawDiscoveryNode> & { path: string }): RawDiscoveryNode {
  return {
    name: overrides.path.split("/").pop() ?? overrides.path,
    language: "TypeScript",
    buildSystem: "package.json",
    description: "",
    evidence: ["package.json"],
    isContainer: false,
    childPaths: [],
    ...overrides,
  };
}

function makeContainer(containerPath: string, children: string[]): RawDiscoveryNode {
  return makeNode({
    path: containerPath,
    name: containerPath === "." ? "root" : containerPath.split("/").pop()!,
    isContainer: true,
    containerKind: "workspace-root",
    childPaths: children,
    evidence: ["pnpm-workspace.yaml"],
  });
}

function makeProduct(productPath: string, children: string[]): DiscoveredProduct {
  return {
    path: productPath,
    kind: "workspace-root",
    children,
    discoveryEvidence: ["pnpm-workspace.yaml"],
  };
}

describe("buildWorkspaceDependencyMap", () => {
  it("builds internal dependency edges between workspace siblings", async () => {
    const container = makeContainer(".", ["packages/cli", "packages/core", "packages/utils"]);
    const leaves = [
      makeNode({ path: "packages/cli", name: "cli" }),
      makeNode({ path: "packages/core", name: "core" }),
      makeNode({ path: "packages/utils", name: "utils" }),
    ];

    vi.mocked(readPackageName).mockImplementation(async (dir: string) => {
      if (dir.endsWith("cli")) return "@app/cli";
      if (dir.endsWith("core")) return "@app/core";
      if (dir.endsWith("utils")) return "@app/utils";
      return null;
    });
    vi.mocked(parsePackageJsonDeps).mockImplementation(async (dir: string) => {
      if (dir.endsWith("cli")) return ["@app/core", "@app/utils", "lodash"];
      if (dir.endsWith("core")) return ["@app/utils", "express"];
      if (dir.endsWith("utils")) return ["lodash"];
      return [];
    });

    const result = await buildWorkspaceDependencyMap("/repo", [container, ...leaves]);

    expect(result.internalDeps.get("packages/cli")).toEqual(new Set(["packages/core", "packages/utils"]));
    expect(result.internalDeps.get("packages/core")).toEqual(new Set(["packages/utils"]));
    expect(result.internalDeps.get("packages/utils")).toEqual(new Set());
    expect(result.packageNameToPath.get("@app/cli")).toBe("packages/cli");
    expect(result.promptSummary).toContain("cli");
    expect(result.promptSummary).toContain("internal deps");
  });
});

describe("clusterWorkspaceMembers", () => {
  it("groups a dense connected component into one module with includePaths", () => {
    // cli → core → utils forms one connected component
    const depMap = {
      internalDeps: new Map<string, Set<string>>([
        ["packages/cli", new Set(["packages/core", "packages/utils"])],
        ["packages/core", new Set(["packages/utils"])],
        ["packages/utils", new Set()],
      ]),
      packageNameToPath: new Map([
        ["@app/cli", "packages/cli"],
        ["@app/core", "packages/core"],
        ["@app/utils", "packages/utils"],
      ]),
      promptSummary: "",
    };

    const container = makeContainer(".", ["packages/cli", "packages/core", "packages/utils"]);
    const nodes = [
      container,
      makeNode({ path: "packages/cli", name: "cli" }),
      makeNode({ path: "packages/core", name: "core" }),
      makeNode({ path: "packages/utils", name: "utils" }),
    ];
    const products = [makeProduct(".", ["packages/cli", "packages/core", "packages/utils"])];

    const modules = clusterWorkspaceMembers(depMap, nodes, products);

    expect(modules).toHaveLength(1);
    // Hub should be utils (highest in-degree: both cli and core depend on it)
    expect(modules[0].includePaths).toBeDefined();
    expect(modules[0].includePaths).toHaveLength(3);
    expect(modules[0].includePaths).toContain("packages/cli");
    expect(modules[0].includePaths).toContain("packages/core");
    expect(modules[0].includePaths).toContain("packages/utils");
    expect(modules[0].discoveryEvidence).toEqual(["deterministic-clustering"]);
  });

  it("produces two modules for two disconnected clusters", () => {
    const depMap = {
      internalDeps: new Map<string, Set<string>>([
        ["packages/backend/api", new Set(["packages/backend/db"])],
        ["packages/backend/db", new Set()],
        ["packages/frontend/ui", new Set(["packages/frontend/design"])],
        ["packages/frontend/design", new Set()],
      ]),
      packageNameToPath: new Map([
        ["@app/api", "packages/backend/api"],
        ["@app/db", "packages/backend/db"],
        ["@app/ui", "packages/frontend/ui"],
        ["@app/design", "packages/frontend/design"],
      ]),
      promptSummary: "",
    };

    const container = makeContainer(".", [
      "packages/backend/api", "packages/backend/db",
      "packages/frontend/ui", "packages/frontend/design",
    ]);
    const nodes = [
      container,
      makeNode({ path: "packages/backend/api", name: "api" }),
      makeNode({ path: "packages/backend/db", name: "db" }),
      makeNode({ path: "packages/frontend/ui", name: "ui" }),
      makeNode({ path: "packages/frontend/design", name: "design" }),
    ];
    const products = [makeProduct(".", container.childPaths)];

    const modules = clusterWorkspaceMembers(depMap, nodes, products);

    expect(modules).toHaveLength(2);
    const backendModule = modules.find((m) => m.includePaths?.includes("packages/backend/api"));
    const frontendModule = modules.find((m) => m.includePaths?.includes("packages/frontend/ui"));
    expect(backendModule).toBeDefined();
    expect(frontendModule).toBeDefined();
    expect(backendModule!.includePaths).toHaveLength(2);
    expect(frontendModule!.includePaths).toHaveLength(2);
  });

  it("keeps isolated packages as standalone modules", () => {
    const depMap = {
      internalDeps: new Map<string, Set<string>>([
        ["packages/standalone-tool", new Set()],
      ]),
      packageNameToPath: new Map([
        ["@app/tool", "packages/standalone-tool"],
      ]),
      promptSummary: "",
    };

    const container = makeContainer(".", ["packages/standalone-tool"]);
    const nodes = [
      container,
      makeNode({ path: "packages/standalone-tool", name: "tool" }),
    ];
    const products = [makeProduct(".", ["packages/standalone-tool"])];

    const modules = clusterWorkspaceMembers(depMap, nodes, products);

    expect(modules).toHaveLength(1);
    expect(modules[0].path).toBe("packages/standalone-tool");
    // Single-member cluster: no includePaths needed
    expect(modules[0].includePaths).toBeUndefined();
  });

  it("excludes test/tooling packages from scan modules", () => {
    const depMap = {
      internalDeps: new Map<string, Set<string>>([
        ["packages/cli", new Set(["packages/core"])],
        ["packages/core", new Set()],
        ["packages/eslint-config", new Set()],
        ["packages/testing/e2e", new Set(["packages/cli"])],
        ["packages/vitest-config", new Set()],
      ]),
      packageNameToPath: new Map([
        ["@app/cli", "packages/cli"],
        ["@app/core", "packages/core"],
        ["@app/eslint-config", "packages/eslint-config"],
        ["@app/e2e", "packages/testing/e2e"],
        ["@app/vitest-config", "packages/vitest-config"],
      ]),
      promptSummary: "",
    };

    const children = ["packages/cli", "packages/core", "packages/eslint-config", "packages/testing/e2e", "packages/vitest-config"];
    const container = makeContainer(".", children);
    const nodes = [
      container,
      makeNode({ path: "packages/cli", name: "cli" }),
      makeNode({ path: "packages/core", name: "core" }),
      makeNode({ path: "packages/eslint-config", name: "eslint-config" }),
      makeNode({ path: "packages/testing/e2e", name: "e2e" }),
      makeNode({ path: "packages/vitest-config", name: "vitest-config" }),
    ];
    const products = [makeProduct(".", children)];

    const modules = clusterWorkspaceMembers(depMap, nodes, products);

    // Only the cli+core cluster should survive; tooling excluded
    expect(modules).toHaveLength(1);
    expect(modules[0].includePaths).toContain("packages/cli");
    expect(modules[0].includePaths).toContain("packages/core");
    expect(modules[0].includePaths).not.toContain("packages/eslint-config");
    expect(modules[0].includePaths).not.toContain("packages/testing/e2e");
    expect(modules[0].includePaths).not.toContain("packages/vitest-config");
  });

  it("includes standalone nodes not in any workspace", () => {
    const depMap = {
      internalDeps: new Map<string, Set<string>>([
        ["packages/cli", new Set()],
      ]),
      packageNameToPath: new Map([["@app/cli", "packages/cli"]]),
      promptSummary: "",
    };

    const container = makeContainer(".", ["packages/cli"]);
    const nodes = [
      container,
      makeNode({ path: "packages/cli", name: "cli" }),
      // Standalone Go module not in any workspace
      makeNode({ path: "services/api", name: "api", language: "Go", buildSystem: "go.mod", evidence: ["go.mod"] }),
    ];
    const products = [makeProduct(".", ["packages/cli"])];

    const modules = clusterWorkspaceMembers(depMap, nodes, products);

    expect(modules).toHaveLength(2);
    expect(modules.find((m) => m.path === "services/api")).toBeDefined();
    expect(modules.find((m) => m.path === "services/api")!.moduleKind).toBe("standalone");
  });

  it("returns empty when no workspace deps exist", () => {
    const depMap = {
      internalDeps: new Map<string, Set<string>>(),
      packageNameToPath: new Map<string, string>(),
      promptSummary: "",
    };
    const modules = clusterWorkspaceMembers(depMap, [], []);
    expect(modules).toHaveLength(0);
  });
});
