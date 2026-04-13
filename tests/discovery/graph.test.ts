import { describe, expect, it } from "vitest";
import { resolveDiscoveryGraph } from "../../src/discovery/graph.js";
import type { RawDiscoveryNode } from "../../src/discovery/adapters/types.js";

function makeNode(overrides: Partial<RawDiscoveryNode> & { path: string }): RawDiscoveryNode {
  return {
    name: overrides.path.split("/").pop() ?? overrides.path,
    language: "unknown",
    buildSystem: "",
    description: "",
    evidence: [],
    isContainer: false,
    childPaths: [],
    ...overrides,
  };
}

describe("resolveDiscoveryGraph", () => {
  it("converts simple leaf nodes to modules", () => {
    const nodes: RawDiscoveryNode[] = [
      makeNode({ path: "apps/web", language: "TypeScript", evidence: ["package.json"] }),
      makeNode({ path: "services/api", language: "Go", evidence: ["go.mod"] }),
    ];

    const { modules, products } = resolveDiscoveryGraph(nodes, 30);

    expect(modules).toHaveLength(2);
    expect(modules[0].path).toBe("apps/web");
    expect(modules[1].path).toBe("services/api");
    expect(products).toHaveLength(0);
  });

  it("separates containers into products and children into modules", () => {
    const nodes: RawDiscoveryNode[] = [
      makeNode({
        path: ".",
        isContainer: true,
        containerKind: "workspace-root",
        childPaths: ["apps/web", "packages/core"],
        evidence: ["pnpm-workspace.yaml"],
      }),
      makeNode({ path: "apps/web", language: "TypeScript", evidence: ["package.json"] }),
      makeNode({ path: "packages/core", language: "TypeScript", evidence: ["package.json"] }),
    ];

    const { modules, products } = resolveDiscoveryGraph(nodes, 30);

    expect(modules).toHaveLength(2);
    expect(modules[0].moduleKind).toBe("workspace-member");
    expect(modules[0].productPath).toBe(".");
    expect(modules[1].moduleKind).toBe("workspace-member");
    expect(products).toHaveLength(1);
    expect(products[0].kind).toBe("workspace-root");
    expect(products[0].children).toEqual(["apps/web", "packages/core"]);
  });

  it("demotes container with no children to standalone leaf", () => {
    const nodes: RawDiscoveryNode[] = [
      makeNode({
        path: ".",
        isContainer: true,
        containerKind: "workspace-root",
        childPaths: [],
        evidence: ["package.json"],
        language: "TypeScript",
      }),
    ];

    const { modules, products } = resolveDiscoveryGraph(nodes, 30);

    expect(modules).toHaveLength(1);
    expect(modules[0].moduleKind).toBe("standalone");
    expect(products).toHaveLength(0);
  });

  it("merges nodes from multiple adapters at the same path", () => {
    const nodes: RawDiscoveryNode[] = [
      makeNode({ path: "services/gateway", language: "JavaScript", evidence: ["package.json"] }),
      makeNode({ path: "services/gateway", language: "Go", evidence: ["go.mod"] }),
    ];

    const { modules } = resolveDiscoveryGraph(nodes, 30);

    expect(modules).toHaveLength(1);
    // Go is more specific, should win
    expect(modules[0].language).toBe("Go");
    expect(modules[0].discoveryEvidence).toContain("package.json");
    expect(modules[0].discoveryEvidence).toContain("go.mod");
  });

  it("innermost container wins for shared children", () => {
    const nodes: RawDiscoveryNode[] = [
      makeNode({
        path: ".",
        isContainer: true,
        containerKind: "workspace-root",
        childPaths: ["services/api"],
        evidence: ["pnpm-workspace.yaml"],
      }),
      makeNode({
        path: "services",
        isContainer: true,
        containerKind: "go-workspace",
        childPaths: ["services/api"],
        evidence: ["go.work"],
      }),
      makeNode({ path: "services/api", language: "Go", evidence: ["go.mod"] }),
    ];

    const { modules, products } = resolveDiscoveryGraph(nodes, 30);

    // "services" is longer path, wins ownership of "services/api".
    // "." container loses its only child → demoted to standalone leaf → 2 modules total.
    const apiModule = modules.find((m) => m.path === "services/api");
    expect(apiModule).toBeDefined();
    expect(apiModule!.productPath).toBe("services");
    expect(apiModule!.moduleKind).toBe("go-workspace-member");

    // "services" container remains a product
    expect(products.some((p) => p.path === "services" && p.kind === "go-workspace")).toBe(true);
  });

  it("assigns correct moduleKind when multiple containers share root path", () => {
    // Simulates a polyglot monorepo: Node workspace + Go workspace + Bazel workspace
    // all at root ".". Each adapter declares its own children.
    const nodes: RawDiscoveryNode[] = [
      // Node workspace root
      makeNode({
        path: ".",
        isContainer: true,
        containerKind: "workspace-root",
        childPaths: ["apps/web", "packages/ui"],
        evidence: ["pnpm-workspace.yaml"],
      }),
      // Go workspace root
      makeNode({
        path: ".",
        isContainer: true,
        containerKind: "go-workspace",
        childPaths: ["services/api", "services/auth"],
        evidence: ["go.work"],
      }),
      // Bazel workspace root
      makeNode({
        path: ".",
        isContainer: true,
        containerKind: "bazel-workspace",
        childPaths: ["src/cpp/engine", "src/cpp/codec"],
        evidence: ["WORKSPACE.bazel"],
      }),
      // Leaf nodes
      makeNode({ path: "apps/web", language: "TypeScript", evidence: ["package.json"] }),
      makeNode({ path: "packages/ui", language: "TypeScript", evidence: ["package.json"] }),
      makeNode({ path: "services/api", language: "Go", evidence: ["go.mod"] }),
      makeNode({ path: "services/auth", language: "Go", evidence: ["go.mod"] }),
      makeNode({ path: "src/cpp/engine", language: "C++", evidence: ["BUILD.bazel"] }),
      makeNode({ path: "src/cpp/codec", language: "C++", evidence: ["BUILD.bazel"] }),
    ];

    const { modules, products } = resolveDiscoveryGraph(nodes, 30);

    expect(modules).toHaveLength(6);

    // Node children → workspace-member
    expect(modules.find((m) => m.path === "apps/web")!.moduleKind).toBe("workspace-member");
    expect(modules.find((m) => m.path === "packages/ui")!.moduleKind).toBe("workspace-member");

    // Go children → go-workspace-member
    expect(modules.find((m) => m.path === "services/api")!.moduleKind).toBe("go-workspace-member");
    expect(modules.find((m) => m.path === "services/auth")!.moduleKind).toBe("go-workspace-member");

    // Bazel children → bazel-package
    expect(modules.find((m) => m.path === "src/cpp/engine")!.moduleKind).toBe("bazel-package");
    expect(modules.find((m) => m.path === "src/cpp/codec")!.moduleKind).toBe("bazel-package");

    // Three separate products at "."
    expect(products).toHaveLength(3);
    expect(products.some((p) => p.kind === "workspace-root")).toBe(true);
    expect(products.some((p) => p.kind === "go-workspace")).toBe(true);
    expect(products.some((p) => p.kind === "bazel-workspace")).toBe(true);
  });

  it("truncates to maxModules", () => {
    const nodes: RawDiscoveryNode[] = [];
    for (let i = 0; i < 10; i++) {
      nodes.push(makeNode({ path: `mod-${i}`, language: "Go" }));
    }

    const { modules } = resolveDiscoveryGraph(nodes, 3);

    expect(modules).toHaveLength(3);
  });

  it("resolves overlapping leaves by dropping shallower one", () => {
    const nodes: RawDiscoveryNode[] = [
      makeNode({ path: "platform", language: "JavaScript", evidence: ["package.json"] }),
      makeNode({ path: "platform/core", language: "Go", evidence: ["go.mod"] }),
    ];

    const { modules } = resolveDiscoveryGraph(nodes, 30);

    // Deeper leaf wins, shallower dropped
    expect(modules).toHaveLength(1);
    expect(modules[0].path).toBe("platform/core");
  });

  it("drops broad-glob shallow leaf when deeper leaf has specific container", () => {
    // Node workspace with broad glob catches src/cpp,
    // Bazel workspace declares src/cpp/engine as a child.
    const nodes: RawDiscoveryNode[] = [
      makeNode({
        path: ".",
        isContainer: true,
        containerKind: "workspace-root",
        childPaths: ["apps/web", "src/cpp"],
        evidence: ["pnpm-workspace.yaml"],
      }),
      makeNode({
        path: ".",
        isContainer: true,
        containerKind: "bazel-workspace",
        childPaths: ["src/cpp/engine"],
        evidence: ["WORKSPACE.bazel"],
      }),
      makeNode({ path: "apps/web", language: "TypeScript", evidence: ["package.json"] }),
      makeNode({ path: "src/cpp", language: "JavaScript", evidence: ["package.json"] }),
      makeNode({ path: "src/cpp/engine", language: "C++", evidence: ["BUILD.bazel"] }),
    ];

    const { modules } = resolveDiscoveryGraph(nodes, 30);

    // src/cpp (shallow, workspace-root) dropped because src/cpp/engine (deep, bazel-workspace) exists
    expect(modules.some((m) => m.path === "src/cpp")).toBe(false);
    expect(modules.some((m) => m.path === "src/cpp/engine")).toBe(true);
    expect(modules.find((m) => m.path === "src/cpp/engine")!.moduleKind).toBe("bazel-package");
    // apps/web unaffected
    expect(modules.some((m) => m.path === "apps/web")).toBe(true);
  });

  it("keeps both nested leaves when same specific container declares both", () => {
    // go.work declares both "galaxy" and "galaxy/cmd/galaxy-cli" as independent modules
    const nodes: RawDiscoveryNode[] = [
      makeNode({
        path: ".",
        isContainer: true,
        containerKind: "go-workspace",
        childPaths: ["galaxy", "galaxy/cmd/galaxy-cli"],
        evidence: ["go.work"],
      }),
      makeNode({ path: "galaxy", language: "Go", evidence: ["go.mod"] }),
      makeNode({ path: "galaxy/cmd/galaxy-cli", language: "Go", evidence: ["go.mod"] }),
    ];

    const { modules } = resolveDiscoveryGraph(nodes, 30);

    // Both kept — they're intentional, not false positives
    expect(modules).toHaveLength(2);
    expect(modules.some((m) => m.path === "galaxy")).toBe(true);
    expect(modules.some((m) => m.path === "galaxy/cmd/galaxy-cli")).toBe(true);
    expect(modules.every((m) => m.moduleKind === "go-workspace-member")).toBe(true);
  });

  it("produces deterministic output across runs", () => {
    const nodes: RawDiscoveryNode[] = [
      makeNode({ path: "z-service", language: "Go" }),
      makeNode({ path: "a-service", language: "Rust" }),
      makeNode({ path: "m-service", language: "TypeScript" }),
    ];

    const result1 = resolveDiscoveryGraph(nodes, 30);
    const result2 = resolveDiscoveryGraph([...nodes].reverse(), 30);

    expect(result1.modules.map((m) => m.path)).toEqual(result2.modules.map((m) => m.path));
  });
});
