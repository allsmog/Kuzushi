import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { NodeAdapter } from "../../../src/discovery/adapters/node-adapter.js";

const tempDirs: string[] = [];
const adapter = new NodeAdapter();

function makeTempRoot(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-node-adapter-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop()!, { recursive: true, force: true });
  }
});

describe("NodeAdapter", () => {
  it("discovers pnpm workspace members", async () => {
    const root = makeTempRoot();
    writeFileSync(
      path.join(root, "pnpm-workspace.yaml"),
      "packages:\n  - apps/*\n  - packages/*\n",
      "utf-8",
    );
    writeFileSync(path.join(root, "package.json"), JSON.stringify({ name: "root" }), "utf-8");

    mkdirSync(path.join(root, "apps", "web"), { recursive: true });
    writeFileSync(
      path.join(root, "apps", "web", "package.json"),
      JSON.stringify({ name: "web" }),
      "utf-8",
    );

    mkdirSync(path.join(root, "packages", "core"), { recursive: true });
    writeFileSync(
      path.join(root, "packages", "core", "package.json"),
      JSON.stringify({ name: "@org/core" }),
      "utf-8",
    );

    const nodes = await adapter.discover(root, 8);

    const container = nodes.find((n) => n.isContainer);
    expect(container).toBeDefined();
    expect(container!.containerKind).toBe("workspace-root");
    expect(container!.childPaths).toContain("apps/web");
    expect(container!.childPaths).toContain("packages/core");

    const children = nodes.filter((n) => !n.isContainer);
    expect(children).toHaveLength(2);
    expect(children.map((c) => c.name).sort()).toEqual(["@org/core", "web"]);
  });

  it("discovers package.json workspaces field", async () => {
    const root = makeTempRoot();
    writeFileSync(
      path.join(root, "package.json"),
      JSON.stringify({
        name: "root",
        workspaces: ["packages/*"],
      }),
      "utf-8",
    );

    mkdirSync(path.join(root, "packages", "lib"), { recursive: true });
    writeFileSync(
      path.join(root, "packages", "lib", "package.json"),
      JSON.stringify({ name: "lib" }),
      "utf-8",
    );

    const nodes = await adapter.discover(root, 8);

    expect(nodes.some((n) => n.isContainer && n.containerKind === "workspace-root")).toBe(true);
    expect(nodes.some((n) => !n.isContainer && n.path === "packages/lib")).toBe(true);
  });

  it("detects TypeScript from tsconfig.json", async () => {
    const root = makeTempRoot();
    writeFileSync(path.join(root, "pnpm-workspace.yaml"), "packages:\n  - apps/*\n", "utf-8");
    writeFileSync(path.join(root, "package.json"), JSON.stringify({ name: "root" }), "utf-8");

    mkdirSync(path.join(root, "apps", "api"), { recursive: true });
    writeFileSync(
      path.join(root, "apps", "api", "package.json"),
      JSON.stringify({ name: "api" }),
      "utf-8",
    );
    writeFileSync(path.join(root, "apps", "api", "tsconfig.json"), "{}", "utf-8");

    const nodes = await adapter.discover(root, 8);

    const apiNode = nodes.find((n) => n.path === "apps/api");
    expect(apiNode?.language).toBe("TypeScript");
  });

  it("returns standalone app when no workspace", async () => {
    const root = makeTempRoot();
    writeFileSync(
      path.join(root, "package.json"),
      JSON.stringify({
        name: "my-app",
        scripts: { start: "node index.js" },
      }),
      "utf-8",
    );

    const nodes = await adapter.discover(root, 8);

    expect(nodes).toHaveLength(1);
    expect(nodes[0].isContainer).toBe(false);
    expect(nodes[0].path).toBe(".");
  });

  it("returns empty for repos with no package.json", async () => {
    const root = makeTempRoot();

    const nodes = await adapter.discover(root, 8);

    expect(nodes).toHaveLength(0);
  });
});
