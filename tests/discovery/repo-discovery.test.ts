import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { discoverRepoStructure, looksLikeMonorepo } from "../../src/discovery/repo-discovery.js";

const tempDirs: string[] = [];

function makeTempRoot(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-repo-disc-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop()!, { recursive: true, force: true });
  }
});

describe("discoverRepoStructure", () => {
  it("discovers mixed Node + Go monorepo", async () => {
    const root = makeTempRoot();

    // Node workspace
    writeFileSync(path.join(root, "pnpm-workspace.yaml"), "packages:\n  - apps/*\n", "utf-8");
    writeFileSync(path.join(root, "package.json"), JSON.stringify({ name: "root" }), "utf-8");
    mkdirSync(path.join(root, "apps", "web"), { recursive: true });
    writeFileSync(
      path.join(root, "apps", "web", "package.json"),
      JSON.stringify({ name: "web" }),
      "utf-8",
    );

    // Standalone Go module
    mkdirSync(path.join(root, "services", "api"), { recursive: true });
    writeFileSync(
      path.join(root, "services", "api", "go.mod"),
      "module example.com/api\n\ngo 1.22\n",
      "utf-8",
    );

    const result = await discoverRepoStructure(root, { maxModules: 30 });

    expect(result.costUsd).toBe(0); // no runtime = no LLM
    expect(result.modules.length).toBeGreaterThanOrEqual(2);
    expect(result.modules.some((m) => m.path === "apps/web")).toBe(true);
    expect(result.modules.some((m) => m.path === "services/api")).toBe(true);
    expect(result.products.length).toBeGreaterThanOrEqual(1);
  });

  it("returns empty for repos with no project metadata", async () => {
    const root = makeTempRoot();
    mkdirSync(path.join(root, "src"), { recursive: true });
    writeFileSync(path.join(root, "src", "main.c"), "int main() {}", "utf-8");

    const result = await discoverRepoStructure(root);

    expect(result.modules).toHaveLength(0);
    expect(result.products).toHaveLength(0);
  });

  it("respects maxModules", async () => {
    const root = makeTempRoot();
    writeFileSync(path.join(root, "pnpm-workspace.yaml"), "packages:\n  - pkg/*\n", "utf-8");
    writeFileSync(path.join(root, "package.json"), JSON.stringify({ name: "root" }), "utf-8");

    for (let i = 0; i < 10; i++) {
      mkdirSync(path.join(root, "pkg", `mod-${i}`), { recursive: true });
      writeFileSync(
        path.join(root, "pkg", `mod-${i}`, "package.json"),
        JSON.stringify({ name: `mod-${i}` }),
        "utf-8",
      );
    }

    const result = await discoverRepoStructure(root, { maxModules: 3 });

    expect(result.modules).toHaveLength(3);
  });

  it("skips LLM refinement when no runtime provided", async () => {
    const root = makeTempRoot();
    writeFileSync(
      path.join(root, "package.json"),
      JSON.stringify({
        name: "app",
        scripts: { start: "node index.js" },
      }),
      "utf-8",
    );

    const result = await discoverRepoStructure(root);

    expect(result.costUsd).toBe(0);
    expect(result.reasoning).toContain("Metadata discovery");
  });
});

describe("looksLikeMonorepo", () => {
  it("detects pnpm-workspace.yaml", async () => {
    const root = makeTempRoot();
    writeFileSync(path.join(root, "pnpm-workspace.yaml"), "packages:\n  - apps/*\n", "utf-8");
    expect(await looksLikeMonorepo(root)).toBe(true);
  });

  it("detects package.json workspaces", async () => {
    const root = makeTempRoot();
    writeFileSync(
      path.join(root, "package.json"),
      JSON.stringify({ workspaces: ["pkg/*"] }),
      "utf-8",
    );
    expect(await looksLikeMonorepo(root)).toBe(true);
  });

  it("detects go.work", async () => {
    const root = makeTempRoot();
    writeFileSync(path.join(root, "go.work"), "go 1.22\n", "utf-8");
    expect(await looksLikeMonorepo(root)).toBe(true);
  });

  it("detects Cargo workspace", async () => {
    const root = makeTempRoot();
    writeFileSync(path.join(root, "Cargo.toml"), '[workspace]\nmembers = ["crates/*"]\n', "utf-8");
    expect(await looksLikeMonorepo(root)).toBe(true);
  });

  it("detects .sln files", async () => {
    const root = makeTempRoot();
    writeFileSync(
      path.join(root, "MySolution.sln"),
      "Microsoft Visual Studio Solution File",
      "utf-8",
    );
    expect(await looksLikeMonorepo(root)).toBe(true);
  });

  it("detects Bazel workspace markers", async () => {
    const root = makeTempRoot();
    writeFileSync(path.join(root, "WORKSPACE.bazel"), "", "utf-8");
    expect(await looksLikeMonorepo(root)).toBe(true);
  });

  it("returns false for empty directory", async () => {
    const root = makeTempRoot();
    expect(await looksLikeMonorepo(root)).toBe(false);
  });
});
