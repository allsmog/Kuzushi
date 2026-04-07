import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  inspectModuleRoot,
  looksLikeMonorepo,
  resolveModuleDirectory,
} from "../../src/discovery/module-discovery.js";

const tempDirs: string[] = [];

function makeTempRoot(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-discovery-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop()!, { recursive: true, force: true });
  }
});

describe("module discovery helpers", () => {
  it("inspects module roots using README and build files", async () => {
    const root = makeTempRoot();
    const moduleDir = path.join(root, "apps", "web");
    mkdirSync(moduleDir, { recursive: true });
    writeFileSync(path.join(moduleDir, "README.md"), "Web frontend for customer traffic", "utf-8");
    writeFileSync(path.join(moduleDir, "package.json"), JSON.stringify({
      name: "web",
      dependencies: { react: "^19.0.0" },
    }), "utf-8");

    const metadata = await inspectModuleRoot(root, "apps/web");

    expect(metadata).toEqual({
      description: "Web frontend for customer traffic",
      language: "JavaScript",
      buildSystem: "package.json",
    });
  });

  it("rejects absolute and escaping module paths", () => {
    const root = makeTempRoot();
    mkdirSync(path.join(root, "service"), { recursive: true });

    expect(() => resolveModuleDirectory(root, "/tmp/outside")).toThrow(/must be relative/);
    expect(() => resolveModuleDirectory(root, "../outside")).toThrow(/escapes the monorepo root/);
  });

  it("detects monorepo shape from workspace markers and shallow structure", async () => {
    const root = makeTempRoot();
    mkdirSync(path.join(root, "apps", "web"), { recursive: true });
    mkdirSync(path.join(root, "services", "api"), { recursive: true });
    writeFileSync(path.join(root, "pnpm-workspace.yaml"), "packages:\n  - apps/*\n  - services/*\n", "utf-8");
    writeFileSync(path.join(root, "apps", "web", "package.json"), JSON.stringify({ name: "web" }), "utf-8");
    writeFileSync(path.join(root, "services", "api", "package.json"), JSON.stringify({ name: "api" }), "utf-8");

    await expect(looksLikeMonorepo(root)).resolves.toBe(true);
  });

  it("does not treat a normal single-package repo as a monorepo", async () => {
    const root = makeTempRoot();
    mkdirSync(path.join(root, "src", "lib"), { recursive: true });
    mkdirSync(path.join(root, "tests"), { recursive: true });
    writeFileSync(path.join(root, "package.json"), JSON.stringify({ name: "single-repo" }), "utf-8");

    await expect(looksLikeMonorepo(root)).resolves.toBe(false);
  });
});
