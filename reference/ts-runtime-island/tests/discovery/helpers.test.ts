import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  buildManualModule,
  normalizeModuleName,
  rejectOverlappingModules,
  resolveModuleDirectory,
} from "../../src/discovery/helpers.js";
import type { DiscoveredModule } from "../../src/discovery/types.js";

const tempDirs: string[] = [];

function makeTempRoot(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-helpers-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop()!, { recursive: true, force: true });
  }
});

describe("normalizeModuleName", () => {
  it("lowercases and replaces non-alphanumeric chars", () => {
    expect(normalizeModuleName("My Package")).toBe("my-package");
    expect(normalizeModuleName("@org/core")).toBe("org-core");
    expect(normalizeModuleName("---")).toBe("module");
  });
});

describe("resolveModuleDirectory", () => {
  it("resolves valid relative paths", () => {
    const root = makeTempRoot();
    mkdirSync(path.join(root, "services", "api"), { recursive: true });
    const resolved = resolveModuleDirectory(root, "services/api");
    expect(resolved).toBe(path.resolve(root, "services/api"));
  });

  it("rejects absolute paths", () => {
    const root = makeTempRoot();
    expect(() => resolveModuleDirectory(root, "/tmp/outside")).toThrow(/must be relative/);
  });

  it("rejects escaping paths", () => {
    const root = makeTempRoot();
    mkdirSync(path.join(root, "service"), { recursive: true });
    expect(() => resolveModuleDirectory(root, "../outside")).toThrow(/escapes the monorepo root/);
  });
});

describe("rejectOverlappingModules", () => {
  it("throws for nested module paths", () => {
    const modules: DiscoveredModule[] = [
      {
        name: "parent",
        path: "platform",
        description: "",
        language: "Go",
        moduleKind: "standalone",
        discoveryEvidence: [],
      },
      {
        name: "child",
        path: "platform/gateway",
        description: "",
        language: "Go",
        moduleKind: "standalone",
        discoveryEvidence: [],
      },
    ];
    expect(() => rejectOverlappingModules(modules)).toThrow(/overlapping module roots/);
  });

  it("accepts non-overlapping paths", () => {
    const modules: DiscoveredModule[] = [
      {
        name: "api",
        path: "services/api",
        description: "",
        language: "Go",
        moduleKind: "standalone",
        discoveryEvidence: [],
      },
      {
        name: "web",
        path: "apps/web",
        description: "",
        language: "TypeScript",
        moduleKind: "standalone",
        discoveryEvidence: [],
      },
    ];
    expect(() => rejectOverlappingModules(modules)).not.toThrow();
  });
});

describe("buildManualModule", () => {
  it("inspects module root and returns full DiscoveredModule", async () => {
    const root = makeTempRoot();
    const moduleDir = path.join(root, "services", "api");
    mkdirSync(moduleDir, { recursive: true });
    writeFileSync(
      path.join(moduleDir, "package.json"),
      JSON.stringify({
        name: "api",
        dependencies: { typescript: "^5.0.0" },
      }),
      "utf-8",
    );
    writeFileSync(path.join(moduleDir, "README.md"), "API service module", "utf-8");

    const module = await buildManualModule(root, "API", "services/api");

    expect(module).toEqual({
      name: "api",
      path: "services/api",
      description: "API service module",
      language: "TypeScript",
      buildSystem: "package.json",
      moduleKind: "standalone",
      discoveryEvidence: ["manual"],
    });
  });

  it("uses custom evidence tag", async () => {
    const root = makeTempRoot();
    mkdirSync(path.join(root, "lib"), { recursive: true });

    const module = await buildManualModule(root, "Lib", "lib", "standalone", "config");

    expect(module.discoveryEvidence).toEqual(["config"]);
  });
});
