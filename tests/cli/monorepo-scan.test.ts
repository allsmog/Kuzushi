import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  applyModuleFilters,
  normalizeConfiguredModules,
  parseManualModules,
} from "../../src/cli/commands/monorepo-scan.js";
import type { DiscoveredModule } from "../../src/discovery/types.js";

const tempDirs: string[] = [];

function makeTempMonorepo(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-monorepo-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop()!, { recursive: true, force: true });
  }
});

describe("monorepo-scan helpers", () => {
  it("parses manual module specs and normalizes names", async () => {
    const root = makeTempMonorepo();
    const moduleDir = path.join(root, "services", "auth");
    mkdirSync(moduleDir, { recursive: true });
    writeFileSync(path.join(moduleDir, "package.json"), JSON.stringify({
      name: "auth-service",
      dependencies: { typescript: "^5.0.0" },
    }), "utf-8");
    writeFileSync(path.join(moduleDir, "README.md"), "Authentication service for the monorepo", "utf-8");

    const modules = await parseManualModules(root, "Auth Service:services/auth");

    expect(modules).toEqual([{
      name: "auth-service",
      path: "services/auth",
      description: "Authentication service for the monorepo",
      language: "TypeScript",
      buildSystem: "package.json",
      moduleKind: "standalone",
      discoveryEvidence: ["manual --modules flag"],
    }]);
  });

  it("normalizes configured modules using canonical paths", async () => {
    const root = makeTempMonorepo();
    const platformDir = path.join(root, "platform");
    const gatewayDir = path.join(root, "gateway");
    mkdirSync(platformDir, { recursive: true });
    mkdirSync(gatewayDir, { recursive: true });
    writeFileSync(path.join(platformDir, "README.md"), "Platform module", "utf-8");
    writeFileSync(path.join(gatewayDir, "go.mod"), "module example.com/gateway", "utf-8");

    const modules: DiscoveredModule[] = [{
      name: "Platform",
      path: "platform",
      description: "",
      language: "",
      moduleKind: "standalone",
      discoveryEvidence: ["config"],
    }, {
      name: "Gateway",
      path: "gateway",
      description: "edge traffic",
      language: "",
      moduleKind: "standalone",
      discoveryEvidence: ["config"],
    }];

    const normalized = await normalizeConfiguredModules(root, modules);

    expect(normalized[0]).toMatchObject({
      name: "platform",
      path: "platform",
      description: "Platform module",
    });
    expect(normalized[1]).toMatchObject({
      name: "gateway",
      path: "gateway",
      description: "edge traffic",
      language: "Go",
      buildSystem: "go.mod",
    });
  });

  it("rejects overlapping configured modules", async () => {
    const root = makeTempMonorepo();
    const parentDir = path.join(root, "platform");
    const childDir = path.join(parentDir, "gateway");
    mkdirSync(childDir, { recursive: true });
    writeFileSync(path.join(parentDir, "README.md"), "Platform parent module", "utf-8");
    writeFileSync(path.join(childDir, "go.mod"), "module example.com/gateway", "utf-8");

    await expect(normalizeConfiguredModules(root, [{
      name: "Platform",
      path: "platform",
      description: "",
      language: "",
      moduleKind: "standalone",
      discoveryEvidence: ["config"],
    }, {
      name: "Gateway",
      path: "platform/gateway",
      description: "",
      language: "",
      moduleKind: "standalone",
      discoveryEvidence: ["config"],
    }])).rejects.toThrow(/overlapping module roots/);
  });

  it("filters by module name patterns and exclusions", () => {
    const modules: DiscoveredModule[] = [
      { name: "platform", path: "platform", description: "", language: "TypeScript", moduleKind: "standalone", discoveryEvidence: [] },
      { name: "platform-gateway", path: "platform/gateway", description: "", language: "Go", moduleKind: "standalone", discoveryEvidence: [] },
      { name: "billing", path: "billing", description: "", language: "Java", moduleKind: "standalone", discoveryEvidence: [] },
    ];

    const filtered = applyModuleFilters(modules, "platform*", ["*-gateway"]);

    expect(filtered).toEqual([
      { name: "platform", path: "platform", description: "", language: "TypeScript", moduleKind: "standalone", discoveryEvidence: [] },
    ]);
  });
});
