import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { DEFAULTS } from "../../src/config.js";
import { prepareScanExecution, resolveMonorepoExecution } from "../../src/cli/commands/scan.js";
import type { ScanCommandOptions } from "../../src/cli/scan-config.js";
import type { KuzushiConfig } from "../../src/types.js";

const tempDirs: string[] = [];

function makeTempRoot(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-scan-mode-"));
  tempDirs.push(dir);
  return dir;
}

function makeConfig(overrides: Partial<KuzushiConfig> = {}): KuzushiConfig {
  return {
    ...structuredClone(DEFAULTS),
    ...overrides,
  };
}

function makeOptions(overrides: Partial<ScanCommandOptions> = {}): ScanCommandOptions {
  return {
    verify: false,
    cryptoBehavioralTest: false,
    pocHarness: false,
    context: true,
    moduleDiscovery: true,
    auditLog: false,
    enableExternalTasks: false,
    qualityGate: false,
    failOnTp: false,
    fresh: false,
    cache: true,
    ...overrides,
  };
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop()!, { recursive: true, force: true });
  }
});

describe("resolveMonorepoExecution", () => {
  it("auto-detects monorepo roots from workspace markers", async () => {
    const root = makeTempRoot();
    mkdirSync(path.join(root, "apps", "web"), { recursive: true });
    mkdirSync(path.join(root, "services", "api"), { recursive: true });
    writeFileSync(path.join(root, "pnpm-workspace.yaml"), "packages:\n  - apps/*\n  - services/*\n", "utf-8");

    const decision = await resolveMonorepoExecution({
      repoRoot: root,
      scanPath: root,
      config: makeConfig(),
      opts: { moduleDiscovery: true },
    });

    expect(decision).toEqual({
      useMonorepo: true,
      reason: "auto-detected",
    });
  });

  it("respects the CLI opt-out even when the target looks like a monorepo", async () => {
    const root = makeTempRoot();
    mkdirSync(path.join(root, "apps", "web"), { recursive: true });
    mkdirSync(path.join(root, "services", "api"), { recursive: true });
    writeFileSync(path.join(root, "pnpm-workspace.yaml"), "packages:\n  - apps/*\n  - services/*\n", "utf-8");

    const decision = await resolveMonorepoExecution({
      repoRoot: root,
      scanPath: root,
      config: makeConfig(),
      opts: { moduleDiscovery: false },
    });

    expect(decision).toEqual({
      useMonorepo: false,
      reason: "cli-opt-out",
    });
  });

  it("treats config.monorepo.modules as an explicit module-mode signal", async () => {
    const root = makeTempRoot();
    mkdirSync(path.join(root, "platform"), { recursive: true });

    const decision = await resolveMonorepoExecution({
      repoRoot: root,
      scanPath: root,
      config: makeConfig({
        monorepo: {
          modules: [{ name: "platform", path: "platform", description: "", language: "unknown" }],
        },
      }),
      opts: { moduleDiscovery: true },
    });

    expect(decision).toEqual({
      useMonorepo: true,
      reason: "config-modules",
    });
  });

  it("treats a monorepo config block as an explicit signal unless mode is off", async () => {
    const root = makeTempRoot();
    writeFileSync(path.join(root, "package.json"), JSON.stringify({ name: "repo" }), "utf-8");

    const onDecision = await resolveMonorepoExecution({
      repoRoot: root,
      scanPath: root,
      config: makeConfig({
        monorepo: {
          mode: "auto",
          excludeModules: ["fixtures*"],
        },
      }),
      opts: { moduleDiscovery: true },
    });

    const offDecision = await resolveMonorepoExecution({
      repoRoot: root,
      scanPath: root,
      config: makeConfig({
        monorepo: {
          mode: "off",
          excludeModules: ["fixtures*"],
        },
      }),
      opts: { moduleDiscovery: true },
    });

    expect(onDecision).toEqual({
      useMonorepo: true,
      reason: "config-monorepo",
    });
    expect(offDecision).toEqual({
      useMonorepo: false,
      reason: "single-root",
    });
  });

  it("lets --list-modules force module resolution preview", async () => {
    const root = makeTempRoot();
    writeFileSync(path.join(root, "package.json"), JSON.stringify({ name: "repo" }), "utf-8");

    const decision = await resolveMonorepoExecution({
      repoRoot: root,
      scanPath: root,
      config: makeConfig({
        monorepo: {
          mode: "off",
        },
      }),
      opts: { listModules: true, moduleDiscovery: false },
    });

    expect(decision).toEqual({
      useMonorepo: true,
      reason: "list-modules",
    });
  });

  it("promotes scanners-only mode when CLI scanner selections expand to AgentTasks", () => {
    const root = makeTempRoot();
    writeFileSync(path.join(root, "package.json"), JSON.stringify({ name: "repo" }), "utf-8");

    const { config, scanOpts } = prepareScanExecution(root, makeOptions({
      preset: "fast",
      scanners: "secrets",
    }));

    expect(config.taskMode).toBe("explicit");
    expect(config.enabledTasks).toContain("secrets-crypto-detect");
    expect(scanOpts.scanners).toEqual([]);
  });
});
