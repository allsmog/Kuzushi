import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  checkRequirements,
  loadManifestFromPath,
  validateManifest,
  validateModuleExport,
} from "../../src/modules/loader.js";

const tempDirs: string[] = [];

function createTempDir(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-loader-test-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop()!, { recursive: true, force: true });
  }
});

describe("validateManifest", () => {
  it("accepts a valid manifest", () => {
    const manifest = validateManifest({
      id: "blackbox",
      displayName: "Blackbox Scanner",
      version: "1.0.0",
      entry: "./dist/index.js",
      category: "offense",
      description: "Network reconnaissance",
    });

    expect(manifest.id).toBe("blackbox");
    expect(manifest.category).toBe("offense");
    expect(manifest.entry).toBe("./dist/index.js");
  });

  it("rejects manifests missing required fields", () => {
    expect(() => validateManifest({})).toThrow("missing or invalid 'id'");
    expect(() => validateManifest({ id: "test" })).toThrow("missing or invalid 'displayName'");
    expect(() =>
      validateManifest({
        id: "test",
        displayName: "T",
        version: "1.0",
        entry: "./x.js",
        category: "invalid",
      }),
    ).toThrow("invalid 'category'");
  });

  it("rejects non-object input", () => {
    expect(() => validateManifest(null)).toThrow("expected an object");
    expect(() => validateManifest("string")).toThrow("expected an object");
    expect(() => validateManifest([1, 2])).toThrow("expected an object");
  });
});

describe("loadManifestFromPath", () => {
  it("loads a valid manifest from disk", () => {
    const dir = createTempDir();
    writeFileSync(
      path.join(dir, "module.manifest.json"),
      JSON.stringify({
        id: "test-mod",
        displayName: "Test Module",
        version: "0.1.0",
        entry: "./index.js",
        category: "intel",
      }),
    );

    const manifest = loadManifestFromPath(dir);
    expect(manifest.id).toBe("test-mod");
    expect(manifest.category).toBe("intel");
  });

  it("throws when manifest file is missing", () => {
    const dir = createTempDir();
    expect(() => loadManifestFromPath(dir)).toThrow("No module.manifest.json");
  });
});

describe("checkRequirements", () => {
  it("reports satisfied when no requirements", () => {
    expect(checkRequirements({})).toEqual({ satisfied: true, missing: [] });
  });

  it("reports missing env vars", () => {
    const result = checkRequirements({
      env: ["DEFINITELY_NOT_SET_XYZ_12345"],
    });
    expect(result.satisfied).toBe(false);
    expect(result.missing).toHaveLength(1);
    expect(result.missing[0]).toContain("DEFINITELY_NOT_SET_XYZ_12345");
  });

  it("satisfies node version for current runtime", () => {
    const result = checkRequirements({ nodeVersion: ">=18" });
    expect(result.satisfied).toBe(true);
  });
});

describe("validateModuleExport", () => {
  it("accepts a valid module shape", () => {
    const mod = {
      id: "test",
      displayName: "Test",
      category: "offense",
      version: "1.0.0",
      description: "A test module",
      tools: [
        {
          name: "test:scan",
          description: "Scan",
          inputSchema: {},
          headless: true,
          execute: () => {},
        },
      ],
    };
    expect(() => validateModuleExport(mod)).not.toThrow();
  });

  it("rejects modules missing required fields", () => {
    expect(() => validateModuleExport({})).toThrow("missing 'id'");
    expect(() =>
      validateModuleExport({ id: "x", displayName: "X", category: "y", version: "1", tools: [{}] }),
    ).toThrow("missing 'name'");
  });

  it("rejects non-object exports", () => {
    expect(() => validateModuleExport(null)).toThrow("must export an object");
    expect(() => validateModuleExport("string")).toThrow("must export an object");
  });
});
