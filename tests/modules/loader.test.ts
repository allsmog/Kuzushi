import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ModuleLoadError } from "../../src/modules/errors.js";
import {
  checkRequirements,
  loadManifestFromPath,
  sdkMajorMismatch,
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
    // Zod surfaces "expected string, received undefined" for the missing `id`.
    expect(() => validateManifest({})).toThrow(/id:/);
    expect(() => validateManifest({ id: "test" })).toThrow(/displayName:/);
    expect(() =>
      validateManifest({
        id: "test",
        displayName: "T",
        version: "1.0.0",
        entry: "./x.js",
        category: "invalid",
      }),
    ).toThrow(/category:/);
  });

  it("rejects non-object input", () => {
    // Zod surfaces "expected object, received null" / "... string" etc.
    expect(() => validateManifest(null)).toThrow(/expected object/);
    expect(() => validateManifest("string")).toThrow(/expected object/);
    expect(() => validateManifest([1, 2])).toThrow(/expected object/);
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

  it("rejects tool names that don't start with <moduleId>:", () => {
    const mod = {
      id: "foo",
      displayName: "Foo",
      category: "offense",
      version: "1.0.0",
      description: "",
      tools: [
        {
          name: "bar:scan", // wrong prefix
          description: "Scan",
          inputSchema: {},
          headless: true,
          execute: () => {},
        },
      ],
    };
    expect(() => validateModuleExport(mod)).toThrow(/must start with "foo:"/);
  });

  it("rejects tool names that don't match the kebab-case regex", () => {
    const mod = {
      id: "foo",
      displayName: "Foo",
      category: "offense",
      version: "1.0.0",
      description: "",
      tools: [
        {
          name: "Foo:Scan", // uppercase not allowed
          description: "Scan",
          inputSchema: {},
          headless: true,
          execute: () => {},
        },
      ],
    };
    expect(() => validateModuleExport(mod)).toThrow(/must match/);
  });

  it("rejects duplicate tool names in a single module", () => {
    const mod = {
      id: "foo",
      displayName: "Foo",
      category: "offense",
      version: "1.0.0",
      description: "",
      tools: [
        {
          name: "foo:scan",
          description: "a",
          inputSchema: {},
          headless: true,
          execute: () => {},
        },
        {
          name: "foo:scan",
          description: "b",
          inputSchema: {},
          headless: true,
          execute: () => {},
        },
      ],
    };
    expect(() => validateModuleExport(mod)).toThrow(/duplicate tool name/);
  });

  it("throws ModuleLoadError with SHAPE_INVALID on prefix violation", () => {
    const mod = {
      id: "foo",
      displayName: "Foo",
      category: "offense",
      version: "1.0.0",
      description: "",
      tools: [
        {
          name: "bar:x",
          description: "",
          inputSchema: {},
          headless: true,
          execute: () => {},
        },
      ],
    };
    try {
      validateModuleExport(mod);
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(ModuleLoadError);
      expect((err as ModuleLoadError).code).toBe("SHAPE_INVALID");
    }
  });
});

describe("ModuleLoadError codes", () => {
  it("throws MANIFEST_MISSING when manifest file absent", () => {
    const dir = createTempDir();
    try {
      loadManifestFromPath(dir);
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(ModuleLoadError);
      expect((err as ModuleLoadError).code).toBe("MANIFEST_MISSING");
    }
  });

  it("throws MANIFEST_INVALID with structured issues on schema failure", () => {
    try {
      validateManifest({ id: 123 });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(ModuleLoadError);
      expect((err as ModuleLoadError).code).toBe("MANIFEST_INVALID");
      const issues = (err as ModuleLoadError).details?.["issues"];
      expect(Array.isArray(issues)).toBe(true);
    }
  });
});

describe("kuzushiSdkVersion compatibility", () => {
  it("accepts manifests with kuzushiSdkVersion set", () => {
    const manifest = validateManifest({
      id: "test",
      displayName: "Test",
      version: "1.0.0",
      entry: "./x.js",
      category: "offense",
      description: "",
      kuzushiSdkVersion: "^0.19.0",
    });
    expect(manifest.kuzushiSdkVersion).toBe("^0.19.0");
  });

  it("detects a major-version mismatch", () => {
    // host is 0.19.x; required 1.0.0 is incompatible
    const mismatch = sdkMajorMismatch("^1.0.0", "0.19.1");
    expect(mismatch).toMatch(/host=0.*required=1/);
  });

  it("reports no mismatch when majors agree", () => {
    expect(sdkMajorMismatch("0.19.0", "0.19.1")).toBeNull();
    expect(sdkMajorMismatch(">=0.19", "0.99.0")).toBeNull();
  });

  it("returns null on unparseable constraint", () => {
    expect(sdkMajorMismatch("not-a-version", "0.19.0")).toBeNull();
  });
});
