import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ModuleLoadError } from "../../src/modules/errors.js";
import { dynamicImportModule, loadManifestFromPath } from "../../src/modules/loader.js";

const tempDirs: string[] = [];

function createTempDir(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-import-test-"));
  tempDirs.push(dir);
  return dir;
}

function writeModule(dir: string, file: string, source: string): string {
  const abs = path.join(dir, file);
  writeFileSync(abs, source);
  return abs;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop()!, { recursive: true, force: true });
  }
});

describe("loadManifestFromPath JSON parse errors", () => {
  it("raises MANIFEST_INVALID when the manifest is not valid JSON", () => {
    const dir = createTempDir();
    writeFileSync(path.join(dir, "module.manifest.json"), "{ not json");
    try {
      loadManifestFromPath(dir);
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(ModuleLoadError);
      expect((err as ModuleLoadError).code).toBe("MANIFEST_INVALID");
      expect((err as ModuleLoadError).message).toMatch(/Failed to parse module manifest/);
    }
  });
});

describe("dynamicImportModule", () => {
  it("raises ENTRY_NOT_FOUND for a missing entry path", async () => {
    const dir = createTempDir();
    const missing = path.join(dir, "does-not-exist.mjs");
    await expect(dynamicImportModule(missing)).rejects.toMatchObject({
      code: "ENTRY_NOT_FOUND",
    });
  });

  it("imports a valid default-exported module", async () => {
    const dir = createTempDir();
    const entry = writeModule(
      dir,
      "default-mod.mjs",
      `export default {
        id: "demo",
        displayName: "Demo",
        category: "offense",
        version: "1.0.0",
        description: "",
        tools: [{ name: "demo:scan", description: "", inputSchema: {}, headless: true, execute: () => {} }],
      };`,
    );
    const mod = await dynamicImportModule(entry);
    expect(mod.id).toBe("demo");
    expect(mod.tools[0]?.name).toBe("demo:scan");
  });

  it("resolves a named `module` export when no default is present", async () => {
    const dir = createTempDir();
    const entry = writeModule(
      dir,
      "named-mod.mjs",
      `export const module = {
        id: "named",
        displayName: "Named",
        category: "intel",
        version: "2.0.0",
        description: "",
        tools: [{ name: "named:run", description: "", inputSchema: {}, headless: true, execute: () => {} }],
      };`,
    );
    const mod = await dynamicImportModule(entry);
    expect(mod.id).toBe("named");
  });

  it("raises SHAPE_INVALID when the imported module fails validation", async () => {
    const dir = createTempDir();
    const entry = writeModule(
      dir,
      "bad-mod.mjs",
      `export default {
        id: "bad",
        displayName: "Bad",
        category: "offense",
        version: "1.0.0",
        description: "",
        tools: [{ name: "wrong:prefix", description: "", inputSchema: {}, headless: true, execute: () => {} }],
      };`,
    );
    await expect(dynamicImportModule(entry)).rejects.toMatchObject({
      code: "SHAPE_INVALID",
    });
  });
});
