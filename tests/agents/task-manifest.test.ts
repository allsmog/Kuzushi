import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  parseTaskManifest,
  loadTaskManifest,
  checkRequirements,
  fingerprintTaskCode,
  type TaskManifest,
} from "../../src/agents/task-manifest.js";
import { mkdirSync, writeFileSync, rmSync, existsSync } from "node:fs";
import path from "node:path";
import os from "node:os";

const VALID_MANIFEST = {
  id: "test-scanner",
  displayName: "Test Scanner",
  version: "1.0.0",
  description: "A test scanner task",
  outputKind: "findings",
  dependsOn: [],
  requires: {
    env: ["TEST_API_KEY"],
    bins: ["node"],
  },
  config: {
    maxFindings: {
      type: "number",
      default: 100,
      description: "Maximum findings to return",
    },
  },
  author: "Test Author",
  license: "MIT",
};

describe("parseTaskManifest", () => {
  it("validates a correct manifest", () => {
    const result = parseTaskManifest(JSON.stringify(VALID_MANIFEST));
    expect(result.valid).toBe(true);
    expect(result.manifest).toBeDefined();
    expect(result.manifest!.id).toBe("test-scanner");
    expect(result.manifest!.version).toBe("1.0.0");
  });

  it("rejects invalid JSON", () => {
    const result = parseTaskManifest("not json{");
    expect(result.valid).toBe(false);
    expect(result.errors).toBeDefined();
    expect(result.errors![0]).toContain("Invalid JSON");
  });

  it("rejects manifest without required fields", () => {
    const result = parseTaskManifest(JSON.stringify({ id: "test" }));
    expect(result.valid).toBe(false);
    expect(result.errors!.length).toBeGreaterThan(0);
  });

  it("rejects invalid version format", () => {
    const manifest = { ...VALID_MANIFEST, version: "not-semver" };
    const result = parseTaskManifest(JSON.stringify(manifest));
    expect(result.valid).toBe(false);
    expect(result.errors!.some((e) => e.includes("semver"))).toBe(true);
  });

  it("rejects invalid outputKind", () => {
    const manifest = { ...VALID_MANIFEST, outputKind: "invalid" };
    const result = parseTaskManifest(JSON.stringify(manifest));
    expect(result.valid).toBe(false);
  });

  it("accepts manifest without optional fields", () => {
    const minimal = {
      id: "minimal",
      displayName: "Minimal Task",
      version: "0.1.0",
      description: "A minimal task",
      outputKind: "custom",
    };
    const result = parseTaskManifest(JSON.stringify(minimal));
    expect(result.valid).toBe(true);
    expect(result.manifest!.dependsOn).toEqual([]);
  });
});

describe("loadTaskManifest", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = path.join(os.tmpdir(), `kuzushi-manifest-test-${Date.now()}`);
    mkdirSync(tmpDir, { recursive: true });
  });

  afterEach(() => {
    if (existsSync(tmpDir)) {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("returns undefined when no manifest file exists", () => {
    const result = loadTaskManifest(tmpDir);
    expect(result).toBeUndefined();
  });

  it("loads and validates a manifest file", () => {
    writeFileSync(
      path.join(tmpDir, "task.manifest.json"),
      JSON.stringify(VALID_MANIFEST),
    );
    const result = loadTaskManifest(tmpDir);
    expect(result).toBeDefined();
    expect(result!.valid).toBe(true);
    expect(result!.manifest!.id).toBe("test-scanner");
  });

  it("reports validation errors for invalid manifest file", () => {
    writeFileSync(
      path.join(tmpDir, "task.manifest.json"),
      JSON.stringify({ id: 123 }),
    );
    const result = loadTaskManifest(tmpDir);
    expect(result).toBeDefined();
    expect(result!.valid).toBe(false);
  });
});

describe("checkRequirements", () => {
  it("reports satisfied when all requirements met", () => {
    const manifest: TaskManifest = {
      ...VALID_MANIFEST,
      requires: { bins: ["node"] },
    };
    const result = checkRequirements(manifest);
    // node should exist on PATH
    expect(result.missing.bins).toEqual([]);
  });

  it("reports missing env variables", () => {
    const manifest: TaskManifest = {
      ...VALID_MANIFEST,
      requires: { env: ["KUZUSHI_TEST_NONEXISTENT_VAR_12345"] },
    };
    const result = checkRequirements(manifest);
    expect(result.satisfied).toBe(false);
    expect(result.missing.env).toContain("KUZUSHI_TEST_NONEXISTENT_VAR_12345");
  });

  it("reports missing binaries", () => {
    const manifest: TaskManifest = {
      ...VALID_MANIFEST,
      requires: { bins: ["__nonexistent_binary_12345__"] },
    };
    const result = checkRequirements(manifest);
    expect(result.satisfied).toBe(false);
    expect(result.missing.bins).toContain("__nonexistent_binary_12345__");
  });

  it("satisfied when no requirements specified", () => {
    const manifest: TaskManifest = {
      ...VALID_MANIFEST,
      requires: undefined,
    };
    const result = checkRequirements(manifest);
    expect(result.satisfied).toBe(true);
  });
});

describe("fingerprintTaskCode", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = path.join(os.tmpdir(), `kuzushi-fp-test-${Date.now()}`);
    mkdirSync(tmpDir, { recursive: true });
  });

  afterEach(() => {
    if (existsSync(tmpDir)) {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("returns undefined for non-existent file", () => {
    expect(fingerprintTaskCode("/nonexistent/path.ts")).toBeUndefined();
  });

  it("returns consistent hash for same content", () => {
    const filePath = path.join(tmpDir, "task.ts");
    writeFileSync(filePath, "export const task = { id: 'test' };");
    const hash1 = fingerprintTaskCode(filePath);
    const hash2 = fingerprintTaskCode(filePath);
    expect(hash1).toBe(hash2);
    expect(hash1).toMatch(/^[0-9a-f]{64}$/);
  });

  it("returns different hash for different content", () => {
    const file1 = path.join(tmpDir, "task1.ts");
    const file2 = path.join(tmpDir, "task2.ts");
    writeFileSync(file1, "version 1");
    writeFileSync(file2, "version 2");
    expect(fingerprintTaskCode(file1)).not.toBe(fingerprintTaskCode(file2));
  });
});
