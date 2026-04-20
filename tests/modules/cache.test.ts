import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { MODULE_CACHE_FILENAME, ModuleCache, projectModule } from "../../src/modules/cache.js";
import type { CopilotModule, ModuleTool, ToolResult } from "../../src/modules/types.js";

function mkMod(id: string, extra: Partial<CopilotModule> = {}): CopilotModule {
  const tool: ModuleTool = {
    name: `${id}:run`,
    description: `${id} runner`,
    inputSchema: { type: "object", properties: {} },
    headless: true,
    async execute(): Promise<ToolResult> {
      return { ok: true, output: "" };
    },
  };
  return {
    id,
    displayName: `Mod ${id}`,
    category: "offense",
    version: "0.1.0",
    description: `module ${id}`,
    rank: "good",
    tools: [tool],
    ...extra,
  };
}

describe("projectModule", () => {
  it("projects scalar fields + tool metadata", () => {
    const mod = mkMod("m");
    const entry = projectModule(mod, 1234);
    expect(entry.id).toBe("m");
    expect(entry.rank).toBe("good");
    expect(entry.mtime).toBe(1234);
    expect(entry.tools).toEqual([{ name: "m:run", description: "m runner", headless: true }]);
  });

  it("omits optional fields when unset", () => {
    const mod = mkMod("m", { rank: undefined });
    const entry = projectModule(mod);
    expect(entry.rank).toBeUndefined();
    expect(entry.references).toBeUndefined();
  });

  it("preserves references + disclosureDate when present", () => {
    const mod = mkMod("m", {
      references: [{ type: "CVE", value: "CVE-2024-9999" }],
      disclosureDate: "2024-01-01",
    });
    const entry = projectModule(mod);
    expect(entry.references).toEqual([{ type: "CVE", value: "CVE-2024-9999" }]);
    expect(entry.disclosureDate).toBe("2024-01-01");
  });
});

describe("ModuleCache", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(tmpdir(), "kzcache-"));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("starts empty when no cache file exists", () => {
    const cache = new ModuleCache(dir);
    cache.load();
    expect(cache.size()).toBe(0);
    expect(cache.all()).toEqual([]);
  });

  it("upsert + save round-trips through disk", () => {
    const cache = new ModuleCache(dir);
    cache.upsertFromModule(mkMod("a"), 1);
    cache.upsertFromModule(mkMod("b"), 2);
    cache.save();

    const reloaded = new ModuleCache(dir);
    reloaded.load();
    expect(reloaded.size()).toBe(2);
    expect(reloaded.get("a")?.mtime).toBe(1);
    expect(reloaded.get("b")?.mtime).toBe(2);
  });

  it("writes to <dataDir>/module-cache.json", () => {
    const cache = new ModuleCache(dir);
    cache.upsertFromModule(mkMod("a"));
    cache.save();
    const file = path.join(dir, MODULE_CACHE_FILENAME);
    expect(existsSync(file)).toBe(true);
    const parsed = JSON.parse(readFileSync(file, "utf8"));
    expect(parsed.version).toBe(1);
    expect(parsed.entries.a.id).toBe("a");
  });

  it("ignores a mismatched-version cache file", () => {
    const cache = new ModuleCache(dir);
    cache.upsertFromModule(mkMod("a"));
    cache.save();

    // Corrupt the on-disk version.
    const file = path.join(dir, MODULE_CACHE_FILENAME);
    const raw = JSON.parse(readFileSync(file, "utf8"));
    raw.version = 99;
    const fs = require("node:fs");
    fs.writeFileSync(file, JSON.stringify(raw));

    const reloaded = new ModuleCache(dir);
    reloaded.load();
    expect(reloaded.size()).toBe(0);
  });

  it("ignores a malformed cache file", () => {
    const file = path.join(dir, MODULE_CACHE_FILENAME);
    const fs = require("node:fs");
    fs.writeFileSync(file, "{not json");
    const cache = new ModuleCache(dir);
    expect(() => cache.load()).not.toThrow();
    expect(cache.size()).toBe(0);
  });

  it("remove() drops an entry", () => {
    const cache = new ModuleCache(dir);
    cache.upsertFromModule(mkMod("a"));
    expect(cache.remove("a")).toBe(true);
    expect(cache.remove("a")).toBe(false);
    expect(cache.size()).toBe(0);
  });

  it("staleIds() flags missing + mismatched-mtime entries", () => {
    const cache = new ModuleCache(dir);
    cache.upsertFromModule(mkMod("a"), 10);
    cache.upsertFromModule(mkMod("b"), 20);

    expect(cache.staleIds({ a: 10, b: 20 })).toEqual([]);
    expect(cache.staleIds({ a: 10, b: 999 })).toEqual(["b"]);
    expect(cache.staleIds({ a: 10, b: 20, c: 1 })).toEqual(["c"]);
  });

  it("upsert overwrites an existing entry", () => {
    const cache = new ModuleCache(dir);
    cache.upsertFromModule(mkMod("a", { description: "v1" }), 1);
    cache.upsertFromModule(mkMod("a", { description: "v2" }), 2);
    expect(cache.size()).toBe(1);
    expect(cache.get("a")?.description).toBe("v2");
    expect(cache.get("a")?.mtime).toBe(2);
  });
});
