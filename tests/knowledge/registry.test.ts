import { describe, expect, it } from "vitest";
import { createDefaultKnowledgeRegistry } from "../../src/knowledge/index.js";
import { InMemoryKnowledgeRegistry } from "../../src/knowledge/registry.js";
import type { KnowledgeModule } from "../../src/knowledge/types.js";

function makeModule(overrides: Partial<KnowledgeModule> = {}): KnowledgeModule {
  return {
    id: "test-mod",
    cwes: ["CWE-89"],
    languages: [],
    frameworks: [],
    dangerousPatterns: [],
    safePatterns: [],
    bypassTechniques: ["technique-1"],
    detectionKeywords: [],
    fixExamples: [],
    tags: ["injection"],
    ...overrides,
  };
}

describe("InMemoryKnowledgeRegistry", () => {
  it("registers and retrieves by id", () => {
    const reg = new InMemoryKnowledgeRegistry();
    const mod = makeModule({ id: "my-mod" });
    reg.register(mod);
    expect(reg.getById("my-mod")).toBe(mod);
    expect(reg.getById("nonexistent")).toBeUndefined();
    expect(reg.ids()).toContain("my-mod");
  });

  it("queries by CWE", () => {
    const reg = new InMemoryKnowledgeRegistry();
    reg.register(makeModule({ id: "sqli", cwes: ["CWE-89"] }));
    reg.register(makeModule({ id: "xss", cwes: ["CWE-79"] }));

    const results = reg.query({ cwes: ["CWE-89"] });
    expect(results).toHaveLength(1);
    expect(results[0].id).toBe("sqli");
  });

  it("queries by CWE without prefix", () => {
    const reg = new InMemoryKnowledgeRegistry();
    reg.register(makeModule({ id: "sqli", cwes: ["CWE-89"] }));

    const results = reg.query({ cwes: ["89"] });
    expect(results).toHaveLength(1);
    expect(results[0].id).toBe("sqli");
  });

  it("queries by vulnType", () => {
    const reg = new InMemoryKnowledgeRegistry();
    reg.register(makeModule({ id: "sqli", tags: ["injection", "sql"] }));
    reg.register(makeModule({ id: "xss", tags: ["injection", "xss"] }));

    const results = reg.query({ vulnType: "sql" });
    expect(results).toHaveLength(1);
    expect(results[0].id).toBe("sqli");
  });

  it("queries by tag", () => {
    const reg = new InMemoryKnowledgeRegistry();
    reg.register(makeModule({ id: "sqli", tags: ["injection"] }));
    reg.register(makeModule({ id: "crypto", tags: ["crypto"] }));

    const results = reg.query({ tags: ["injection"] });
    expect(results).toHaveLength(1);
    expect(results[0].id).toBe("sqli");
  });

  it("filters by language", () => {
    const reg = new InMemoryKnowledgeRegistry();
    reg.register(makeModule({ id: "go-race", cwes: ["CWE-362"], languages: ["Go"] }));
    reg.register(makeModule({ id: "js-race", cwes: ["CWE-362"], languages: ["JavaScript"] }));

    const goResults = reg.query({ cwes: ["CWE-362"], language: "Go" });
    expect(goResults).toHaveLength(1);
    expect(goResults[0].id).toBe("go-race");
  });

  it("returns all modules when no filter", () => {
    const reg = new InMemoryKnowledgeRegistry();
    reg.register(makeModule({ id: "a" }));
    reg.register(makeModule({ id: "b" }));
    const results = reg.query({});
    expect(results).toHaveLength(2);
  });

  it("formatForPrompt returns bypass section", () => {
    const reg = new InMemoryKnowledgeRegistry();
    const mod = makeModule({ id: "sqli", bypassTechniques: ["technique-A"] });
    reg.register(mod);

    const lines = reg.formatForPrompt([mod], "bypass");
    expect(lines.some((l) => l.includes("technique-A"))).toBe(true);
    expect(lines.some((l) => l.includes("Bypass Techniques"))).toBe(true);
  });

  it("formatForPrompt returns empty for empty modules", () => {
    const reg = new InMemoryKnowledgeRegistry();
    expect(reg.formatForPrompt([])).toEqual([]);
  });
});

describe("createDefaultKnowledgeRegistry", () => {
  it("contains expected built-in modules", () => {
    const reg = createDefaultKnowledgeRegistry();
    const ids = reg.ids();
    expect(ids).toContain("sqli");
    expect(ids).toContain("xss");
    expect(ids).toContain("ssrf");
    expect(ids).toContain("crypto-misuse");
    expect(ids).toContain("command-injection");
    expect(ids).toContain("path-traversal");
    expect(ids).toContain("auth-bypass");
    expect(ids).toContain("deserialization");
    expect(ids).toContain("race-condition");
  });

  it("all modules have valid CWEs", () => {
    const reg = createDefaultKnowledgeRegistry();
    for (const id of reg.ids()) {
      const mod = reg.getById(id)!;
      expect(mod.cwes.length).toBeGreaterThan(0);
      for (const cwe of mod.cwes) {
        expect(cwe).toMatch(/^CWE-\d+$/);
      }
    }
  });

  it("all modules have non-empty bypass techniques", () => {
    const reg = createDefaultKnowledgeRegistry();
    for (const id of reg.ids()) {
      const mod = reg.getById(id)!;
      expect(mod.bypassTechniques.length).toBeGreaterThan(0);
    }
  });

  it("queries by CWE-918 return SSRF module", () => {
    const reg = createDefaultKnowledgeRegistry();
    const results = reg.query({ cwes: ["CWE-918"] });
    expect(results.some((m) => m.id === "ssrf")).toBe(true);
  });
});
