import { describe, expect, it } from "vitest";
import { formatSearchResult, parseQuery, searchCatalog } from "../../src/copilot/search.js";
import type { CopilotModule, ModuleTool, ToolResult } from "../../src/modules/types.js";

function tool(name: string, description: string, headless = true): ModuleTool {
  return {
    name,
    description,
    inputSchema: { type: "object" },
    headless,
    async execute(): Promise<ToolResult> {
      return { ok: true, output: name };
    },
  };
}

const modules: CopilotModule[] = [
  {
    id: "sast",
    displayName: "SAST",
    category: "defense",
    version: "1.0.0",
    description: "Static analysis and triage",
    rank: "excellent",
    authors: ["Kuzushi Team"],
    references: [
      { type: "CVE", value: "2024-1234" },
      { type: "CWE", value: "79" },
    ],
    tools: [tool("sast:scan", "Run the SAST pipeline"), tool("sast:triage", "Triage findings")],
  },
  {
    id: "randori",
    displayName: "Randori",
    category: "offense",
    version: "0.2.0",
    description: "PASTA threat modeling",
    rank: "good",
    tools: [tool("randori:pasta", "Run PASTA stages")],
  },
];

describe("parseQuery", () => {
  it("splits free text and key:value filters", () => {
    const q = parseQuery("threat type:module category:offense -cve:2024 -S /pasta/");
    expect(q.freeText).toEqual(["threat"]);
    expect(q.filters.map((f) => f.key)).toEqual(["type", "category", "cve"]);
    expect(q.postRegex?.source).toContain("pasta");
  });

  it("supports numeric rank comparisons", () => {
    const q = parseQuery("rank:gte400");
    expect(q.filters[0].key).toBe("rank");
  });
});

describe("searchCatalog", () => {
  it("returns modules + tools, sorted by rank", () => {
    const res = searchCatalog(modules, "");
    const firstRanks = res.hits.map((h) => h.rank);
    // "excellent" > "good"
    expect(firstRanks[0]).toBe("excellent");
  });

  it("filters by type", () => {
    const res = searchCatalog(modules, "type:tool");
    expect(res.hits.every((h) => h.kind === "tool")).toBe(true);
  });

  it("filters by category", () => {
    const res = searchCatalog(modules, "category:offense");
    expect(res.hits.every((h) => h.module.id === "randori")).toBe(true);
  });

  it("filters by cve reference", () => {
    const res = searchCatalog(modules, "cve:2024");
    expect(res.hits.length).toBeGreaterThan(0);
    expect(res.hits.every((h) => h.module.id === "sast")).toBe(true);
  });

  it("supports rank numeric comparison", () => {
    const res = searchCatalog(modules, "rank:gte500");
    // Only "excellent" (600) matches
    expect(res.hits.every((h) => h.rank === "excellent")).toBe(true);
  });

  it("negates with leading dash", () => {
    const res = searchCatalog(modules, "-category:offense");
    expect(res.hits.some((h) => h.module.id === "randori")).toBe(false);
  });

  it("free-text matches name or description", () => {
    const res = searchCatalog(modules, "pasta");
    expect(res.hits.length).toBeGreaterThan(0);
    expect(res.hits[0].ref).toMatch(/randori/);
  });
});

describe("formatSearchResult", () => {
  it("renders a table with headers", () => {
    const res = searchCatalog(modules, "");
    const out = formatSearchResult(res);
    expect(out).toContain("Rank");
    expect(out).toContain("Type");
    expect(out).toContain("sast");
  });

  it("reports no results gracefully", () => {
    const res = searchCatalog(modules, "nothingmatches");
    expect(formatSearchResult(res)).toBe("  No results.");
  });
});
