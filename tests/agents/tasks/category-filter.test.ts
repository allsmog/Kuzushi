import { describe, expect, it } from "vitest";
import {
  CATEGORY_SCOPE_HEADER,
  type CategoryBlock,
  type CategoryRelevance,
  filterBlocks,
  filterCategories,
  normalizeLanguageName,
} from "../../../src/agents/tasks/category-filter.js";
import type { FileIndex, RepoContext } from "../../../src/types.js";

function makeContext(overrides: Partial<RepoContext> = {}): RepoContext {
  return {
    languages: [],
    frameworks: [],
    authPatterns: [],
    sanitizationLibs: [],
    ormOrDb: [],
    entryPoints: [],
    ...overrides,
  };
}

function makeFileIndex(paths: string[]): FileIndex {
  return {
    tree: paths.map((p) => ({ path: p })),
    totalFiles: paths.length,
    truncated: false,
    patternMatches: {},
  };
}

const SAMPLE_MAPPINGS: CategoryRelevance[] = [
  { id: "always-on", always: true },
  { id: "js-only", languages: ["JavaScript", "TypeScript"] },
  { id: "go-only", languages: ["Go"] },
  { id: "auth-gated", requiresAuth: true },
  { id: "mongo-gated", ormOrDbPattern: /mongo|mongoose/i },
  { id: "docker-gated", fileTreePattern: /Dockerfile|docker-compose/i },
  { id: "web-framework-gated", requiresWebFramework: true },
];

describe("normalizeLanguageName", () => {
  it("normalizes common language names", () => {
    expect(normalizeLanguageName("TypeScript")).toBe("typescript");
    expect(normalizeLanguageName("JavaScript")).toBe("javascript");
    expect(normalizeLanguageName("Python")).toBe("python");
    expect(normalizeLanguageName("Go")).toBe("go");
  });

  it("resolves aliases", () => {
    expect(normalizeLanguageName("ts")).toBe("typescript");
    expect(normalizeLanguageName("tsx")).toBe("typescript");
    expect(normalizeLanguageName("js")).toBe("javascript");
    expect(normalizeLanguageName("jsx")).toBe("javascript");
    expect(normalizeLanguageName("py")).toBe("python");
    expect(normalizeLanguageName("golang")).toBe("go");
    expect(normalizeLanguageName("kt")).toBe("kotlin");
    expect(normalizeLanguageName("rb")).toBe("ruby");
  });

  it("is case-insensitive", () => {
    expect(normalizeLanguageName("TYPESCRIPT")).toBe("typescript");
    expect(normalizeLanguageName("gO")).toBe("go");
  });
});

describe("filterCategories", () => {
  it("returns all categories when no context", () => {
    const result = filterCategories(SAMPLE_MAPPINGS, undefined);
    expect(result.size).toBe(SAMPLE_MAPPINGS.length);
    for (const m of SAMPLE_MAPPINGS) {
      expect(result.has(m.id)).toBe(true);
    }
  });

  it("includes always-on categories regardless of context", () => {
    const result = filterCategories(SAMPLE_MAPPINGS, makeContext());
    expect(result.has("always-on")).toBe(true);
  });

  it("includes language-matched categories", () => {
    const jsContext = makeContext({ languages: ["TypeScript"] });
    const result = filterCategories(SAMPLE_MAPPINGS, jsContext);
    expect(result.has("js-only")).toBe(true);
    expect(result.has("go-only")).toBe(false);
  });

  it("includes Go-specific categories for Go repos", () => {
    const goContext = makeContext({ languages: ["Go"] });
    const result = filterCategories(SAMPLE_MAPPINGS, goContext);
    expect(result.has("go-only")).toBe(true);
    expect(result.has("js-only")).toBe(false);
  });

  it("includes auth-gated categories when auth patterns present", () => {
    const withAuth = makeContext({ authPatterns: ["JWT"] });
    const result = filterCategories(SAMPLE_MAPPINGS, withAuth);
    expect(result.has("auth-gated")).toBe(true);
  });

  it("excludes auth-gated categories when no auth patterns", () => {
    const result = filterCategories(SAMPLE_MAPPINGS, makeContext());
    expect(result.has("auth-gated")).toBe(false);
  });

  it("includes ormOrDb-matched categories", () => {
    const withMongo = makeContext({ ormOrDb: ["mongoose"] });
    const result = filterCategories(SAMPLE_MAPPINGS, withMongo);
    expect(result.has("mongo-gated")).toBe(true);
  });

  it("excludes ormOrDb-gated categories when no match", () => {
    const withSql = makeContext({ ormOrDb: ["postgresql"] });
    const result = filterCategories(SAMPLE_MAPPINGS, withSql);
    expect(result.has("mongo-gated")).toBe(false);
  });

  it("includes file-tree-matched categories", () => {
    const fileIndex = makeFileIndex(["Dockerfile", "src/app.ts"]);
    const result = filterCategories(SAMPLE_MAPPINGS, makeContext(), fileIndex);
    expect(result.has("docker-gated")).toBe(true);
  });

  it("excludes file-tree-gated categories when no matching files", () => {
    const fileIndex = makeFileIndex(["src/app.ts", "package.json"]);
    const result = filterCategories(SAMPLE_MAPPINGS, makeContext(), fileIndex);
    expect(result.has("docker-gated")).toBe(false);
  });

  it("includes web-framework-gated categories when web framework present", () => {
    const ctx = makeContext({ frameworks: ["Express"] });
    const result = filterCategories(SAMPLE_MAPPINGS, ctx);
    expect(result.has("web-framework-gated")).toBe(true);
  });

  it("excludes web-framework-gated categories when no web framework", () => {
    const ctx = makeContext({ frameworks: ["gRPC"] });
    const result = filterCategories(SAMPLE_MAPPINGS, ctx);
    expect(result.has("web-framework-gated")).toBe(false);
  });
});

describe("filterBlocks", () => {
  const blocks: CategoryBlock[] = [
    { id: "a", lines: ["line-a1", "line-a2"] },
    { id: "b", lines: ["line-b1"] },
    { id: "c", lines: ["line-c1", "line-c2", "line-c3"] },
  ];

  it("returns all lines when all included", () => {
    const included = new Set(["a", "b", "c"]);
    const result = filterBlocks(blocks, included);
    expect(result).toEqual(["line-a1", "line-a2", "line-b1", "line-c1", "line-c2", "line-c3"]);
  });

  it("filters out excluded blocks", () => {
    const included = new Set(["a", "c"]);
    const result = filterBlocks(blocks, included);
    expect(result).toEqual(["line-a1", "line-a2", "line-c1", "line-c2", "line-c3"]);
  });

  it("returns empty when none included", () => {
    const included = new Set<string>();
    const result = filterBlocks(blocks, included);
    expect(result).toEqual([]);
  });
});

describe("CATEGORY_SCOPE_HEADER", () => {
  it("contains category scope text", () => {
    const joined = CATEGORY_SCOPE_HEADER.join("\n");
    expect(joined).toContain("pre-filtered");
    expect(joined).toContain("not applicable");
  });
});
