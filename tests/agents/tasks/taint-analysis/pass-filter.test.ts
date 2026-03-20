import { describe, expect, it } from "vitest";
import {
  resolveContextAwarePasses,
  PASS_RELEVANCE_MAP,
  type TaintAnalysisPassId,
} from "../../../../src/agents/tasks/taint-analysis/types.js";
import type { RepoContext } from "../../../../src/types.js";

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

const DEFAULT_FALLBACK: TaintAnalysisPassId[] = [1, 2, 3, 4, 5];

describe("resolveContextAwarePasses", () => {
  it("returns fallback passes when no context", () => {
    const result = resolveContextAwarePasses(undefined, DEFAULT_FALLBACK);
    expect(result).toEqual(DEFAULT_FALLBACK);
  });

  it("always includes passes 1, 2, 6, 11 (always-on)", () => {
    const ctx = makeContext({ languages: ["Go"] });
    const result = resolveContextAwarePasses(ctx, DEFAULT_FALLBACK);
    expect(result).toContain(1);  // Path Traversal
    expect(result).toContain(2);  // Command Injection
    expect(result).toContain(6);  // Unsafe Deserialization
    expect(result).toContain(11); // Log Injection
  });

  it("filters out SSRF/XSS/redirect/header-injection for non-web repos", () => {
    const ctx = makeContext({ languages: ["Go"] }); // no web framework
    const result = resolveContextAwarePasses(ctx, DEFAULT_FALLBACK);
    expect(result).not.toContain(3);  // SSRF
    expect(result).not.toContain(7);  // XSS
    expect(result).not.toContain(9);  // Open Redirect
    expect(result).not.toContain(10); // HTTP Header Injection
    expect(result).not.toContain(16); // File Upload
  });

  it("includes web-specific passes when web framework present", () => {
    const ctx = makeContext({ languages: ["Go"], frameworks: ["Gin"] });
    const result = resolveContextAwarePasses(ctx, DEFAULT_FALLBACK);
    expect(result).toContain(3);  // SSRF
    expect(result).toContain(7);  // XSS
    expect(result).toContain(9);  // Open Redirect
    expect(result).toContain(10); // HTTP Header Injection
    expect(result).toContain(16); // File Upload
  });

  it("includes prototype-pollution for JS/TS repos", () => {
    const ctx = makeContext({ languages: ["TypeScript"], frameworks: ["Express"] });
    const result = resolveContextAwarePasses(ctx, DEFAULT_FALLBACK);
    expect(result).toContain(14); // Prototype Pollution
  });

  it("excludes prototype-pollution for Go repos", () => {
    const ctx = makeContext({ languages: ["Go"], frameworks: ["Gin"] });
    const result = resolveContextAwarePasses(ctx, DEFAULT_FALLBACK);
    expect(result).not.toContain(14);
  });

  it("includes SQL injection when SQL DB detected", () => {
    const ctx = makeContext({ languages: ["Python"], ormOrDb: ["PostgreSQL"] });
    const result = resolveContextAwarePasses(ctx, DEFAULT_FALLBACK);
    expect(result).toContain(5);  // SQL Injection
    expect(result).toContain(19); // Second-Order Injection
  });

  it("excludes SQL injection when no SQL DB", () => {
    const ctx = makeContext({ languages: ["Python"] });
    const result = resolveContextAwarePasses(ctx, DEFAULT_FALLBACK);
    expect(result).not.toContain(5);
    expect(result).not.toContain(19);
  });

  it("includes LDAP injection for Java repos", () => {
    const ctx = makeContext({ languages: ["Java"], frameworks: ["Spring"] });
    const result = resolveContextAwarePasses(ctx, DEFAULT_FALLBACK);
    expect(result).toContain(12); // LDAP Injection
  });

  it("excludes LDAP injection for JS repos", () => {
    const ctx = makeContext({ languages: ["JavaScript"], frameworks: ["Express"] });
    const result = resolveContextAwarePasses(ctx, DEFAULT_FALLBACK);
    expect(result).not.toContain(12);
  });

  it("includes integer overflow for C/C++/Go/Rust", () => {
    const ctx = makeContext({ languages: ["Go"] });
    const result = resolveContextAwarePasses(ctx, DEFAULT_FALLBACK);
    expect(result).toContain(17); // Integer Overflow
  });

  it("excludes integer overflow for Python", () => {
    const ctx = makeContext({ languages: ["Python"] });
    const result = resolveContextAwarePasses(ctx, DEFAULT_FALLBACK);
    expect(result).not.toContain(17);
  });

  it("includes SSTI for Python repos", () => {
    const ctx = makeContext({ languages: ["Python"], frameworks: ["Flask"] });
    const result = resolveContextAwarePasses(ctx, DEFAULT_FALLBACK);
    expect(result).toContain(13); // SSTI
  });

  it("returns sorted passes", () => {
    const ctx = makeContext({ languages: ["TypeScript"], frameworks: ["Express"], ormOrDb: ["MySQL"] });
    const result = resolveContextAwarePasses(ctx, DEFAULT_FALLBACK);
    for (let i = 1; i < result.length; i++) {
      expect(result[i]).toBeGreaterThan(result[i - 1]);
    }
  });

  it("Go repo with no web framework gets correct subset", () => {
    const ctx = makeContext({ languages: ["Go"] });
    const result = resolveContextAwarePasses(ctx, DEFAULT_FALLBACK);
    // Should include: 1 (path traversal), 2 (cmd injection), 6 (deser),
    // 8 (XXE), 11 (log injection), 17 (integer overflow)
    expect(result).toEqual([1, 2, 6, 8, 11, 17]);
  });

  it("JS/TS Express repo gets comprehensive set", () => {
    const ctx = makeContext({
      languages: ["TypeScript"],
      frameworks: ["Express"],
      ormOrDb: ["prisma"],
    });
    const result = resolveContextAwarePasses(ctx, DEFAULT_FALLBACK);
    // Should include many passes
    expect(result).toContain(1);  // Path Traversal
    expect(result).toContain(3);  // SSRF (web)
    expect(result).toContain(4);  // Code Injection (JS/TS)
    expect(result).toContain(5);  // SQL Injection (prisma)
    expect(result).toContain(7);  // XSS (web)
    expect(result).toContain(13); // SSTI (JS/TS)
    expect(result).toContain(14); // Prototype Pollution (JS/TS)
    expect(result).toContain(15); // Mass Assignment (JS/TS)
    expect(result).toContain(18); // Regex Injection (JS/TS)
    expect(result).toContain(19); // Second-Order (sql db)
  });
});

describe("PASS_RELEVANCE_MAP", () => {
  it("covers all 19 passes", () => {
    const passIds = PASS_RELEVANCE_MAP.map(m => m.passId);
    expect(passIds).toHaveLength(19);
    for (let i = 1; i <= 19; i++) {
      expect(passIds).toContain(i);
    }
  });
});
