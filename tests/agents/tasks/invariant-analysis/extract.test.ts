import { describe, expect, it } from "vitest";
import {
  __invariantExtractInternals,
  invariantExtractTask,
} from "../../../../src/agents/tasks/invariant-analysis/extract.js";

const { buildExtractionPrompt, parseInvariants, normalizeInvariant } = __invariantExtractInternals;

describe("invariantExtractTask", () => {
  it("has correct metadata", () => {
    expect(invariantExtractTask.id).toBe("invariant-extract");
    expect(invariantExtractTask.outputKind).toBe("custom");
    expect(invariantExtractTask.dependsOn).toEqual(["context-gatherer"]);
  });
});

describe("buildExtractionPrompt", () => {
  it("includes repo context when provided", () => {
    const prompt = buildExtractionPrompt(
      {
        languages: ["Python"],
        frameworks: ["Django"],
        authPatterns: ["JWT"],
        sanitizationLibs: [],
        ormOrDb: [],
        entryPoints: [],
      },
      true,
      200,
    );
    expect(prompt).toContain("Python");
    expect(prompt).toContain("Django");
    expect(prompt).toContain("security-relevant");
  });

  it("works without repo context", () => {
    const prompt = buildExtractionPrompt(undefined, false, 100);
    expect(prompt).toContain("invariant");
    expect(prompt).toContain("100");
    expect(prompt).toContain("all invariants");
  });
});

describe("parseInvariants", () => {
  it("parses valid invariants", () => {
    const raw = {
      invariants: [
        {
          id: "inv-1",
          kind: "security-invariant",
          filePath: "src/auth/middleware.ts",
          startLine: 10,
          endLine: 15,
          statement: "User must be authenticated",
          confidence: 0.9,
          derivedFrom: "middleware check",
          securityRelevance: "high",
          category: "authentication",
        },
      ],
    };

    const invariants = parseInvariants(raw, false, 200);
    expect(invariants).toHaveLength(1);
    expect(invariants[0].id).toBe("inv-1");
    expect(invariants[0].kind).toBe("security-invariant");
    expect(invariants[0].scope.filePath).toBe("src/auth/middleware.ts");
    expect(invariants[0].statement).toBe("User must be authenticated");
    expect(invariants[0].securityRelevance).toBe("high");
  });

  it("filters non-security invariants when securityOnly", () => {
    const raw = {
      invariants: [
        {
          id: "inv-1",
          kind: "security-invariant",
          filePath: "a.ts",
          startLine: 1,
          endLine: 1,
          statement: "Auth required",
          confidence: 0.9,
          derivedFrom: "x",
          securityRelevance: "high",
        },
        {
          id: "inv-2",
          kind: "data-invariant",
          filePath: "b.ts",
          startLine: 1,
          endLine: 1,
          statement: "Array not empty",
          confidence: 0.9,
          derivedFrom: "x",
          securityRelevance: "none",
        },
        {
          id: "inv-3",
          kind: "precondition",
          filePath: "c.ts",
          startLine: 1,
          endLine: 1,
          statement: "Low relevance",
          confidence: 0.8,
          derivedFrom: "x",
          securityRelevance: "low",
        },
      ],
    };

    const invariants = parseInvariants(raw, true, 200);
    expect(invariants).toHaveLength(1);
    expect(invariants[0].id).toBe("inv-1");
  });

  it("respects maxInvariants", () => {
    const raw = {
      invariants: Array.from({ length: 10 }, (_, i) => ({
        id: `inv-${i}`,
        kind: "security-invariant",
        filePath: `src/file${i}.ts`,
        startLine: 1,
        endLine: 1,
        statement: `Invariant ${i}`,
        confidence: 0.9,
        derivedFrom: "x",
        securityRelevance: "high",
      })),
    };

    const invariants = parseInvariants(raw, false, 3);
    expect(invariants).toHaveLength(3);
  });

  it("returns empty for invalid input", () => {
    expect(parseInvariants(null, false, 200)).toEqual([]);
    expect(parseInvariants({ invariants: "not-array" }, false, 200)).toEqual([]);
  });
});

describe("normalizeInvariant", () => {
  it("returns null for missing required fields", () => {
    expect(normalizeInvariant({})).toBeNull();
    expect(normalizeInvariant({ id: "inv-1" })).toBeNull();
    expect(normalizeInvariant({ id: "inv-1", filePath: "a.ts" })).toBeNull();
  });

  it("normalizes valid invariant", () => {
    const inv = normalizeInvariant({
      id: "inv-1",
      kind: "precondition",
      filePath: "src/handler.ts",
      startLine: 5,
      endLine: 10,
      functionName: "handleRequest",
      statement: "Input is validated",
      confidence: 0.85,
      derivedFrom: "guard clause",
      securityRelevance: "medium",
    });

    expect(inv).not.toBeNull();
    expect(inv!.kind).toBe("precondition");
    expect(inv!.scope.functionName).toBe("handleRequest");
    expect(inv!.confidence).toBe(0.85);
  });

  it("defaults invalid kind to security-invariant", () => {
    const inv = normalizeInvariant({
      id: "inv-1",
      kind: "invalid",
      filePath: "a.ts",
      startLine: 1,
      endLine: 1,
      statement: "x",
      confidence: 0.5,
      derivedFrom: "x",
      securityRelevance: "low",
    });

    expect(inv!.kind).toBe("security-invariant");
  });
});
