import { describe, expect, it } from "vitest";
import {
  __contextEnricherInternals,
  contextEnricherTask,
} from "../../../src/agents/tasks/context-enricher.js";
import type { DagRunContext } from "../../../src/agents/types.js";
import type { KuzushiConfig } from "../../../src/types.js";

const { resolveConfig, buildPrompt, normalizeOutput } = __contextEnricherInternals;

function makeContext(overrides: Record<string, unknown> = {}): DagRunContext {
  return {
    runId: "test-run",
    repoRoot: "/tmp/repo",
    repoName: "test-repo",
    config: makeConfig(overrides),
    bus: {} as DagRunContext["bus"],
    upstreamOutputs: new Map(),
  };
}

function makeConfig(overrides: Record<string, unknown> = {}): KuzushiConfig {
  return {
    model: "anthropic:claude-sonnet-4-6",
    busBackend: "in-process",
    triageBatchSize: 15,
    triageConcurrency: 1,
    scanMode: "sequential",
    tasks: ["semgrep"],
    severity: ["ERROR"],
    excludePatterns: [],
    taskConfig: {},
    ...overrides,
  };
}

describe("contextEnricherTask", () => {
  it("has correct metadata", () => {
    expect(contextEnricherTask.id).toBe("context-enricher");
    expect(contextEnricherTask.outputKind).toBe("custom");
    expect(contextEnricherTask.dependsOn).toEqual(["context-gatherer"]);
  });
});

describe("resolveConfig", () => {
  it("uses default model when no override", () => {
    const ctx = makeContext();
    const cfg = resolveConfig(ctx);
    expect(cfg.model).toBe("anthropic:claude-sonnet-4-6");
  });

  it("uses contextEnrichmentModel when set", () => {
    const ctx = makeContext({ taskConfig: { "context-enricher": { model: "openai:gpt-4" } } });
    const cfg = resolveConfig(ctx);
    expect(cfg.model).toBe("openai:gpt-4");
  });
});

describe("buildPrompt", () => {
  it("includes analysis tasks", () => {
    const prompt = buildPrompt(undefined);
    expect(prompt).toContain("Custom middleware discovery");
    expect(prompt).toContain("Custom sanitizer discovery");
    expect(prompt).toContain("Trust boundary mapping");
    expect(prompt).toContain("Data classification");
    expect(prompt).toContain("Architectural notes");
  });

  it("includes repo context when provided", () => {
    const prompt = buildPrompt({
      languages: ["TypeScript"],
      frameworks: ["Express"],
      authPatterns: ["JWT"],
      sanitizationLibs: ["DOMPurify"],
      ormOrDb: ["Prisma"],
      entryPoints: ["src/index.ts"],
    });
    expect(prompt).toContain("TypeScript");
    expect(prompt).toContain("Express");
    expect(prompt).toContain("JWT");
  });
});

describe("normalizeOutput", () => {
  it("normalizes valid enrichment output", () => {
    const raw = {
      customMiddleware: [
        { name: "authMiddleware", filePath: "src/middleware/auth.ts", purpose: "JWT validation" },
      ],
      customSanitizers: [
        {
          name: "sanitizeInput",
          filePath: "src/utils/sanitize.ts",
          sanitizationType: "XSS prevention",
        },
      ],
      trustBoundaries: [
        {
          name: "API Gateway",
          description: "External requests enter here",
          entryPoints: ["src/routes/api.ts"],
        },
      ],
      dataClassifications: [
        { dataType: "User PII", sensitivity: "confidential", locations: ["src/models/user.ts"] },
      ],
      architecturalNotes: ["Uses Redis for session storage"],
    };

    const result = normalizeOutput(raw);
    expect(result.customMiddleware).toHaveLength(1);
    expect(result.customMiddleware[0].name).toBe("authMiddleware");
    expect(result.customSanitizers).toHaveLength(1);
    expect(result.trustBoundaries).toHaveLength(1);
    expect(result.dataClassifications).toHaveLength(1);
    expect(result.dataClassifications[0].sensitivity).toBe("confidential");
    expect(result.architecturalNotes).toEqual(["Uses Redis for session storage"]);
  });

  it("returns empty arrays for missing fields", () => {
    const result = normalizeOutput({});
    expect(result.customMiddleware).toEqual([]);
    expect(result.customSanitizers).toEqual([]);
    expect(result.trustBoundaries).toEqual([]);
    expect(result.dataClassifications).toEqual([]);
    expect(result.architecturalNotes).toEqual([]);
  });

  it("returns empty arrays for invalid input", () => {
    const result = normalizeOutput(null);
    expect(result.customMiddleware).toEqual([]);
    expect(result.architecturalNotes).toEqual([]);
  });

  it("filters invalid sensitivity values", () => {
    const raw = {
      customMiddleware: [],
      customSanitizers: [],
      trustBoundaries: [],
      dataClassifications: [{ dataType: "test", sensitivity: "invalid-level", locations: [] }],
      architecturalNotes: [],
    };

    const result = normalizeOutput(raw);
    expect(result.dataClassifications).toEqual([]);
  });
});
