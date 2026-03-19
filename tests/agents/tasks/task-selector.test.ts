import { describe, it, expect } from "vitest";
import { __taskSelectorInternals } from "../../../src/agents/tasks/task-selector.js";
import type { RepoContext } from "../../../src/types.js";

const { selectTasks } = __taskSelectorInternals;

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

describe("selectTasks", () => {
  it("always includes runnable secrets-crypto and code-config tasks", () => {
    const result = selectTasks(undefined);
    expect(result.recommendedTasks).toContain("secrets-crypto-detect");
    expect(result.recommendedTasks).toContain("code-config-detect");
  });

  it("recommends JS-specific tasks for TypeScript repos", () => {
    const ctx = makeContext({ languages: ["TypeScript"] });
    const result = selectTasks(ctx);
    expect(result.recommendedTasks).toContain("code-config-detect");
    expect(result.recommendedTasks).toContain("ssrf-detect");
    expect(result.recommendedTasks).toContain("secrets-crypto-detect");
    expect(result.recommendedTasks).toContain("prototype-pollution-detect");
    expect(result.recommendedTasks).toContain("template-injection-detect");
    expect(result.recommendedTasks).toContain("supply-chain-detect");
  });

  it("recommends Go-specific tasks for Go repos", () => {
    const ctx = makeContext({ languages: ["Go"] });
    const result = selectTasks(ctx);
    expect(result.recommendedTasks).toContain("race-condition-detect");
    expect(result.recommendedTasks).toContain("secrets-crypto-detect");
    expect(result.recommendedTasks).toContain("supply-chain-detect");
  });

  it("recommends Python-specific tasks", () => {
    const ctx = makeContext({ languages: ["Python"] });
    const result = selectTasks(ctx);
    expect(result.recommendedTasks).toContain("code-config-detect");
    expect(result.recommendedTasks).toContain("template-injection-detect");
  });

  it("recommends code-config-detect when auth patterns detected", () => {
    const ctx = makeContext({ authPatterns: ["JWT", "passport"] });
    const result = selectTasks(ctx);
    expect(result.recommendedTasks).toContain("code-config-detect");
  });

  it("recommends NoSQL injection and GraphQL checks when matching context is present", () => {
    const ctx = makeContext({
      ormOrDb: ["Mongoose"],
      frameworks: ["GraphQL"],
      entryPoints: ["src/graphql/resolvers.ts"],
    });
    const result = selectTasks(ctx);
    expect(result.recommendedTasks).toContain("nosql-injection-detect");
    expect(result.recommendedTasks).toContain("graphql-security-detect");
  });

  it("recommends threat-model-stride for multi-language repos", () => {
    const ctx = makeContext({ languages: ["TypeScript", "Python"] });
    const result = selectTasks(ctx);
    expect(result.recommendedTasks).toContain("threat-model-stride");
  });

  it("provides reasoning for each recommended task", () => {
    const ctx = makeContext({ languages: ["Go"] });
    const result = selectTasks(ctx);
    expect(result.reasoning["race-condition-detect"]).toBeDefined();
    expect(result.reasoning["secrets-crypto-detect"]).toBeDefined();
  });

  it("handles undefined context gracefully", () => {
    const result = selectTasks(undefined);
    expect(result.recommendedTasks.length).toBeGreaterThanOrEqual(2);
    expect(result.skippedTasks).toBeDefined();
    expect(result.skippedTasks!.some((s) => s.reason.includes("No repo context"))).toBe(true);
  });
});
