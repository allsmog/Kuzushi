import { describe, it, expect } from "vitest";
import { __taskSelectorInternals, SELECTABLE_TASK_IDS } from "../../../src/agents/tasks/task-selector.js";
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

  it("includes code-config-detect as always-recommended regardless of context", () => {
    // code-config-detect is always present via ALWAYS_RECOMMENDED ("security-misconfig").
    // Auth patterns and ORM/DB context do not add distinct tasks — they also
    // resolve to code-config-detect which is already included.
    const emptyCtx = makeContext({});
    const result = selectTasks(emptyCtx);
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

  it("recommends both threat-model-stride and threat-model-pasta for multi-language repos", () => {
    const ctx = makeContext({ languages: ["TypeScript", "Python"] });
    const result = selectTasks(ctx);
    expect(result.recommendedTasks).toContain("threat-model-stride");
    expect(result.recommendedTasks).toContain("threat-model-pasta");
  });

  it("provides reasoning for each recommended task", () => {
    const ctx = makeContext({ languages: ["Go"] });
    const result = selectTasks(ctx);
    expect(result.reasoning["race-condition-detect"]).toBe(
      "Go: goroutine races, crypto misuse, and dependency risk are common review targets",
    );
    // secrets-crypto-detect is always-recommended — reasoning should be the default
    expect(result.reasoning["secrets-crypto-detect"]).toBe(
      "Always recommended: secrets and crypto detection",
    );
  });

  it("preserves always-recommended reasoning even when rules also match", () => {
    // TypeScript rule includes "secrets" which normalizes to secrets-crypto-detect,
    // but the always-recommended reasoning should be preserved
    const ctx = makeContext({ languages: ["TypeScript"] });
    const result = selectTasks(ctx);
    expect(result.reasoning["secrets-crypto-detect"]).toBe(
      "Always recommended: secrets and crypto detection",
    );
    expect(result.reasoning["code-config-detect"]).toBe(
      "Always recommended: code and config security checks",
    );
  });

  it("uses first matching rule reasoning for multi-rule tasks", () => {
    // supply-chain-detect is matched by JS/TS rule (first) and Go rule (second).
    // First-match-wins should use the JS/TS reasoning, not Go.
    const ctx = makeContext({ languages: ["TypeScript", "Go"] });
    const result = selectTasks(ctx);
    expect(result.reasoning["supply-chain-detect"]).toBe(
      "JS/TS ecosystem: prioritize dangerous APIs, SSRF, prototype pollution, templating, and package supply-chain risk",
    );
  });

  it("returns undefined skippedTasks when context is provided", () => {
    const ctx = makeContext({ languages: ["Go"] });
    const result = selectTasks(ctx);
    expect(result.skippedTasks).toBeUndefined();
  });

  it("handles undefined context gracefully", () => {
    const result = selectTasks(undefined);
    expect(result.recommendedTasks.length).toBeGreaterThanOrEqual(2);
    expect(result.skippedTasks).toBeDefined();
    expect(result.skippedTasks!.some((s) => s.reason.includes("No repo context"))).toBe(true);
  });
});

describe("SELECTABLE_TASK_IDS", () => {
  it("contains all task IDs reachable from SELECTION_RULES", () => {
    // Every task that selectTasks can ever recommend must be in SELECTABLE_TASK_IDS
    // (after normalization). Test with a context that triggers all rules.
    const ctx = makeContext({
      languages: ["TypeScript", "Go", "Python", "Java", "Ruby", "PHP"],
      frameworks: ["GraphQL"],
      authPatterns: ["JWT"],
      ormOrDb: ["Mongoose", "Prisma"],
      entryPoints: ["src/graphql/resolvers.ts"],
    });
    const result = selectTasks(ctx);
    for (const taskId of result.recommendedTasks) {
      expect(SELECTABLE_TASK_IDS.has(taskId)).toBe(true);
    }
  });

  it("does not contain infrastructure tasks", () => {
    const infrastructureTasks = [
      "context-gatherer",
      "context-enricher",
      "task-selector",
      "taint-analysis-source",
      "taint-analysis-sink",
      "taint-analysis-propagation",
      "diff-review",
    ];
    for (const taskId of infrastructureTasks) {
      expect(SELECTABLE_TASK_IDS.has(taskId)).toBe(false);
    }
  });

  it("contains threat-model-pasta", () => {
    expect(SELECTABLE_TASK_IDS.has("threat-model-pasta")).toBe(true);
  });

  it("does not contain diff-review", () => {
    expect(SELECTABLE_TASK_IDS.has("diff-review")).toBe(false);
  });
});
