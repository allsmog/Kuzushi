import { describe, it, expect } from "vitest";
import {
  antiHallucinationModule,
  confidenceEscalationModule,
  frameworkAwarenessModule,
  falseDismissalModule,
  bypassExhaustionModule,
  proofLevelModule,
  knowledgeInjectionModule,
  composePromptModules,
} from "../../src/prompts/modules.js";
import type { RepoContext } from "../../src/types.js";

describe("antiHallucinationModule", () => {
  it("returns default constraints", () => {
    const result = antiHallucinationModule();
    expect(result).toContain("Anti-hallucination constraints");
    expect(result).toContain("Do NOT infer or speculate");
    expect(result).toContain("Confidence must reflect");
  });

  it("appends extra constraints", () => {
    const result = antiHallucinationModule({ extra: ["Only flag confirmed issues"] });
    expect(result).toContain("Only flag confirmed issues");
  });
});

describe("confidenceEscalationModule", () => {
  it("returns triage variant", () => {
    const result = confidenceEscalationModule("triage");
    expect(result).toContain("Confidence Escalation Protocol");
    expect(result).toContain("0.1-0.3: Read flagged code");
    expect(result).toContain("rationale MUST cite");
  });

  it("returns verification variant", () => {
    const result = confidenceEscalationModule("verification");
    expect(result).toContain("Confidence Escalation Protocol");
    expect(result).toContain("0.1-0.3: Identified theoretical weakness");
    expect(result).toContain("account takeover");
  });

  it("returns detection variant", () => {
    const result = confidenceEscalationModule("detection");
    expect(result).toContain("Confidence Escalation Protocol");
    expect(result).toContain("Pattern matched");
  });
});

describe("frameworkAwarenessModule", () => {
  it("returns empty string when no context", () => {
    expect(frameworkAwarenessModule()).toBe("");
    expect(frameworkAwarenessModule(undefined)).toBe("");
  });

  it("returns empty string when no frameworks", () => {
    const ctx: RepoContext = {
      languages: ["TypeScript"],
      frameworks: [],
      authPatterns: [],
      sanitizationLibs: [],
      ormOrDb: [],
      entryPoints: [],
    };
    expect(frameworkAwarenessModule(ctx)).toBe("");
  });

  it("includes framework names", () => {
    const ctx: RepoContext = {
      languages: ["TypeScript"],
      frameworks: ["Express", "React"],
      authPatterns: [],
      sanitizationLibs: [],
      ormOrDb: [],
      entryPoints: [],
    };
    const result = frameworkAwarenessModule(ctx);
    expect(result).toContain("Express");
    expect(result).toContain("React");
    expect(result).toContain("Framework Awareness");
  });
});

describe("falseDismissalModule", () => {
  it("contains all false-dismissal patterns", () => {
    const result = falseDismissalModule();
    expect(result).toContain("WAF will catch it");
    expect(result).toContain("parameterized queries");
    expect(result).toContain("framework handles XSS");
    expect(result).toContain("validate on the frontend");
    expect(result).toContain("re-investigate before concluding");
  });
});

describe("bypassExhaustionModule", () => {
  it("contains required bypass techniques", () => {
    const result = bypassExhaustionModule();
    expect(result).toContain("Bypass Exhaustion Protocol");
    expect(result).toContain("Direct exploitation");
    expect(result).toContain("Parameter pollution");
    expect(result).toContain("Encoding bypass");
    expect(result).toContain("Race condition");
    expect(result).toContain("Chained exploitation");
  });
});

describe("proofLevelModule", () => {
  it("contains all proof levels and verdicts", () => {
    const result = proofLevelModule();
    expect(result).toContain("Level 1");
    expect(result).toContain("Level 2");
    expect(result).toContain("Level 3");
    expect(result).toContain("Level 4");
    expect(result).toContain("EXPLOITED");
    expect(result).toContain("BLOCKED_BY_SECURITY");
    expect(result).toContain("OUT_OF_SCOPE");
    expect(result).toContain("FALSE_POSITIVE");
  });
});

describe("knowledgeInjectionModule", () => {
  it("returns empty string for empty sections", () => {
    expect(knowledgeInjectionModule([])).toBe("");
  });

  it("formats sections under Domain Knowledge header", () => {
    const result = knowledgeInjectionModule(["- Pattern 1", "- Pattern 2"]);
    expect(result).toContain("Domain Knowledge");
    expect(result).toContain("Pattern 1");
  });
});

describe("composePromptModules", () => {
  it("joins non-empty sections with double newlines", () => {
    const result = composePromptModules("Section A", "Section B");
    expect(result).toBe("Section A\n\nSection B");
  });

  it("filters out empty strings", () => {
    const result = composePromptModules("Section A", "", "Section C");
    expect(result).toBe("Section A\n\nSection C");
  });

  it("returns empty string for all-empty input", () => {
    expect(composePromptModules("", "")).toBe("");
  });
});
