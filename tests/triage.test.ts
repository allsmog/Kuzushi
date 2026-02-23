import { describe, it, expect } from "vitest";
import { triageFinding, parseVerdict, extractJson, parseTriageResponse } from "../src/triage.js";
import type { LLMClient, RawFinding } from "../src/types.js";

function makeFinding(): RawFinding {
  return {
    fingerprint: "test-fp",
    ruleId: "test.rule",
    filePath: "src/test.ts",
    startLine: 10,
    severity: "ERROR",
    message: "test finding",
    semgrepConfidence: "HIGH",
    subcategory: ["vuln"],
    likelihood: "HIGH",
    impact: "HIGH",
    cwe: ["CWE-79"],
    score: 54,
  };
}

function mockLLM(response: string): LLMClient {
  return {
    async complete(_system: string, _user: string): Promise<string> {
      return response;
    },
  };
}

describe("parseVerdict", () => {
  it("accepts tp", () => expect(parseVerdict("tp")).toBe("tp"));
  it("accepts fp", () => expect(parseVerdict("fp")).toBe("fp"));
  it("accepts needs_review", () => expect(parseVerdict("needs_review")).toBe("needs_review"));
  it("defaults unknown to needs_review", () => expect(parseVerdict("bogus")).toBe("needs_review"));
});

describe("extractJson", () => {
  it("extracts from markdown fence", () => {
    const text = 'Some text\n```json\n{"a":1}\n```\nmore text';
    expect(extractJson(text)).toBe('{"a":1}');
  });

  it("extracts bare JSON object", () => {
    const text = 'Here is the result: {"verdict":"fp"}';
    expect(extractJson(text)).toBe('{"verdict":"fp"}');
  });

  it("returns trimmed text when no JSON found", () => {
    expect(extractJson("  just text  ")).toBe("just text");
  });
});

describe("parseTriageResponse", () => {
  it("parses a valid JSON response", () => {
    const json = JSON.stringify({
      verdict: "fp",
      confidence: 0.95,
      rationale: "safe",
      verification_steps: ["step 1"],
      fix_patch: null,
    });
    const result = parseTriageResponse(json, "fp123");
    expect(result.fingerprint).toBe("fp123");
    expect(result.verdict).toBe("fp");
    expect(result.confidence).toBe(0.95);
    expect(result.verificationSteps).toEqual(["step 1"]);
  });

  it("clamps confidence above 1", () => {
    const json = JSON.stringify({ verdict: "tp", confidence: 1.5, rationale: "x", verification_steps: [] });
    expect(parseTriageResponse(json, "x").confidence).toBe(1);
  });

  it("clamps confidence below 0", () => {
    const json = JSON.stringify({ verdict: "tp", confidence: -0.5, rationale: "x", verification_steps: [] });
    expect(parseTriageResponse(json, "x").confidence).toBe(0);
  });

  it("handles missing verification_steps", () => {
    const json = JSON.stringify({ verdict: "fp", confidence: 0.9, rationale: "ok" });
    expect(parseTriageResponse(json, "x").verificationSteps).toEqual([]);
  });
});

describe("triageFinding", () => {
  it("returns a properly shaped TriageResult from mock LLM", async () => {
    const llm = mockLLM(
      JSON.stringify({
        fingerprint: "test-fp",
        verdict: "fp",
        confidence: 0.95,
        rationale: "Variable is hardcoded, not user-controlled",
        verification_steps: ["Check source", "Verify no user input"],
        fix_patch: null,
      }),
    );

    const result = await triageFinding(llm, makeFinding(), "// code context", "test-repo");

    expect(result.fingerprint).toBe("test-fp");
    expect(result.verdict).toBe("fp");
    expect(result.confidence).toBe(0.95);
    expect(result.rationale).toContain("hardcoded");
    expect(result.verificationSteps).toHaveLength(2);
    expect(result.fixPatch).toBeNull();
  });

  it("handles markdown-fenced JSON from LLM", async () => {
    const llm = mockLLM(
      '```json\n{"verdict":"tp","confidence":0.8,"rationale":"Real vuln","verification_steps":["step"],"fix_patch":"diff"}\n```',
    );

    const result = await triageFinding(llm, makeFinding(), "code", "repo");
    expect(result.verdict).toBe("tp");
    expect(result.fixPatch).toBe("diff");
  });

  it("defaults unknown verdict to needs_review", async () => {
    const llm = mockLLM(
      JSON.stringify({ verdict: "maybe", confidence: 0.5, rationale: "unsure", verification_steps: [] }),
    );

    const result = await triageFinding(llm, makeFinding(), "code", "repo");
    expect(result.verdict).toBe("needs_review");
  });
});
