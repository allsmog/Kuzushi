import { describe, expect, it } from "vitest";
import { assessNarrativeArtifact } from "../../../../src/agents/tasks/threat-modeling/randori.js";

describe("assessNarrativeArtifact", () => {
  const fullNarrative = {
    overview:
      "Kuzushi is a Node.js CLI security scanner that orchestrates scanners and LLM triage locally or in CI. It reads repository contents, calls external LLM providers, and writes findings to a local SQLite database.",
    input_categories: {
      attacker_controlled: ["Repository contents (src/cli.ts:10)"],
      operator_controlled: ["CLI flags (src/cli.ts:20)"],
      developer_controlled: ["Built-in tasks (src/agents/)"],
      external_services: ["Anthropic API"],
      sandbox_boundary: ["Docker --network=none"],
      assumptions: ["Trusted operator"],
    },
    attacker_stories: [
      { title: "Prompt injection", narrative: "Alice does X.", mitigation: "Deny Bash." },
    ],
    criticality_buckets: {
      critical: ["RCE via shell"],
      high: ["~/.ssh leak"],
      medium: ["DoS"],
      low: ["logs leak"],
    },
    out_of_scope: ["Web-app issues — CLI has no web UI"],
  };

  it("accepts a complete narrative", () => {
    expect(assessNarrativeArtifact(fullNarrative)).toEqual([]);
  });

  it("flags a missing/invalid artifact", () => {
    expect(assessNarrativeArtifact(null)).toContain(
      "pasta-narrative.json is missing or is not a JSON object",
    );
    expect(assessNarrativeArtifact(undefined)).toContain(
      "pasta-narrative.json is missing or is not a JSON object",
    );
    expect(assessNarrativeArtifact(["array"])).toContain(
      "pasta-narrative.json is missing or is not a JSON object",
    );
  });

  it("flags a missing/too-short overview", () => {
    const issues = assessNarrativeArtifact({ ...fullNarrative, overview: "short" });
    expect(issues.some((i) => i.includes("overview"))).toBe(true);
  });

  it("flags empty attacker_stories", () => {
    const issues = assessNarrativeArtifact({ ...fullNarrative, attacker_stories: [] });
    expect(issues.some((i) => i.includes("attacker_stories"))).toBe(true);
  });

  it("flags missing input category lists", () => {
    const issues = assessNarrativeArtifact({
      ...fullNarrative,
      input_categories: { attacker_controlled: [] },
    });
    expect(issues.some((i) => i.includes("input_categories"))).toBe(true);
  });

  it("flags empty out_of_scope", () => {
    const issues = assessNarrativeArtifact({ ...fullNarrative, out_of_scope: [] });
    expect(issues.some((i) => i.includes("out_of_scope"))).toBe(true);
  });

  it("accepts camelCase keys as equivalents", () => {
    const camel = {
      overview: fullNarrative.overview,
      inputCategories: {
        attackerControlled: ["x"],
        operatorControlled: ["y"],
        developerControlled: ["z"],
      },
      attackerStories: fullNarrative.attacker_stories,
      criticalityBuckets: fullNarrative.criticality_buckets,
      outOfScope: fullNarrative.out_of_scope,
    };
    expect(assessNarrativeArtifact(camel)).toEqual([]);
  });
});
