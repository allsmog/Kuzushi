import { describe, expect, it } from "vitest";
import { convertRandoriToThreatModel } from "../../../../src/agents/tasks/threat-modeling/randori-adapter.js";

describe("convertRandoriToThreatModel — narrative layer", () => {
  it("parses a full narrative object (snake_case) into ThreatModelNarrative", () => {
    const raw = {
      dfd: { elements: [], trust_boundaries: [] },
      threats: [],
      narrative: {
        overview: "One-liner overview.",
        input_categories: {
          attacker_controlled: ["a"],
          operator_controlled: ["b"],
          developer_controlled: ["c"],
          external_services: ["d"],
          sandbox_boundary: ["e"],
          assumptions: ["f"],
        },
        attacker_stories: [
          {
            title: "Story one",
            narrative: "Alice does X to achieve Y.",
            mitigation: "Do Z.",
            threat_ids: ["T-1"],
          },
        ],
        criticality_buckets: {
          critical: ["crit-1"],
          high: ["high-1"],
          medium: ["med-1"],
          low: ["low-1"],
        },
        out_of_scope: ["oos-1"],
      },
    };

    const doc = convertRandoriToThreatModel(raw);
    expect(doc).not.toBeNull();
    const narrative = doc?.narrative;
    expect(narrative).toBeDefined();
    expect(narrative?.overview).toBe("One-liner overview.");
    expect(narrative?.inputCategories.attackerControlled).toEqual(["a"]);
    expect(narrative?.inputCategories.operatorControlled).toEqual(["b"]);
    expect(narrative?.inputCategories.developerControlled).toEqual(["c"]);
    expect(narrative?.inputCategories.externalServices).toEqual(["d"]);
    expect(narrative?.inputCategories.sandboxBoundary).toEqual(["e"]);
    expect(narrative?.inputCategories.assumptions).toEqual(["f"]);
    expect(narrative?.attackerStories).toHaveLength(1);
    expect(narrative?.attackerStories[0].title).toBe("Story one");
    expect(narrative?.attackerStories[0].threatIds).toEqual(["T-1"]);
    expect(narrative?.criticalityBuckets.critical).toEqual(["crit-1"]);
    expect(narrative?.outOfScope).toEqual(["oos-1"]);
  });

  it("accepts camelCase keys as equivalents (robustness)", () => {
    const raw = {
      dfd: { elements: [], trust_boundaries: [] },
      threats: [],
      narrative: {
        overview: "",
        inputCategories: { attackerControlled: ["x"] },
        attackerStories: [],
        criticalityBuckets: {},
        outOfScope: ["y"],
      },
    };

    const doc = convertRandoriToThreatModel(raw);
    expect(doc?.narrative?.inputCategories.attackerControlled).toEqual(["x"]);
    expect(doc?.narrative?.outOfScope).toEqual(["y"]);
  });

  it("omits narrative when every section is empty", () => {
    const raw = {
      dfd: { elements: [], trust_boundaries: [] },
      threats: [],
      narrative: {
        overview: "",
        input_categories: {},
        attacker_stories: [],
        criticality_buckets: {},
        out_of_scope: [],
      },
    };

    const doc = convertRandoriToThreatModel(raw);
    expect(doc?.narrative).toBeUndefined();
  });

  it("omits narrative when the key is missing entirely", () => {
    const raw = { dfd: { elements: [], trust_boundaries: [] }, threats: [] };
    const doc = convertRandoriToThreatModel(raw);
    expect(doc?.narrative).toBeUndefined();
  });
});
