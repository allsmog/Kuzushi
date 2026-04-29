import { describe, expect, it } from "vitest";
import { convertRandoriToThreatModel } from "../../../../src/agents/tasks/threat-modeling/randori-adapter.js";

describe("convertRandoriToThreatModel — graph v2 link repair", () => {
  it("repairs generated A-EXT/A-DEV actor aliases to DFD external-entity ids", () => {
    const doc = convertRandoriToThreatModel({
      dfd: {
        nodes: [
          {
            id: "E1",
            type: "external_entity",
            name: "Fork / external PR contributor",
            description: "Untrusted fork contributor opening pull requests",
            trust_zone: "external",
          },
          {
            id: "E2",
            type: "external_entity",
            name: "Internal monorepo engineer (org member)",
            description: "Trusted internal engineer and PR author",
            trust_zone: "external",
          },
          {
            id: "P1",
            type: "process",
            name: "Privileged workflow",
            description: "pull_request_target workflow",
            trust_zone: "internal",
          },
        ],
        flows: [],
        trust_boundaries: [],
      },
      threats: [
        {
          id: "TS-1",
          title: "Fork PR code execution in pull_request_target workflow",
          description: "An external contributor opens a fork pull request.",
          stride_category: "elevation-of-privilege",
          actor_ids: ["A-EXT", "A-DEV"],
          target_element_ids: ["P1"],
          flow_ids: [],
          attack_scenario: "Fork PR reaches privileged workflow.",
          required_capabilities: ["Open a pull request from a fork"],
          impact: "critical",
          probability: 0.8,
          evidence_anchors: [
            {
              file_path: "workflows/semgrep-prcheck.yaml",
              start_line: 23,
              description: "pull_request_target trigger",
            },
          ],
        },
      ],
    });

    expect(doc?.threats[0]?.actorIds).toEqual(["E1", "E2"]);
  });
});
