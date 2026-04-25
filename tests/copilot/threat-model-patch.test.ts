import { describe, expect, it } from "vitest";
import type { ThreatModelDocument } from "../../src/agents/tasks/threat-modeling/types.js";
import {
  applyThreatModelPatch,
  type ThreatModelPatchProposal,
  validateThreatModelPatch,
} from "../../src/threat-model-patch.js";

function doc(): ThreatModelDocument {
  return {
    version: "1",
    dfd: {
      elements: [
        {
          id: "E1",
          type: "external-entity",
          name: "SSO provider",
          description: "identity provider",
          trustZone: "internet",
        },
        {
          id: "P1",
          type: "process",
          name: "auth-module",
          description: "auth",
          trustZone: "edge",
        },
        {
          id: "F1",
          type: "data-flow",
          name: "OIDC callback",
          description: "identity",
          trustZone: "edge",
          source: "E1",
          target: "P1",
        },
      ],
      trustBoundaries: [
        {
          id: "B1",
          name: "perimeter",
          innerZone: "edge",
          outerZone: "internet",
          crossingFlows: ["F1"],
        },
      ],
    },
    threats: [
      {
        id: "T1",
        elementId: "E1",
        category: "spoofing",
        title: "spoof identity",
        description: "",
        attackVector: "",
        preconditions: [],
        impact: "high",
        likelihood: "medium",
        existingMitigations: [],
        missingMitigations: [],
        relatedCwe: [],
        affectedFiles: [],
      },
    ],
    summary: {
      total: 1,
      bySeverity: { high: 1 },
      byCategory: {
        spoofing: 1,
        tampering: 0,
        repudiation: 0,
        "information-disclosure": 0,
        "denial-of-service": 0,
        "elevation-of-privilege": 0,
      },
    },
  };
}

function proposal(): ThreatModelPatchProposal {
  return {
    instruction: "remove the SSO provider from the dfd",
    summary: "Remove SSO provider",
    operations: [
      {
        op: "remove",
        target: "element",
        matchName: "SSO provider",
        reason: "operator requested removal",
      },
    ],
    diffLines: [],
    validationErrors: [],
    createdAt: 1,
    source: "heuristic",
  };
}

describe("threat-model patch", () => {
  it("removes a DFD element, connected flows, boundary references, and linked threats", () => {
    const applied = applyThreatModelPatch(doc(), proposal());

    expect(applied.ok).toBe(true);
    if (!applied.ok) return;
    expect(applied.document.dfd.elements.map((element) => element.id)).toEqual(["P1"]);
    expect(applied.document.dfd.trustBoundaries[0]?.crossingFlows).toEqual([]);
    expect(applied.document.threats).toEqual([]);
    expect(applied.document.userEdited).toBe(true);
  });

  it("rejects dangling flow endpoints", () => {
    const errors = validateThreatModelPatch(doc(), [
      {
        op: "update",
        target: "flow",
        id: "F1",
        fields: { source: "missing" },
        reason: "bad patch",
      },
    ]);

    expect(errors.some((error) => error.includes("missing source"))).toBe(true);
  });
});
