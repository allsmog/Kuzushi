/**
 * Selectors moved out of `threat-hunt.ts` so the UI can call them without
 * dragging in the agent-runtime. The behavior should match what the old
 * inline implementation produced.
 */
import { describe, expect, it } from "vitest";
import type { ThreatModelDocument } from "../../../src/agents/tasks/threat-modeling/types.js";
import {
  actorsFromDocument,
  extractActorsWithThreats,
} from "../../../src/modules/threat-hunt/selectors.js";

function makeStride(elementId: string, impact: "critical" | "high" | "medium" | "low", i: number) {
  return {
    id: `t-${i}`,
    elementId,
    category: "spoofing" as const,
    title: `threat ${i}`,
    description: "",
    attackVector: "/x",
    preconditions: [],
    impact,
    likelihood: "medium" as const,
    existingMitigations: [],
    missingMitigations: [],
    relatedCwe: [],
    affectedFiles: [],
  };
}

function makeDoc(): ThreatModelDocument {
  return {
    version: "1",
    dfd: {
      elements: [
        {
          id: "ext-1",
          type: "external-entity",
          name: "Authenticated User",
          description: "logged-in operator",
          trustZone: "external",
        },
        {
          id: "ext-2",
          type: "external-entity",
          name: "Anonymous Visitor",
          description: "unauthenticated browsing visitor",
          trustZone: "external",
        },
        {
          id: "proc-1",
          type: "process",
          name: "API",
          description: "internal",
          trustZone: "internal",
        },
      ],
      trustBoundaries: [],
    },
    threats: [
      makeStride("ext-1", "critical", 1),
      makeStride("ext-1", "high", 2),
      makeStride("ext-2", "medium", 3),
    ],
    summary: { total: 3, bySeverity: {}, byCategory: {} as never },
  } as unknown as ThreatModelDocument;
}

describe("extractActorsWithThreats", () => {
  it("includes both lists with all actors and ranks prioritized by criticality", () => {
    const doc = makeDoc();
    const wrapper = new Map<string, unknown>([["threat-model-randori", { document: doc }]]);
    const result = extractActorsWithThreats(wrapper);
    expect(result.allActors.map((a) => a.id)).toEqual(["ext-1", "ext-2"]);
    expect(result.prioritized.map((a) => a.actor.id)).toEqual(["ext-1"]);
    expect(result.prioritized[0]?.threats).toHaveLength(2);
  });

  it("returns empty when the upstream map has no document", () => {
    expect(extractActorsWithThreats(new Map())).toEqual({ prioritized: [], allActors: [] });
  });
});

describe("actorsFromDocument", () => {
  it("accepts a ThreatModelDocument directly", () => {
    const doc = makeDoc();
    const result = actorsFromDocument(doc);
    expect(result.allActors).toHaveLength(2);
    expect(result.prioritized).toHaveLength(1);
  });

  it("tolerates null / missing dfd", () => {
    expect(actorsFromDocument(null)).toEqual({ prioritized: [], allActors: [] });
    expect(actorsFromDocument(undefined)).toEqual({ prioritized: [], allActors: [] });
  });
});
