/**
 * Selectors moved out of `carlini-threat-hunt.ts` so the UI can call them without
 * dragging in the agent-runtime. The behavior should match what the old
 * inline implementation produced.
 */
import { describe, expect, it } from "vitest";
import type { ThreatModelDocument } from "../../../src/agents/tasks/threat-modeling/types.js";
import {
  actorsFromDocument,
  extractActorsWithThreats,
} from "../../../src/modules/carlini-threat-hunt/selectors.js";

function makeStride(elementId: string, impact: "critical" | "high" | "medium" | "low", i: number) {
  return {
    id: `t-${i}`,
    actorIds: [elementId],
    entrypointIds: [],
    targetElementIds: [elementId],
    flowIds: [],
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
    version: "2.0",
    dfd: {
      nodes: [
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
      flows: [],
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

  it("uses threat text to repair unresolved generator actor ids before flow fallback", () => {
    const doc = makeDoc();
    doc.dfd.nodes = [
      {
        id: "A-EXT",
        type: "external-entity",
        name: "External / fork contributor",
        description: "External contributor opening fork pull requests",
        trustZone: "external",
      },
      {
        id: "A-ARTIFACTORY",
        type: "external-entity",
        name: "repository.example.com (Artifactory)",
        description: "Artifact registry",
        trustZone: "external",
      },
      {
        id: "C-WF",
        type: "process",
        name: "Privileged workflow",
        description: "pull_request_target workflow",
        trustZone: "internal",
      },
    ];
    doc.dfd.flows = [
      {
        id: "DF-1",
        name: "artifact download",
        description: "Workflow downloads build artifact",
        sourceId: "C-WF",
        targetId: "A-ARTIFACTORY",
        protocol: "HTTPS",
        trustBoundaryIds: [],
      },
    ];
    doc.threats = [
      {
        ...makeStride("AC-2", "critical", 1),
        actorIds: ["AC-2"],
        targetElementIds: ["C-WF"],
        flowIds: ["DF-1"],
        title: "Fork PR can execute privileged pull_request_target workflow",
        requiredCapabilities: ["Open a pull request from a fork"],
      },
    ];

    const result = actorsFromDocument(doc);

    expect(result.prioritized.map((item) => item.actor.id)).toEqual(["A-EXT"]);
  });

  it("falls back to linked flows when direct and semantic actor links are missing", () => {
    const doc = makeDoc();
    doc.dfd.flows = [
      {
        id: "flow-1",
        name: "request",
        description: "Visitor sends a request to the API",
        sourceId: "ext-2",
        targetId: "proc-1",
        protocol: "HTTPS",
        trustBoundaryIds: [],
      },
    ];
    doc.threats = [
      {
        ...makeStride("missing-actor", "high", 1),
        actorIds: ["missing-actor"],
        targetElementIds: ["proc-1"],
        flowIds: ["flow-1"],
        title: "Cache poisoning through request header",
      },
    ];

    const result = actorsFromDocument(doc);

    expect(result.prioritized.map((item) => item.actor.id)).toEqual(["ext-2"]);
  });
});
