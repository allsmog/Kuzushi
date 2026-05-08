import { describe, expect, it } from "vitest";
import type { ThreatModelDocument } from "../../src/agents/tasks/threat-modeling/types.js";
import { deriveAttackSurfaceDfdModel } from "../../src/attack-surface-dfd.js";
import type { ApplicationModel } from "../../src/types.js";
import type { ContextSnapshot } from "../../src/ui/state.js";

function appModel(): ApplicationModel {
  return {
    version: "1",
    routes: [
      {
        id: "r1",
        method: "GET",
        path: "/public",
        filePath: "routes.ts",
        startLine: 1,
        middleware: [],
        authMechanisms: [],
      },
      {
        id: "r2",
        method: "POST",
        path: "/admin",
        filePath: "routes.ts",
        startLine: 2,
        middleware: [],
        authMechanisms: ["auth-module"],
      },
    ],
    outboundClients: [],
    dataStores: [
      { id: "ds1", kind: "postgres", name: "users db", filePath: "db.ts", startLine: 1 },
    ],
    backgroundJobs: [],
    serviceBoundaries: [
      {
        id: "b1",
        name: "access service",
        kind: "entrypoint",
        description: "authz boundary",
        evidenceAnchors: [],
      },
    ],
    relevantFiles: [],
    notes: [],
  };
}

function snapshot(overrides: Partial<ContextSnapshot> = {}): ContextSnapshot {
  return {
    target: "/repo",
    timestamp: 1,
    discovery: "flat",
    options: { enrichment: true, threatModel: true, scenarios: true },
    appModel: appModel(),
    repoContext: {
      languages: ["TypeScript"],
      frameworks: ["Express"],
      authPatterns: ["auth-module"],
      ormOrDb: ["postgres"],
      entryPoints: [],
      sanitizationLibs: [],
    },
    ...overrides,
  };
}

function threatModel(): ThreatModelDocument {
  return {
    version: "1",
    dfd: {
      elements: [
        {
          id: "E1",
          type: "external-entity",
          name: "attacker",
          description: "unauth caller",
          trustZone: "internet",
        },
        {
          id: "P1",
          type: "process",
          name: "web router",
          description: "public routes",
          trustZone: "edge",
        },
        {
          id: "F1",
          type: "data-flow",
          name: "public request",
          description: "public input",
          trustZone: "edge",
          source: "E1",
          target: "P1",
          protocol: "https",
          dataClassification: "user-input",
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
    threats: [],
    summary: {
      total: 0,
      bySeverity: {},
      byCategory: {} as ThreatModelDocument["summary"]["byCategory"],
    },
  };
}

describe("deriveAttackSurfaceDfdModel", () => {
  it("builds an attack-surface fallback from app model context", () => {
    const model = deriveAttackSurfaceDfdModel({
      contextSnapshot: snapshot(),
      sourceKind: "context",
    });

    expect(model.basis).toBe("app-model-inferred");
    expect(model.qualityNotice).toContain("low-confidence");
    expect(model.stats.routes).toBe(2);
    expect(model.stats.publicRoutes).toBe(1);
    expect(model.stats.dataStores).toBe(1);
    expect(model.nodes.map((node) => node.name)).toContain("web router");
    expect(model.nodes.map((node) => node.name)).toContain("users db");
    expect(model.flows.some((flow) => flow.crosses.includes("B1"))).toBe(true);
  });

  it("prefers explicit threat-model DFD elements when present", () => {
    const model = deriveAttackSurfaceDfdModel({
      threatModel: threatModel(),
      contextSnapshot: snapshot(),
      sourceKind: "persistent",
    });

    expect(model.basis).toBe("threat-model");
    expect(model.qualityNotice).toBeUndefined();
    expect(model.nodes.map((node) => node.id)).toEqual(["E1", "P1"]);
    expect(model.flows).toHaveLength(1);
    expect(model.boundaries[0]?.id).toBe("B1");
  });

  it("does not synthesize public ingress without route or entrypoint evidence", () => {
    const weakAppModel: ApplicationModel = {
      ...appModel(),
      routes: [],
      serviceBoundaries: [
        {
          id: "ds-boundary",
          name: "datastore access",
          kind: "datastore",
          description: "datastore access point",
          evidenceAnchors: [],
        },
      ],
    };
    const model = deriveAttackSurfaceDfdModel({
      contextSnapshot: snapshot({
        appModel: weakAppModel,
        repoContext: {
          languages: ["TypeScript"],
          frameworks: ["React"],
          authPatterns: ["middleware-guards"],
          ormOrDb: [],
          entryPoints: [],
          sanitizationLibs: [],
        },
        threatModel: {
          ...threatModel(),
          dfd: { elements: [], trustBoundaries: [] },
        },
      }),
      sourceKind: "context",
    });

    expect(model.basis).toBe("app-model-inferred");
    expect(model.nodes.map((node) => node.id)).not.toContain("E1");
    expect(model.nodes.map((node) => node.id)).not.toContain("P1");
    expect(model.flows.some((flow) => flow.source === "P1" || flow.target === "P1")).toBe(false);
    expect(model.flows.some((flow) => flow.crosses.includes("B1"))).toBe(false);
    expect(model.boundaries.map((boundary) => boundary.id)).not.toContain("B1");
  });

  it("returns an empty model without context", () => {
    const model = deriveAttackSurfaceDfdModel({});

    expect(model.nodes).toHaveLength(0);
    expect(model.basis).toBe("empty");
    expect(model.sourceKind).toBe("empty");
  });
});
