import { describe, expect, it } from "vitest";
import type { ThreatModelDocument } from "../../../src/agents/tasks/threat-modeling/types.js";
import {
  __threatScenarioBuildInternals,
  threatScenarioBuildTask,
} from "../../../src/agents/tasks/threat-scenario-build.js";
import type { ApplicationModel, ThreatScenario } from "../../../src/types.js";

const {
  buildThreatScenarios,
  matchesDetector,
  collectThreatFiles,
  asApplicationModel,
  asStrideDocument,
} = __threatScenarioBuildInternals;

function makeAppModel(overrides: Partial<ApplicationModel> = {}): ApplicationModel {
  return {
    version: "1",
    routes: [
      {
        method: "POST",
        path: "/api/proxy",
        filePath: "src/proxy.ts",
        startLine: 10,
        middleware: ["auth"],
        authMechanisms: ["jwt"],
        framework: "express",
      },
    ],
    outboundClients: [
      {
        kind: "http-client",
        filePath: "src/proxy.ts",
        startLine: 15,
        protocol: "https",
      },
    ],
    dataStores: [
      {
        name: "users",
        kind: "mongodb",
        filePath: "src/db.ts",
        startLine: 5,
      },
    ],
    backgroundJobs: [],
    serviceBoundaries: [],
    relevantFiles: ["src/proxy.ts", "src/db.ts"],
    notes: [],
    ...overrides,
  };
}

function makeStrideDocument(threats: Array<Record<string, unknown>>): ThreatModelDocument {
  return {
    version: "1.0",
    dfd: { elements: [], trustBoundaries: [] },
    threats: threats.map((t) => ({
      id: "threat-1",
      elementId: "elem-1",
      category: "information-disclosure" as const,
      title: "Test threat",
      description: "desc",
      attackVector: "test",
      preconditions: [],
      impact: "high" as const,
      likelihood: "high" as const,
      existingMitigations: [],
      missingMitigations: [],
      relatedCwe: [],
      affectedFiles: [],
      evidenceAnchors: [],
      ...t,
    })),
    summary: {
      total: threats.length,
      bySeverity: {},
      byCategory: {
        spoofing: 0,
        tampering: 0,
        repudiation: 0,
        "information-disclosure": threats.length,
        "denial-of-service": 0,
        "elevation-of-privilege": 0,
      },
    },
  } as ThreatModelDocument;
}

describe("threat-scenario-build task", () => {
  it("has correct task contract", () => {
    expect(threatScenarioBuildTask.id).toBe("threat-scenario-build");
    expect(threatScenarioBuildTask.outputKind).toBe("custom");
    expect(threatScenarioBuildTask.dependsOn).toContain("app-model-build");
  });

  it("maps STRIDE SSRF threat to ssrf-detect scenario", () => {
    const appModel = makeAppModel();
    const stride = makeStrideDocument([
      {
        id: "threat-ssrf",
        title: "User-controlled URL can reach internal metadata",
        description: "A proxy endpoint fetches attacker-provided URLs without an allowlist.",
        relatedCwe: ["CWE-918"],
        affectedFiles: [{ filePath: "src/proxy.ts", startLine: 10 }],
        evidenceAnchors: [{ filePath: "src/proxy.ts", startLine: 15, description: "fetch call" }],
      },
    ]);

    const scenarios = buildThreatScenarios(appModel, stride);
    const ssrfScenarios = scenarios.filter((s: ThreatScenario) => s.detectorId === "ssrf-detect");

    expect(ssrfScenarios.length).toBeGreaterThanOrEqual(1);
    expect(ssrfScenarios[0].title).toBe("User-controlled URL can reach internal metadata");
    expect(ssrfScenarios[0].expectedGuard).toContain("allowlist");
  });

  it("maps auth/access threat to auth-access-detect scenario", () => {
    const appModel = makeAppModel();
    const stride = makeStrideDocument([
      {
        id: "threat-auth",
        title: "Missing authorization on admin endpoint",
        description: "An endpoint allows unauthorized access to admin resources.",
        relatedCwe: ["CWE-862"],
        affectedFiles: [{ filePath: "src/proxy.ts", startLine: 10 }],
      },
    ]);

    const scenarios = buildThreatScenarios(appModel, stride);
    const authScenarios = scenarios.filter(
      (s: ThreatScenario) => s.detectorId === "auth-access-detect",
    );

    expect(authScenarios.length).toBeGreaterThanOrEqual(1);
  });

  it("deduplicates scenarios by ID", () => {
    const appModel = makeAppModel();
    const stride = makeStrideDocument([
      {
        id: "threat-dup",
        title: "SSRF via fetch",
        description: "ssrf via user-controlled url",
        relatedCwe: ["CWE-918"],
        affectedFiles: [{ filePath: "src/proxy.ts", startLine: 10 }],
      },
    ]);

    const scenarios = buildThreatScenarios(appModel, stride);
    const ids = scenarios.map((s: ThreatScenario) => s.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("collectThreatFiles extracts file paths from affectedFiles", () => {
    const files = collectThreatFiles({
      id: "t1",
      elementId: "e1",
      category: "spoofing",
      title: "x",
      description: "x",
      attackVector: "x",
      preconditions: [],
      impact: "low",
      likelihood: "low",
      existingMitigations: [],
      missingMitigations: [],
      relatedCwe: [],
      affectedFiles: [
        { filePath: "src/a.ts", startLine: 1 },
        { filePath: "src/b.ts", startLine: 2 },
      ],
      evidenceAnchors: [{ filePath: "src/c.ts", startLine: 3, description: "anchor" }],
    });

    expect(files).toContain("src/a.ts");
    expect(files).toContain("src/b.ts");
    expect(files).toContain("src/c.ts");
  });

  it("returns empty scenarios when upstream data is missing", () => {
    expect(asApplicationModel(undefined)).toBeUndefined();
    expect(asApplicationModel({ nope: true })).toBeUndefined();
    expect(asStrideDocument(undefined)).toBeUndefined();
    expect(asStrideDocument({ nope: true })).toBeUndefined();
  });
});
