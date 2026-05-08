import { describe, expect, it } from "vitest";
import {
  __scenarioGuidanceInternals,
  buildApplicationModelSection,
} from "../../../src/agents/tasks/scenario-guidance.js";
import type {
  ApplicationModel,
  ApplicationOutboundClient,
  ApplicationRoute,
} from "../../../src/types.js";

const { selectRoutes, selectOutboundClients, selectScenarios } = __scenarioGuidanceInternals;

function makeRoute(overrides: Partial<ApplicationRoute> = {}): ApplicationRoute {
  return {
    method: "POST",
    path: "/api/data",
    filePath: "src/routes.ts",
    startLine: 10,
    middleware: [],
    authMechanisms: [],
    framework: "express",
    ...overrides,
  };
}

function makeClient(overrides: Partial<ApplicationOutboundClient> = {}): ApplicationOutboundClient {
  return {
    kind: "http-client",
    filePath: "src/http.ts",
    startLine: 5,
    protocol: "https",
    ...overrides,
  };
}

function makeAppModel(overrides: Partial<ApplicationModel> = {}): ApplicationModel {
  return {
    version: "1",
    routes: [makeRoute()],
    outboundClients: [makeClient()],
    dataStores: [],
    backgroundJobs: [],
    serviceBoundaries: [],
    relevantFiles: [],
    notes: ["Uses Express framework"],
    ...overrides,
  };
}

describe("scenario-guidance", () => {
  describe("selectRoutes", () => {
    it("filters SSRF to non-GET or auth-bearing routes", () => {
      const routes = [
        makeRoute({ method: "GET", authMechanisms: [] }),
        makeRoute({ method: "POST", path: "/api/proxy" }),
        makeRoute({ method: "GET", authMechanisms: ["jwt"] }),
      ];
      const selected = selectRoutes("ssrf-detect", routes);
      expect(selected).toHaveLength(2);
      expect(selected.map((r) => r.method)).toContain("POST");
    });

    it("filters GraphQL detector to graphql-related routes", () => {
      const routes = [
        makeRoute({ path: "/api/data" }),
        makeRoute({ path: "/graphql" }),
        makeRoute({ path: "/api/rest", filePath: "src/graphql/resolver.ts" }),
      ];
      const selected = selectRoutes("graphql-security-detect", routes);
      expect(selected).toHaveLength(2);
    });

    it("filters auth-access to routes with auth or middleware", () => {
      const routes = [
        makeRoute({ authMechanisms: ["jwt"], middleware: [] }),
        makeRoute({ authMechanisms: [], middleware: ["rateLimiter"] }),
        makeRoute({ authMechanisms: [], middleware: [] }),
      ];
      const selected = selectRoutes("auth-access-detect", routes);
      expect(selected).toHaveLength(2);
    });

    it("returns all routes for unmatched detector", () => {
      const routes = [makeRoute(), makeRoute({ path: "/other" })];
      const selected = selectRoutes("nosql-injection-detect", routes);
      expect(selected).toHaveLength(2);
    });
  });

  describe("selectOutboundClients", () => {
    it("filters SSRF to exclude graphql-client", () => {
      const clients = [makeClient({ kind: "http-client" }), makeClient({ kind: "graphql-client" })];
      const selected = selectOutboundClients("ssrf-detect", clients);
      expect(selected).toHaveLength(1);
      expect(selected[0].kind).toBe("http-client");
    });

    it("filters GraphQL detector to graphql-client only", () => {
      const clients = [makeClient({ kind: "http-client" }), makeClient({ kind: "graphql-client" })];
      const selected = selectOutboundClients("graphql-security-detect", clients);
      expect(selected).toHaveLength(1);
      expect(selected[0].kind).toBe("graphql-client");
    });

    it("returns all clients for unmatched detector", () => {
      const clients = [makeClient(), makeClient({ kind: "graphql-client" })];
      const selected = selectOutboundClients("template-injection-detect", clients);
      expect(selected).toHaveLength(2);
    });
  });

  describe("selectScenarios", () => {
    const scenarios = [
      { detectorId: "ssrf-detect", id: "s1" },
      { detectorId: "auth-access-detect", id: "s2" },
      { detectorId: "dangerous-api-detect", id: "s3" },
      { detectorId: "security-misconfig-detect", id: "s4" },
      { detectorId: "template-injection-detect", id: "s5" },
    ] as any[];

    it("filters by exact detector ID", () => {
      const selected = selectScenarios("ssrf-detect", scenarios);
      expect(selected).toHaveLength(1);
      expect(selected[0].id).toBe("s1");
    });

    it("routes code-config-detect to its sub-detectors", () => {
      const selected = selectScenarios("code-config-detect", scenarios);
      expect(selected).toHaveLength(3);
      expect(selected.map((s: any) => s.detectorId)).toEqual(
        expect.arrayContaining([
          "auth-access-detect",
          "dangerous-api-detect",
          "security-misconfig-detect",
        ]),
      );
    });
  });

  describe("buildApplicationModelSection", () => {
    it("renders routes, clients, and notes", () => {
      const model = makeAppModel({
        routes: [makeRoute({ method: "POST", path: "/api/proxy", handlerSymbol: "handleProxy" })],
        outboundClients: [makeClient({ kind: "http-client", targetHint: "external-api" })],
        notes: ["Uses Express framework"],
      });
      const section = buildApplicationModelSection("ssrf-detect", model);
      expect(section).toContain("## Application model");
      expect(section).toContain("POST /api/proxy");
      expect(section).toContain("handleProxy");
      expect(section).toContain("http-client");
      expect(section).toContain("target=external-api");
      expect(section).toContain("Uses Express framework");
    });

    it("returns empty string when model is undefined", () => {
      expect(buildApplicationModelSection("ssrf-detect", undefined)).toBe("");
    });
  });
});
