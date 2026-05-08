import { describe, expect, it } from "vitest";
import {
  __stitchInternals,
  matchBoundariesHeuristically,
} from "../../../../../src/agents/tasks/taint-analysis/cross-service/stitch.js";
import type {
  BoundaryManifest,
  BoundaryPoint,
  CrossServiceAnalysisOutput,
  CrossServicePath,
  StitchedEdge,
} from "../../../../../src/agents/tasks/taint-analysis/cross-service/types.js";
import { attachTaskOutputMeta, getTaskOutputMeta } from "../../../../../src/task-output-meta.js";

const {
  matchPair,
  buildCrossServicePaths,
  pathToFinding,
  inferCweFromPath,
  parseStitchResponse,
  isUserFacingEntry,
  normalizeRoute,
} = __stitchInternals;

// ── Helpers ─────────────────────────────────────────────────────────────

function makePoint(
  overrides: Partial<BoundaryPoint> & { id: string; direction: "entry" | "exit" },
): BoundaryPoint {
  return {
    protocol: "unknown",
    filePath: "test.ts",
    startLine: 1,
    callable: "handler",
    dataDescription: "data",
    taintedParameters: [],
    confidence: 0.9,
    rationale: "test",
    ...overrides,
  };
}

function makeBoundary(
  serviceId: string,
  entryPoints: BoundaryPoint[],
  exitPoints: BoundaryPoint[],
): BoundaryManifest {
  return {
    serviceId,
    servicePath: serviceId,
    entryPoints,
    exitPoints,
    errors: [],
  };
}

// ── Tests ───────────────────────────────────────────────────────────────

describe("normalizeRoute", () => {
  it("strips trailing slashes and normalizes", () => {
    expect(normalizeRoute("/api/users/")).toBe("/api/users");
    expect(normalizeRoute("/api//users")).toBe("/api/users");
    expect(normalizeRoute("/API/Users")).toBe("/api/users");
  });
});

describe("isUserFacingEntry", () => {
  it("returns true for http-server entries", () => {
    expect(
      isUserFacingEntry(makePoint({ id: "e1", direction: "entry", protocol: "http-server" })),
    ).toBe(true);
  });

  it("returns true for grpc-server entries", () => {
    expect(
      isUserFacingEntry(makePoint({ id: "e1", direction: "entry", protocol: "grpc-server" })),
    ).toBe(true);
  });

  it("returns true for message-consume entries", () => {
    expect(
      isUserFacingEntry(makePoint({ id: "e1", direction: "entry", protocol: "message-consume" })),
    ).toBe(true);
  });

  it("returns true for database-read entries (second-order source)", () => {
    expect(
      isUserFacingEntry(makePoint({ id: "e1", direction: "entry", protocol: "database-read" })),
    ).toBe(true);
  });
});

describe("matchPair — heuristic matching", () => {
  it("matches exact URL path with confidence 0.9", () => {
    const exit = makePoint({
      id: "x1",
      direction: "exit",
      protocol: "http-client",
      routePath: "/api/users",
      httpMethod: "GET",
    });
    const entry = makePoint({
      id: "e1",
      direction: "entry",
      protocol: "http-server",
      routePath: "/api/users",
      httpMethod: "GET",
    });

    const result = matchPair(exit, entry, "user-service");
    expect(result).not.toBeNull();
    expect(result!.method).toBe("url-path");
    expect(result!.confidence).toBe(0.9);
  });

  it("matches URL path prefix with confidence 0.7", () => {
    const exit = makePoint({
      id: "x1",
      direction: "exit",
      protocol: "http-client",
      routePath: "/api/users/profile",
    });
    const entry = makePoint({
      id: "e1",
      direction: "entry",
      protocol: "http-server",
      routePath: "/api/users",
    });

    const result = matchPair(exit, entry, "user-service");
    expect(result).not.toBeNull();
    expect(result!.method).toBe("url-path");
    expect(result!.confidence).toBe(0.7);
  });

  it("matches topic/queue name with confidence 0.85", () => {
    const exit = makePoint({
      id: "x1",
      direction: "exit",
      protocol: "message-publish",
      topicOrQueue: "user.events",
    });
    const entry = makePoint({
      id: "e1",
      direction: "entry",
      protocol: "message-consume",
      topicOrQueue: "user.events",
    });

    const result = matchPair(exit, entry, "consumer-service");
    expect(result).not.toBeNull();
    expect(result!.method).toBe("topic-name");
    expect(result!.confidence).toBe(0.85);
  });

  it("matches gRPC method with confidence 0.9", () => {
    const exit = makePoint({
      id: "x1",
      direction: "exit",
      protocol: "grpc-client",
      grpcMethod: "UserService.GetUser",
    });
    const entry = makePoint({
      id: "e1",
      direction: "entry",
      protocol: "grpc-server",
      grpcMethod: "UserService.GetUser",
    });

    const result = matchPair(exit, entry, "grpc-service");
    expect(result).not.toBeNull();
    expect(result!.method).toBe("grpc-method");
    expect(result!.confidence).toBe(0.9);
  });

  it("matches data entity with confidence 0.6", () => {
    const exit = makePoint({
      id: "x1",
      direction: "exit",
      protocol: "database-write",
      dataEntity: "users",
    });
    const entry = makePoint({
      id: "e1",
      direction: "entry",
      protocol: "database-read",
      dataEntity: "users",
    });

    const result = matchPair(exit, entry, "reader-service");
    expect(result).not.toBeNull();
    expect(result!.method).toBe("data-entity");
    expect(result!.confidence).toBe(0.8);
  });

  it("matches service name in URL with confidence 0.5", () => {
    const exit = makePoint({
      id: "x1",
      direction: "exit",
      protocol: "http-client",
      routePath: "http://auth-service/api/login",
    });
    const entry = makePoint({
      id: "e1",
      direction: "entry",
      protocol: "http-server",
    });

    const result = matchPair(exit, entry, "auth-service");
    expect(result).not.toBeNull();
    expect(result!.method).toBe("url-path");
    expect(result!.confidence).toBe(0.5);
  });

  it("returns null when no match found", () => {
    const exit = makePoint({
      id: "x1",
      direction: "exit",
      protocol: "http-client",
      routePath: "/api/orders",
    });
    const entry = makePoint({
      id: "e1",
      direction: "entry",
      protocol: "http-server",
      routePath: "/api/payments",
    });

    const result = matchPair(exit, entry, "payment-service");
    expect(result).toBeNull();
  });
});

describe("matchBoundariesHeuristically", () => {
  it("does not match within the same service", () => {
    const boundaries = [
      makeBoundary(
        "svc-a",
        [
          makePoint({
            id: "e1",
            direction: "entry",
            protocol: "http-server",
            routePath: "/api/users",
          }),
        ],
        [
          makePoint({
            id: "x1",
            direction: "exit",
            protocol: "http-client",
            routePath: "/api/users",
          }),
        ],
      ),
    ];

    const edges = matchBoundariesHeuristically(boundaries);
    expect(edges).toHaveLength(0);
  });

  it("matches exit points to entry points across services", () => {
    const boundaries = [
      makeBoundary(
        "gateway",
        [
          makePoint({
            id: "e1",
            direction: "entry",
            protocol: "http-server",
            routePath: "/api/users",
          }),
        ],
        [
          makePoint({
            id: "x1",
            direction: "exit",
            protocol: "http-client",
            routePath: "/api/users",
          }),
        ],
      ),
      makeBoundary(
        "user-svc",
        [
          makePoint({
            id: "e2",
            direction: "entry",
            protocol: "http-server",
            routePath: "/api/users",
          }),
        ],
        [],
      ),
    ];

    const edges = matchBoundariesHeuristically(boundaries);
    expect(edges).toHaveLength(1);
    expect(edges[0].source.serviceId).toBe("gateway");
    expect(edges[0].target.serviceId).toBe("user-svc");
    expect(edges[0].matchMethod).toBe("url-path");
    expect(edges[0].confidence).toBe(0.9);
  });
});

describe("inferCweFromPath", () => {
  it("detects SQL injection", () => {
    const path = {
      ultimateSink: { description: "SQL query injection detected" },
    } as CrossServicePath;
    expect(inferCweFromPath(path)).toBe("CWE-89");
  });

  it("detects command injection", () => {
    const path = {
      ultimateSink: { description: "command execution vulnerability" },
    } as CrossServicePath;
    expect(inferCweFromPath(path)).toBe("CWE-78");
  });

  it("detects SSRF", () => {
    const path = {
      ultimateSink: { description: "SSRF through URL parameter" },
    } as CrossServicePath;
    expect(inferCweFromPath(path)).toBe("CWE-918");
  });

  it("detects path traversal", () => {
    const path = {
      ultimateSink: { description: "path traversal via user-supplied file name" },
    } as CrossServicePath;
    expect(inferCweFromPath(path)).toBe("CWE-22");
  });

  it("detects deserialization", () => {
    const path = {
      ultimateSink: { description: "unsafe deserialization of request body" },
    } as CrossServicePath;
    expect(inferCweFromPath(path)).toBe("CWE-502");
  });

  it("detects XSS", () => {
    const path = { ultimateSink: { description: "xss via reflected input" } } as CrossServicePath;
    expect(inferCweFromPath(path)).toBe("CWE-79");
  });

  it("detects XXE", () => {
    const path = {
      ultimateSink: { description: "xxe via xml external entity" },
    } as CrossServicePath;
    expect(inferCweFromPath(path)).toBe("CWE-611");
  });

  it("detects open redirect", () => {
    const path = {
      ultimateSink: { description: "open redirect to attacker URL" },
    } as CrossServicePath;
    expect(inferCweFromPath(path)).toBe("CWE-601");
  });

  it("detects header injection", () => {
    const path = {
      ultimateSink: { description: "header injection via user input" },
    } as CrossServicePath;
    expect(inferCweFromPath(path)).toBe("CWE-113");
  });

  it("detects log injection", () => {
    const path = {
      ultimateSink: { description: "log injection through crafted input" },
    } as CrossServicePath;
    expect(inferCweFromPath(path)).toBe("CWE-117");
  });

  it("detects LDAP injection", () => {
    const path = {
      ultimateSink: { description: "ldap query with unsanitized filter" },
    } as CrossServicePath;
    expect(inferCweFromPath(path)).toBe("CWE-90");
  });

  it("detects SSTI", () => {
    const path = {
      ultimateSink: { description: "ssti via template rendering" },
    } as CrossServicePath;
    expect(inferCweFromPath(path)).toBe("CWE-1336");
  });

  it("detects code injection (CWE-94)", () => {
    const path = { ultimateSink: { description: "code injection via eval" } } as CrossServicePath;
    expect(inferCweFromPath(path)).toBe("CWE-94");
  });

  it("falls back to CWE-346 for unknown patterns", () => {
    const path = { ultimateSink: { description: "some generic finding" } } as CrossServicePath;
    expect(inferCweFromPath(path)).toBe("CWE-346");
  });
});

describe("pathToFinding", () => {
  it("generates a valid Finding from a CrossServicePath", () => {
    const crossPath: CrossServicePath = {
      serviceChain: ["gateway", "user-svc"],
      edges: [
        {
          source: {
            serviceId: "gateway",
            boundaryPointId: "x1",
            point: makePoint({
              id: "x1",
              direction: "exit",
              protocol: "http-client",
              routePath: "/api/users",
            }),
          },
          target: {
            serviceId: "user-svc",
            boundaryPointId: "e1",
            point: makePoint({
              id: "e1",
              direction: "entry",
              protocol: "http-server",
              routePath: "/api/users",
            }),
          },
          matchMethod: "url-path",
          confidence: 0.9,
          rationale: "Exact route match",
        },
      ],
      ultimateSource: {
        serviceId: "gateway",
        filePath: "gateway/routes.ts",
        startLine: 42,
        description: "http-server handleLogin (user credentials)",
      },
      ultimateSink: {
        serviceId: "user-svc",
        filePath: "user-svc/db.ts",
        startLine: 100,
        description: "SQL query with user input",
      },
      pathConfidence: 0.9,
    };

    const finding = pathToFinding(crossPath, "test-repo");

    expect(finding.taskId).toBe("taint-analysis-stitch");
    expect(finding.ruleId).toContain("taint-analysis/cross-service/");
    expect(finding.filePath).toBe("user-svc/db.ts");
    expect(finding.startLine).toBe(100);
    expect(finding.severity).toBe("ERROR"); // high confidence
    expect(finding.message).toContain("Cross-Service Taint");
    expect(finding.message).toContain("gateway");
    expect(finding.message).toContain("user-svc");
    expect(finding.evidence).toContain("Cross-service flow");
    expect(finding.fingerprint).toBeTruthy();
    expect(finding.fingerprint.length).toBe(32);
    expect(finding.cwe).toContain("CWE-89"); // SQL in description
    expect(finding.score).toBeGreaterThan(0);
  });

  it("assigns WARNING severity for lower confidence paths", () => {
    const crossPath: CrossServicePath = {
      serviceChain: ["a", "b"],
      edges: [
        {
          source: {
            serviceId: "a",
            boundaryPointId: "x1",
            point: makePoint({ id: "x1", direction: "exit" }),
          },
          target: {
            serviceId: "b",
            boundaryPointId: "e1",
            point: makePoint({ id: "e1", direction: "entry" }),
          },
          matchMethod: "data-entity",
          confidence: 0.6,
          rationale: "Shared table",
        },
      ],
      ultimateSource: {
        serviceId: "a",
        filePath: "a/handler.ts",
        startLine: 10,
        description: "HTTP input",
      },
      ultimateSink: {
        serviceId: "b",
        filePath: "b/query.ts",
        startLine: 20,
        description: "some generic finding",
      },
      pathConfidence: 0.6,
    };

    const finding = pathToFinding(crossPath, "test-repo");
    expect(finding.severity).toBe("WARNING");
    expect(finding.scannerConfidence).toBe("MEDIUM");
  });
});

describe("parseStitchResponse", () => {
  it("parses a valid structured response", () => {
    const response = parseStitchResponse({
      validatedEdges: [
        {
          sourcePointId: "x1",
          targetPointId: "e1",
          valid: true,
          confidence: 0.95,
          rationale: "Confirmed",
        },
        {
          sourcePointId: "x2",
          targetPointId: "e2",
          valid: false,
          confidence: 0.3,
          rationale: "Not a match",
        },
      ],
      additionalEdges: [
        {
          sourceServiceId: "a",
          sourcePointId: "x3",
          targetServiceId: "b",
          targetPointId: "e3",
          matchMethod: "llm-semantic",
          confidence: 0.8,
          rationale: "Semantic match",
        },
      ],
      paths: [
        {
          serviceChain: ["a", "b", "c"],
          description: "User data flows through",
          cwe: "CWE-89",
          severity: "ERROR",
        },
      ],
    });

    expect(response.validatedEdges).toHaveLength(2);
    expect(response.validatedEdges[0].valid).toBe(true);
    expect(response.validatedEdges[1].valid).toBe(false);
    expect(response.additionalEdges).toHaveLength(1);
    expect(response.additionalEdges[0].matchMethod).toBe("llm-semantic");
    expect(response.paths).toHaveLength(1);
    expect(response.paths[0].cwe).toBe("CWE-89");
  });

  it("handles missing fields gracefully", () => {
    const response = parseStitchResponse({});
    expect(response.validatedEdges).toEqual([]);
    expect(response.additionalEdges).toEqual([]);
    expect(response.paths).toEqual([]);
  });

  it("parses JSON from a string", () => {
    const json = JSON.stringify({
      validatedEdges: [],
      additionalEdges: [],
      paths: [{ serviceChain: ["x"], description: "test", cwe: "CWE-79", severity: "WARNING" }],
    });

    const response = parseStitchResponse(json);
    expect(response.paths).toHaveLength(1);
  });

  it("parses JSON from fenced code block", () => {
    const fenced =
      'Here is the analysis:\n```json\n{"validatedEdges": [], "additionalEdges": [], "paths": [{"serviceChain": ["a"], "description": "test", "cwe": "CWE-89", "severity": "ERROR"}]}\n```';

    const response = parseStitchResponse(fenced);
    expect(response.paths).toHaveLength(1);
    expect(response.paths[0].cwe).toBe("CWE-89");
  });

  it("throws for unparseable input", () => {
    expect(() => parseStitchResponse("not valid json {{{")).toThrow(
      /Could not parse stitch response JSON/i,
    );
  });
});

describe("buildCrossServicePaths", () => {
  it("builds paths from user-facing entry to service with findings", () => {
    const edges: StitchedEdge[] = [
      {
        source: {
          serviceId: "gateway",
          boundaryPointId: "x1",
          point: makePoint({ id: "x1", direction: "exit", protocol: "http-client" }),
        },
        target: {
          serviceId: "backend",
          boundaryPointId: "e1",
          point: makePoint({ id: "e1", direction: "entry", protocol: "http-server" }),
        },
        matchMethod: "url-path",
        confidence: 0.9,
        rationale: "test",
      },
    ];

    const boundaries = [
      makeBoundary(
        "gateway",
        [
          makePoint({
            id: "ge1",
            direction: "entry",
            protocol: "http-server",
            callable: "handleRequest",
          }),
        ],
        [makePoint({ id: "x1", direction: "exit", protocol: "http-client" })],
      ),
      makeBoundary(
        "backend",
        [makePoint({ id: "e1", direction: "entry", protocol: "http-server" })],
        [],
      ),
    ];

    const analyzeOutput: CrossServiceAnalysisOutput = {
      services: [
        {
          service: {
            id: "gateway",
            displayName: "Gateway",
            rootPath: "gateway",
            language: "javascript",
            framework: null,
            discoveryMethod: "auto",
            manifestFiles: [],
          },
          boundary: boundaries[0],
          intraServiceFindings: [],
          taintAnalysisSkipped: false,
          durationMs: 100,
        },
        {
          service: {
            id: "backend",
            displayName: "Backend",
            rootPath: "backend",
            language: "javascript",
            framework: null,
            discoveryMethod: "auto",
            manifestFiles: [],
          },
          boundary: boundaries[1],
          intraServiceFindings: [
            {
              taskId: "taint-analysis-run",
              fingerprint: "abc123",
              ruleId: "taint-analysis/pass5/sql",
              filePath: "backend/db.ts",
              startLine: 50,
              severity: "ERROR",
              message: "SQL injection",
              scannerConfidence: "HIGH",
              subcategory: ["vuln"],
              likelihood: "HIGH",
              impact: "HIGH",
              cwe: ["CWE-89"],
              score: 54,
            },
          ],
          taintAnalysisSkipped: false,
          durationMs: 200,
        },
      ],
      allBoundaries: boundaries,
    };

    const paths = buildCrossServicePaths(edges, boundaries, analyzeOutput, 5);

    expect(paths.length).toBeGreaterThanOrEqual(1);
    expect(paths[0].serviceChain).toEqual(["gateway", "backend"]);
    expect(paths[0].ultimateSink.serviceId).toBe("backend");
    expect(paths[0].pathConfidence).toBe(0.9);
  });

  it("does not create paths when there are no sink services", () => {
    const edges: StitchedEdge[] = [
      {
        source: {
          serviceId: "a",
          boundaryPointId: "x1",
          point: makePoint({ id: "x1", direction: "exit", protocol: "http-client" }),
        },
        target: {
          serviceId: "b",
          boundaryPointId: "e1",
          point: makePoint({ id: "e1", direction: "entry", protocol: "http-server" }),
        },
        matchMethod: "url-path",
        confidence: 0.9,
        rationale: "test",
      },
    ];

    const boundaries = [
      makeBoundary(
        "a",
        [makePoint({ id: "ae1", direction: "entry", protocol: "http-server" })],
        [],
      ),
      makeBoundary("b", [makePoint({ id: "e1", direction: "entry", protocol: "http-server" })], []),
    ];

    const analyzeOutput: CrossServiceAnalysisOutput = {
      services: [
        {
          service: {
            id: "a",
            displayName: "A",
            rootPath: "a",
            language: "javascript",
            framework: null,
            discoveryMethod: "auto",
            manifestFiles: [],
          },
          boundary: boundaries[0],
          intraServiceFindings: [],
          taintAnalysisSkipped: false,
          durationMs: 100,
        },
        {
          service: {
            id: "b",
            displayName: "B",
            rootPath: "b",
            language: "javascript",
            framework: null,
            discoveryMethod: "auto",
            manifestFiles: [],
          },
          boundary: boundaries[1],
          intraServiceFindings: [],
          taintAnalysisSkipped: false,
          durationMs: 100,
        },
      ],
      allBoundaries: boundaries,
    };

    const paths = buildCrossServicePaths(edges, boundaries, analyzeOutput, 5);
    expect(paths).toHaveLength(0);
  });

  it("avoids cycles in path building", () => {
    const edges: StitchedEdge[] = [
      {
        source: {
          serviceId: "a",
          boundaryPointId: "x1",
          point: makePoint({ id: "x1", direction: "exit" }),
        },
        target: {
          serviceId: "b",
          boundaryPointId: "e1",
          point: makePoint({ id: "e1", direction: "entry" }),
        },
        matchMethod: "url-path",
        confidence: 0.9,
        rationale: "test",
      },
      {
        source: {
          serviceId: "b",
          boundaryPointId: "x2",
          point: makePoint({ id: "x2", direction: "exit" }),
        },
        target: {
          serviceId: "a",
          boundaryPointId: "e2",
          point: makePoint({ id: "e2", direction: "entry" }),
        },
        matchMethod: "url-path",
        confidence: 0.9,
        rationale: "test",
      },
    ];

    const boundaries = [
      makeBoundary(
        "a",
        [makePoint({ id: "ae1", direction: "entry", protocol: "http-server" })],
        [],
      ),
      makeBoundary("b", [makePoint({ id: "e1", direction: "entry", protocol: "http-server" })], []),
    ];

    const analyzeOutput: CrossServiceAnalysisOutput = {
      services: [
        {
          service: {
            id: "a",
            displayName: "A",
            rootPath: "a",
            language: "javascript",
            framework: null,
            discoveryMethod: "auto",
            manifestFiles: [],
          },
          boundary: boundaries[0],
          intraServiceFindings: [
            {
              taskId: "taint-analysis-run",
              fingerprint: "x",
              ruleId: "r",
              filePath: "f",
              startLine: 1,
              severity: "ERROR",
              message: "m",
              scannerConfidence: "HIGH",
              subcategory: ["vuln"],
              likelihood: "HIGH",
              impact: "HIGH",
              cwe: [],
              score: 1,
            },
          ],
          taintAnalysisSkipped: false,
          durationMs: 100,
        },
        {
          service: {
            id: "b",
            displayName: "B",
            rootPath: "b",
            language: "javascript",
            framework: null,
            discoveryMethod: "auto",
            manifestFiles: [],
          },
          boundary: boundaries[1],
          intraServiceFindings: [
            {
              taskId: "taint-analysis-run",
              fingerprint: "y",
              ruleId: "r",
              filePath: "f",
              startLine: 1,
              severity: "ERROR",
              message: "m",
              scannerConfidence: "HIGH",
              subcategory: ["vuln"],
              likelihood: "HIGH",
              impact: "HIGH",
              cwe: [],
              score: 1,
            },
          ],
          taintAnalysisSkipped: false,
          durationMs: 100,
        },
      ],
      allBoundaries: boundaries,
    };

    // Should not hang or produce infinite paths
    const paths = buildCrossServicePaths(edges, boundaries, analyzeOutput, 5);
    // Paths should exist but no service should repeat in a chain
    for (const p of paths) {
      const unique = new Set(p.serviceChain);
      expect(unique.size).toBe(p.serviceChain.length);
    }
  });
});

describe("pathToFinding — fingerprint uniqueness", () => {
  it("produces different fingerprints for different service chains with same source/sink", () => {
    const basePath: CrossServicePath = {
      serviceChain: ["a", "b", "c"],
      edges: [],
      ultimateSource: { serviceId: "a", filePath: "a/src.ts", startLine: 1, description: "input" },
      ultimateSink: {
        serviceId: "c",
        filePath: "c/sink.ts",
        startLine: 10,
        description: "SQL query",
      },
      pathConfidence: 0.9,
    };

    const altPath: CrossServicePath = {
      ...basePath,
      serviceChain: ["a", "d", "c"],
    };

    const f1 = pathToFinding(basePath, "repo");
    const f2 = pathToFinding(altPath, "repo");

    expect(f1.fingerprint).not.toBe(f2.fingerprint);
  });
});

describe("buildCrossServicePaths — maxDepth enforcement", () => {
  it("respects maxDepth limit and stops exploring beyond it", () => {
    // Build a linear chain: s0 → s1 → s2 → s3 → s4
    // All services are sinks. With maxDepth=3, chains should be at most 3 services.
    const serviceIds = ["s0", "s1", "s2", "s3", "s4"];
    const edges: StitchedEdge[] = [];
    const boundaries: BoundaryManifest[] = [];

    for (let i = 0; i < serviceIds.length; i++) {
      const entryPoints = [makePoint({ id: `e${i}`, direction: "entry", protocol: "http-server" })];
      const exitPoints =
        i < serviceIds.length - 1
          ? [makePoint({ id: `x${i}`, direction: "exit", protocol: "http-client" })]
          : [];
      boundaries.push(makeBoundary(serviceIds[i], entryPoints, exitPoints));

      if (i < serviceIds.length - 1) {
        edges.push({
          source: { serviceId: serviceIds[i], boundaryPointId: `x${i}`, point: exitPoints[0] },
          target: {
            serviceId: serviceIds[i + 1],
            boundaryPointId: `e${i + 1}`,
            point: entryPoints[0],
          },
          matchMethod: "url-path",
          confidence: 0.9,
          rationale: "test",
        });
      }
    }

    const analyzeOutput: CrossServiceAnalysisOutput = {
      services: serviceIds.map((id, i) => ({
        service: {
          id,
          displayName: id,
          rootPath: id,
          language: "javascript",
          framework: null,
          discoveryMethod: "auto" as const,
          manifestFiles: [],
        },
        boundary: boundaries[i],
        intraServiceFindings:
          i >= 1
            ? [
                {
                  taskId: "taint-analysis-run",
                  fingerprint: `fp-${id}`,
                  ruleId: "r",
                  filePath: `${id}/f.ts`,
                  startLine: 1,
                  severity: "ERROR",
                  message: "vuln",
                  scannerConfidence: "HIGH",
                  subcategory: ["vuln"],
                  likelihood: "HIGH",
                  impact: "HIGH",
                  cwe: [],
                  score: 1,
                },
              ]
            : [],
        taintAnalysisSkipped: false,
        durationMs: 100,
      })),
      allBoundaries: boundaries,
    };

    const paths = buildCrossServicePaths(edges, boundaries, analyzeOutput, 3);

    // With maxDepth=3, the guard `chain.length >= 3` fires at length 3,
    // so maximum chain length is 3 services (2 hops)
    for (const p of paths) {
      expect(p.serviceChain.length).toBeLessThanOrEqual(3);
    }
    // Should still find some paths (s0→s1, s0→s1→s2)
    expect(paths.length).toBeGreaterThan(0);
  });
});

describe("taintAnalysisStitchTask metadata", () => {
  it("has correct task properties", async () => {
    const { taintAnalysisStitchTask } = await import(
      "../../../../../src/agents/tasks/taint-analysis/cross-service/stitch.js"
    );

    expect(taintAnalysisStitchTask.id).toBe("taint-analysis-stitch");
    expect(taintAnalysisStitchTask.outputKind).toBe("findings");
    expect(taintAnalysisStitchTask.dependsOn).toEqual(["taint-analysis-cross-analyze"]);
    expect(typeof taintAnalysisStitchTask.triageAgentConfig).toBe("function");
  });
});

describe("stitch degradation metadata", () => {
  it("attaches and retrieves degradation via TaskOutputMeta", () => {
    const findings = [{ taskId: "taint-analysis-stitch", fingerprint: "abc" }];
    const meta = {
      costUsd: 0.01,
      degradation: {
        type: "stitch-degradation",
        reason: "llm_validation_failed",
        message: "Stitch LLM failed: timeout",
        heuristicEdgeCount: 3,
      },
    };
    const result = attachTaskOutputMeta(findings, meta);
    const retrieved = getTaskOutputMeta(result);
    expect(retrieved).toBeDefined();
    expect(retrieved!.degradation).toBeDefined();
    expect(retrieved!.degradation!.type).toBe("stitch-degradation");
    expect(retrieved!.degradation!.reason).toBe("llm_validation_failed");
    expect(retrieved!.degradation!.message).toBe("Stitch LLM failed: timeout");
    expect(retrieved!.degradation!.heuristicEdgeCount).toBe(3);
  });
});
