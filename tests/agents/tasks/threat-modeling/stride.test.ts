import { describe, expect, it } from "vitest";
import { threatModelStrideTask, __strideInternals } from "../../../../src/agents/tasks/threat-modeling/stride.js";

const { buildStridePrompt, parseStrideResponse, threatsToFindings, computeFingerprint, buildSummary } = __strideInternals;

describe("threatModelStrideTask", () => {
  it("has correct metadata", () => {
    expect(threatModelStrideTask.id).toBe("threat-model-stride");
    expect(threatModelStrideTask.outputKind).toBe("threat-model");
    expect(threatModelStrideTask.dependsOn).toEqual(["context-gatherer"]);
  });
});

describe("buildStridePrompt", () => {
  it("includes repo context when provided", () => {
    const prompt = buildStridePrompt(
      { languages: ["Go"], frameworks: ["Gin"], authPatterns: ["JWT"], sanitizationLibs: [], ormOrDb: ["GORM"], entryPoints: ["cmd/server/main.go"] },
      50,
      100,
    );
    expect(prompt).toContain("Go");
    expect(prompt).toContain("JWT");
    expect(prompt).toContain("GORM");
    expect(prompt).toContain("STRIDE");
  });

  it("works without repo context", () => {
    const prompt = buildStridePrompt(undefined, 50, 100);
    expect(prompt).toContain("STRIDE");
    expect(prompt).toContain("50");
    expect(prompt).toContain("100");
  });
});

describe("parseStrideResponse", () => {
  it("parses valid STRIDE response", () => {
    const raw = {
      elements: [
        { id: "elem-1", type: "process", name: "API Server", description: "Main API", trustZone: "internal" },
        { id: "elem-2", type: "external-entity", name: "User", description: "End user", trustZone: "internet" },
      ],
      trustBoundaries: [
        { id: "tb-1", name: "Internet boundary", innerZone: "internal", outerZone: "internet", crossingFlows: ["elem-2"] },
      ],
      threats: [
        {
          id: "threat-1",
          elementId: "elem-1",
          category: "spoofing",
          title: "JWT spoofing",
          description: "Attacker crafts JWT",
          attackVector: "Weak secret",
          preconditions: ["Weak JWT secret"],
          impact: "high",
          likelihood: "medium",
          existingMitigations: ["HTTPS"],
          missingMitigations: ["Key rotation"],
          relatedCwe: ["347"],
          affectedFiles: [{ filePath: "src/auth/jwt.ts", startLine: 15 }],
        },
      ],
    };

    const result = parseStrideResponse(raw, 50, 100);
    expect(result.elements).toHaveLength(2);
    expect(result.trustBoundaries).toHaveLength(1);
    expect(result.threats).toHaveLength(1);
    expect(result.threats[0].category).toBe("spoofing");
  });

  it("filters invalid element types", () => {
    const raw = {
      elements: [
        { id: "elem-1", type: "invalid-type", name: "Bad", description: "Bad", trustZone: "x" },
        { id: "elem-2", type: "process", name: "Good", description: "Good", trustZone: "y" },
      ],
      trustBoundaries: [],
      threats: [],
    };

    const result = parseStrideResponse(raw, 50, 100);
    expect(result.elements).toHaveLength(1);
    expect(result.elements[0].name).toBe("Good");
  });

  it("filters invalid STRIDE categories", () => {
    const raw = {
      elements: [],
      trustBoundaries: [],
      threats: [
        { id: "t1", elementId: "e1", category: "not-a-category", title: "Bad", description: "Bad", attackVector: "x", impact: "high", likelihood: "high" },
        { id: "t2", elementId: "e1", category: "tampering", title: "Good", description: "Good", attackVector: "x", impact: "high", likelihood: "high" },
      ],
    };

    const result = parseStrideResponse(raw, 50, 100);
    expect(result.threats).toHaveLength(1);
    expect(result.threats[0].title).toBe("Good");
  });

  it("respects maxElements and maxThreats", () => {
    const raw = {
      elements: Array.from({ length: 10 }, (_, i) => ({ id: `e${i}`, type: "process", name: `P${i}`, description: `D${i}`, trustZone: "internal" })),
      trustBoundaries: [],
      threats: Array.from({ length: 10 }, (_, i) => ({ id: `t${i}`, elementId: "e0", category: "spoofing", title: `T${i}`, description: "x", attackVector: "x", impact: "high", likelihood: "high" })),
    };

    const result = parseStrideResponse(raw, 3, 5);
    expect(result.elements).toHaveLength(3);
    expect(result.threats).toHaveLength(5);
  });

  it("returns empty for invalid input", () => {
    const result = parseStrideResponse(null, 50, 100);
    expect(result.elements).toEqual([]);
    expect(result.threats).toEqual([]);
  });
});

describe("threatsToFindings", () => {
  it("converts high-impact threats to findings", () => {
    const threats = [
      {
        id: "threat-1",
        elementId: "elem-1",
        category: "spoofing" as const,
        title: "JWT spoofing",
        description: "Attacker crafts JWT",
        attackVector: "Weak secret",
        preconditions: [],
        impact: "high" as const,
        likelihood: "medium" as const,
        existingMitigations: [],
        missingMitigations: ["Key rotation"],
        relatedCwe: ["347"],
        affectedFiles: [{ filePath: "src/auth/jwt.ts", startLine: 15 }],
      },
    ];

    const findings = threatsToFindings(threats, "/tmp/repo", "test-repo", "high");
    expect(findings).toHaveLength(1);
    expect(findings[0].scanner).toBe("threat-model-stride");
    expect(findings[0].ruleId).toBe("threat-model/spoofing/347");
    expect(findings[0].message).toContain("JWT spoofing");
    expect(findings[0].evidence).toContain("Key rotation");
  });

  it("respects finding threshold", () => {
    const threats = [
      {
        id: "t1", elementId: "e1", category: "tampering" as const, title: "T1", description: "D1",
        attackVector: "x", preconditions: [], impact: "medium" as const, likelihood: "medium" as const,
        existingMitigations: [], missingMitigations: [], relatedCwe: [],
        affectedFiles: [{ filePath: "a.ts", startLine: 1 }],
      },
    ];

    expect(threatsToFindings(threats, "/tmp/repo", "test-repo", "high")).toHaveLength(0);
    expect(threatsToFindings(threats, "/tmp/repo", "test-repo", "medium")).toHaveLength(1);
    expect(threatsToFindings(threats, "/tmp/repo", "test-repo", "low")).toHaveLength(1);
  });

  it("includes low-impact threats when threshold is 'low'", () => {
    const threats = [
      {
        id: "t1", elementId: "e1", category: "repudiation" as const, title: "T1", description: "D1",
        attackVector: "x", preconditions: [], impact: "low" as const, likelihood: "low" as const,
        existingMitigations: [], missingMitigations: [], relatedCwe: [],
        affectedFiles: [{ filePath: "a.ts", startLine: 1 }],
      },
    ];
    expect(threatsToFindings(threats, "/tmp/repo", "test-repo", "low")).toHaveLength(1);
    expect(threatsToFindings(threats, "/tmp/repo", "test-repo", "medium")).toHaveLength(0);
  });

  it("emits synthetic finding for threats without affected files", () => {
    const threats = [
      {
        id: "t1", elementId: "e1", category: "spoofing" as const, title: "T1", description: "D1",
        attackVector: "x", preconditions: [], impact: "critical" as const, likelihood: "high" as const,
        existingMitigations: [], missingMitigations: [], relatedCwe: [],
        affectedFiles: [],
      },
    ];

    const findings = threatsToFindings(threats, "/tmp/repo", "test-repo", "high");
    expect(findings).toHaveLength(1);
    expect(findings[0].filePath).toBe(".");
    expect(findings[0].startLine).toBe(1);
  });

  it("assigns unique startLines to multiple threats without affected files", () => {
    const threats = [
      {
        id: "t1", elementId: "e1", category: "spoofing" as const, title: "Spoofing 1", description: "D1",
        attackVector: "x", preconditions: [], impact: "high" as const, likelihood: "high" as const,
        existingMitigations: [], missingMitigations: [], relatedCwe: [],
        affectedFiles: [],
      },
      {
        id: "t2", elementId: "e1", category: "spoofing" as const, title: "Spoofing 2", description: "D2",
        attackVector: "y", preconditions: [], impact: "high" as const, likelihood: "high" as const,
        existingMitigations: [], missingMitigations: [], relatedCwe: [],
        affectedFiles: [],
      },
    ];

    const findings = threatsToFindings(threats, "/tmp/repo", "test-repo", "high");
    expect(findings).toHaveLength(2);
    expect(findings[0].startLine).not.toBe(findings[1].startLine);
  });
});

describe("buildSummary", () => {
  it("summarizes threats correctly", () => {
    const threats = [
      { id: "t1", elementId: "e1", category: "spoofing" as const, title: "T1", description: "", attackVector: "", preconditions: [], impact: "high" as const, likelihood: "high" as const, existingMitigations: [], missingMitigations: [], relatedCwe: [], affectedFiles: [] },
      { id: "t2", elementId: "e1", category: "spoofing" as const, title: "T2", description: "", attackVector: "", preconditions: [], impact: "medium" as const, likelihood: "medium" as const, existingMitigations: [], missingMitigations: [], relatedCwe: [], affectedFiles: [] },
      { id: "t3", elementId: "e2", category: "tampering" as const, title: "T3", description: "", attackVector: "", preconditions: [], impact: "high" as const, likelihood: "low" as const, existingMitigations: [], missingMitigations: [], relatedCwe: [], affectedFiles: [] },
    ];

    const summary = buildSummary(threats);
    expect(summary.total).toBe(3);
    expect(summary.bySeverity["high"]).toBe(2);
    expect(summary.bySeverity["medium"]).toBe(1);
    expect(summary.byCategory["spoofing"]).toBe(2);
    expect(summary.byCategory["tampering"]).toBe(1);
  });
});

describe("computeFingerprint", () => {
  it("produces stable fingerprints", () => {
    const threat = {
      id: "threat-1", elementId: "elem-1", category: "spoofing" as const, title: "JWT spoofing",
      description: "D", attackVector: "x", preconditions: [], impact: "high" as const, likelihood: "high" as const,
      existingMitigations: [], missingMitigations: [], relatedCwe: ["347"],
      affectedFiles: [{ filePath: "src/auth.ts", startLine: 15 }],
    };
    const fp1 = computeFingerprint("repo", threat);
    const fp2 = computeFingerprint("repo", threat);
    expect(fp1).toBe(fp2);
    expect(fp1).toHaveLength(64);
  });

  it("is stable when LLM-generated IDs differ but structure is same", () => {
    const base = {
      category: "spoofing" as const, title: "JWT spoofing",
      description: "D", attackVector: "x", preconditions: [], impact: "high" as const, likelihood: "high" as const,
      existingMitigations: [], missingMitigations: [], relatedCwe: ["347"],
      affectedFiles: [{ filePath: "src/auth.ts", startLine: 15 }],
    };
    const fp1 = computeFingerprint("repo", { ...base, id: "threat-1", elementId: "elem-1" });
    const fp2 = computeFingerprint("repo", { ...base, id: "threat-42", elementId: "elem-99" });
    expect(fp1).toBe(fp2);
  });

  it("differs when category or files change", () => {
    const base = {
      id: "t1", elementId: "e1", title: "JWT spoofing",
      description: "D", attackVector: "x", preconditions: [], impact: "high" as const, likelihood: "high" as const,
      existingMitigations: [], missingMitigations: [], relatedCwe: ["347"],
      affectedFiles: [{ filePath: "src/auth.ts", startLine: 15 }],
    };
    const fp1 = computeFingerprint("repo", { ...base, category: "spoofing" as const });
    const fp2 = computeFingerprint("repo", { ...base, category: "tampering" as const });
    expect(fp1).not.toBe(fp2);
  });
});

describe("triageAgentConfig", () => {
  it("returns a prompt mentioning STRIDE", () => {
    const finding = {
      scanner: "threat-model-stride",
      fingerprint: "abc",
      ruleId: "threat-model/spoofing/347",
      filePath: "src/auth.ts",
      startLine: 15,
      severity: "ERROR",
      message: "[STRIDE/spoofing] JWT spoofing",
      evidence: "Weak secret",
      scannerConfidence: "HIGH",
      subcategory: ["vuln"],
      likelihood: "HIGH",
      impact: "HIGH",
      cwe: ["347"],
      score: 54,
    };

    const config = threatModelStrideTask.triageAgentConfig!(finding, "test-repo");
    expect(config.prompt).toContain("STRIDE");
    expect(config.prompt).toContain("threat-model/spoofing/347");
  });
});
