import { describe, expect, it } from "vitest";
import { threatModelPastaTask, __pastaInternals } from "../../../../src/agents/tasks/threat-modeling/pasta.js";
import type { TaskContext } from "../../../../src/agents/types.js";
import type { Finding } from "../../../../src/scanners/types.js";

const { buildPastaPrompt, parsePastaResponse, normalizeTree, normalizeNode, treesToFindings, describeTree, computeFingerprint } = __pastaInternals;

describe("threatModelPastaTask", () => {
  it("has correct metadata", () => {
    expect(threatModelPastaTask.id).toBe("threat-model-pasta");
    expect(threatModelPastaTask.outputKind).toBe("threat-model");
    expect(threatModelPastaTask.dependsOn).toEqual(["threat-model-stride"]);
  });
});

describe("buildPastaPrompt", () => {
  it("includes stride threats and upstream findings", () => {
    const prompt = buildPastaPrompt(
      ["[threat-1] spoofing: JWT spoofing (impact: high)"],
      ["[abc12345] crypto-misuse/hash-for-auth: MD5 for passwords"],
      10,
    );
    expect(prompt).toContain("PASTA");
    expect(prompt).toContain("JWT spoofing");
    expect(prompt).toContain("MD5 for passwords");
    expect(prompt).toContain("10");
  });

  it("works with empty inputs", () => {
    const prompt = buildPastaPrompt([], [], 5);
    expect(prompt).toContain("PASTA");
    expect(prompt).not.toContain("STRIDE threats");
  });
});

describe("parsePastaResponse", () => {
  it("parses valid PASTA response", () => {
    const raw = {
      trees: [
        {
          goal: "Exfiltrate user data",
          overallRisk: "critical",
          rootNode: {
            id: "node-1",
            description: "Achieve data exfiltration",
            type: "OR",
            probability: 0.7,
            impact: "critical",
            children: [
              {
                id: "node-2",
                description: "SQL injection",
                type: "LEAF",
                probability: 0.5,
                impact: "high",
                children: [],
                technique: "T1190",
              },
            ],
          },
        },
      ],
    };

    const trees = parsePastaResponse(raw, 10);
    expect(trees).toHaveLength(1);
    expect(trees[0].goal).toBe("Exfiltrate user data");
    expect(trees[0].overallRisk).toBe("critical");
    expect(trees[0].rootNode.children).toHaveLength(1);
    expect(trees[0].rootNode.children[0].technique).toBe("T1190");
  });

  it("respects maxTrees", () => {
    const raw = {
      trees: Array.from({ length: 5 }, (_, i) => ({
        goal: `Goal ${i}`,
        overallRisk: "medium",
        rootNode: { id: `n${i}`, description: `Node ${i}`, type: "LEAF", probability: 0.5, impact: "medium", children: [] },
      })),
    };

    const trees = parsePastaResponse(raw, 2);
    expect(trees).toHaveLength(2);
  });

  it("returns empty for invalid input", () => {
    expect(parsePastaResponse(null, 10)).toEqual([]);
    expect(parsePastaResponse({ trees: "not-array" }, 10)).toEqual([]);
  });
});

describe("normalizeTree", () => {
  it("returns null for missing goal", () => {
    expect(normalizeTree({ overallRisk: "high", rootNode: {} })).toBeNull();
  });

  it("returns null for missing rootNode", () => {
    expect(normalizeTree({ goal: "Test", overallRisk: "high" })).toBeNull();
  });

  it("defaults invalid overallRisk to medium", () => {
    const tree = normalizeTree({
      goal: "Test",
      overallRisk: "invalid",
      rootNode: { id: "n1", description: "Test", type: "LEAF", probability: 0.5, impact: "high", children: [] },
    });
    expect(tree!.overallRisk).toBe("medium");
  });
});

describe("normalizeNode", () => {
  it("returns null for missing id or description", () => {
    expect(normalizeNode({ description: "test" })).toBeNull();
    expect(normalizeNode({ id: "n1" })).toBeNull();
  });

  it("normalizes valid node", () => {
    const node = normalizeNode({
      id: "n1",
      description: "SQL injection via input",
      type: "AND",
      probability: 0.8,
      impact: "critical",
      technique: "T1190",
      relatedFindings: ["fp1"],
      relatedThreats: ["t1"],
      children: [
        { id: "n2", description: "Unsanitized input", type: "LEAF", probability: 0.9, impact: "high", children: [] },
      ],
    });

    expect(node).not.toBeNull();
    expect(node!.type).toBe("AND");
    expect(node!.children).toHaveLength(1);
    expect(node!.technique).toBe("T1190");
    expect(node!.relatedFindings).toEqual(["fp1"]);
  });

  it("defaults invalid type to LEAF", () => {
    const node = normalizeNode({ id: "n1", description: "test", type: "INVALID", probability: 0.5, impact: "high", children: [] });
    expect(node!.type).toBe("LEAF");
  });

  it("truncates deeply nested trees beyond depth limit", () => {
    // Build a tree 25 levels deep — should be truncated at depth 20
    let innermost: Record<string, unknown> = { id: "n-25", description: "deep leaf", type: "LEAF", probability: 0.1, impact: "low", children: [] };
    for (let i = 24; i >= 0; i--) {
      innermost = { id: `n-${i}`, description: `level ${i}`, type: "AND", probability: 0.5, impact: "high", children: [innermost] };
    }
    const root = normalizeNode(innermost);
    expect(root).not.toBeNull();
    // Walk to find the deepest node
    let node = root;
    let depth = 0;
    while (node && node.children.length > 0) {
      node = node.children[0];
      depth++;
    }
    // Should be truncated before reaching depth 25
    expect(depth).toBeLessThanOrEqual(20);
  });
});

describe("treesToFindings", () => {
  it("converts critical/high risk trees to findings", () => {
    const trees = [
      {
        goal: "Exfiltrate data",
        overallRisk: "critical" as const,
        rootNode: { id: "n1", description: "Data exfiltration", type: "OR" as const, probability: 0.7, impact: "critical", children: [], technique: "T1567" },
      },
    ];

    const findings = treesToFindings(trees, "/tmp/repo", "test-repo");
    expect(findings).toHaveLength(1);
    expect(findings[0].scanner).toBe("threat-model-pasta");
    expect(findings[0].ruleId).toBe("attack-tree/T1567");
    expect(findings[0].message).toContain("Exfiltrate data");
    expect(findings[0].startLine).toBe(1);
  });

  it("uses goal-based ruleId and unique startLine when technique is absent", () => {
    const trees = [
      {
        goal: "Exfiltrate data via SQL injection",
        overallRisk: "critical" as const,
        rootNode: { id: "n1", description: "Root", type: "OR" as const, probability: 0.7, impact: "critical", children: [] },
      },
      {
        goal: "Escalate privilege via SSRF",
        overallRisk: "high" as const,
        rootNode: { id: "n2", description: "Root", type: "OR" as const, probability: 0.5, impact: "high", children: [] },
      },
    ];

    const findings = treesToFindings(trees, "/tmp/repo", "test-repo");
    expect(findings).toHaveLength(2);
    expect(findings[0].ruleId).toContain("attack-tree/exfiltrate-data-via-sql-injection");
    expect(findings[1].ruleId).toContain("attack-tree/escalate-privilege-via-ssrf");
    expect(findings[0].startLine).toBe(1);
    expect(findings[1].startLine).toBe(2);
  });

  it("skips medium/low risk trees", () => {
    const trees = [
      {
        goal: "Minor issue",
        overallRisk: "medium" as const,
        rootNode: { id: "n1", description: "test", type: "LEAF" as const, probability: 0.3, impact: "low", children: [] },
      },
    ];

    expect(treesToFindings(trees, "/tmp/repo", "test-repo")).toHaveLength(0);
  });
});

describe("describeTree", () => {
  it("renders tree with indentation", () => {
    const node = {
      id: "n1",
      description: "Root",
      type: "OR" as const,
      probability: 0.7,
      impact: "high",
      children: [
        { id: "n2", description: "Child", type: "LEAF" as const, probability: 0.5, impact: "medium", children: [] },
      ],
    };

    const desc = describeTree(node, 0);
    expect(desc).toContain("n1: Root [OR]");
    expect(desc).toContain("  n2: Child");
  });
});

describe("computeFingerprint", () => {
  it("produces stable fingerprints", () => {
    const tree = {
      goal: "Test",
      overallRisk: "high" as const,
      rootNode: { id: "n1", description: "test", type: "LEAF" as const, probability: 0.5, impact: "high", children: [] },
    };
    const fp1 = computeFingerprint("repo", tree);
    const fp2 = computeFingerprint("repo", tree);
    expect(fp1).toBe(fp2);
    expect(fp1).toHaveLength(64);
  });

  it("is stable when goal text differs but structure is same", () => {
    const tree1 = {
      goal: "Exfiltrate user data via SQL injection",
      overallRisk: "high" as const,
      rootNode: { id: "n1", description: "Root", type: "LEAF" as const, probability: 0.5, impact: "high", children: [], technique: "T1190" },
    };
    const tree2 = {
      goal: "Achieve data exfiltration through SQL injection",
      overallRisk: "high" as const,
      rootNode: { id: "n1", description: "Root node", type: "LEAF" as const, probability: 0.6, impact: "high", children: [], technique: "T1190" },
    };
    expect(computeFingerprint("repo", tree1)).toBe(computeFingerprint("repo", tree2));
  });

  it("differs when tree structure changes", () => {
    const tree1 = {
      goal: "Test",
      overallRisk: "high" as const,
      rootNode: { id: "n1", description: "test", type: "LEAF" as const, probability: 0.5, impact: "high", children: [], technique: "T1190" },
    };
    const tree2 = {
      goal: "Test",
      overallRisk: "high" as const,
      rootNode: { id: "n1", description: "test", type: "LEAF" as const, probability: 0.5, impact: "high", children: [], technique: "T1059" },
    };
    expect(computeFingerprint("repo", tree1)).not.toBe(computeFingerprint("repo", tree2));
  });
});

describe("evidence anchors", () => {
  it("prompt includes evidence keyword", () => {
    const prompt = buildPastaPrompt(["[t1] spoofing: JWT spoofing"], [], 10);
    expect(prompt).toContain("evidence");
    expect(prompt).toContain("evidence_anchors");
  });

  it("normalizeNode parses evidence anchors", () => {
    const node = normalizeNode({
      id: "n1",
      description: "SQL injection",
      type: "LEAF",
      probability: 0.5,
      impact: "high",
      children: [],
      evidence_anchors: [
        { file_path: "src/db.ts", start_line: 42, description: "Unsanitized query" },
      ],
    });
    expect(node).not.toBeNull();
    expect(node!.evidenceAnchors).toHaveLength(1);
    expect(node!.evidenceAnchors![0].filePath).toBe("src/db.ts");
    expect(node!.evidenceAnchors![0].startLine).toBe(42);
  });

  it("normalizeNode omits evidence anchors when empty", () => {
    const node = normalizeNode({
      id: "n1",
      description: "test",
      type: "LEAF",
      probability: 0.5,
      impact: "high",
      children: [],
    });
    expect(node).not.toBeNull();
    expect(node!.evidenceAnchors).toBeUndefined();
  });
});

describe("triageAgentConfig", () => {
  it("returns a prompt mentioning PASTA", () => {
    const finding: Finding = {
      scanner: "threat-model-pasta",
      fingerprint: "abc",
      ruleId: "attack-tree/T1567",
      filePath: ".",
      startLine: 1,
      severity: "ERROR",
      message: "Attack tree: Exfiltrate data",
      evidence: "n1: Root [OR]",
      scannerConfidence: "HIGH",
      subcategory: ["vuln"],
      likelihood: "HIGH",
      impact: "HIGH",
      cwe: [],
      score: 54,
    };

    const config = threatModelPastaTask.triageAgentConfig!(finding, "test-repo");
    expect(config.prompt).toContain("PASTA");
    expect(config.prompt).toContain("multi-step attack chain");
  });
});
