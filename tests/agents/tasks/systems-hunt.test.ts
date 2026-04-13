import { describe, expect, it } from "vitest";
import {
  __systemsHuntInternals,
} from "../../../src/agents/tasks/systems-hunt/hunt.js";
import {
  buildSystemsHuntArtifactDetail,
  buildSystemsHuntArtifactPath,
  extractSystemsHuntArtifactPath,
} from "../../../src/agents/tasks/systems-hunt/artifacts.js";
import type { Finding } from "../../../src/scanners/types.js";
import type {
  RankedSystemsSurface,
  SystemsHuntConfig,
  SystemsInvariant,
} from "../../../src/agents/tasks/systems-hunt/types.js";

const {
  buildLensPrompt,
  parseLensOutput,
  mergeLensFindings,
  createSystemsHuntToolGuard,
} = __systemsHuntInternals;

function makeSurface(overrides: Partial<RankedSystemsSurface> = {}): RankedSystemsSurface {
  return {
    id: "surface-1",
    filePath: "src/vmm/guest_mem.rs",
    startLine: 88,
    displayName: "unsafe-region in src/vmm/guest_mem.rs",
    kind: "unsafe-region",
    score: 18,
    domains: ["unsafe-memory", "integer-boundary"],
    reasons: ["unsafe or memory-manipulation path"],
    attackerControlledFields: ["guest_len"],
    hardeningSignals: [],
    evidence: [
      {
        domain: "unsafe-memory",
        lineNumber: 88,
        lineContent: "unsafe { std::slice::from_raw_parts(ptr, guest_len) }",
        reason: "Unsafe memory primitive at src/vmm/guest_mem.rs:88",
      },
    ],
    ...overrides,
  };
}

function makeConfig(): SystemsHuntConfig {
  return {
    model: "anthropic:claude-orchid-preview",
    maxFindings: 10,
    maxSurfaces: 4,
    maxConcurrentSurfaces: 2,
    maxTurnsPerSurface: 16,
    artifactRoot: "/tmp/repo/.kuzushi/systems-hunt",
    artifactRootRelative: ".kuzushi/systems-hunt",
    enableCodeqlAssist: true,
    enableBashProbing: true,
  };
}

describe("systems-hunt", () => {
  it("builds lens prompts with codeql and turn budget context", () => {
    const prompt = buildLensPrompt(
      makeSurface(),
      [{
        id: "inv-1",
        surfaceId: "surface-1",
        kind: "unsafe-precondition",
        summary: "guest_len must be validated before entering unsafe",
        statement: "guest_len <= mapped region length",
        rationale: "from_raw_parts trusts caller-provided length",
        evidence: ["src/vmm/guest_mem.rs:88"],
        attackerControlledFields: ["guest_len"],
        cheapVerifiable: true,
      } satisfies SystemsInvariant],
      "buffer-unsafe",
      makeConfig(),
      "/tmp/repo/.kuzushi/codeql-db",
    );

    expect(prompt).toContain("within 16 turns");
    expect(prompt).toContain("CodeQL database");
    expect(prompt).toContain("from_raw_parts");
  });

  it("parses and merges lens outputs by location and cwe", () => {
    const protocolFindings = parseLensOutput("protocol-state", {
      findings: [
        {
          title: "Guest length reaches unsafe slice constructor",
          cwe: "CWE-787",
          severity: "ERROR",
          confidence: "HIGH",
          filePath: "src/vmm/guest_mem.rs",
          startLine: 88,
          message: "Unchecked guest_len can overrun host slice bounds",
          rationale: "Protocol state allows guest_len before region validation",
          violatedInvariantIds: ["inv-1"],
          violatedInvariant: "guest_len must be validated before entering unsafe",
          triggerSequence: ["Map guest memory", "Send oversized descriptor"],
          attackerControlledFields: ["guest_len"],
          memoryPrimitive: "out-of-bounds write",
          hardeningNotes: ["No guard before from_raw_parts"],
          cheapVerifiable: true,
          analysisPath: [{ filePath: "src/vmm/guest_mem.rs", line: 88, role: "unsafe-enter" }],
        },
      ],
    }, "/tmp/repo");
    const arithmeticFindings = parseLensOutput("arithmetic-sentinel", {
      findings: [
        {
          title: "Guest length reaches unsafe slice constructor",
          cwe: "CWE-787",
          severity: "ERROR",
          confidence: "MEDIUM",
          filePath: "src/vmm/guest_mem.rs",
          startLine: 88,
          message: "Unchecked guest_len can overrun host slice bounds",
          rationale: "guest_len truncation can bypass caller assumptions",
          violatedInvariantIds: ["inv-1"],
          violatedInvariant: "guest_len must be validated before entering unsafe",
          triggerSequence: ["Map guest memory", "Use large guest_len"],
          attackerControlledFields: ["guest_len"],
          memoryPrimitive: "out-of-bounds write",
          hardeningNotes: ["No saturating cast"],
          cheapVerifiable: false,
          analysisPath: [{ filePath: "src/vmm/guest_mem.rs", line: 90, role: "length-cast" }],
        },
      ],
    }, "/tmp/repo");

    const merged = mergeLensFindings([makeSurface()], [...protocolFindings, ...arithmeticFindings]);
    const [finding] = [...merged.values()];
    expect(finding.lenses).toEqual(new Set(["protocol-state", "arithmetic-sentinel"]));
    expect(finding.cheapVerifiable).toBe(true);
    expect([...finding.triggerSequence]).toEqual(
      expect.arrayContaining(["Map guest memory", "Send oversized descriptor", "Use large guest_len"]),
    );
  });

  it("guards Bash and Write usage to deterministic analysis only", () => {
    const guard = createSystemsHuntToolGuard("/tmp/repo", "/tmp/repo/.kuzushi/systems-hunt/scratch");

    expect(guard("Write", { file_path: "/tmp/repo/.kuzushi/systems-hunt/scratch/note.txt" }))
      .toEqual({ behavior: "allow" });
    expect(guard("Write", { file_path: "/tmp/repo/src/main.c" }).behavior).toBe("deny");
    expect(guard("Bash", { command: "rg -n packet src" })).toEqual({ behavior: "allow" });
    expect(guard("Bash", { command: "rg -n packet src && rm -rf /tmp/repo" }).behavior).toBe("deny");
  });

  it("uses stable artifact naming and provenance details", () => {
    const artifactPath = buildSystemsHuntArtifactPath("/tmp/repo/.kuzushi/systems-hunt", "fp-001");
    const finding: Finding = {
      fingerprint: "fp-001",
      scanner: "systems-hunt",
      ruleId: "systems-hunt/CWE-787",
      filePath: "src/vmm/guest_mem.rs",
      startLine: 88,
      severity: "ERROR",
      message: "Unchecked guest_len can overrun host slice bounds",
      scannerConfidence: "HIGH",
      subcategory: ["memory-safety"],
      likelihood: "HIGH",
      impact: "HIGH",
      cwe: ["CWE-787"],
      score: 9,
      engineProvenance: [{ kind: "agentic", detail: buildSystemsHuntArtifactDetail(".kuzushi/systems-hunt/fp-001.json") }],
    };

    expect(artifactPath).toBe("/tmp/repo/.kuzushi/systems-hunt/fp-001.json");
    expect(extractSystemsHuntArtifactPath(finding)).toBe(".kuzushi/systems-hunt/fp-001.json");
  });
});
