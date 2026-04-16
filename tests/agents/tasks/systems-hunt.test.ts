import { describe, expect, it } from "vitest";
import {
  buildSystemsHuntArtifactDetail,
  buildSystemsHuntArtifactPath,
  extractSystemsHuntArtifactPath,
} from "../../../src/agents/tasks/systems-hunt/artifacts.js";
import { __systemsHuntInternals } from "../../../src/agents/tasks/systems-hunt/hunt.js";
import type {
  RankedSystemsSurface,
  SystemsHuntConfig,
  SystemsInvariant,
} from "../../../src/agents/tasks/systems-hunt/types.js";
import type { Finding } from "../../../src/scanners/types.js";

const {
  buildLensPrompt,
  buildCorroborationPrompt,
  parseLensOutput,
  parseCorroborationOutput,
  resolveEmissionDecision,
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
    surfacePackDepth: 4,
    maxTriggerHypothesesPerSurface: 3,
    maxConcurrentSurfaces: 2,
    maxTurnsPerSurface: 16,
    minLensAgreement: 2,
    maxCorroborationTurns: 8,
    artifactRoot: "/tmp/repo/.kuzushi/systems-hunt",
    artifactRootRelative: ".kuzushi/systems-hunt",
    enableCodeqlAssist: true,
    enableBashProbing: true,
    enableCodeqlTemplates: true,
    enableCounterexamplePass: true,
  };
}

describe("systems-hunt", () => {
  it("builds lens prompts with codeql and turn budget context", () => {
    const prompt = buildLensPrompt(
      makeSurface(),
      undefined,
      [
        {
          id: "inv-1",
          surfaceId: "surface-1",
          kind: "unsafe-precondition",
          summary: "guest_len must be validated before entering unsafe",
          statement: "guest_len <= mapped region length",
          rationale: "from_raw_parts trusts caller-provided length",
          evidence: ["src/vmm/guest_mem.rs:88"],
          attackerControlledFields: ["guest_len"],
          cheapVerifiable: true,
        } satisfies SystemsInvariant,
      ],
      [],
      "buffer-unsafe",
      makeConfig(),
      "/tmp/repo/.kuzushi/codeql-db",
    );

    expect(prompt).toContain("within 16 turns");
    expect(prompt).toContain("CodeQL database");
    expect(prompt).toContain("from_raw_parts");
  });

  it("parses and merges lens outputs by location and cwe", () => {
    const protocolFindings = parseLensOutput(
      "protocol-state",
      {
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
            triggerHypothesisIds: ["trig-1"],
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
      },
      "/tmp/repo",
    );
    const arithmeticFindings = parseLensOutput(
      "arithmetic-sentinel",
      {
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
            triggerHypothesisIds: ["trig-1"],
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
      },
      "/tmp/repo",
    );

    const merged = mergeLensFindings([makeSurface()], [...protocolFindings, ...arithmeticFindings]);
    const [finding] = [...merged.values()];
    expect(finding.lenses).toEqual(new Set(["protocol-state", "arithmetic-sentinel"]));
    expect(finding.cheapVerifiable).toBe(true);
    expect(finding.triggerHypothesisIds).toEqual(new Set(["trig-1"]));
    expect([...finding.triggerSequence]).toEqual(
      expect.arrayContaining([
        "Map guest memory",
        "Send oversized descriptor",
        "Use large guest_len",
      ]),
    );
  });

  it("guards Bash and Write usage to deterministic analysis only", () => {
    const guard = createSystemsHuntToolGuard(
      "/tmp/repo",
      "/tmp/repo/.kuzushi/systems-hunt/scratch",
    );

    expect(
      guard("Write", { file_path: "/tmp/repo/.kuzushi/systems-hunt/scratch/note.txt" }),
    ).toEqual({ behavior: "allow" });
    expect(guard("Write", { file_path: "/tmp/repo/src/main.c" }).behavior).toBe("deny");
    expect(guard("Bash", { command: "rg -n packet src" })).toEqual({ behavior: "allow" });
    expect(guard("Bash", { command: "rg -n packet src && rm -rf /tmp/repo" }).behavior).toBe(
      "deny",
    );
  });

  it("uses stable artifact naming and provenance details", () => {
    const artifactPath = buildSystemsHuntArtifactPath("/tmp/repo/.kuzushi/systems-hunt", "fp-001");
    const finding: Finding = {
      fingerprint: "fp-001",
      taskId: "systems-hunt",
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
      engineProvenance: [
        {
          kind: "agentic",
          detail: buildSystemsHuntArtifactDetail(".kuzushi/systems-hunt/fp-001.json"),
        },
      ],
    };

    expect(artifactPath).toBe("/tmp/repo/.kuzushi/systems-hunt/fp-001.json");
    expect(extractSystemsHuntArtifactPath(finding)).toBe(".kuzushi/systems-hunt/fp-001.json");
  });

  it("parses corroboration output and applies emission gating", () => {
    const corroboration = parseCorroborationOutput(
      {
        status: "insufficient-corroboration",
        rationale: "No local guard found, but direct confirmation is still broad.",
        coherentTrigger: true,
        cheapVerifiable: false,
        guardLocations: [],
        counterexampleNotes: ["No state reset found before unsafe entry"],
      },
      "/tmp/repo",
      false,
      0.25,
    );

    expect(corroboration.status).toBe("insufficient-corroboration");
    expect(corroboration.coherentTrigger).toBe(true);
    expect(corroboration.costUsd).toBe(0.25);
    expect(
      resolveEmissionDecision({
        lensCount: 2,
        minLensAgreement: 2,
        coherentTrigger: true,
        corroboration,
      }),
    ).toEqual({
      emit: true,
      corroborationStatus: "lens-agreement-only",
      cheapVerifiable: false,
    });
    expect(
      resolveEmissionDecision({
        lensCount: 1,
        minLensAgreement: 2,
        coherentTrigger: true,
        corroboration: {
          ...corroboration,
          status: "counterexample-found",
        },
      }),
    ).toEqual({
      emit: false,
      cheapVerifiable: false,
    });
  });

  it("builds corroboration prompts with trigger and pack context", () => {
    const prompt = buildCorroborationPrompt(
      {
        key: "src/vmm/guest_mem.rs:88:CWE-787",
        surface: makeSurface(),
        title: "Guest length reaches unsafe slice constructor",
        cwe: ["CWE-787"],
        severity: "ERROR",
        confidence: "HIGH",
        filePath: "src/vmm/guest_mem.rs",
        startLine: 88,
        message: "Unchecked guest_len can overrun host slice bounds",
        lenses: new Set(["buffer-unsafe", "arithmetic-sentinel"]),
        rationales: ["Unsafe length reaches slice constructor"],
        triggerHypothesisIds: new Set(["trig-1"]),
        violatedInvariantIds: new Set(["inv-1"]),
        violatedInvariant: "guest_len must be validated before entering unsafe",
        triggerSequence: new Set(["Map guest memory", "Use large guest_len"]),
        attackerControlledFields: new Set(["guest_len"]),
        memoryPrimitive: "out-of-bounds write",
        hardeningNotes: new Set(["No guard before from_raw_parts"]),
        cheapVerifiable: false,
        analysisPath: [{ filePath: "src/vmm/guest_mem.rs", line: 88, role: "unsafe-enter" }],
      },
      {
        surfaceId: "surface-1",
        anchorFilePath: "src/vmm/guest_mem.rs",
        anchorStartLine: 88,
        anchorSymbol: "map_guest",
        relatedFiles: ["src/vmm/guest_mem.rs", "src/vmm/dispatch.rs"],
        callers: [],
        callees: [],
        compareCastSites: [],
        counterSites: [
          { filePath: "src/vmm/guest_mem.rs", line: 90, snippet: "guest_len as usize" },
        ],
        sentinelConstants: [],
        allocationCopySites: [],
        unsafeSites: [
          { filePath: "src/vmm/guest_mem.rs", line: 88, snippet: "from_raw_parts(ptr, guest_len)" },
        ],
        inputSites: [
          { filePath: "src/vmm/dispatch.rs", line: 22, snippet: "descriptor.guest_len" },
        ],
        hardeningSites: [],
        helperTemplates: [
          {
            id: "rust-unsafe-len",
            title: "Rust unsafe len/pointer misuse",
            rationale: "Inspect unsafe length assumptions.",
          },
        ],
      },
      [
        {
          id: "trig-1",
          surfaceId: "surface-1",
          orderedSteps: ["Map guest memory", "Provide oversized descriptor"],
          boundaryAssignments: { guest_len: "0xffff" },
          statePreconditions: ["descriptor accepted before validation"],
          attackerControlledFields: ["guest_len"],
          expectedPrimitive: "out-of-bounds write",
          cheapVerifiable: true,
          rationale: "Large descriptor length reaches unsafe slice constructor",
        },
      ],
      makeConfig(),
      "/tmp/repo/.kuzushi/codeql-db",
    );

    expect(prompt).toContain("counterexample/corroboration pass");
    expect(prompt).toContain("Map guest memory -> Provide oversized descriptor");
    expect(prompt).toContain("Related files: src/vmm/guest_mem.rs, src/vmm/dispatch.rs");
    expect(prompt).toContain("Optional CodeQL database");
  });
});
