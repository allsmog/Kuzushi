import { describe, expect, it } from "vitest";
import { __systemsTriggerSynthInternals } from "../../../src/agents/tasks/systems-hunt/trigger-synth.js";
import type {
  RankedSystemsSurface,
  SystemsInvariant,
  SystemsSurfacePack,
} from "../../../src/agents/tasks/systems-hunt/types.js";

const { buildTriggerPrompt, parseTriggers } = __systemsTriggerSynthInternals;

function makeSurface(overrides: Partial<RankedSystemsSurface> = {}): RankedSystemsSurface {
  return {
    id: "surface-1",
    filePath: "src/net/tcp_input.c",
    startLine: 42,
    displayName: "protocol-parser in src/net/tcp_input.c",
    kind: "protocol-parser",
    score: 21,
    domains: ["protocol-parser", "integer-boundary", "unsafe-memory"],
    reasons: ["network or packet-processing path", "multi-domain signal overlap (3)"],
    attackerControlledFields: ["seq", "ack", "len"],
    hardeningSignals: ["__stack_chk_fail"],
    evidence: [
      {
        domain: "protocol-parser",
        lineNumber: 42,
        lineContent: "if (seq < (int)ack && ack == 0xFFFF) memcpy(dst, pkt, len);",
        reason: "Protocol or parser signal at src/net/tcp_input.c:42",
      },
    ],
    ...overrides,
  };
}

function makePack(): SystemsSurfacePack {
  return {
    surfaceId: "surface-1",
    anchorFilePath: "src/net/tcp_input.c",
    anchorStartLine: 42,
    anchorSymbol: "handle_sack",
    relatedFiles: ["src/net/tcp_input.c"],
    callers: [],
    callees: [],
    compareCastSites: [
      {
        filePath: "src/net/tcp_input.c",
        line: 42,
        snippet: "if (seq < (int)ack && ack == 0xFFFF)",
      },
    ],
    counterSites: [{ filePath: "src/net/tcp_input.c", line: 42, snippet: "len" }],
    sentinelConstants: [{ filePath: "src/net/tcp_input.c", line: 42, snippet: "0xFFFF" }],
    allocationCopySites: [
      { filePath: "src/net/tcp_input.c", line: 42, snippet: "memcpy(dst, pkt, len)" },
    ],
    unsafeSites: [],
    resourceProvenanceSites: [],
    aliasingSites: [],
    scratchWriteSites: [],
    failureSideEffectSites: [],
    provenanceFacts: [],
    provenanceSummaries: [],
    provenanceChains: [],
    inputSites: [{ filePath: "src/net/tcp_input.c", line: 41, snippet: "tcp option parsing" }],
    hardeningSites: [{ filePath: "src/net/tcp_input.c", line: 80, snippet: "__stack_chk_fail();" }],
    helperTemplates: [
      {
        id: "signed-wraparound",
        title: "Signed/unsigned compare and wraparound",
        rationale: "Inspect wraparound sites.",
      },
      {
        id: "hardening-presence",
        title: "Hardening and mitigation presence",
        rationale: "Inspect hardening.",
      },
    ],
  };
}

describe("systems-trigger-synth", () => {
  it("builds prompts with surface-pack and boundary guidance", () => {
    const prompt = buildTriggerPrompt(
      [makeSurface()],
      [makePack()],
      [
        {
          id: "inv-1",
          surfaceId: "surface-1",
          kind: "packet-ordering",
          summary: "SACK state must be initialized before option processing",
          statement: "option parsing requires state != NULL",
          rationale: "later dereference assumes initialized state",
          evidence: ["src/net/tcp_input.c:42"],
          attackerControlledFields: ["seq", "ack"],
          cheapVerifiable: false,
        } satisfies SystemsInvariant,
      ],
      3,
    );

    expect(prompt).toContain("at most 3 trigger hypotheses per surface");
    expect(prompt).toContain("0xffff");
    expect(prompt).toContain("Related files: src/net/tcp_input.c");
    expect(prompt).toContain("[inv-1] SACK state must be initialized before option processing");
    expect(prompt).toContain("resource-origin");
  });

  it("normalizes trigger hypotheses", () => {
    const triggers = parseTriggers({
      triggers: [
        {
          id: "trig-1",
          surfaceId: "surface-1",
          orderedSteps: ["Send SYN", "Send crafted SACK option"],
          boundaryAssignments: [
            { field: "ack", value: "0xffff" },
            { field: "seq", value: "-1 wrapped to max" },
          ],
          statePreconditions: ["state allocated but not initialized"],
          attackerControlledFields: ["ack", "seq"],
          expectedPrimitive: "null pointer dereference",
          cheapVerifiable: false,
          rationale: "Option interaction reaches null state dereference",
        },
      ],
    });

    expect(triggers).toEqual([
      {
        id: "trig-1",
        surfaceId: "surface-1",
        orderedSteps: ["Send SYN", "Send crafted SACK option"],
        boundaryAssignments: { ack: "0xffff", seq: "-1 wrapped to max" },
        statePreconditions: ["state allocated but not initialized"],
        attackerControlledFields: ["ack", "seq"],
        expectedPrimitive: "null pointer dereference",
        cheapVerifiable: false,
        rationale: "Option interaction reaches null state dereference",
      },
    ]);
  });
});
