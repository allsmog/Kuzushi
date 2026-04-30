import { describe, expect, it } from "vitest";
import { __systemsInvariantExtractInternals } from "../../../src/agents/tasks/systems-hunt/invariant-extract.js";
import type { RankedSystemsSurface } from "../../../src/agents/tasks/systems-hunt/types.js";

const { buildInvariantPrompt, parseInvariants } = __systemsInvariantExtractInternals;

function makeSurface(overrides: Partial<RankedSystemsSurface> = {}): RankedSystemsSurface {
  return {
    id: "surface-1",
    filePath: "src/net/tcp_input.c",
    startLine: 42,
    displayName: "protocol-parser in src/net/tcp_input.c",
    kind: "protocol-parser",
    score: 15,
    domains: ["protocol-parser", "integer-boundary"],
    reasons: ["network or packet-processing path"],
    attackerControlledFields: ["seq", "ack"],
    hardeningSignals: ["__stack_chk_fail"],
    evidence: [
      {
        domain: "protocol-parser",
        lineNumber: 42,
        lineContent: "if (seq < (int)ack && ack == 0xFFFF)",
        reason: "Protocol or parser signal at src/net/tcp_input.c:42",
      },
    ],
    ...overrides,
  };
}

describe("systems-invariant-extract", () => {
  it("builds a prompt with invariants and cheap verification guidance", () => {
    const prompt = buildInvariantPrompt([makeSurface()]);
    expect(prompt).toContain("packet-ordering");
    expect(prompt).toContain("resource-provenance");
    expect(prompt).toContain("aliasing-boundary");
    expect(prompt).toContain("failure-side-effect");
    expect(prompt).toContain("cheapVerifiable");
    expect(prompt).toContain("src/net/tcp_input.c:42");
  });

  it("parses structured invariants", () => {
    const invariants = parseInvariants({
      invariants: [
        {
          id: "inv-1",
          surfaceId: "surface-1",
          kind: "packet-ordering",
          summary: "SACK options must not be compared before state is initialized",
          statement: "The comparison must only execute after state pointer allocation",
          rationale: "Two crafted packets can force the comparison before allocation",
          evidence: ["src/net/tcp_input.c:42"],
          attackerControlledFields: ["seq", "ack"],
          cheapVerifiable: false,
        },
      ],
    });

    expect(invariants).toEqual([
      expect.objectContaining({
        id: "inv-1",
        surfaceId: "surface-1",
        kind: "packet-ordering",
        cheapVerifiable: false,
      }),
    ]);
  });

  it("parses resource provenance invariant classes", () => {
    const invariants = parseInvariants({
      invariants: [
        {
          id: "inv-rp",
          surfaceId: "surface-1",
          kind: "resource-provenance",
          summary: "shared backing page must not become writable scratch output",
          statement: "page-cache-backed src must be copied or isolated before dst writes",
          rationale: "zero-copy aliases can preserve mutation after validation failure",
          evidence: ["src/crypto/algif_aead.c:42"],
          attackerControlledFields: ["src", "dst", "authsize"],
          cheapVerifiable: true,
        },
        {
          id: "inv-alias",
          surfaceId: "surface-1",
          kind: "aliasing-boundary",
          summary: "source and destination aliases must be rejected before in-place writes",
          statement: "src == dst requires a private output buffer before scratch writes",
          rationale: "caller-owned input may be chained as a writable destination",
          evidence: ["src/crypto/algif_aead.c:48"],
          attackerControlledFields: ["src", "dst"],
          cheapVerifiable: true,
        },
      ],
    });

    expect(invariants.map((invariant) => invariant.kind)).toEqual([
      "resource-provenance",
      "aliasing-boundary",
    ]);
  });
});
