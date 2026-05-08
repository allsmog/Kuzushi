import { describe, expect, it } from "vitest";
import {
  assessStrideArtifact,
  buildStridePrompt,
  buildStrideRetryPrompt,
} from "../../../../src/agents/tasks/threat-modeling/randori-runner.js";

describe("assessStrideArtifact", () => {
  it("flags missing artifact", () => {
    expect(assessStrideArtifact(null)[0]).toMatch(/missing or is not a JSON object/);
  });

  it("flags empty threats array", () => {
    expect(assessStrideArtifact({ stage: "S4", threats: [] })[0]).toMatch(
      /at least one specific scenario/,
    );
  });

  it("flags threats with no valid evidence anchors", () => {
    const reasons = assessStrideArtifact({
      stage: "S4",
      threats: [
        { id: "T1", title: "Real threat", evidence_anchors: [] },
        { id: "T2", title: "Real threat 2", evidence_anchors: [{}] },
        {
          id: "T3",
          title: "Real threat 3",
          evidenceAnchors: [{ filePath: "", startLine: 0 }],
        },
      ],
    });
    expect(reasons.some((r) => /no valid evidence_anchors/.test(r))).toBe(true);
  });

  it("flags all-stub titles as the lazy template pattern", () => {
    const reasons = assessStrideArtifact({
      stage: "S4",
      threats: [
        {
          id: "T1",
          title: "Boundary abuse: TB-01",
          evidence_anchors: [{ file_path: "a", start_line: 1 }],
          probability: 0.7,
        },
        {
          id: "T2",
          title: "Entrypoint abuse: EP-01",
          evidence_anchors: [{ file_path: "b", start_line: 2 }],
          probability: 0.8,
        },
      ],
    });
    expect(reasons.some((r) => /placeholder titles/.test(r))).toBe(true);
  });

  it("flags missing and out-of-range probabilities", () => {
    const reasons = assessStrideArtifact({
      stage: "S4",
      threats: [
        {
          id: "T1",
          title: "Missing probability",
          evidence_anchors: [{ file_path: "a", start_line: 1 }],
        },
        {
          id: "T2",
          title: "Negative probability",
          evidence_anchors: [{ file_path: "b", start_line: 2 }],
          probability: -0.1,
        },
        {
          id: "T3",
          title: "Too high probability",
          evidence_anchors: [{ file_path: "c", start_line: 3 }],
          probability: 1.1,
        },
      ],
    });
    expect(reasons.some((r) => /invalid probability/.test(r))).toBe(true);
  });

  it("flags all-default 0.5 probabilities", () => {
    const reasons = assessStrideArtifact({
      stage: "S4",
      threats: [
        {
          id: "T1",
          title: "PR fork code execution",
          evidence_anchors: [{ file_path: "a", start_line: 1 }],
          probability: 0.5,
        },
        {
          id: "T2",
          title: "SSRF via alfred",
          evidence_anchors: [{ file_path: "b", start_line: 2 }],
          probability: 0.5,
        },
        {
          id: "T3",
          title: "Vault leak",
          evidence_anchors: [{ file_path: "c", start_line: 3 }],
          probability: 0.5,
        },
      ],
    });
    expect(reasons.some((r) => /probability=0\.5/.test(r))).toBe(true);
  });

  it("returns no issues for a well-formed artifact", () => {
    expect(
      assessStrideArtifact({
        stage: "S4",
        threats: [
          {
            id: "TS-001",
            title: "PR fork code execution with Vault credential exposure",
            evidenceAnchors: [
              {
                filePath: ".github/workflows/semgrep-prcheck.yaml",
                startLine: 58,
                description: "checkout fork",
              },
            ],
            probability: 0.82,
          },
        ],
      }),
    ).toEqual([]);
  });
});

describe("buildStridePrompt scaffolding", () => {
  it("includes STRIDE table, ATT&CK mapping, VerSprite, evidence anchors, and stub rejection", () => {
    const prompt = buildStridePrompt(20, "randori-output", null, "/repo");
    expect(prompt).toMatch(/STRIDE classification/);
    expect(prompt).toMatch(/MITRE ATT&CK \+ OWASP/);
    expect(prompt).toMatch(/VerSprite 5-factor/);
    expect(prompt).toMatch(/evidence_anchors/);
    expect(prompt).toMatch(/Reject.*Boundary abuse/);
    expect(prompt).toMatch(/file_path.*content.*snake_case/i);
  });

  it("includes the Read-before-Write guard for existing pasta-s4.json", () => {
    const prompt = buildStridePrompt(20, "randori-output", null, "/repo");
    expect(prompt).toMatch(/Read-before-Write guard/);
    expect(prompt).toMatch(/File has not been read yet/);
    expect(prompt).toContain("/repo/randori-output/pasta-s4.json");
  });

  it("retry prompt lists the supplied issues and the Read-before-Write guard", () => {
    const retry = buildStrideRetryPrompt(
      "randori-output",
      ["3/13 threats have no evidence_anchors", "all 13 threats use placeholder titles"],
      20,
      "/repo",
    );
    expect(retry).toMatch(/3\/13 threats have no evidence_anchors/);
    expect(retry).toMatch(/all 13 threats use placeholder titles/);
    expect(retry).toContain("/repo/randori-output/pasta-s4.json");
    expect(retry).toMatch(/Read-before-Write guard/);
  });
});
