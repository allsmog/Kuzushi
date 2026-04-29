import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  buildFallbackS4Threats,
  ensureFallbackS4Artifact,
  mergeRandoriStageOutputs,
  type RandoriArtifacts,
} from "../../../../src/agents/tasks/threat-modeling/randori-artifacts.js";

let tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
  tempDirs = [];
});

function makeArtifacts(partial: Partial<RandoriArtifacts> = {}): RandoriArtifacts {
  return {
    state: null,
    s1Objectives: null,
    s2Scope: null,
    s3Decomposition: null,
    s4Threats: null,
    narrative: null,
    ...partial,
  };
}

describe("Randori artifact fallback S4", () => {
  it("derives bounded STRIDE threats from S3 trust boundaries when S4 is missing", () => {
    const artifacts = makeArtifacts({
      s3Decomposition: {
        trust_boundaries: [
          {
            id: "TB-01",
            name: "pull_request_target Privilege Boundary",
            description:
              "Untrusted PR content can cross into a privileged GitHub Actions runner with write token access.",
            risk_level: "critical",
            gaps: ["PR branch checkout happens after privileged trigger"],
            controls: ["GitHub token scoping"],
            grounding: [
              "workflows/semgrep-prcheck.yaml:58-75 - git checkout $BRANCH_NAME after pull_request_target",
            ],
          },
        ],
      },
    });

    const threats = buildFallbackS4Threats(artifacts, 3);

    expect(threats).toHaveLength(1);
    expect(threats[0]).toMatchObject({
      id: "S4-FB-001",
      stride_category: "elevation-of-privilege",
      impact: "critical",
      target_assets: ["TB-01"],
    });
    expect(threats[0]?.["evidence_anchors"]).toEqual([
      {
        file_path: "workflows/semgrep-prcheck.yaml",
        start_line: 58,
        description: "git checkout $BRANCH_NAME after pull_request_target",
      },
    ]);
  });

  it("merges fallback threats into the normal S4 contract for downstream conversion", () => {
    const merged = mergeRandoriStageOutputs(
      makeArtifacts({
        s2Scope: {
          components: {
            workflows: [
              {
                id: "WF-01",
                name: "semgrep-prcheck",
                type: "workflow",
                description: "Runs Semgrep on PR branches.",
              },
            ],
          },
        },
        s3Decomposition: {
          trust_boundaries: [
            {
              id: "TB-01",
              name: "Vault Secret Injection Boundary",
              description: "Vault credentials enter runner steps that later execute scripts.",
              risk_level: "high",
              grounding: ["workflows/stark-fossa-pr-scan.yaml:24 - vault-action injects secrets"],
            },
          ],
        },
      }),
      { fallbackMaxThreats: 2 },
    );

    expect(merged?.["fallback_generated"]).toBe(true);
    expect(merged?.["threat_scenarios"]).toHaveLength(1);
    expect(merged?.["dfd"]).toMatchObject({
      elements: expect.arrayContaining([expect.objectContaining({ id: "WF-01" })]),
    });
  });

  it("converts S3 graph arrays into canonical graph v2 nodes and flows", () => {
    const merged = mergeRandoriStageOutputs(
      makeArtifacts({
        s3Decomposition: {
          external_entities: [{ id: "E-EXT", name: "External PR author", trust_zone: "external" }],
          entry_points: [{ id: "EP-PR", name: "pull_request event", trust_zone: "github" }],
          processes: [{ id: "P-WF", name: "Privileged workflow", trust_zone: "runner" }],
          data_stores: [{ id: "DS-SECRETS", name: "Vault secrets", trust_zone: "internal" }],
          data_flows: [
            {
              id: "F-1",
              from: "E-EXT",
              to: "EP-PR",
              label: "Open PR",
              protocol: "https",
              crosses: ["TB-INTERNET"],
            },
            {
              id: "F-2",
              from: "P-WF",
              to: "DS-SECRETS",
              label: "Read secrets",
              crosses: ["TB-SECRETS"],
            },
          ],
          trust_boundaries: [
            { id: "TB-INTERNET", name: "Public internet" },
            { id: "TB-SECRETS", name: "Secret boundary" },
          ],
        },
        s4Threats: { threats: [] },
      }),
      { synthesizeThreats: false },
    );

    const dfd = merged?.["dfd"] as Record<string, unknown>;
    expect(dfd["nodes"]).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: "E-EXT", type: "external-entity" }),
        expect.objectContaining({ id: "EP-PR", type: "process" }),
        expect.objectContaining({ id: "P-WF", type: "process" }),
        expect.objectContaining({ id: "DS-SECRETS", type: "data-store" }),
      ]),
    );
    expect(dfd["flows"]).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: "F-1",
          source_id: "E-EXT",
          target_id: "EP-PR",
          trust_boundary_ids: ["TB-INTERNET"],
        }),
        expect.objectContaining({
          id: "F-2",
          source_id: "P-WF",
          target_id: "DS-SECRETS",
          trust_boundary_ids: ["TB-SECRETS"],
        }),
      ]),
    );
    expect(dfd["trust_boundaries"]).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: "TB-INTERNET", crossing_flow_ids: ["F-1"] }),
        expect.objectContaining({ id: "TB-SECRETS", crossing_flow_ids: ["F-2"] }),
      ]),
    );
  });

  it("writes pasta-s4.json when a run has useful S3 but no S4", () => {
    const repoRoot = mkdtempSync(path.join(tmpdir(), "kuzushi-randori-"));
    tempDirs.push(repoRoot);
    const artifacts = makeArtifacts({
      s3Decomposition: {
        entry_points: [
          {
            id: "EP-01",
            name: "comment command trigger",
            description: "Issue comment command controls privileged workflow behavior.",
            file: "workflows/stark-sail-commands.yaml",
          },
        ],
      },
    });

    const result = ensureFallbackS4Artifact(
      repoRoot,
      ".kuzushi/runs/1/randori-output",
      artifacts,
      1,
    );
    const written = JSON.parse(readFileSync(result.path, "utf-8"));

    expect(result.written).toBe(true);
    expect(written).toMatchObject({
      stage: "S4",
      generated_by: "kuzushi-fallback",
      threats: [expect.objectContaining({ id: "S4-FB-001" })],
    });
  });
});
