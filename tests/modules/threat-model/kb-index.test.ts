import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { ThreatModelDocument } from "../../../src/agents/tasks/threat-modeling/types.js";
import { contextSnapshotPath } from "../../../src/modules/sast/context-persist.js";
import {
  buildThreatModelKbChunks,
  ensureThreatModelKbIndex,
  readThreatModelKbStatus,
  searchThreatModelKb,
  threatModelKbPath,
  threatModelSourcePath,
} from "../../../src/modules/threat-model/kb-index.js";

const tempDirs: string[] = [];

function tempRepo(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-tm-kb-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function doc(title = "Fork PR can steal secrets"): ThreatModelDocument {
  return {
    version: "2.0",
    dfd: {
      nodes: [
        {
          id: "E1",
          type: "external-entity",
          name: "Fork contributor",
          description: "External contributor opening pull requests",
          trustZone: "external",
        },
        {
          id: "P1",
          type: "process",
          name: "Privileged workflow",
          description: "pull_request_target workflow",
          trustZone: "ci",
        },
      ],
      flows: [
        {
          id: "DF-1",
          name: "PR checkout",
          description: "PR head ref reaches privileged workflow",
          sourceId: "E1",
          targetId: "P1",
          protocol: "git",
          trustBoundaryIds: ["TB-1"],
        },
      ],
      trustBoundaries: [
        {
          id: "TB-1",
          name: "GitHub to CI",
          outerZone: "external",
          innerZone: "ci",
          crossingFlowIds: ["DF-1"],
        },
      ],
    },
    threats: [
      {
        id: "T1",
        actorIds: ["E1"],
        entrypointIds: ["P1"],
        targetElementIds: ["P1"],
        flowIds: ["DF-1"],
        category: "elevation-of-privilege",
        title,
        description: "A fork PR controls code that executes with privileged workflow context.",
        attackVector: "Open a fork pull request with malicious workflow-reached code.",
        preconditions: ["Fork PR opened"],
        impact: "critical",
        likelihood: "high",
        existingMitigations: [],
        missingMitigations: ["pin checkout to merge ref"],
        relatedCwe: ["CWE-269"],
        affectedFiles: [{ filePath: "workflows/review.yaml", startLine: 12 }],
        sources: [
          {
            name: "PR head ref",
            kind: "source",
            filePath: "workflows/review.yaml",
            startLine: 12,
          },
        ],
        sinks: [
          {
            name: "privileged script",
            kind: "sink",
            filePath: "workflows/review.yaml",
            startLine: 42,
          },
        ],
        guards: [{ name: "none", description: "No actor permission gate" }],
        requiredCapabilities: ["Open a fork PR"],
        evidenceAnchors: [
          {
            filePath: "workflows/review.yaml",
            startLine: 42,
            description: "Runs PR-controlled script",
          },
        ],
      },
    ],
    summary: {
      total: 1,
      bySeverity: { critical: 1 },
      byCategory: {
        spoofing: 0,
        tampering: 0,
        repudiation: 0,
        "information-disclosure": 0,
        "denial-of-service": 0,
        "elevation-of-privilege": 1,
      },
    },
  };
}

function persist(repo: string, document: ThreatModelDocument): void {
  const filePath = threatModelSourcePath(repo);
  mkdirSync(path.dirname(filePath), { recursive: true });
  writeFileSync(filePath, `${JSON.stringify(document, null, 2)}\n`, "utf8");
}

describe("threat-model KB index", () => {
  it("chunks graph v2 threats, flows, evidence, and references", () => {
    const chunks = buildThreatModelKbChunks(doc());
    expect(chunks.map((chunk) => chunk.kind)).toEqual(
      expect.arrayContaining([
        "actor",
        "flow",
        "boundary",
        "threat",
        "source",
        "sink",
        "guard",
        "evidence",
      ]),
    );
    expect(chunks.some((chunk) => chunk.threatIds.includes("T1"))).toBe(true);
    expect(chunks.some((chunk) => chunk.flowIds.includes("DF-1"))).toBe(true);
  });

  it("builds once and reuses the index while hashes match", () => {
    const repo = tempRepo();
    const document = doc();
    persist(repo, document);

    const first = ensureThreatModelKbIndex({ repoRoot: repo, document });
    const second = ensureThreatModelKbIndex({ repoRoot: repo, document });

    expect(first.rebuilt).toBe(true);
    expect(second.rebuilt).toBe(false);
    expect(second.reason).toBe("current");
    expect(readThreatModelKbStatus(repo, document).current).toBe(true);
  });

  it("marks the index stale when the threat model or context snapshot changes", () => {
    const repo = tempRepo();
    const document = doc();
    persist(repo, document);
    const built = ensureThreatModelKbIndex({ repoRoot: repo, document });
    expect(built.rebuilt).toBe(true);

    const changed = doc("Changed threat title");
    persist(repo, changed);
    expect(readThreatModelKbStatus(repo, changed).staleReason).toBe("threat-model-hash");

    ensureThreatModelKbIndex({ repoRoot: repo, document: changed });
    writeFileSync(
      contextSnapshotPath(repo),
      JSON.stringify({ target: repo, timestamp: Date.now(), discovery: "auto" }),
      "utf8",
    );
    expect(readThreatModelKbStatus(repo, changed).staleReason).toBe("context-hash");
  });

  it("searches by text and filters by actor, flow, threat, and kind", () => {
    const repo = tempRepo();
    const document = doc();
    persist(repo, document);
    ensureThreatModelKbIndex({ repoRoot: repo, document });

    const result = searchThreatModelKb(threatModelKbPath(repo), {
      query: "privileged script",
      actorId: "E1",
      flowIds: ["DF-1"],
      threatIds: ["T1"],
      kinds: ["sink"],
      limit: 5,
    });

    expect(result.results).toHaveLength(1);
    expect(result.results[0]?.kind).toBe("sink");
    expect(result.results[0]?.title).toContain("Fork PR can steal secrets");
  });
});
