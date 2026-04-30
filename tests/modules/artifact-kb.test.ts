import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { ThreatModelDocument } from "../../src/agents/tasks/threat-modeling/types.js";
import type { XRayReportData } from "../../src/agents/tasks/x-ray/runner.js";
import {
  artifactKbPath,
  buildContextSnapshotChunks,
  buildThreatModelArtifactChunks,
  buildXRayInvariantChunks,
  createArtifactKbSearchTool,
  indexArtifactKb,
  indexContextSnapshotArtifact,
  indexThreatModelArtifact,
  indexXRayArtifacts,
  searchArtifactKb,
} from "../../src/modules/_shared/artifact-kb/index.js";
import type { ContextSnapshot } from "../../src/ui/state.js";

const tempDirs: string[] = [];

function tempRoot(): string {
  const dir = mkdtempSync(path.join(tmpdir(), "artifact-kb-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function sampleContextSnapshot(root: string): ContextSnapshot {
  return {
    target: root,
    timestamp: Date.now(),
    discovery: "flat",
    options: { enrichment: false },
    repoContext: {
      languages: ["TypeScript"],
      frameworks: ["Express"],
      authPatterns: ["JWT"],
      sanitizationLibs: ["DOMPurify"],
      ormOrDb: ["Prisma"],
      entryPoints: ["src/server.ts"],
    },
    fileIndex: {
      tree: [{ path: "src/server.ts" }],
      totalFiles: 1,
      truncated: false,
      patternMatches: {
        "auth-session": [
          {
            pattern: "jwt",
            filePath: "src/server.ts",
            lineNumber: 12,
            lineContent: "app.use(jwtMiddleware)",
          },
        ],
      },
    },
    appModel: {
      version: "1",
      routes: [
        {
          id: "route:GET:/admin",
          method: "GET",
          path: "/admin",
          filePath: "src/server.ts",
          startLine: 42,
          framework: "Express",
          middleware: ["jwtMiddleware"],
          authMechanisms: ["JWT"],
        },
      ],
      outboundClients: [],
      dataStores: [],
      backgroundJobs: [],
      serviceBoundaries: [],
      relevantFiles: ["src/server.ts"],
      notes: [],
    },
  };
}

function sampleThreatModel(): ThreatModelDocument {
  return {
    version: "2.0",
    methodology: "stride",
    dfd: {
      nodes: [
        {
          id: "actor:user",
          type: "external-entity",
          name: "User",
          description: "Internet user",
          trustZone: "public",
        },
        {
          id: "process:api",
          type: "process",
          name: "API",
          description: "Backend API",
          trustZone: "app",
        },
      ],
      flows: [
        {
          id: "flow:login",
          sourceId: "actor:user",
          targetId: "process:api",
          protocol: "HTTPS",
          description: "User submits credentials",
          trustBoundaryIds: ["boundary:internet"],
        },
      ],
      trustBoundaries: [
        {
          id: "boundary:internet",
          name: "Internet boundary",
          outerZone: "public",
          innerZone: "app",
          crossingFlowIds: ["flow:login"],
        },
      ],
    },
    threats: [
      {
        id: "T-1",
        targetElementIds: ["process:api"],
        actorIds: ["actor:user"],
        flowIds: ["flow:login"],
        category: "spoofing",
        title: "JWT replay",
        description: "A user replays a stale token.",
        attackVector: "Replay stolen JWT against /admin.",
        preconditions: ["Token leakage"],
        impact: "high",
        likelihood: "medium",
        existingMitigations: ["JWT expiry"],
        missingMitigations: ["Token binding"],
        relatedCwe: ["CWE-287"],
        affectedFiles: [{ filePath: "src/server.ts", startLine: 42 }],
      },
    ],
    summary: {
      total: 1,
      bySeverity: { high: 1 },
      byCategory: {
        spoofing: 1,
        tampering: 0,
        repudiation: 0,
        "information-disclosure": 0,
        "denial-of-service": 0,
        "elevation-of-privilege": 0,
      },
    },
  };
}

function writeXRayArtifacts(root: string): XRayReportData {
  const dir = path.join(root, "x-ray");
  mkdirSync(dir, { recursive: true });
  const paths = {
    xRay: path.join(dir, "x-ray.md"),
    entryPoints: path.join(dir, "entry-points.md"),
    invariants: path.join(dir, "invariants.md"),
    architectureSvg: path.join(dir, "architecture.svg"),
  };
  writeFileSync(
    paths.xRay,
    [
      "# X-Ray Report",
      "## Protocol Overview",
      "A tiny vault with deposits and withdrawals.",
      "## Key Attack Surfaces",
      "Share accounting and owner fee controls.",
    ].join("\n"),
  );
  writeFileSync(
    paths.entryPoints,
    [
      "# Entry Point Map",
      "## Permissionless",
      "### `TinyVault.deposit()`",
      "ETH in: user to vault.",
      "### `TinyVault.withdraw(uint256 shareAmount)`",
      "ETH out: vault to user.",
    ].join("\n"),
  );
  writeFileSync(
    paths.invariants,
    [
      "# Invariant Map",
      "#### G-1",
      "Fee is capped.",
      "#### I-1",
      "totalShares equals user shares.",
    ].join("\n"),
  );
  writeFileSync(paths.architectureSvg, '<svg xmlns="http://www.w3.org/2000/svg" />\n');
  return {
    target: root,
    repoName: "fixture",
    runtimeMode: "codex",
    artifactPaths: paths,
    verdict: { tier: "READY", summary: "Fixture ready." },
    entryPointCounts: { permissionless: 2, roleGated: 0, adminOnly: 0, total: 2 },
    invariantCounts: { global: 1, integration: 1, crossChain: 0, economic: 0, total: 2 },
    costUsd: 0,
  };
}

describe("artifact KB store", () => {
  it("indexes, searches, filters, and replaces stale chunks by source", () => {
    const root = tempRoot();
    const first = indexArtifactKb({
      repoRoot: root,
      moduleId: "demo",
      runId: "run-1",
      artifacts: [
        {
          path: ".kuzushi/demo.md",
          content: "deposit artifact",
          chunks: [
            {
              id: "deposit",
              kind: "entry_point",
              title: "deposit()",
              body: "deposit mints shares",
              refs: ["src/Vault.sol:10"],
            },
          ],
        },
      ],
    });
    expect(first.chunks).toBe(1);

    const deposit = searchArtifactKb(first.path, {
      query: "deposit",
      moduleId: "demo",
      kinds: ["entry_point"],
    });
    expect(deposit.results).toHaveLength(1);
    expect(deposit.results[0]!.refs).toEqual(["src/Vault.sol:10"]);
    expect(searchArtifactKb(first.path, { query: "deposit", runId: "run-1" }).results).toHaveLength(
      1,
    );
    expect(searchArtifactKb(first.path, { query: "deposit", runId: "run-2" }).results).toHaveLength(
      0,
    );
    expect(
      searchArtifactKb(first.path, { query: "deposit", path: "demo.md" }).results,
    ).toHaveLength(1);
    expect(
      searchArtifactKb(first.path, { query: "deposit", path: "other.md" }).results,
    ).toHaveLength(0);

    indexArtifactKb({
      repoRoot: root,
      moduleId: "demo",
      runId: "run-1",
      artifacts: [
        {
          path: ".kuzushi/demo.md",
          content: "withdraw artifact",
          chunks: [
            {
              id: "withdraw",
              kind: "entry_point",
              title: "withdraw()",
              body: "withdraw burns shares",
            },
          ],
        },
      ],
    });

    expect(searchArtifactKb(first.path, { query: "deposit" }).results).toHaveLength(0);
    expect(searchArtifactKb(first.path, { query: "withdraw" }).results[0]!.title).toBe(
      "withdraw()",
    );
  });

  it("exposes ArtifactKbSearch as a reusable runtime custom tool", () => {
    const root = tempRoot();
    const indexed = indexArtifactKb({
      repoRoot: root,
      moduleId: "context",
      artifacts: [
        {
          path: ".kuzushi/context-snapshot.json",
          content: "{}",
          chunks: [
            {
              id: "route",
              kind: "surface",
              title: "GET /admin",
              body: "admin route requires JWT",
            },
          ],
        },
      ],
    });
    const tool = createArtifactKbSearchTool({
      kbPath: indexed.path,
      defaultLimit: 8,
      maxChunkChars: 400,
    });
    const output = JSON.parse(
      tool.execute({ query: "admin", moduleId: "context" }, { cwd: root, toolUseId: "t1" }),
    ) as { count: number; results: Array<{ title: string }> };
    expect(output.count).toBe(1);
    expect(output.results[0]!.title).toBe("GET /admin");
  });
});

describe("artifact KB producers", () => {
  it("chunks and indexes ContextSnapshot data", () => {
    const root = tempRoot();
    const snapshot = sampleContextSnapshot(root);
    const chunks = buildContextSnapshotChunks(snapshot);
    expect(chunks.map((chunk) => chunk.kind)).toContain("repo_overview");
    expect(chunks.map((chunk) => chunk.kind)).toContain("entrypoint_hint");
    expect(chunks.map((chunk) => chunk.kind)).toContain("surface");

    const indexed = indexContextSnapshotArtifact({ repoRoot: root, snapshot });
    const result = searchArtifactKb(indexed.path, { query: "admin", moduleId: "context" });
    expect(result.results.some((hit) => hit.kind === "surface")).toBe(true);
  });

  it("chunks and indexes ThreatModelDocument data", () => {
    const root = tempRoot();
    const document = sampleThreatModel();
    const chunks = buildThreatModelArtifactChunks(document);
    expect(chunks.map((chunk) => chunk.kind)).toContain("dfd_flow");
    expect(chunks.map((chunk) => chunk.kind)).toContain("trust_boundary");
    expect(chunks.map((chunk) => chunk.kind)).toContain("threat");

    const indexed = indexThreatModelArtifact({ repoRoot: root, document });
    const result = searchArtifactKb(indexed.path, {
      query: "JWT replay",
      moduleId: "threat-model",
      kinds: ["threat"],
    });
    expect(result.results[0]!.title).toContain("JWT replay");
  });

  it("indexes validated X-Ray artifact data", () => {
    const root = tempRoot();
    const report = writeXRayArtifacts(root);
    const indexed = indexXRayArtifacts({ repoRoot: root, report });

    expect(indexed.path).toBe(artifactKbPath(root));
    expect(
      searchArtifactKb(indexed.path, { query: "deposit", kinds: ["entry_point"] }).results,
    ).toHaveLength(1);
    expect(
      searchArtifactKb(indexed.path, { query: "totalShares", kinds: ["invariant"] }).results,
    ).toHaveLength(1);
  });

  it("chunks X-Ray invariant headings with compact IDs", () => {
    const chunks = buildXRayInvariantChunks(
      [
        "# Invariants",
        "",
        "### G1: Amount positive",
        "Guard body.",
        "",
        "### I1 Conservation",
        "Invariant body.",
      ].join("\n"),
    );

    expect(chunks.map((chunk) => chunk.title)).toEqual(["G1: Amount positive", "I1 Conservation"]);
  });

  it("lets a downstream tool retrieve context, threat-model, and X-Ray chunks from one KB", () => {
    const root = tempRoot();
    indexContextSnapshotArtifact({ repoRoot: root, snapshot: sampleContextSnapshot(root) });
    indexThreatModelArtifact({ repoRoot: root, document: sampleThreatModel() });
    const indexed = indexXRayArtifacts({ repoRoot: root, report: writeXRayArtifacts(root) });
    const tool = createArtifactKbSearchTool({
      kbPath: indexed.path,
      defaultLimit: 5,
      maxChunkChars: 500,
    });
    const search = (input: Record<string, unknown>) =>
      JSON.parse(tool.execute(input, { cwd: root, toolUseId: "artifact-kb" })) as {
        results: Array<{ moduleId: string; kind: string }>;
      };

    expect(search({ query: "admin", moduleId: "context" }).results[0]).toMatchObject({
      moduleId: "context",
      kind: "surface",
    });
    expect(search({ query: "JWT replay", moduleId: "threat-model" }).results[0]).toMatchObject({
      moduleId: "threat-model",
      kind: "threat",
    });
    expect(search({ query: "deposit", moduleId: "x-ray" }).results[0]).toMatchObject({
      moduleId: "x-ray",
      kind: "entry_point",
    });
  });
});
