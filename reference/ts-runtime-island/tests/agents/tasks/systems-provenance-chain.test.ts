import path from "node:path";
import { describe, expect, it } from "vitest";
import { gatherContextForRoot } from "../../../src/agents/tasks/context-gatherer.js";
import { __systemsContextGathererInternals } from "../../../src/agents/tasks/systems-hunt/context.js";
import { buildSystemsSurfacePack } from "../../../src/agents/tasks/systems-hunt/helpers.js";
import { __systemsProvenanceChainInternals } from "../../../src/agents/tasks/systems-hunt/provenance-chain.js";
import type { SystemsProvenanceFact } from "../../../src/agents/tasks/systems-hunt/types.js";
import { getCodeIntelligenceProvider } from "../../../src/analysis-support/index.js";

const FIXTURE_ROOT = path.resolve("tests/fixtures/systems-hunt");
const { rankSystemsSurfaces } = __systemsContextGathererInternals;
const { buildProvenanceChains } = __systemsProvenanceChainInternals;

describe("systems provenance chains", () => {
  it("assembles a complete Copy Fail-style chain across functions", async () => {
    const pack = await buildFixturePack("resource-provenance-positive");
    const [chain] = pack.provenanceChains;

    expect(chain?.status).toBe("complete");
    expect(chain?.steps.map((step) => step.role)).toEqual(
      expect.arrayContaining(["origin", "alias", "write", "failure"]),
    );
    expect(chain?.narrative).toContain("complete provenance chain");
  });

  it("marks a chain blocked by a nonalias validation guard", async () => {
    const pack = await buildFixturePack("resource-provenance-negative-validated");
    const [chain] = pack.provenanceChains;

    expect(chain?.status).toBe("blocked-by-guard");
    expect(
      chain?.steps.some((step) => step.role === "guard" && step.kind === "nonalias-guard"),
    ).toBe(true);
    expect(chain?.narrative).toContain("blocked by hard guard");
  });

  it("marks a chain blocked by a private-copy guard", () => {
    const chains = buildProvenanceChains({
      surfaceId: "surface-private-copy",
      summaries: [],
      facts: [
        fact("src/file.c", 10, "struct pipe_buffer pipe = { .page = page_cache_page };", {
          state: "PIPE_PAGE_SHARED",
          kind: "alias-preserving-transport",
          resourceFamily: "pipe/page",
          strength: "strong",
        }),
        fact("src/file.c", 20, "req->src = req->dst;", {
          state: "REQ_ALIAS_MUST",
          kind: "request-alias",
          resourceFamily: "request src/dst",
          strength: "strong",
        }),
        fact("src/file.c", 25, "private_dst = kmalloc(size);", {
          state: "PRIVATE_OWNED",
          kind: "private-copy-guard",
          resourceFamily: "private copy",
          strength: "hard-guard",
        }),
        fact("src/file.c", 30, "scatterwalk_map_and_copy(tag, req->dst, off, 4, 1);", {
          state: "MUTATED_SHARED",
          kind: "write-through-shared",
          resourceFamily: "scatterlist/page",
          strength: "strong",
        }),
        fact("src/file.c", 32, "return -EBADMSG;", {
          state: "FAILED_AFTER_MUTATION",
          kind: "failure-after-mutation",
          resourceFamily: "failure path",
          strength: "strong",
        }),
      ],
      limit: 1,
    });

    expect(chains[0]?.status).toBe("blocked-by-guard");
    expect(chains[0]?.guardSummary).toContain("private-copy-guard");
  });
});

async function buildFixturePack(fixtureName: string) {
  const repoRoot = path.join(FIXTURE_ROOT, fixtureName);
  const context = await gatherContextForRoot(repoRoot);
  const surfaces = await rankSystemsSurfaces(context.fileIndex, context.repoContext, repoRoot, 5);
  const surface = surfaces.find((candidate) => candidate.kind === "resource-provenance");
  if (!surface) {
    throw new Error(`No resource-provenance surface found for ${fixtureName}`);
  }
  const provider = await getCodeIntelligenceProvider(repoRoot);
  return buildSystemsSurfacePack({
    repoRoot,
    fileIndex: context.fileIndex,
    surface,
    provider,
    surfacePackDepth: 6,
    enableCodeqlTemplates: false,
  });
}

function fact(
  filePath: string,
  line: number,
  snippet: string,
  overrides: Pick<SystemsProvenanceFact, "state" | "kind" | "resourceFamily" | "strength">,
): SystemsProvenanceFact {
  return {
    filePath,
    line,
    snippet,
    reason: `${overrides.state}/${overrides.kind}/${overrides.strength}`,
    ...overrides,
  };
}
