import path from "node:path";
import { describe, expect, it } from "vitest";
import { gatherContextForRoot } from "../../../src/agents/tasks/context-gatherer.js";
import { __systemsContextGathererInternals } from "../../../src/agents/tasks/systems-hunt/context.js";
import { buildSystemsSurfacePack } from "../../../src/agents/tasks/systems-hunt/helpers.js";
import { getCodeIntelligenceProvider } from "../../../src/analysis-support/index.js";

const FIXTURE_ROOT = path.resolve("tests/fixtures/systems-hunt");
const { rankSystemsSurfaces } = __systemsContextGathererInternals;

describe("systems provenance summaries", () => {
  it("summarizes cross-function Copy Fail-style provenance effects", async () => {
    const pack = await buildFixturePack("resource-provenance-positive");

    const recvSummary = summaryByName(pack.provenanceSummaries, "algif_aead_recvmsg_splice");
    const tailSummary = summaryByName(pack.provenanceSummaries, "authencesn_decrypt_tail");

    expect(recvSummary?.aliasBehavior).toBe("creates-alias");
    expect(recvSummary?.states).toEqual(
      expect.arrayContaining(["PIPE_PAGE_SHARED", "SG_SHARED", "REQ_ALIAS_MUST"]),
    );
    expect(tailSummary?.writesThroughSharedAlias).toBe(true);
    expect(tailSummary?.validationFailureAfterMutation).toBe(true);
    expect(tailSummary?.factKinds).toEqual(
      expect.arrayContaining(["write-through-shared", "failure-after-mutation"]),
    );
  });

  it("summarizes validation guards as alias-breaking counterexamples", async () => {
    const pack = await buildFixturePack("resource-provenance-negative-validated");

    const recvSummary = summaryByName(
      pack.provenanceSummaries,
      "algif_aead_recvmsg_splice_validated",
    );

    expect(recvSummary?.aliasBehavior).toBe("breaks-alias");
    expect(recvSummary?.hardGuards.join(" ")).toContain("nonalias-guard");
    expect(recvSummary?.summary).toContain("alias=breaks-alias");
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

function summaryByName<T extends { functionName: string }>(
  summaries: T[],
  functionName: string,
): T | undefined {
  return summaries.find((summary) => summary.functionName === functionName);
}
