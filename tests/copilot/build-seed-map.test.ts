/**
 * Regression coverage for context/threat-model → upstreamOutputs seed map.
 *
 * Bug being locked in: threat-hunt (and every other downstream task that
 * reads `context.upstreamOutputs.get("threat-model-randori")`) dereferences
 * `.document` on the upstream value, because the real task returns
 * `{ document, findings }`. Seeding the bare ThreatModelDocument caused
 * threat-hunt to find 0 actors and emit 0 findings silently.
 */
import { describe, expect, it } from "vitest";
import { __shellInternals } from "../../src/copilot/shell.js";
import type { ContextSnapshot } from "../../src/ui/state.js";

const { buildSeedMapFromSnapshot } = __shellInternals;

function makeSnapshot(partial: Partial<ContextSnapshot> = {}): ContextSnapshot {
  return {
    target: "/repo",
    timestamp: Date.now(),
    discovery: "flat",
    options: { enrichment: true },
    ...partial,
  };
}

describe("buildSeedMapFromSnapshot", () => {
  it("threat-model-randori seed wraps persistent threatModel in { document, findings }", () => {
    const tm = { dfd: { elements: [] }, threats: [{ id: "T1" }], summary: { total: 1 } };
    const snap = makeSnapshot();
    const seed = buildSeedMapFromSnapshot(snap, { threatModel: tm });
    const seeded = seed.get("threat-model-randori") as {
      document: unknown;
      findings: unknown;
    };
    expect(seeded).toBeDefined();
    expect(seeded.document).toEqual(tm);
    expect(seeded.findings).toEqual([]);
  });

  it("threat-hunt's extractActorsWithThreats can deref raw.document from the seed (the whole point)", () => {
    // Mirrors the null-check in threat-hunt.ts:
    //   if (!isRecord(raw) || !isRecord(raw["document"])) return {...empty};
    const tm = { dfd: { elements: [] }, threats: [] };
    const snap = makeSnapshot();
    const seed = buildSeedMapFromSnapshot(snap, { threatModel: tm });
    const raw = seed.get("threat-model-randori");
    const isRecord = (v: unknown): v is Record<string, unknown> =>
      typeof v === "object" && v !== null && !Array.isArray(v);
    expect(isRecord(raw)).toBe(true);
    expect(isRecord((raw as Record<string, unknown>).document)).toBe(true);
  });

  it("app-model-build seed is the bare ApplicationModel (consumers read it unwrapped)", () => {
    const appModel = { routes: [{ path: "/api/x" }], dataStores: [] };
    const snap = makeSnapshot({ appModel });
    const seed = buildSeedMapFromSnapshot(snap);
    expect(seed.get("app-model-build")).toEqual(appModel);
  });

  it("context-gatherer seed bundles repoContext + fileIndex", () => {
    const repoContext = { languages: ["go"] };
    const fileIndex = { files: ["a.go"] };
    const snap = makeSnapshot({ repoContext, fileIndex });
    const seed = buildSeedMapFromSnapshot(snap);
    expect(seed.get("context-gatherer")).toEqual({ repoContext, fileIndex });
  });

  it("threat-scenario-build seed wraps supplied scenarios array in { scenarios }", () => {
    const scenarios = [{ id: "s1" }, { id: "s2" }];
    const snap = makeSnapshot();
    const seed = buildSeedMapFromSnapshot(snap, { scenarios });
    expect(seed.get("threat-scenario-build")).toEqual({ scenarios });
  });

  it("skips keys whose snapshot field is absent", () => {
    const snap = makeSnapshot({ appModel: { routes: [] } }); // only appModel
    const seed = buildSeedMapFromSnapshot(snap);
    expect(seed.has("app-model-build")).toBe(true);
    expect(seed.has("threat-model-randori")).toBe(false);
    expect(seed.has("context-gatherer")).toBe(false);
    expect(seed.has("context-enricher")).toBe(false);
    expect(seed.has("threat-scenario-build")).toBe(false);
  });
});
