import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  type ContextBuildEvent,
  gatherContextForRoot,
} from "../../../src/agents/tasks/context-gatherer.js";

const TMP_ROOT = path.join(import.meta.dirname, "..", "..", ".tmp-context-observer");

beforeEach(() => {
  rmSync(TMP_ROOT, { recursive: true, force: true });
  mkdirSync(TMP_ROOT, { recursive: true });
});

afterEach(() => {
  rmSync(TMP_ROOT, { recursive: true, force: true });
});

function seedTsProject(): void {
  writeFileSync(
    path.join(TMP_ROOT, "package.json"),
    JSON.stringify(
      {
        name: "demo",
        dependencies: { express: "^4.0.0", helmet: "^7.0.0", typescript: "^5.0.0" },
      },
      null,
      2,
    ),
  );
  mkdirSync(path.join(TMP_ROOT, "src"), { recursive: true });
  writeFileSync(
    path.join(TMP_ROOT, "src", "server.ts"),
    "import express from 'express';\nimport { Cipher } from 'crypto';\nexport const app = express();\n",
  );
}

describe("gatherContextForRoot observer", () => {
  it("emits start→done for all five phases, in order", async () => {
    seedTsProject();
    const events: ContextBuildEvent[] = [];
    await gatherContextForRoot(TMP_ROOT, undefined, (e) => events.push(e));

    const phaseOrder = events
      .filter((e) => e.type === "phase-start" || e.type === "phase-done")
      .map((e) => `${e.type}:${(e as { phase: string }).phase}`);

    expect(phaseOrder).toEqual([
      "phase-start:manifests",
      "phase-done:manifests",
      "phase-start:walk",
      "phase-done:walk",
      "phase-start:path-signals",
      "phase-done:path-signals",
      "phase-start:grep",
      "phase-done:grep",
      "phase-start:assemble",
      "phase-done:assemble",
    ]);
  });

  it("reports package.json as found and other manifests as missing", async () => {
    seedTsProject();
    const events: ContextBuildEvent[] = [];
    await gatherContextForRoot(TMP_ROOT, undefined, (e) => events.push(e));

    const manifestResults = events.filter((e) => e.type === "manifest-result") as Extract<
      ContextBuildEvent,
      { type: "manifest-result" }
    >[];
    const byKey = new Map(manifestResults.map((m) => [m.which, m.found]));
    expect(byKey.get("package.json")).toBe(true);
    expect(byKey.get("go.mod")).toBe(false);
    expect(byKey.get("pyproject")).toBe(false);
    expect(byKey.get("Cargo.toml")).toBe(false);
    expect(byKey.get("native-build")).toBe(false);
  });

  it("emits grep-start with non-zero filesTotal and a final per-domain state", async () => {
    seedTsProject();
    const events: ContextBuildEvent[] = [];
    await gatherContextForRoot(TMP_ROOT, undefined, (e) => events.push(e));

    const grepStart = events.find((e) => e.type === "grep-start");
    expect(grepStart).toBeDefined();
    expect(
      (grepStart as Extract<ContextBuildEvent, { type: "grep-start" }>).filesTotal,
    ).toBeGreaterThan(0);

    const domainStates = events.filter((e) => e.type === "grep-domain-state");
    expect(domainStates.length).toBeGreaterThan(0);
  });

  it("emits assemble-result with the repo context", async () => {
    seedTsProject();
    const events: ContextBuildEvent[] = [];
    await gatherContextForRoot(TMP_ROOT, undefined, (e) => events.push(e));

    const assemble = events.find((e) => e.type === "assemble-result") as
      | Extract<ContextBuildEvent, { type: "assemble-result" }>
      | undefined;
    expect(assemble).toBeDefined();
    expect(assemble?.repoContext.languages).toContain("TypeScript");
    expect(assemble?.repoContext.frameworks).toContain("Express");
  });

  it("honours AbortSignal early — short-circuits before grep", async () => {
    seedTsProject();
    const events: ContextBuildEvent[] = [];
    const controller = new AbortController();
    controller.abort();
    await expect(
      gatherContextForRoot(TMP_ROOT, controller.signal, (e) => events.push(e)),
    ).rejects.toThrow();
    // The manifest + walk phases complete before the abort throw; grep never starts.
    expect(events.some((e) => e.type === "grep-start")).toBe(false);
  });
});
