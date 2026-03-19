import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { InProcessBus } from "../../../src/bus/adapters/in-process.js";
import { contextGathererTask } from "../../../src/agents/tasks/context-gatherer.js";
import type { KuzushiConfig, ScanOpts } from "../../../src/types.js";

const TMP_ROOT = path.join(import.meta.dirname, "..", "..", ".tmp-context-gatherer");

function makeConfig(): KuzushiConfig {
  return {
    model: "anthropic:claude-sonnet-4-6",
    triageMaxTurns: 10,
    busBackend: "in-process",
    triageBatchSize: 15,
    triageConcurrency: 1,
    scanMode: "sequential",
    scanners: ["semgrep"],
    severity: ["ERROR"],
    excludePatterns: [],
    scannerConfig: { semgrep: {} },
  };
}

function makeScanOpts(): ScanOpts {
  return {
    severity: ["ERROR"],
    excludePatterns: [],
    scanners: ["semgrep"],
    fresh: false,
  };
}

beforeEach(() => {
  rmSync(TMP_ROOT, { recursive: true, force: true });
  mkdirSync(TMP_ROOT, { recursive: true });
});

afterEach(() => {
  rmSync(TMP_ROOT, { recursive: true, force: true });
});

describe("context-gatherer task", () => {
  it("extracts frameworks and ORMs from package.json heuristics", async () => {
    writeFileSync(path.join(TMP_ROOT, "package.json"), JSON.stringify({
      name: "demo",
      dependencies: {
        express: "^4.0.0",
        prisma: "^5.0.0",
        jsonwebtoken: "^9.0.0",
        helmet: "^7.0.0",
      },
    }, null, 2));

    mkdirSync(path.join(TMP_ROOT, "src", "pages", "api"), { recursive: true });
    writeFileSync(path.join(TMP_ROOT, "src", "pages", "api", "route.ts"), "export default {}\n");

    const bus = new InProcessBus();
    const output = await contextGathererTask.run(makeScanOpts(), {
      runId: "run-1",
      repoRoot: TMP_ROOT,
      repoName: "repo",
      config: makeConfig(),
      bus,
      upstreamOutputs: new Map(),
    });

    expect(output.repoContext.frameworks).toContain("Express");
    expect(output.repoContext.ormOrDb).toContain("Prisma");
    expect(output.repoContext.authPatterns).toContain("JWT");
    expect(output.repoContext.sanitizationLibs).toContain("helmet");
    expect(output.repoContext.entryPoints).toContain("src/pages/api/*");
    expect(output.fileIndex).toBeDefined();
    expect(output.fileIndex.tree.length).toBeGreaterThan(0);
    expect(output.fileIndex.totalFiles).toBeGreaterThan(0);

    await bus.close();
  });
});
