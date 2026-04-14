import { describe, expect, it } from "vitest";
import { ScannerRegistry } from "../src/scanners/registry.js";
import type {
  Finding,
  TaskConfig,
  ScannerPlugin,
  TriageAgentConfig,
} from "../src/scanners/types.js";
import type { KuzushiConfig, ScanOpts } from "../src/types.js";

function makeFinding(fp: string, taskId: string, score: number): Finding {
  return {
    taskId,
    fingerprint: fp,
    ruleId: "test.rule",
    filePath: "src/test.ts",
    startLine: 1,
    severity: "WARNING",
    message: "test",
    scannerConfidence: "MEDIUM",
    subcategory: ["audit"],
    likelihood: "MEDIUM",
    impact: "LOW",
    cwe: [],
    score,
  };
}

class FakePlugin implements ScannerPlugin {
  readonly displayName: string;
  initCalled = 0;

  constructor(
    readonly id: string,
    private readonly findings: Finding[],
  ) {
    this.displayName = id;
  }

  async init(_config: TaskConfig): Promise<void> {
    this.initCalled += 1;
  }

  async scan(_repoRoot: string, _opts: ScanOpts, _config: TaskConfig): Promise<Finding[]> {
    return this.findings;
  }

  triageAgentConfig(): TriageAgentConfig {
    return { prompt: "triage prompt" };
  }
}

function makeConfig(): KuzushiConfig {
  return {
    model: "anthropic:claude-sonnet-4-6",
    busBackend: "in-process",
    triageBatchSize: 15,
    triageConcurrency: 1,
    scanMode: "sequential",
    tasks: ["a", "b"],
    severity: ["ERROR", "WARNING"],
    excludePatterns: ["node_modules"],
    taskConfig: {
      a: {},
      b: {},
    },
  };
}

describe("ScannerRegistry", () => {
  it("register/get/ids work", () => {
    const registry = new ScannerRegistry();
    const plugin = new FakePlugin("a", []);

    registry.register(plugin);

    expect(registry.has("a")).toBe(true);
    expect(registry.get("a")).toBe(plugin);
    expect(registry.ids()).toEqual(["a"]);
  });

  it("resolveEnabled filters non-plugin IDs from explicit override", () => {
    const registry = new ScannerRegistry();
    registry.register(new FakePlugin("a", []));

    const opts: ScanOpts = {
      severity: ["ERROR"],
      excludePatterns: [],
      fresh: false,
      tasks: ["a", "taint-analysis"],
    };

    // "taint-analysis" is not a registered plugin — it should be silently dropped.
    expect(registry.resolveEnabled(opts, makeConfig())).toEqual(["a"]);
  });

  it("resolveEnabled throws for unknown explicit scanner IDs", () => {
    const registry = new ScannerRegistry();
    registry.register(new FakePlugin("a", []));

    const opts: ScanOpts = {
      severity: ["ERROR"],
      excludePatterns: [],
      fresh: false,
      tasks: ["a", "semgrpe"],
    };

    expect(() => registry.resolveEnabled(opts, makeConfig())).toThrow("Unknown scanner");
  });

  it("resolveEnabled returns empty list when override contains only non-plugin IDs", () => {
    const registry = new ScannerRegistry();
    registry.register(new FakePlugin("a", []));

    const opts: ScanOpts = {
      severity: ["ERROR"],
      excludePatterns: [],
      fresh: false,
      tasks: ["taint-analysis"],
    };

    expect(registry.resolveEnabled(opts, makeConfig())).toEqual([]);
  });

  it("resolveEnabled validates unknown tasks in config defaults", () => {
    const registry = new ScannerRegistry();
    registry.register(new FakePlugin("a", []));

    // No explicit override — falls through to config.tasks which has unknown "b".
    const opts: ScanOpts = {
      severity: ["ERROR"],
      excludePatterns: [],
      fresh: false,
    };

    expect(() => registry.resolveEnabled(opts, makeConfig())).toThrow("Unknown scanner");
  });

  it("resolveEnabled accepts non-plugin aliases in config defaults path", () => {
    const registry = new ScannerRegistry();
    registry.register(new FakePlugin("semgrep", []));

    const opts: ScanOpts = {
      severity: ["ERROR"],
      excludePatterns: [],
      fresh: false,
    };
    const config: KuzushiConfig = {
      ...makeConfig(),
      tasks: ["semgrep", "crypto-misuse"],
    };

    // "crypto-misuse" is in NON_PLUGIN_SCANNER_ALIASES — should not throw
    const enabled = registry.resolveEnabled(opts, config);
    // Only plugin IDs are returned (crypto-misuse is handled by task DAG, not plugin layer)
    expect(enabled).toEqual(["semgrep"]);
  });

  it("runAll deduplicates by fingerprint keeping highest score", async () => {
    const registry = new ScannerRegistry();
    const pluginA = new FakePlugin("a", [makeFinding("fp", "a", 1)]);
    const pluginB = new FakePlugin("b", [makeFinding("fp", "b", 5)]);
    registry.register(pluginA);
    registry.register(pluginB);

    const result = await registry.runAll(
      "/tmp/repo",
      {
        severity: ["ERROR"],
        excludePatterns: [],
        fresh: false,
      },
      makeConfig(),
    );

    expect(pluginA.initCalled).toBe(1);
    expect(pluginB.initCalled).toBe(1);
    expect(result).toHaveLength(1);
    expect(result[0].score).toBe(5);
  });

  it("runAll honors maxFindings", async () => {
    const registry = new ScannerRegistry();
    registry.register(new FakePlugin("a", [makeFinding("a", "a", 1), makeFinding("b", "a", 2)]));
    registry.register(new FakePlugin("b", [makeFinding("c", "b", 3)]));

    const result = await registry.runAll(
      "/tmp/repo",
      {
        severity: ["ERROR"],
        excludePatterns: [],
        fresh: false,
        maxFindings: 2,
      },
      makeConfig(),
    );

    expect(result).toHaveLength(2);
    expect(result[0].score).toBeGreaterThanOrEqual(result[1].score);
  });
});
