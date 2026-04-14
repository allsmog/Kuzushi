import { describe, expect, it } from "vitest";
import { adaptScannerPlugin } from "../../src/agents/scanner-adapter.js";
import type { ScannerPlugin, Finding, TaskConfig, TriageAgentConfig } from "../../src/scanners/types.js";
import type { ScanOpts, KuzushiConfig } from "../../src/types.js";
import type { MessageBus } from "../../src/bus/types.js";

class FakeScannerPlugin implements ScannerPlugin {
  readonly id = "semgrep";
  readonly displayName = "Semgrep";
  initCalled = 0;
  lastConfig: TaskConfig | undefined;
  lastScanRoot: string | undefined;

  async init(config: TaskConfig): Promise<void> {
    this.initCalled += 1;
    this.lastConfig = config;
  }

  async scan(repoRoot: string, _opts: ScanOpts, config: TaskConfig): Promise<Finding[]> {
    this.lastConfig = config;
    this.lastScanRoot = repoRoot;
    return [
      {
        taskId: "semgrep",
        fingerprint: "fp-1",
        ruleId: "rule",
        filePath: "src/a.ts",
        startLine: 1,
        severity: "ERROR",
        message: "msg",
        scannerConfidence: "HIGH",
        subcategory: ["vuln"],
        likelihood: "HIGH",
        impact: "HIGH",
        cwe: [],
        score: 54,
      },
    ];
  }

  triageAgentConfig(): TriageAgentConfig {
    return { prompt: "p" };
  }
}

function makeConfig(): KuzushiConfig {
  return {
    model: "anthropic:claude-sonnet-4-6",
    busBackend: "in-process",
    triageBatchSize: 15,
    triageConcurrency: 1,
    scanMode: "sequential",
    tasks: [],
    tasks: ["semgrep"],
    severity: ["ERROR"],
    excludePatterns: [],
    taskConfig: {
      semgrep: { binary: "opengrep" },
    },
  };
}

function makeBus(): MessageBus {
  return {
    async publish() {},
    subscribe() {},
    unsubscribe() {},
    async waitFor() {
      throw new Error("not used");
    },
    async close() {},
  };
}

describe("adaptScannerPlugin", () => {
  it("wraps scanner plugin as a findings task", async () => {
    const plugin = new FakeScannerPlugin();
    const task = adaptScannerPlugin(plugin);

    expect(task.id).toBe("semgrep");
    expect(task.outputKind).toBe("findings");
    expect(task.dependsOn).toEqual([]);

    const config = makeConfig();
    const findings = await task.run(
      {
        severity: ["ERROR"],
        excludePatterns: [],
        fresh: false,
      },
      {
        runId: "run-1",
        repoRoot: "/tmp/repo",
        scanPath: "/tmp/repo/subdir",
        repoName: "repo",
        config,
        bus: makeBus(),
        upstreamOutputs: new Map(),
      },
    );

    expect(findings).toHaveLength(1);
    expect(plugin.lastConfig).toEqual({ binary: "opengrep" });
    expect(plugin.lastScanRoot).toBe("/tmp/repo/subdir");
  });

  it("forwards init() when plugin supports it", async () => {
    const plugin = new FakeScannerPlugin();
    const task = adaptScannerPlugin(plugin);

    await task.init?.({ binary: "semgrep" });
    expect(plugin.initCalled).toBe(1);
    expect(plugin.lastConfig).toEqual({ binary: "semgrep" });
  });

  it("forwards triageAgentConfig() for findings tasks", () => {
    const plugin = new FakeScannerPlugin();
    const task = adaptScannerPlugin(plugin);

    const finding: Finding = {
      taskId: "semgrep",
      fingerprint: "fp-1",
      ruleId: "rule",
      filePath: "src/a.ts",
      startLine: 1,
      severity: "ERROR",
      message: "msg",
      scannerConfidence: "HIGH",
      subcategory: ["vuln"],
      likelihood: "HIGH",
      impact: "HIGH",
      cwe: [],
      score: 54,
    };

    expect(task.triageAgentConfig?.(finding, "repo").prompt).toBe("p");
  });
});
