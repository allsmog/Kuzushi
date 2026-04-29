import { describe, expect, it } from "vitest";
import { resolveActivePiAiModels } from "../../src/cli/pi-ai.js";
import {
  applyScanCommandConfigOverrides,
  type ScanCommandOptions,
} from "../../src/cli/scan-config.js";
import { DEFAULTS } from "../../src/config/defaults.js";
import type { KuzushiConfig } from "../../src/types.js";

function makeConfig(): KuzushiConfig {
  return {
    ...structuredClone(DEFAULTS),
    taskConfig: structuredClone(DEFAULTS.taskConfig),
    tasks: [...DEFAULTS.tasks],
    severity: [...DEFAULTS.severity],
    excludePatterns: [...DEFAULTS.excludePatterns],
  };
}

function makeOptions(overrides: Partial<ScanCommandOptions> = {}): ScanCommandOptions {
  return {
    verify: false,
    cryptoBehavioralTest: false,
    codeGraph: false,
    multiStrategy: false,
    multiStrategyFull: false,
    multiStrategyAutoRules: false,
    autoRuleGen: false,
    stream: false,
    githubPr: false,
    githubComment: false,
    autoPatch: false,
    pocHarness: false,
    context: true,
    auditLog: false,
    qualityGate: false,
    failOnTp: false,
    moduleDiscovery: true,
    fresh: false,
    cache: true,
    ...overrides,
  };
}

describe("task-only scan config", () => {
  it("applies per-task model overrides via --task-model", () => {
    const config = makeConfig();

    applyScanCommandConfigOverrides(
      config,
      makeOptions({
        taskModels: [
          "systems-hunt=anthropic:claude-sonnet-4-6",
          "carlini-threat-hunt=anthropic:claude-opus-4-1",
        ],
      }),
    );

    expect(config.taskConfig["systems-hunt"]?.model).toBe("anthropic:claude-sonnet-4-6");
    expect(config.taskConfig["carlini-threat-hunt"]?.model).toBe("anthropic:claude-opus-4-1");
  });

  it("reference replaces the configured task list with the deep DAG and deep-merges taskConfig", () => {
    const config = makeConfig();
    // The user's prior task list is intentionally narrow — reference now
    // promotes them to the full deep DAG so the preset matches the
    // README description ("deep + PoC + threat-informed hunting +
    // frontier model"). Per-task tuning still deep-merges on top.
    config.tasks = ["semgrep", "systems-hunt"];
    config.taskConfig["systems-hunt"] = { maxSurfaces: 4 };

    applyScanCommandConfigOverrides(config, makeOptions({ preset: "reference" }));

    expect(config.tasks).toEqual([
      "context:context-gatherer",
      "context:context-enricher",
      "agentic-sast:secrets-crypto-detect",
      "context:code-config-detect",
      "pipeline:taint-cwe-select",
      "taint-iris:hunt",
      "threat-model:threat-model-randori",
      "carlini-threat-hunt:run",
      "systems-hunt:systems-context-gatherer",
      "systems-hunt:systems-invariant-extract",
      "systems-hunt:systems-trigger-synth",
      "systems-hunt:systems-hunt",
    ]);
    expect(config.taskConfig["systems-hunt"]).toEqual(
      expect.objectContaining({
        maxSurfaces: 12,
        model: "anthropic:claude-orchid-preview",
        maxConcurrentSurfaces: 3,
      }),
    );
  });

  it("discovers stage-task models through reserved taskConfig ids", () => {
    const config = makeConfig();
    config.verify = true;
    config.pocHarness = true;
    config.dynamicAnalysisEnabled = true;
    config.taskConfig.triage = { model: "anthropic:claude-sonnet-4-6" };
    config.taskConfig.verify = { model: "anthropic:claude-opus-4-1" };
    config.taskConfig["poc-harness"] = { model: "openai:gpt-5" };
    config.taskConfig["dynamic-analysis"] = { model: "google:gemini-2.5-pro" };

    const models = resolveActivePiAiModels(
      config,
      ["semgrep", "systems-hunt"],
      ["semgrep", "systems-hunt"],
    );

    expect(models).toEqual(
      expect.arrayContaining([
        "anthropic:claude-sonnet-4-6",
        "anthropic:claude-opus-4-1",
        "openai:gpt-5",
        "google:gemini-2.5-pro",
      ]),
    );
  });
});
