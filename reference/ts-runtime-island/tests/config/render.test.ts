import { describe, expect, it } from "vitest";
import { DEFAULTS } from "../../src/config/defaults.js";
import { formatConfigText, renderConfig } from "../../src/config/render.js";
import type { KuzushiConfig } from "../../src/types.js";

function cloneDefaults(): KuzushiConfig {
  return JSON.parse(JSON.stringify(DEFAULTS));
}

describe("renderConfig", () => {
  it("reports every top-level key as default for an unmodified config", () => {
    const config = cloneDefaults();
    const rendered = renderConfig(config);
    for (const group of rendered.groups) {
      expect(group.overrides).toEqual([]);
    }
  });

  it("surfaces user overrides in the correct group", () => {
    const config = cloneDefaults();
    config.verifyMaxTurns = 42;
    config.scanMode = "sequential";
    config.model = "anthropic:claude-opus-4-7";

    const rendered = renderConfig(config);
    const verifyGroup = rendered.groups.find((g) => g.title === "Verify");
    const scanGroup = rendered.groups.find((g) => g.title === "Scan pipeline");
    const modelGroup = rendered.groups.find((g) => g.title === "Model & runtime");

    expect(verifyGroup?.overrides.map((r) => r.key)).toContain("verifyMaxTurns");
    expect(scanGroup?.overrides.map((r) => r.key)).toContain("scanMode");
    expect(modelGroup?.overrides.map((r) => r.key)).toContain("model");
  });

  it("collapses taskConfig entries that match defaults into noopTaskOverrides", () => {
    const config = cloneDefaults();
    // These entries match DEFAULTS byte-for-byte — they're noise in the user's config.json.
    const rendered = renderConfig(config);
    expect(rendered.noopTaskOverrides).toContain("systems-hunt");
    expect(rendered.noopTaskOverrides).toContain("semgrep");

    const taskGroup = rendered.groups.find((g) => g.title === "Task overrides");
    const overrideKeys = taskGroup?.overrides.map((r) => r.key) ?? [];
    // No systems-hunt sub-keys should appear in overrides — the whole task collapsed.
    expect(overrideKeys.some((k) => k.startsWith("taskConfig.systems-hunt."))).toBe(false);
  });

  it("surfaces only diverging sub-keys for a partially-overridden task", () => {
    const config = cloneDefaults();
    config.taskConfig["systems-hunt"] = {
      ...config.taskConfig["systems-hunt"],
      maxFindings: 99, // override
    };

    const rendered = renderConfig(config);
    expect(rendered.noopTaskOverrides).not.toContain("systems-hunt");

    const taskGroup = rendered.groups.find((g) => g.title === "Task overrides");
    const overrideKeys = taskGroup?.overrides.map((r) => r.key) ?? [];
    expect(overrideKeys).toContain("taskConfig.systems-hunt.maxFindings");
    // sibling keys that still match defaults should live in defaults, not overrides
    expect(overrideKeys).not.toContain("taskConfig.systems-hunt.maxSurfaces");
  });

  it("reports user-added tasks in customTaskIds", () => {
    const config = cloneDefaults();
    config.taskConfig["custom-task"] = { maxFindings: 10 };

    const rendered = renderConfig(config);
    expect(rendered.customTaskIds).toContain("custom-task");
  });

  it("detects custom tasks that copy another task's DEFAULTS block verbatim", () => {
    const config = cloneDefaults();
    config.taskConfig["deep-semantic"] = { ...config.taskConfig["systems-hunt"] };

    const rendered = renderConfig(config);
    expect(rendered.templateCopies).toContainEqual({
      taskId: "deep-semantic",
      copiedFrom: "systems-hunt",
    });
    const taskGroup = rendered.groups.find((g) => g.title === "Task overrides");
    const overrideKeys = taskGroup?.overrides.map((r) => r.key) ?? [];
    expect(overrideKeys.some((k) => k.startsWith("taskConfig.deep-semantic."))).toBe(false);
  });
});

describe("formatConfigText", () => {
  it("produces compact output (<= 20 lines) for a stock config", () => {
    const config = cloneDefaults();
    const out = formatConfigText(config);
    expect(out.split("\n").length).toBeLessThanOrEqual(20);
  });

  it("omits default values by default but includes them with showDefaults", () => {
    const config = cloneDefaults();
    config.verifyMaxTurns = 50;

    const compact = formatConfigText(config);
    expect(compact).toContain("verifyMaxTurns");
    expect(compact).not.toContain("triageBatchSize"); // still default

    const full = formatConfigText(config, { showDefaults: true });
    expect(full).toContain("verifyMaxTurns");
    expect(full).toContain("triageBatchSize");
  });

  it("shows the noop-task summary when taskConfig entries match defaults", () => {
    const config = cloneDefaults();
    const out = formatConfigText(config);
    expect(out).toContain("no-op overrides");
    expect(out).toContain("systems-hunt");
  });

  it("shows the default alongside the override value", () => {
    const config = cloneDefaults();
    config.scanMode = "sequential";
    const out = formatConfigText(config);
    expect(out).toMatch(/scanMode\s+sequential\s+\(default: concurrent\)/);
  });

  it("reports the hidden-defaults count footer", () => {
    const config = cloneDefaults();
    const out = formatConfigText(config);
    expect(out).toMatch(/\d+ default values? hidden/);
  });

  it("redacts nested credential values", () => {
    const config = cloneDefaults();
    config.agentRuntimeConfig = {
      claude: {
        apiKey: "sk-ant-secret",
      },
    };

    const out = formatConfigText(config);
    expect(out).toContain("***redacted***");
    expect(out).not.toContain("sk-ant-secret");
  });
});
