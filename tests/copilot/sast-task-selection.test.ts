import { describe, expect, it } from "vitest";
import {
  buildSastTaskRows,
  buildSastTaskSelectionSummary,
  formatSastTaskLegend,
  formatSastTaskStateLine,
  resolveSastTaskCapability,
} from "../../src/copilot/sast-task-selection.js";
import type { TuneSnapshot } from "../../src/ui/state.js";

const tune: TuneSnapshot = {
  preset: "standard",
  tasks: ["semgrep"],
  verify: false,
  autoPatch: false,
  triageConcurrency: 2,
  model: "anthropic:claude-sonnet-4-6",
};

describe("SAST task selection summary", () => {
  it("derives effective counts and active action from task rows", () => {
    const rows = buildSastTaskRows({
      options: { disabledTasks: ["codeql"] },
      tune,
    });
    const summary = buildSastTaskSelectionSummary({
      options: { disabledTasks: ["codeql"] },
      tune,
      cursor: 1,
      rows,
    });

    expect(summary.profile).toBe("standard");
    expect(summary.modeLabel).toBe("auto + denylist");
    expect(summary.blockedCount).toBe(1);
    expect(summary.requiredCount).toBe(1);
    expect(summary.activeRow?.id).toBe("codeql");
    expect(summary.activeAction).toBe("Space allows codeql.");
  });

  it("reports manual allowlist state without treating unselected rows as blocked", () => {
    const summary = buildSastTaskSelectionSummary({
      options: { taskMode: "manual", tasks: ["semgrep"] },
      tune,
      cursor: 5,
    });

    expect(summary.mode).toBe("manual");
    expect(summary.enabledCount).toBe(2);
    expect(summary.blockedCount).toBe(0);
    expect(summary.activeRow?.id).toBe("ssrf");
    expect(summary.activeAction).toBe("Space blocks ssrf.");
  });

  it("formats a compact state line for TUI and plain output", () => {
    const summary = buildSastTaskSelectionSummary({
      options: { taskMode: "manual", tasks: ["semgrep"], disabledTasks: ["codeql"] },
      tune,
    });

    expect(formatSastTaskStateLine(summary)).toContain("profile standard");
    expect(formatSastTaskStateLine(summary)).toContain("manual allowlist");
    expect(formatSastTaskStateLine(summary)).toContain("1 blocked");
  });

  it("exposes the short legend used by both renderers", () => {
    expect(formatSastTaskLegend()).toBe(
      "[x] enabled  [A] auto candidate  [ ] blocked/off  [!] required",
    );
  });

  it("resolves task ids and display ids to known row capabilities", () => {
    expect(resolveSastTaskCapability("agentic-sast:ssrf-detect")?.id).toBe("ssrf");
    expect(resolveSastTaskCapability("ssrf")?.id).toBe("ssrf");
    expect(resolveSastTaskCapability("context:context-gatherer")?.toggleable).toBe(false);
    expect(resolveSastTaskCapability("not-real")).toBeUndefined();
  });
});
