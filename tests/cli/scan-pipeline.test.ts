import { describe, expect, it } from "vitest";
import { __scanPipelineInternals } from "../../src/cli/commands/scan-pipeline.js";
import { createUIStore } from "../../src/ui/state.js";

const { shouldShowPipelineNotice } = __scanPipelineInternals;

describe("scan pipeline shell notice gating", () => {
  it("suppresses late cancellation notices while the shell is mounted", () => {
    const store = createUIStore();
    store.update({
      mode: "shell",
      shell: {
        modules: [],
        moduleCatalog: [],
        tools: [],
        focusedModule: "sast",
        shellView: "module",
        openFindingId: null,
        target: ".",
        workspace: null,
        history: [],
        commandHistory: [],
        moduleOptions: {},
        processing: false,
      },
    });

    expect(shouldShowPipelineNotice(store, undefined)).toBe(false);
    expect(shouldShowPipelineNotice(store, "shell")).toBe(false);
  });

  it("keeps cancellation notices for non-shell pipeline surfaces", () => {
    const store = createUIStore();
    store.update({ mode: "running" });

    expect(shouldShowPipelineNotice(store, undefined)).toBe(true);
    expect(shouldShowPipelineNotice(store, "summary")).toBe(true);
    expect(shouldShowPipelineNotice(store, "shell")).toBe(false);
  });
});
