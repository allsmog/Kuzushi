import { describe, expect, it } from "vitest";
import type { InteractionKey } from "../../src/ui/interaction-key-policy.js";
import { resolveRunningKey } from "../../src/ui/running-mode-keys.js";

const noKey = (overrides: Partial<InteractionKey> = {}): InteractionKey => ({
  ctrl: false,
  meta: false,
  tab: false,
  escape: false,
  shift: false,
  ...overrides,
});

describe("resolveRunningKey", () => {
  it("maps 1/2/3 to scan-view switches and never to abort", () => {
    expect(resolveRunningKey("1", noKey(), { costCapHalted: false })).toEqual({
      kind: "switch-scan-view",
      view: "pipeline",
    });
    expect(resolveRunningKey("2", noKey(), { costCapHalted: false })).toEqual({
      kind: "switch-scan-view",
      view: "findings",
    });
    expect(resolveRunningKey("3", noKey(), { costCapHalted: false })).toEqual({
      kind: "switch-scan-view",
      view: "cost",
    });
  });

  it("never lets a digit trigger abort even with stray Ctrl flags", () => {
    expect(resolveRunningKey("3", noKey({ ctrl: true }), { costCapHalted: false })).toEqual({
      kind: "none",
    });
    expect(resolveRunningKey("3", noKey({ meta: true }), { costCapHalted: false })).toEqual({
      kind: "none",
    });
  });

  it("routes Ctrl+C to abort, Ctrl+D too", () => {
    expect(resolveRunningKey("c", noKey({ ctrl: true }), { costCapHalted: false })).toEqual({
      kind: "abort",
    });
    expect(resolveRunningKey("d", noKey({ ctrl: true }), { costCapHalted: false })).toEqual({
      kind: "abort",
    });
  });

  it("routes m to heartbeat toggle and n to notice-rail toggle", () => {
    expect(resolveRunningKey("m", noKey(), { costCapHalted: false })).toEqual({
      kind: "toggle-heartbeat",
    });
    expect(resolveRunningKey("n", noKey(), { costCapHalted: false })).toEqual({
      kind: "toggle-notice-rail",
    });
  });

  it("when cost-cap-halted, only c/a/Ctrl+C are observed", () => {
    expect(resolveRunningKey("c", noKey(), { costCapHalted: true })).toEqual({
      kind: "cost-cap-continue",
    });
    expect(resolveRunningKey("a", noKey(), { costCapHalted: true })).toEqual({
      kind: "cost-cap-abort",
    });
    expect(resolveRunningKey("c", noKey({ ctrl: true }), { costCapHalted: true })).toEqual({
      kind: "cost-cap-abort",
    });
    // Digits are ignored while halted.
    expect(resolveRunningKey("3", noKey(), { costCapHalted: true })).toEqual({ kind: "none" });
  });

  it("plain unrecognised characters route to none", () => {
    expect(resolveRunningKey("x", noKey(), { costCapHalted: false })).toEqual({ kind: "none" });
    expect(resolveRunningKey("", noKey(), { costCapHalted: false })).toEqual({ kind: "none" });
  });
});
