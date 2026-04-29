/**
 * Lock-ins for the pure `resolveKeybind` reducer that drives the shell.
 *
 * These tests exercise the full priority ladder documented in
 * `src/ui/shell-keybinds.ts`:
 *
 *   1. Ctrl+C arms, then commits within the window (two-stage exit).
 *   2. Any other key resets the arm logic at the reducer boundary.
 *   3. In-flight work gets an immediate abort, even with a stale idle-exit arm.
 *   4. Plan-pending overlay steals y / n / Esc.
 *   5. Context-build L/q expands the tail or aborts/backs out.
 *   6. Threat-view digits cycle through `/threats <sub>`.
 *   7. Findings cursor keybinds clamp to `looseFindingCount`.
 *   8. `q` + empty buffer on a backable view → `/back`.
 *   9. Esc clears non-empty buffer before considering `/back`.
 *   10. Typing / Enter / history keys fall through to `{ type: "none" }`.
 */

import { describe, expect, it } from "vitest";
import {
  CTRL_C_ARM_WINDOW_MS,
  isBackableShellView,
  isThreatShellView,
  type KeybindAction,
  type Keystroke,
  PASTE_GUARD_WINDOW_MS,
  resolveKeybind,
  resolveTaskStoryToggleView,
  shouldSubmitOnReturn,
} from "../../src/ui/shell-keybinds.js";
import type { ShellState, UIState } from "../../src/ui/state.js";

function baseShell(overrides: Partial<ShellState> = {}): ShellState {
  return {
    modules: [],
    tools: [],
    focusedModule: null,
    shellView: "catalog",
    openFindingId: null,
    target: null,
    workspace: null,
    history: [],
    commandHistory: [],
    moduleOptions: {},
    processing: false,
    ...overrides,
  } as ShellState;
}

function baseState(shell: ShellState, overrides: Partial<UIState> = {}): UIState {
  return {
    mode: "shell",
    phase: "idle",
    repoName: "",
    tasks: [],
    totalFindings: 0,
    selectedForTriage: 0,
    skippedAlreadyTriaged: 0,
    model: "",
    progress: { current: 0, total: 0 },
    runningCostUsd: 0,
    costBreakdown: { triage: 0, verify: 0, poc: 0 },
    scanView: "pipeline",
    results: [],
    agentActivity: new Map(),
    summary: null,
    qualityGate: null,
    notices: [],
    warnings: [],
    bannerShown: false,
    shellSplashShown: false,
    startBannerShown: false,
    stages: [],
    preflight: null,
    review: null,
    shell,
    ...overrides,
  } as UIState;
}

function contextBuildState(
  status: NonNullable<ShellState["contextBuild"]>["status"] = "running",
  tailExpanded = false,
): ShellState["contextBuild"] {
  return { status, tailExpanded } as unknown as ShellState["contextBuild"];
}

function stroke(partial: Partial<Keystroke> = {}): Keystroke {
  return {
    char: partial.char ?? "",
    key: { ...(partial.key ?? {}) },
  };
}

function dispatch(input: string, shell: ShellState, state: UIState, now = 1_000): KeybindAction {
  return resolveKeybind({
    stroke: stroke({ char: input, key: {} }),
    input: "",
    state,
    looseFindingCount: 0,
    now,
  });
}

describe("resolveKeybind — Ctrl+C two-stage", () => {
  it("first Ctrl+C at idle arms the exit without committing", () => {
    const shell = baseShell();
    const state = baseState(shell);
    const action = resolveKeybind({
      stroke: stroke({ char: "c", key: { ctrl: true } }),
      input: "",
      state,
      looseFindingCount: 0,
      now: 5_000,
    });
    expect(action).toEqual({ type: "arm-exit", at: 5_000 });
  });

  it("second Ctrl+C within the window commits the exit", () => {
    const shell = baseShell();
    const armedAt = 5_000;
    const state = baseState(shell, { ctrlCArmedAt: armedAt });
    const action = resolveKeybind({
      stroke: stroke({ char: "c", key: { ctrl: true } }),
      input: "",
      state,
      looseFindingCount: 0,
      now: armedAt + CTRL_C_ARM_WINDOW_MS - 10,
    });
    expect(action).toEqual({ type: "exit" });
  });

  it("second Ctrl+C after the window expires re-arms instead of exiting", () => {
    const shell = baseShell();
    const armedAt = 5_000;
    const state = baseState(shell, { ctrlCArmedAt: armedAt });
    const now = armedAt + CTRL_C_ARM_WINDOW_MS + 500;
    const action = resolveKeybind({
      stroke: stroke({ char: "c", key: { ctrl: true } }),
      input: "",
      state,
      looseFindingCount: 0,
      now,
    });
    expect(action).toEqual({ type: "arm-exit", at: now });
  });

  it("Ctrl+C during in-flight work aborts immediately (no arm)", () => {
    const shell = baseShell({ processing: true });
    const state = baseState(shell);
    const action = resolveKeybind({
      stroke: stroke({ char: "c", key: { ctrl: true } }),
      input: "",
      state,
      looseFindingCount: 0,
      now: 0,
    });
    expect(action).toEqual({ type: "abort-inflight" });
  });

  it("stale idle-exit arm does not exit while work is in flight", () => {
    const shell = baseShell({ processing: true });
    const armedAt = 5_000;
    const state = baseState(shell, { ctrlCArmedAt: armedAt });
    const action = resolveKeybind({
      stroke: stroke({ char: "c", key: { ctrl: true } }),
      input: "",
      state,
      looseFindingCount: 0,
      now: armedAt + 250,
    });
    expect(action).toEqual({ type: "abort-inflight" });
  });

  it("Ctrl+D follows the same two-stage contract as Ctrl+C", () => {
    const shell = baseShell();
    const state = baseState(shell);
    const action = resolveKeybind({
      stroke: stroke({ char: "d", key: { ctrl: true } }),
      input: "",
      state,
      looseFindingCount: 0,
      now: 0,
    });
    expect(action).toEqual({ type: "arm-exit", at: 0 });
  });

  it("accepts ETX/EOT control bytes for Ctrl+C/Ctrl+D from raw stdin", () => {
    const shell = baseShell();
    const state = baseState(shell);
    const etxAction = resolveKeybind({
      stroke: stroke({ char: "\u0003", key: { ctrl: true } }),
      input: "",
      state,
      looseFindingCount: 0,
      now: 111,
    });
    expect(etxAction).toEqual({ type: "arm-exit", at: 111 });

    const eotAction = resolveKeybind({
      stroke: stroke({ char: "\u0004", key: { ctrl: true } }),
      input: "",
      state,
      looseFindingCount: 0,
      now: 222,
    });
    expect(eotAction).toEqual({ type: "arm-exit", at: 222 });
  });
});

describe("resolveKeybind — plan-pending overlay", () => {
  const pendingPlan = { source: "t" } as unknown as ShellState["pendingPlan"];

  it("intercepts `y` / `Y` when a plan is pending and the buffer is empty", () => {
    const shell = baseShell({ pendingPlan });
    const state = baseState(shell);
    expect(dispatch("y", shell, state)).toEqual({ type: "dispatch", command: "/yes" });
    expect(dispatch("Y", shell, state)).toEqual({ type: "dispatch", command: "/yes" });
  });

  it("intercepts `n` / `N` and Esc when a plan is pending", () => {
    const shell = baseShell({ pendingPlan });
    const state = baseState(shell);
    expect(dispatch("n", shell, state)).toEqual({ type: "dispatch", command: "/no" });
    const escAction = resolveKeybind({
      stroke: stroke({ key: { escape: true } }),
      input: "",
      state,
      looseFindingCount: 0,
      now: 0,
    });
    expect(escAction).toEqual({ type: "dispatch", command: "/no" });
  });

  it("does NOT intercept y/n when the buffer has typing in progress", () => {
    const shell = baseShell({ pendingPlan });
    const state = baseState(shell);
    const action = resolveKeybind({
      stroke: stroke({ char: "y" }),
      input: "t",
      state,
      looseFindingCount: 0,
      now: 0,
    });
    expect(action.type).toBe("none");
  });
});

describe("resolveKeybind — task story details", () => {
  it("opens task story details with Ctrl+O even while work is in flight", () => {
    const shell = baseShell({ processing: true });
    const state = baseState(shell);
    const action = resolveKeybind({
      stroke: stroke({ char: "o", key: { ctrl: true } }),
      input: "",
      state,
      looseFindingCount: 0,
      now: 0,
    });

    expect(action).toEqual({ type: "toggle-story", nextView: "task-story" });
  });

  it("closes task story details with Ctrl+O while work is in flight", () => {
    const shell = baseShell({
      focusedModule: "context",
      shellView: "task-story",
      processing: true,
    });
    const state = baseState(shell);
    const action = resolveKeybind({
      stroke: stroke({ char: "o", key: { ctrl: true } }),
      input: "",
      state,
      looseFindingCount: 0,
      now: 0,
    });

    expect(action).toEqual({ type: "toggle-story", nextView: "module" });
  });

  it("closes task story details back to catalog when no module is focused", () => {
    expect(resolveTaskStoryToggleView(baseShell({ shellView: "task-story" }))).toBe("catalog");
  });
});

describe("resolveKeybind — threat digits", () => {
  it("maps 1..5 to the correct /threats subcommand on a threat view", () => {
    const shell = baseShell({ shellView: "threats", threatTab: "dfd" });
    const state = baseState(shell);
    const calls = ["1", "2", "3", "4", "5"].map((c) => dispatch(c, shell, state));
    expect(calls).toEqual([
      { type: "dispatch", command: "/threats dfd" },
      { type: "dispatch", command: "/threats stride" },
      { type: "dispatch", command: "/threats stories" },
      { type: "dispatch", command: "/threats scope" },
      { type: "dispatch", command: "/threats summary" },
    ]);
  });

  it("keeps r as the threat-view regen shortcut and does not bind a to an empty ask", () => {
    const shell = baseShell({ shellView: "threats", threatTab: "dfd" });
    const state = baseState(shell);

    expect(dispatch("r", shell, state)).toEqual({ type: "dispatch", command: "/threats regen" });
    expect(dispatch("a", shell, state).type).toBe("none");
  });

  it("does not trigger on non-threat views", () => {
    const shell = baseShell({ shellView: "catalog" });
    const state = baseState(shell);
    expect(dispatch("1", shell, state).type).toBe("none");
  });

  it("isThreatShellView covers the threat view and rejects catalog", () => {
    expect(isThreatShellView("threats")).toBe(true);
    expect(isThreatShellView("catalog")).toBe(false);
    expect(isThreatShellView("findings")).toBe(false);
    expect(isThreatShellView(undefined)).toBe(false);
  });
});

describe("resolveKeybind — findings cursor", () => {
  function findingsState(cursor?: number, pageSize?: number) {
    const shell = baseShell({
      shellView: "findings",
      findingCursor: cursor,
      findingPageSize: pageSize,
    });
    const state = baseState(shell);
    return { shell, state };
  }

  it("j / ArrowDown increment the cursor (clamped to looseFindingCount-1)", () => {
    const { state } = findingsState(0);
    const jAction = resolveKeybind({
      stroke: stroke({ char: "j" }),
      input: "",
      state,
      looseFindingCount: 10,
      now: 0,
    });
    expect(jAction).toEqual({ type: "set-finding-cursor", cursor: 1 });

    const downAction = resolveKeybind({
      stroke: stroke({ key: { downArrow: true } }),
      input: "",
      state,
      looseFindingCount: 10,
      now: 0,
    });
    expect(downAction).toEqual({ type: "set-finding-cursor", cursor: 1 });
  });

  it("k / ArrowUp decrement the cursor (clamped to 0)", () => {
    const { state } = findingsState(0);
    const kAction = resolveKeybind({
      stroke: stroke({ char: "k" }),
      input: "",
      state,
      looseFindingCount: 10,
      now: 0,
    });
    // Already at 0, clamp keeps it at 0.
    expect(kAction).toEqual({ type: "set-finding-cursor", cursor: 0 });
  });

  it("g jumps to top; G jumps to last index", () => {
    const { state } = findingsState(5);
    const gAction = resolveKeybind({
      stroke: stroke({ char: "g" }),
      input: "",
      state,
      looseFindingCount: 20,
      now: 0,
    });
    expect(gAction).toEqual({ type: "set-finding-cursor", cursor: 0 });

    const GAction = resolveKeybind({
      stroke: stroke({ char: "G" }),
      input: "",
      state,
      looseFindingCount: 20,
      now: 0,
    });
    expect(GAction).toEqual({ type: "set-finding-cursor", cursor: 19 });
  });

  it("PgUp / PgDown move by pageSize and clamp at boundaries", () => {
    const { state } = findingsState(5, 10);
    const pageDown = resolveKeybind({
      stroke: stroke({ key: { pageDown: true } }),
      input: "",
      state,
      looseFindingCount: 100,
      now: 0,
    });
    expect(pageDown).toEqual({ type: "set-finding-cursor", cursor: 15 });

    const pageUp = resolveKeybind({
      stroke: stroke({ key: { pageUp: true } }),
      input: "",
      state,
      looseFindingCount: 100,
      now: 0,
    });
    expect(pageUp).toEqual({ type: "set-finding-cursor", cursor: 0 });
  });

  it("no-ops when the loose list is empty (falls through to typing)", () => {
    const { state } = findingsState(0);
    const action = resolveKeybind({
      stroke: stroke({ char: "j" }),
      input: "",
      state,
      looseFindingCount: 0,
      now: 0,
    });
    expect(action.type).toBe("none");
  });

  it("does not move the cursor while the buffer is non-empty", () => {
    const { state } = findingsState(0);
    const action = resolveKeybind({
      stroke: stroke({ char: "j" }),
      input: "search term",
      state,
      looseFindingCount: 20,
      now: 0,
    });
    expect(action.type).toBe("none");
  });
});

describe("resolveKeybind — SAST task selector", () => {
  function taskState(cursor = 0) {
    const shell = baseShell({
      shellView: "sast-tasks",
      focusedModule: "sast",
      sastTaskCursor: cursor,
    });
    const state = baseState(shell);
    return { shell, state };
  }

  it("j/k move the SAST task cursor and clamp to available rows", () => {
    const { state } = taskState(1);
    expect(
      resolveKeybind({
        stroke: stroke({ char: "j" }),
        input: "",
        state,
        looseFindingCount: 0,
        sastTaskCount: 3,
        now: 0,
      }),
    ).toEqual({ type: "set-sast-task-cursor", cursor: 2 });
    expect(
      resolveKeybind({
        stroke: stroke({ char: "k" }),
        input: "",
        state,
        looseFindingCount: 0,
        sastTaskCount: 3,
        now: 0,
      }),
    ).toEqual({ type: "set-sast-task-cursor", cursor: 0 });
  });

  it("Space, a, o, and r dispatch the matching task commands", () => {
    const { shell, state } = taskState();
    expect(dispatch(" ", shell, state)).toEqual({ type: "dispatch", command: "/task toggle" });
    expect(dispatch("a", shell, state)).toEqual({
      type: "dispatch",
      command: "/task mode toggle",
    });
    expect(dispatch("o", shell, state)).toEqual({ type: "dispatch", command: "/options" });
    expect(dispatch("r", shell, state)).toEqual({ type: "dispatch", command: "/task reset" });
  });

  it("does not dispatch task selector keys while typing", () => {
    const { state } = taskState();
    const action = resolveKeybind({
      stroke: stroke({ char: "o" }),
      input: "query",
      state,
      looseFindingCount: 0,
      sastTaskCount: 3,
      now: 0,
    });
    expect(action.type).toBe("none");
  });
});

describe("resolveKeybind — KB attachment list", () => {
  function kbState(cursor = 0) {
    const docs = [
      { id: "doc-a", title: "a.md" },
      { id: "doc-b", title: "b.md" },
      { id: "doc-c", title: "c.md" },
    ];
    const shell = baseShell({
      shellView: "kb",
      focusedModule: "threat-model",
      kb: { moduleId: "threat-model", cursor, collapsed: false },
      kbState: { "threat-model": { documents: docs } },
    } as unknown as Partial<ShellState>);
    const state = baseState(shell);
    return { shell, state };
  }

  it("j/k and arrow keys move the KB cursor and clamp to available rows", () => {
    const { state } = kbState(1);
    expect(
      resolveKeybind({
        stroke: stroke({ char: "j" }),
        input: "",
        state,
        looseFindingCount: 0,
        now: 0,
      }),
    ).toEqual({ type: "set-kb-cursor", cursor: 2 });
    expect(
      resolveKeybind({
        stroke: stroke({ key: { upArrow: true } }),
        input: "",
        state,
        looseFindingCount: 0,
        now: 0,
      }),
    ).toEqual({ type: "set-kb-cursor", cursor: 0 });
  });

  it("g/G jump to top and bottom", () => {
    const { state } = kbState(1);
    expect(dispatch("g", state.shell!, state)).toEqual({ type: "set-kb-cursor", cursor: 0 });
    expect(dispatch("G", state.shell!, state)).toEqual({ type: "set-kb-cursor", cursor: 2 });
  });

  it("d and r dispatch commands for the selected attachment", () => {
    const { state } = kbState(1);
    expect(dispatch("d", state.shell!, state)).toEqual({
      type: "dispatch",
      command: "detach doc-b",
    });
    expect(dispatch("r", state.shell!, state)).toEqual({
      type: "dispatch",
      command: "reparse doc-b",
    });
  });

  it("ignores list movement while typing", () => {
    const { state } = kbState(1);
    const action = resolveKeybind({
      stroke: stroke({ char: "j" }),
      input: "attach ",
      state,
      looseFindingCount: 0,
      now: 0,
    });
    expect(action.type).toBe("none");
  });
});

describe("resolveKeybind — q, Esc, and /back", () => {
  it("L toggles the context-build tail while work is in flight", () => {
    const shell = baseShell({
      shellView: "context-build",
      processing: true,
      contextBuild: contextBuildState("running"),
    });
    const state = baseState(shell);
    const action = resolveKeybind({
      stroke: stroke({ char: "L" }),
      input: "",
      state,
      looseFindingCount: 0,
      now: 0,
    });

    expect(action).toEqual({ type: "toggle-context-tail" });
  });

  it("q aborts a running context-build view", () => {
    const shell = baseShell({
      shellView: "context-build",
      processing: true,
      contextBuild: contextBuildState("running"),
    });
    const state = baseState(shell);
    expect(dispatch("q", shell, state)).toEqual({ type: "abort-inflight" });
  });

  it("q backs out of a terminal context-build view", () => {
    const shell = baseShell({
      shellView: "context-build",
      contextBuild: contextBuildState("done"),
    });
    const state = baseState(shell);
    expect(dispatch("q", shell, state)).toEqual({ type: "dispatch", command: "/back" });
  });

  it("q on a backable view with empty buffer dispatches /back", () => {
    const shell = baseShell({ shellView: "findings" });
    const state = baseState(shell);
    expect(dispatch("q", shell, state)).toEqual({ type: "dispatch", command: "/back" });
  });

  it("b on a backable view with empty buffer dispatches /back", () => {
    const shell = baseShell({ shellView: "kb" });
    const state = baseState(shell);
    expect(dispatch("b", shell, state)).toEqual({ type: "dispatch", command: "/back" });
  });

  it("q on the catalog is a no-op (prevents recursing out of the shell)", () => {
    const shell = baseShell({ shellView: "catalog" });
    const state = baseState(shell);
    expect(dispatch("q", shell, state).type).toBe("none");
  });

  it("q when typing lets the char fall through to the editor", () => {
    const shell = baseShell({ shellView: "findings" });
    const state = baseState(shell);
    const action = resolveKeybind({
      stroke: stroke({ char: "q" }),
      input: "query",
      state,
      looseFindingCount: 0,
      now: 0,
    });
    expect(action.type).toBe("none");
  });

  it("Esc with a non-empty buffer clears the buffer", () => {
    const shell = baseShell({ shellView: "findings" });
    const state = baseState(shell);
    const action = resolveKeybind({
      stroke: stroke({ key: { escape: true } }),
      input: "hello",
      state,
      looseFindingCount: 0,
      now: 0,
    });
    expect(action).toEqual({ type: "clear-input" });
  });

  it("Esc with empty buffer on a backable view dispatches /back", () => {
    const shell = baseShell({ shellView: "module" });
    const state = baseState(shell);
    const action = resolveKeybind({
      stroke: stroke({ key: { escape: true } }),
      input: "",
      state,
      looseFindingCount: 0,
      now: 0,
    });
    expect(action).toEqual({ type: "dispatch", command: "/back" });
  });

  it("Esc with empty buffer on the catalog is a no-op", () => {
    const shell = baseShell({ shellView: "catalog" });
    const state = baseState(shell);
    const action = resolveKeybind({
      stroke: stroke({ key: { escape: true } }),
      input: "",
      state,
      looseFindingCount: 0,
      now: 0,
    });
    expect(action.type).toBe("none");
  });

  it("isBackableShellView rejects catalog + undefined, accepts the rest", () => {
    expect(isBackableShellView("catalog")).toBe(false);
    expect(isBackableShellView(undefined)).toBe(false);
    expect(isBackableShellView("module")).toBe(true);
    expect(isBackableShellView("findings")).toBe(true);
    expect(isBackableShellView("finding")).toBe(true);
    expect(isBackableShellView("threats")).toBe(true);
    expect(isBackableShellView("sast-tasks")).toBe(true);
    expect(isBackableShellView("task-story")).toBe(true);
  });
});

describe("resolveKeybind — fall-through", () => {
  it("typing a plain character returns none so the editor handles it", () => {
    const shell = baseShell({ shellView: "catalog" });
    const state = baseState(shell);
    const action = resolveKeybind({
      stroke: stroke({ char: "x" }),
      input: "",
      state,
      looseFindingCount: 0,
      now: 0,
    });
    expect(action.type).toBe("none");
  });

  it("Enter with content returns none (the component handles submit)", () => {
    const shell = baseShell({ shellView: "catalog" });
    const state = baseState(shell);
    const action = resolveKeybind({
      stroke: stroke({ key: { return: true } }),
      input: "scan .",
      state,
      looseFindingCount: 0,
      now: 0,
    });
    expect(action.type).toBe("none");
  });

  it("ArrowUp on the catalog returns none (frees the editor to do history)", () => {
    const shell = baseShell({ shellView: "catalog" });
    const state = baseState(shell);
    const action = resolveKeybind({
      stroke: stroke({ key: { upArrow: true } }),
      input: "",
      state,
      looseFindingCount: 0,
      now: 0,
    });
    expect(action.type).toBe("none");
  });
});

describe("shouldSubmitOnReturn (paste guard)", () => {
  it("never submits an empty buffer", () => {
    expect(
      shouldSubmitOnReturn({
        bufferedInputLength: 0,
        msSinceLastTextInput: 1000,
        lastTextInputCharLength: 1,
      }),
    ).toBe(false);
  });

  it("submits immediately after a single-char keystroke", () => {
    // Real human typing: e.g. typed "/help" then pressed Enter 50 ms later.
    expect(
      shouldSubmitOnReturn({
        bufferedInputLength: 5,
        msSinceLastTextInput: 50,
        lastTextInputCharLength: 1,
      }),
    ).toBe(true);
  });

  it("submits immediately after `tmux send-keys` (single-char events, microsecond gap)", () => {
    // tmux send-keys delivers chars one at a time over PTY; gap can be < 1 ms.
    // The fix: single-char events bypass the paste guard regardless of timing.
    expect(
      shouldSubmitOnReturn({
        bufferedInputLength: 5,
        msSinceLastTextInput: 0,
        lastTextInputCharLength: 1,
      }),
    ).toBe(true);
  });

  it("buffers when last event was a multi-char paste within the guard window", () => {
    // Multi-line clipboard paste: the trailing \n on a non-last line should
    // not auto-submit. Last text event delivered "line2\nline3" together.
    expect(
      shouldSubmitOnReturn({
        bufferedInputLength: 50,
        msSinceLastTextInput: 1,
        lastTextInputCharLength: 12,
      }),
    ).toBe(false);
  });

  it("submits when last event was multi-char but outside the guard window", () => {
    // User pasted, then waited > guard window before pressing Enter — that's
    // a deliberate submit, not a paste-trailing newline.
    expect(
      shouldSubmitOnReturn({
        bufferedInputLength: 50,
        msSinceLastTextInput: PASTE_GUARD_WINDOW_MS + 5,
        lastTextInputCharLength: 12,
      }),
    ).toBe(true);
  });

  it("PASTE_GUARD_WINDOW_MS is small enough to never block real keystrokes", () => {
    // Anchor: humans cannot type faster than ~30 ms/keystroke. The guard
    // should be far below that so real typing never accidentally triggers it.
    expect(PASTE_GUARD_WINDOW_MS).toBeLessThanOrEqual(10);
  });
});
