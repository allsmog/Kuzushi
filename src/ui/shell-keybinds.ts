/**
 * shell-keybinds — pure keybind-reducer for the interactive shell.
 *
 * The Ink `useInput` handler in `CopilotShell.tsx` is wall-to-wall side
 * effects (it calls `setInput`, `store.update`, `liveShell.onInput`, etc.),
 * which makes it hard to unit-test. This module factors the decision logic
 * into a single pure function: given a keystroke + live state, return a
 * structured `KeybindAction` describing what should happen.  The component
 * then translates the action into the right setState / store update.
 *
 * Everything that affects UX (Ctrl+C two-stage, y/n for pending plans,
 * 1..5 threat cycling, j/k on findings, q/Esc back, Enter submit, Tab
 * completion, input editing) goes through this one reducer. That gives
 * us a single table of truth for what the shell responds to — see
 * tests/copilot/keybinds.test.ts for the lock-ins.
 *
 * Intentionally *not* exhaustive over input editing (typing a char,
 * backspace) — the component handles those inline because they only
 * touch local React state. We only gate / prioritize the higher-order
 * dispatches here.
 */

import type { ShellState, UIState } from "./state.js";

/** Window during which a second Ctrl+C at the idle prompt commits the exit. */
export const CTRL_C_ARM_WINDOW_MS = 2000;

/** Default pageSize mirror — must match FindingsView's DEFAULT_PAGE_SIZE. */
export const FINDINGS_DEFAULT_PAGE_SIZE = 50;

/**
 * How long after the last text-input event we treat an Enter as paste-trailing
 * rather than a deliberate submit. Tight enough that real keystrokes followed
 * by Enter (`tmux send-keys "/cmd" Enter`) submit immediately.
 */
export const PASTE_GUARD_WINDOW_MS = 5;

/**
 * Decide whether an Enter that arrives after some text input should submit
 * immediately or buffer (in case it's the trailing newline of a multi-line
 * paste). Pure helper so `tests/copilot/keybinds.test.ts` can lock the
 * behavior without spinning up Ink.
 *
 * Rules:
 * - If there's no buffered input, never submit (caller falls through to arm).
 * - If the last text-input event was a single character (typing or `tmux
 *   send-keys`, which delivers one byte at a time over PTY), submit. Even if
 *   the gap is microseconds.
 * - If the last text-input event was multi-character (genuine paste blob)
 *   AND it landed within `PASTE_GUARD_WINDOW_MS`, treat the Enter as paste
 *   trailing newline and buffer.
 * - Otherwise submit.
 */
export function shouldSubmitOnReturn(opts: {
  bufferedInputLength: number;
  msSinceLastTextInput: number;
  lastTextInputCharLength: number;
}): boolean {
  if (opts.bufferedInputLength === 0) return false;
  const looksLikePaste =
    opts.lastTextInputCharLength > 1 && opts.msSinceLastTextInput < PASTE_GUARD_WINDOW_MS;
  return !looksLikePaste;
}

/** Description of a single Ink `useInput` keystroke. */
export interface Keystroke {
  /** Printable character (if any). */
  char: string;
  /** Ink key flags — `ctrl`, `escape`, `return`, `upArrow`, etc. */
  key: {
    ctrl?: boolean;
    meta?: boolean;
    shift?: boolean;
    tab?: boolean;
    return?: boolean;
    escape?: boolean;
    backspace?: boolean;
    delete?: boolean;
    upArrow?: boolean;
    downArrow?: boolean;
    leftArrow?: boolean;
    rightArrow?: boolean;
    pageUp?: boolean;
    pageDown?: boolean;
  };
}

/** Discriminated union of high-order keybind outcomes. */
export type KeybindAction =
  /** Nothing to do — the component falls back to its local-edit path. */
  | { type: "none" }
  /** Abort the in-flight tool/agent call. */
  | { type: "abort-inflight" }
  /** First Ctrl+C at idle prompt — arm the two-stage exit. */
  | { type: "arm-exit"; at: number }
  /** Second Ctrl+C within the arm window — exit the shell. */
  | { type: "exit" }
  /** Forward a slash-command string through `shell.onInput`. */
  | { type: "dispatch"; command: string }
  /** Set `shell.findingCursor` to the given (already-clamped) index. */
  | { type: "set-finding-cursor"; cursor: number }
  /** Set `shell.sastTaskCursor` to the given (already-clamped) index. */
  | { type: "set-sast-task-cursor"; cursor: number }
  /** Set `shell.kb.cursor` to the given (already-clamped) index. */
  | { type: "set-kb-cursor"; cursor: number }
  /** Open or close the active/latest task story details view. */
  | { type: "toggle-story"; nextView: ShellState["shellView"] }
  /** Toggle the `/context build` tail log between compact and expanded. */
  | { type: "toggle-context-tail" }
  /** Clear the in-progress input buffer. */
  | { type: "clear-input" };

export interface KeybindInputs {
  /** The keystroke to resolve. */
  stroke: Keystroke;
  /** Current input buffer (pre-keystroke). */
  input: string;
  /** Live UI state (ctrl-c arm timestamp, summary count, etc.). */
  state: UIState;
  /** Loose-finding count — used to clamp cursor movement. */
  looseFindingCount: number;
  /** SAST task row count — used to clamp the SAST task selector cursor. */
  sastTaskCount?: number;
  /** Current time — injectable for deterministic tests. */
  now: number;
}

/** True for any of the Phase C threat-model sub-views. */
export function isThreatShellView(view: ShellState["shellView"] | undefined): boolean {
  return view === "threats";
}

/**
 * True when the shell is showing a non-catalog sub-view where `q` / Esc
 * should route to `/back`. The catalog is the top level — falling through
 * `/back` there would recurse out of the shell with surprising effect.
 */
export function isBackableShellView(view: ShellState["shellView"] | undefined): boolean {
  if (!view) return false;
  return view !== "catalog";
}

const THREAT_DIGIT_TO_SUB: Record<string, string> = {
  "1": "dfd",
  "2": "stride",
  "3": "stories",
  "4": "scope",
  "5": "summary",
};

function isCtrlChord(char: string, key: Keystroke["key"], letter: string): boolean {
  if (!key.ctrl) return false;
  const lower = letter.toLowerCase();
  const ctrlCode = String.fromCharCode(lower.charCodeAt(0) - 96);
  return char === lower || char === lower.toUpperCase() || char === ctrlCode;
}

export function resolveTaskStoryToggleView(
  shell: Pick<ShellState, "shellView" | "focusedModule">,
): ShellState["shellView"] {
  if (shell.shellView !== "task-story") return "task-story";
  return shell.focusedModule ? "module" : "catalog";
}

function hasAbortableModuleRun(shell: ShellState): boolean {
  return shell.shellView === "module-run" && shell.moduleRun?.status === "running";
}

function hasLivePauseResume(shell: ShellState): boolean {
  return hasAbortableModuleRun(shell) && shell.moduleRun?.liveControl === "pause-resume";
}

/**
 * Resolve a keystroke into an action, applying the shell's dispatch
 * priority:
 *
 *   1. Ctrl+C / Ctrl+D — commit an armed exit, abort in-flight work, else arm.
 *   2. Plan-pending overlay — y / n / Esc apply / discard / cancel.
 *   3. Context-build L/q — expand the live tail or abort/back out.
 *   4. Threat-view 1..5 — cycle views when buffer is empty.
 *   5. Findings j/k/g/G/arrow/PgUp/PgDown — drive cursor when buffer is empty.
 *   6. `q` with empty buffer on a backable view — /back.
 *   7. `Esc` — clear buffer if non-empty, else /back on backable views.
 *
 * Everything else returns `{ type: "none" }` so the component handles it
 * locally (typing, backspace, Enter submit, Tab completion, history).
 */
export function resolveKeybind(inputs: KeybindInputs): KeybindAction {
  const { stroke, input, state, looseFindingCount, now } = inputs;
  const { char, key } = stroke;
  const shell = state.shell;
  if (!shell) return { type: "none" };

  // --- 1. Ctrl+C / Ctrl+D ---------------------------------------------------
  if (isCtrlChord(char, key, "c") || isCtrlChord(char, key, "d")) {
    if (shell.processing || hasAbortableModuleRun(shell)) {
      return { type: "abort-inflight" };
    }
    const armedAt = state.ctrlCArmedAt ?? 0;
    if (armedAt > 0 && now - armedAt <= CTRL_C_ARM_WINDOW_MS) {
      return { type: "exit" };
    }
    return { type: "arm-exit", at: now };
  }

  if (isCtrlChord(char, key, "o")) {
    return { type: "toggle-story", nextView: resolveTaskStoryToggleView(shell) };
  }

  // If we got here with an armed timestamp, any other keystroke should
  // disarm — the component handles the store update alongside its other
  // state mutations. We still compute the real action below.
  // (Reporting the disarm is the component's concern.)

  if (shell.shellView === "context-build" && input.length === 0) {
    if (char === "L") return { type: "toggle-context-tail" };
    if (char === "q") {
      return shell.processing || shell.contextBuild?.status === "running"
        ? { type: "abort-inflight" }
        : { type: "dispatch", command: "/back" };
    }
  }

  if (hasLivePauseResume(shell) && input.length === 0) {
    if (char === "p" || char === "P") return { type: "dispatch", command: "/pause" };
    if (char === "r" || char === "R") return { type: "dispatch", command: "/resume" };
  }

  if (shell.processing) return { type: "none" };

  // --- 2. Plan-pending overlay ----------------------------------------------
  if (shell.pendingPlan && input.length === 0) {
    if (char === "y" || char === "Y") return { type: "dispatch", command: "/yes" };
    if (char === "n" || char === "N" || key.escape) {
      return { type: "dispatch", command: "/no" };
    }
  }

  if (shell.pendingThreatPatch && input.length === 0) {
    if (char === "y" || char === "Y") return { type: "dispatch", command: "/threats apply" };
    if (char === "n" || char === "N" || key.escape) {
      return { type: "dispatch", command: "/threats reject" };
    }
  }

  // --- 3. Threat-view 1..5 cycle --------------------------------------------
  if (isThreatShellView(shell.shellView) && input.length === 0) {
    if (char === "r" || char === "R") return { type: "dispatch", command: "/threats regen" };
    const sub = THREAT_DIGIT_TO_SUB[char];
    if (sub) return { type: "dispatch", command: `/threats ${sub}` };
  }

  // --- 3b. ModuleRunView 1..4 actor drill-in --------------------------------
  // Pressing a digit while the view is `module-run` dispatches `/actor <n>`,
  // which the slash router resolves to a per-actor fingerprint and flips
  // the view to `actor-detail`. Range 1..4 mirrors the four actor cards
  // ModuleRunView reserves space for; higher digits fall through.
  if (shell.shellView === "module-run" && input.length === 0 && /^[1-4]$/.test(char)) {
    return { type: "dispatch", command: `/actor ${char}` };
  }

  if (shell.shellView === "sast-tasks" && input.length === 0) {
    const count = inputs.sastTaskCount ?? 0;
    const cur = shell.sastTaskCursor ?? 0;
    const clamp = (next: number): number => Math.max(0, Math.min(Math.max(0, count - 1), next));
    if (count > 0 && (char === "j" || key.downArrow)) {
      return { type: "set-sast-task-cursor", cursor: clamp(cur + 1) };
    }
    if (count > 0 && (char === "k" || key.upArrow)) {
      return { type: "set-sast-task-cursor", cursor: clamp(cur - 1) };
    }
    if (char === " ") return { type: "dispatch", command: "/task toggle" };
    if (char === "a" || char === "A") return { type: "dispatch", command: "/task mode toggle" };
    if (char === "o" || char === "O") return { type: "dispatch", command: "/options" };
    if (char === "r" || char === "R") return { type: "dispatch", command: "/task reset" };
    if (char === "b" || char === "B") return { type: "dispatch", command: "/back" };
  }

  if (shell.shellView === "kb" && input.length === 0) {
    const moduleId = shell.kb?.moduleId ?? shell.focusedModule ?? "";
    const docs = moduleId ? (shell.kbState?.[moduleId]?.documents ?? []) : [];
    const count = docs.length;
    const cur = shell.kb?.cursor ?? 0;
    const clamp = (next: number): number => Math.max(0, Math.min(Math.max(0, count - 1), next));
    if (count > 0 && (char === "j" || key.downArrow)) {
      return { type: "set-kb-cursor", cursor: clamp(cur + 1) };
    }
    if (count > 0 && (char === "k" || key.upArrow)) {
      return { type: "set-kb-cursor", cursor: clamp(cur - 1) };
    }
    if (count > 0 && char === "g") return { type: "set-kb-cursor", cursor: 0 };
    if (count > 0 && char === "G") return { type: "set-kb-cursor", cursor: count - 1 };
    const selected = docs[clamp(cur)];
    if (selected && (char === "d" || char === "D")) {
      return { type: "dispatch", command: `detach ${selected.id}` };
    }
    if (selected && (char === "r" || char === "R")) {
      return { type: "dispatch", command: `reparse ${selected.id}` };
    }
  }

  // --- 4. Findings cursor ---------------------------------------------------
  if (shell.shellView === "findings" && input.length === 0 && looseFindingCount > 0) {
    const cur = shell.findingCursor ?? 0;
    const pageSize = shell.findingPageSize ?? FINDINGS_DEFAULT_PAGE_SIZE;
    const clamp = (next: number): number => Math.max(0, Math.min(looseFindingCount - 1, next));
    if (char === "j" || key.downArrow) {
      return { type: "set-finding-cursor", cursor: clamp(cur + 1) };
    }
    if (char === "k" || key.upArrow) {
      return { type: "set-finding-cursor", cursor: clamp(cur - 1) };
    }
    if (char === "g") return { type: "set-finding-cursor", cursor: 0 };
    if (char === "G") {
      return { type: "set-finding-cursor", cursor: looseFindingCount - 1 };
    }
    if (key.pageDown) {
      return { type: "set-finding-cursor", cursor: clamp(cur + pageSize) };
    }
    if (key.pageUp) {
      return { type: "set-finding-cursor", cursor: clamp(cur - pageSize) };
    }
  }

  // --- 5. `q` → /back on backable views -------------------------------------
  if (
    (char === "q" || char === "b") &&
    input.length === 0 &&
    isBackableShellView(shell.shellView)
  ) {
    return { type: "dispatch", command: "/back" };
  }

  // --- 6. Esc ---------------------------------------------------------------
  if (key.escape) {
    if (input.length > 0) return { type: "clear-input" };
    if (isBackableShellView(shell.shellView)) {
      return { type: "dispatch", command: "/back" };
    }
  }

  return { type: "none" };
}
