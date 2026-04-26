/**
 * Navigation-only slash-command router for the mock TUI.
 *
 * Accepts the same slash-command grammar the real shell uses, but only
 * implements view navigation — no real tools execute, no LLM calls, no
 * file I/O. Anything outside the supported set lands as a `kuzushi/...
 * info: command not available in mock mode` history line so the operator
 * sees a tangible response.
 *
 * Supported (mirroring the table in CLAUDE.md → "Operator verbs"):
 *
 *   /use <id>            — focus module, switch to module view
 *   /findings, /f        — list view
 *   /finding F-NNNN
 *   /open F-NNNN         — single-finding deep page
 *   /threats [sub]
 *   1..5 in threats      — DFD/STRIDE/stories/scope/summary cycler
 *   /tune, /t            — focused-module tune view
 *   /prompts             — focused-module prompts editor
 *   /actor <fingerprint> — drill into per-actor transcript
 *   /back                — pop to prior view
 *   /quit, /q, /exit, :q — clean exit
 */
import type { ShellHistoryEntry, ShellView, ThreatTab, UIStore } from "../../ui/state.js";

const THREAT_TABS = new Set<ThreatTab>(["dfd", "stride", "stories", "scope", "summary"]);
const THREAT_TAB_BY_INDEX: ThreatTab[] = ["dfd", "stride", "stories", "scope", "summary"];

interface RouterState {
  /** Stack of prior `shellView`s for `/back`. Newest on top. */
  history: ShellView[];
}

export interface BuildSlashCommandRouterOptions {
  /** Called when the operator types `/quit` (or aliases). Default: process.exit(0). */
  onExit?: () => void;
}

/**
 * Build an `onInput` callback the harness wires into `shell.onInput`.
 * Pass it to `mountMockShell({ onInput })` or `applySeedToStore(store, ...,
 * { onInput })`.
 */
export function buildSlashCommandRouter(
  store: UIStore,
  options: BuildSlashCommandRouterOptions = {},
): (input: string) => void {
  const state: RouterState = { history: [] };

  return (input: string) => {
    const trimmed = input.trim();
    if (trimmed.length === 0) return;

    if (handleQuit(trimmed)) {
      (options.onExit ?? defaultExit)();
      return;
    }

    if (trimmed === "/back") {
      goBack(store, state);
      return;
    }

    const threatCycle = matchThreatCycle(trimmed, store);
    if (threatCycle) {
      navigate(store, state, { shellView: "threats", threatTab: threatCycle });
      return;
    }

    if (trimmed === "/findings" || trimmed === "/f") {
      navigate(store, state, { shellView: "findings" });
      return;
    }

    if (trimmed === "/tune" || trimmed === "/t") {
      const focused = currentShell(store).focusedModule;
      if (!focused) {
        appendHistory(store, "tune requires a focused module — try `/use <id>` first.");
        return;
      }
      navigate(store, state, { shellView: "tune" });
      return;
    }

    if (trimmed === "/prompts") {
      const focused = currentShell(store).focusedModule;
      if (!focused) {
        appendHistory(store, "prompts requires a focused module — try `/use <id>` first.");
        return;
      }
      navigate(store, state, { shellView: "prompts-editor" });
      return;
    }

    if (trimmed === "/catalog") {
      navigate(store, state, { shellView: "catalog", focusedModule: null });
      return;
    }

    const useMatch = trimmed.match(/^\/use\s+(\S+)$/);
    if (useMatch) {
      navigate(store, state, { shellView: "module", focusedModule: useMatch[1] });
      return;
    }

    const findingMatch = trimmed.match(/^\/(?:finding|open)\s+(\S+)$/);
    if (findingMatch) {
      navigate(store, state, { shellView: "finding", openFindingId: findingMatch[1] });
      return;
    }

    const threatsMatch = trimmed.match(/^\/threats(?:\s+(\S+))?$/);
    if (threatsMatch) {
      const requested = (threatsMatch[1] as ThreatTab | undefined) ?? "summary";
      const tab = THREAT_TABS.has(requested) ? requested : "summary";
      navigate(store, state, { shellView: "threats", threatTab: tab });
      return;
    }

    const actorMatch = trimmed.match(/^\/actor\s+(\S+)$/);
    if (actorMatch) {
      navigate(store, state, { shellView: "actor-detail", focusedActor: actorMatch[1] });
      return;
    }

    appendHistory(store, `command not available in mock mode: ${trimmed}`);
  };
}

function handleQuit(input: string): boolean {
  return ["/quit", "/q", "/exit", ":q"].includes(input);
}

function defaultExit(): void {
  process.exit(0);
}

function currentShell(store: UIStore): {
  shellView: ShellView;
  focusedModule: string | null;
} {
  const shell = store.getState().shell;
  return {
    shellView: shell?.shellView ?? "catalog",
    focusedModule: shell?.focusedModule ?? null,
  };
}

interface NavigatePatch {
  shellView: ShellView;
  threatTab?: ThreatTab;
  focusedModule?: string | null;
  focusedActor?: string | null;
  openFindingId?: string | null;
}

function navigate(store: UIStore, state: RouterState, patch: NavigatePatch): void {
  const shell = store.getState().shell;
  if (!shell) return;
  state.history.push(shell.shellView);
  store.update({
    shell: {
      ...shell,
      ...patch,
    },
  });
}

function goBack(store: UIStore, state: RouterState): void {
  const shell = store.getState().shell;
  if (!shell) return;
  const prior = state.history.pop();
  if (!prior) {
    appendHistory(store, "/back: no prior view in this session.");
    return;
  }
  store.update({ shell: { ...shell, shellView: prior } });
}

function matchThreatCycle(input: string, store: UIStore): ThreatTab | null {
  const shell = store.getState().shell;
  if (!shell || shell.shellView !== "threats") return null;
  const idx = Number.parseInt(input, 10);
  if (Number.isInteger(idx) && idx >= 1 && idx <= 5) {
    return THREAT_TAB_BY_INDEX[idx - 1] ?? null;
  }
  return null;
}

function appendHistory(store: UIStore, text: string): void {
  const shell = store.getState().shell;
  if (!shell) return;
  const entry: ShellHistoryEntry = {
    type: "output",
    text: `info: ${text}`,
    timestamp: Date.now(),
  };
  store.update({
    shell: {
      ...shell,
      history: [...shell.history, entry],
    },
  });
}
