/**
 * Mock TUI playthrough — slim path that mounts the Ink shell with a fully
 * pre-populated `UIStore` so a developer can visually test every shell
 * view without booting `CopilotCore`, the message bus, agent runtime, or
 * any of `startInkShell`'s ~1700 lines of side effects.
 *
 * Surface:
 * - `mountMockShell(seed, opts)` — primitive that creates the renderer,
 *   merges seed into the store, wires `onExit`/`onAbort`, and returns a
 *   handle with cleanup. Pure rendering — no slash-command navigation
 *   yet (added in Step 4).
 * - `SCENARIOS` — registry populated by `./scenarios/index.ts` (Step 3+).
 *
 * Used by `scripts/mock-tui.ts` and `tests/ui/mock-tui.test.ts`.
 */

import { baseShell, baseSummary } from "../../ui/mock-fixtures.js";
import { createUIRenderer } from "../../ui/render.js";
import type { UIState, UIStore } from "../../ui/state.js";
import { buildSlashCommandRouter } from "./slash-commands.js";

/**
 * One scenario seeds the shell with a chosen view + supporting data.
 *
 * `seed` returns a `Partial<UIState>` so view-specific fields land on the
 * existing tree without overwriting `mode`/`shell`/etc. that the harness
 * sets. `playback` is optional — when present and `--playback` is on, it
 * runs after mount and returns a cleanup that the harness invokes on
 * Ctrl+C / unmount to stop timers.
 */
export interface MockScenario {
  id: string;
  description: string;
  seed: (opts?: Record<string, unknown>) => Partial<UIState>;
  playback?: (store: UIStore) => () => void;
}

export interface MountOptions {
  /** Override the default `process.exit(0)` exit handler. */
  onExit?: () => void;
  /** Override the default no-op abort handler. */
  onAbort?: () => void;
  /** Override the input handler. Defaults to navigation router (Step 4). */
  onInput?: (input: string) => void;
}

export interface MockMount {
  store: UIStore;
  cleanup: () => Promise<void>;
}

/**
 * Apply a scenario seed to an existing store. Always seeds a default
 * `summary` and merges the scenario partial onto a `baseShell()` so
 * view-dispatcher invariants hold — `findings`, `finding`, and
 * `module-run` views read across `summary.actionableFindings` even when
 * the chosen view doesn't directly populate them.
 *
 * Exported separately from `mountMockShell` so tests can drive scenarios
 * through the plain-renderer without mounting Ink.
 */
export function applySeedToStore(
  store: UIStore,
  seed: Partial<UIState>,
  handlers: {
    onExit?: () => void;
    onAbort?: () => void;
    onInput?: (input: string) => void;
  } = {},
): void {
  const onExit = handlers.onExit ?? (() => {});
  const onAbort = handlers.onAbort ?? (() => {});
  const onInput = handlers.onInput ?? ((_input: string) => {});

  const seededShell = seed.shell ?? null;
  const mergedShell = baseShell({
    ...(seededShell ?? {}),
    onExit,
    onAbort,
    onInput,
  });

  const summary = seed.summary ?? baseSummary([]);

  store.update({
    ...seed,
    mode: "shell",
    summary,
    shell: mergedShell,
  });
}

/**
 * Mount the Ink shell with a seeded `UIState`. Caller owns the returned
 * `cleanup` — call it (and only it) on SIGINT.
 *
 * Two-stage Ctrl+C and `exitOnCtrlC: false` mean both `onExit` AND
 * `onAbort` must be wired or the operator's keypress is silently
 * swallowed. See CopilotShell.tsx:222-225, App.tsx:147, render.ts:94.
 */
export async function mountMockShell(
  seed: Partial<UIState>,
  opts: MountOptions = {},
): Promise<MockMount> {
  const renderer = await createUIRenderer();
  const { store, cleanup: cleanupRenderer } = renderer;

  let cleanedUp = false;
  const runCleanup = async (): Promise<void> => {
    if (cleanedUp) return;
    cleanedUp = true;
    try {
      cleanupRenderer();
    } catch {
      /* renderer cleanup must be best-effort during process teardown */
    }
  };

  const onExit =
    opts.onExit ??
    (() => {
      void runCleanup().finally(() => process.exit(0));
    });
  const onAbort = opts.onAbort ?? (() => {});
  const onInput =
    opts.onInput ??
    buildSlashCommandRouter(store, {
      onExit: () => {
        void runCleanup().finally(() => process.exit(0));
      },
    });

  applySeedToStore(store, seed, { onExit, onAbort, onInput });

  return { store, cleanup: runCleanup };
}

/**
 * Scenario registry. Populated by `./scenarios/*.ts` files via
 * `registerScenario`. Empty until Step 3 lands — keep the registry-shaped
 * surface here so the dev script and tests can already import it.
 */
export const SCENARIOS: Record<string, MockScenario> = {};

/** Register a scenario in `SCENARIOS`. Throws on duplicate id. */
export function registerScenario(scenario: MockScenario): void {
  if (SCENARIOS[scenario.id]) {
    throw new Error(`mock-tui: duplicate scenario id "${scenario.id}"`);
  }
  SCENARIOS[scenario.id] = scenario;
}

export function listScenarios(): MockScenario[] {
  return Object.values(SCENARIOS).sort((a, b) => a.id.localeCompare(b.id));
}
