/**
 * Ink component for the copilot shell.
 *
 * Clean conversation stream with proper spacing. User messages, agent
 * responses, inline tool activity. The Ink App handles mode transitions —
 * when a scan runs, the app switches to "running" mode and renders
 * PipelineIndicator/StatusFooter, then switches back here.
 *
 * Uses tokens for all styling and registers its active keybindings with
 * the shared footer.
 */

import { Box, Static, Text, useApp, useInput, useStdout } from "ink";
import React, { memo, useEffect, useRef, useState } from "react";
import { computeFindingAliases, resolveAlias } from "../../copilot/finding-alias.js";
import { SAST_TASK_CAPABILITIES } from "../../copilot/sast-task-selection.js";
import {
  buildShellPrompt,
  firstShellSuggestion,
  listShellSuggestions,
} from "../../copilot/shell-commands.js";
import { formatClock, truncateEnd } from "../format.js";
import { BLACK_CIRCLE, LOWER_HOOK, OUTCOME_GLYPH } from "../glyphs.js";
import { applyBackspace, isCtrlChord } from "../hooks/text-edit-actions.js";
import { useRegisterKeybindings } from "../hooks/useKeybindings.js";
import { shallowEqual, useElapsed, useUISelector } from "../hooks.js";
import { useLayoutContext } from "../layout-context.js";
import { ExpandableSection } from "../primitives/ExpandableSection.js";
import { Gutter } from "../primitives/Gutter.js";
import { Markdown } from "../primitives/Markdown.js";
import { Ratchet } from "../primitives/Ratchet.js";
import { renderShellInputSegments } from "../shell-input-line.js";
import {
  CTRL_C_ARM_WINDOW_MS as CTRL_C_ARM_WINDOW_MS_IMPORTED,
  resolveKeybind,
  shouldSubmitOnReturn,
} from "../shell-keybinds.js";
import type {
  ActionableFinding,
  AgentActivityLine,
  HuntActorSnapshot,
  ShellHistoryEntry,
  ShellState,
  SummaryData,
  UIStore,
} from "../state.js";
import {
  type ShellStoryEvent,
  type ShellTaskStoryState,
  storyKindLabel,
  storyStatusLabel,
  storyTabEvents,
} from "../task-story.js";
import { SPACING, tokens } from "../tokens.js";
import { ActorTranscriptView } from "./ActorTranscriptView.js";
import { AttackerStoriesView } from "./AttackerStoriesView.js";
import { BannerSplash } from "./BannerSplash.js";
import { ContextBuildView } from "./ContextBuildView.js";
import { CostCapHalt } from "./CostCapHalt.js";
import { DelayedBusyIndicator } from "./DelayedBusyIndicator.js";
import { DiffSinceView } from "./DiffSinceView.js";
import { ErrorCard } from "./ErrorCard.js";
import { FindingCard } from "./FindingCard.js";
import { FindingsView } from "./FindingsView.js";
import { InteractionErrorBoundary } from "./InteractionErrorBoundary.js";
import { KbView } from "./KbView.js";
import { ModuleCatalog } from "./ModuleCatalog.js";
import { ModuleHome } from "./ModuleHome.js";
import { ModuleRunView } from "./ModuleRunView.js";
import { OptionsView } from "./OptionsView.js";
import { PlanCard } from "./PlanCard.js";
import { PromptsEditorView } from "./PromptsEditorView.js";
import { PulseDot } from "./PulseDot.js";
import { RateLimitBanner } from "./RateLimitBanner.js";
import { SastTasksView } from "./SastTasksView.js";
import { ScopeAndCriticalityView } from "./ScopeAndCriticalityView.js";
import { Spinner } from "./Spinner.js";
import { ThreatDfdView } from "./ThreatDfdView.js";
import { ThreatStrideMatrix } from "./ThreatStrideMatrix.js";
import { ThreatSummaryExport } from "./ThreatSummaryExport.js";
import { TuneView } from "./TuneView.js";

interface CopilotShellProps {
  store: UIStore;
}

const IDLE_KEYBINDS = [
  { keys: "Enter", label: "Send" },
  { keys: "←/→", label: "Cursor", secondary: true },
  { keys: "\u2191/\u2193", label: "History" },
  { keys: "Tab", label: "Autocomplete", secondary: true },
  { keys: "?", label: "Help", secondary: true },
  { keys: "Ctrl+U", label: "Clear line", secondary: true },
  { keys: "Esc", label: "Clear input", secondary: true },
  { keys: "Ctrl+C", label: "Exit", secondary: true },
];

/**
 * Build the idle-prompt keybinds row, augmenting with a `/back` hint
 * when the current view has a parent to step up to (catalog has no
 * parent). Keeps the shell footer's actionable state aligned with the
 * `ShellWayfinding` "/back -> ..." line above the prompt.
 *
 * Exported for tests in `tests/ui/`.
 */
export function buildIdleKeybindsForView(
  shellView: ShellState["shellView"] | undefined,
): ReadonlyArray<{ keys: string; label: string; secondary?: boolean }> {
  const base = IDLE_KEYBINDS.slice();
  if (shellView && shellView !== "catalog") {
    // Insert /back after Send/History so the discoverable navigation
    // verb sits next to the primary action keys, not lost in the tail.
    base.splice(3, 0, { keys: "/back", label: "Back" });
  }
  return base;
}

const PROCESSING_KEYBINDS = [
  { keys: "Ctrl+C", label: "Interrupt" },
  { keys: "Ctrl+O", label: "Details", secondary: true },
];
const MODULE_RUN_LIVE_KEYBINDS = [
  { keys: "1–4", label: "drill into actor" },
  { keys: "p", label: "pause queued work", secondary: true },
  { keys: "r", label: "resume queued work", secondary: true },
  { keys: "b", label: "back", secondary: true },
  { keys: "Ctrl+C", label: "interrupt", secondary: true },
];
const PLAN_KEYBINDS = [
  { keys: "Y", label: "Apply plan" },
  { keys: "N/Esc", label: "Discard plan" },
  { keys: "Ctrl+C", label: "Exit", secondary: true },
];
export const SAST_TASK_KEYBINDS = [
  { keys: "Space", label: "Toggle block" },
  { keys: "j/k", label: "Move", secondary: true },
  { keys: "a", label: "Mode", secondary: true },
  { keys: "o", label: "Options", secondary: true },
  { keys: "r", label: "Reset", secondary: true },
  { keys: "q/Esc", label: "Back", secondary: true },
  { keys: "?", label: "Help", secondary: true },
];

/** Window during which a second Ctrl+C at the idle prompt commits the exit. */
const CTRL_C_ARM_WINDOW_MS = CTRL_C_ARM_WINDOW_MS_IMPORTED;

/**
 * Count loose (non-chain) findings in the current summary — the population
 * that the findings cursor scans over. Kept in sync with FindingsView's own
 * filter so j/k clamps match exactly what the operator sees on screen.
 */
function countLooseFindings(
  findings: ReadonlyArray<ActionableFinding>,
  chains: NonNullable<SummaryData["exploitChains"]>,
): number {
  const chainFingerprints = new Set<string>();
  for (const chain of chains) {
    for (const step of chain.steps) chainFingerprints.add(step.findingFingerprint);
  }
  let count = 0;
  for (const f of findings) if (!chainFingerprints.has(f.fingerprint)) count += 1;
  return count;
}

export function CopilotShell({ store }: CopilotShellProps): React.ReactElement {
  const { theme } = useLayoutContext();
  const shellState = useUISelector(
    store,
    (s) => ({
      shell: s.shell,
      summary: s.summary,
      agentActivity: s.agentActivity,
      ctrlCArmedAt: s.ctrlCArmedAt,
      shellSplashShown: s.shellSplashShown,
    }),
    shallowEqual,
  );
  const shell = shellState.shell;
  const { stdout } = useStdout();
  const columns = stdout?.columns ?? 120;
  const pendingAssistantStartedAtRef = useRef<number>(Date.now());

  const showSplash = shellState.shellSplashShown !== true;

  React.useEffect(() => {
    if (showSplash) {
      store.update({ shellSplashShown: true });
    }
  }, [store, showSplash]);

  React.useEffect(() => {
    if (!shellState.ctrlCArmedAt) return;
    const remaining = CTRL_C_ARM_WINDOW_MS - (Date.now() - shellState.ctrlCArmedAt);
    if (remaining <= 0) {
      store.update({ ctrlCArmedAt: undefined });
      return;
    }
    const timer = setTimeout(() => {
      store.update({ ctrlCArmedAt: undefined });
    }, remaining + 25);
    return () => clearTimeout(timer);
  }, [store, shellState.ctrlCArmedAt]);

  // Raw-mode watchdog now lives on `AppInner` via `useRawModeWatchdog` so it
  // survives `mode` flips ("shell" ↔ "running" ↔ "summary"). Previously the
  // watchdog was scoped here; when a tool dispatch caused the report-worker
  // to flip `mode` to "running", `CopilotShell` unmounted, the watchdog
  // unmounted with it, and the Claude Agent SDK subprocess could drop raw
  // mode for the rest of the run with nobody watching.

  if (shell?.pendingAssistantText) {
    if (pendingAssistantStartedAtRef.current === 0) {
      pendingAssistantStartedAtRef.current = Date.now();
    }
  } else {
    pendingAssistantStartedAtRef.current = 0;
  }

  // ModuleCatalog re-reads shell.moduleCatalog on every render; wrapping it
  // in <Static> would freeze the first snapshot and hide module/last-run
  // updates, so we render it plainly when present. The memoized wrapper
  // stops it from re-rendering on every heartbeat tick.
  const showCatalog = (shell?.moduleCatalog?.length ?? 0) > 0;
  const { staticHistory, liveHistory } = React.useMemo(
    () => splitShellHistory(shell?.history ?? []),
    [shell?.history],
  );
  const showStaticHistory =
    shell?.shellView === undefined ||
    shell.shellView === "catalog" ||
    shell.shellView === "task-story";
  const visibleLiveHistory = React.useMemo(() => {
    if (showStaticHistory) return liveHistory;
    const lastInputIdx = findLastHistoryInputIndex(liveHistory);
    const recentHistory = lastInputIdx >= 0 ? liveHistory.slice(lastInputIdx + 1) : liveHistory;
    return recentHistory.filter((entry) => !isStructuredViewNoise(entry)).slice(-1);
  }, [liveHistory, showStaticHistory]);
  const suppressRunningToolName =
    shell?.shellView === "module-run" || shell?.shellView === "actor-detail"
      ? shell.moduleRun?.status === "running"
        ? shell.moduleRun.toolName
        : undefined
      : undefined;
  const hasSpecificBusySurface =
    Boolean(shell?.currentTool) ||
    Boolean(shell?.plannerBusy) ||
    Boolean(shell?.pendingAssistantText) ||
    shell?.moduleRun?.status === "running" ||
    shell?.contextBuild?.status === "running";
  const staticItems = React.useMemo<Array<ShellStaticItem>>(() => {
    const items: Array<ShellStaticItem> = [];
    if (showStaticHistory && showSplash) {
      items.push({
        key: "kz-splash",
        kind: "splash",
        workspace: shell?.workspace,
        target: shell?.target,
      });
    }
    if (showStaticHistory && shell && !showCatalog && !shell.processing) {
      items.push({
        key: "shell-banner",
        kind: "banner",
        shell,
      });
    }
    if (showStaticHistory) {
      for (const entry of staticHistory) {
        items.push({
          key: `history:${historyEntryKey(entry)}`,
          kind: "history",
          entry,
        });
      }
    }
    return items;
  }, [shell, showCatalog, showSplash, showStaticHistory, staticHistory]);
  if (!shell) return <Text>Loading...</Text>;

  return (
    <Box
      flexDirection="column"
      flexGrow={1}
      height="100%"
      overflow="hidden"
      justifyContent={showStaticHistory ? "space-between" : "flex-start"}
    >
      <Box
        flexDirection="column"
        flexGrow={showStaticHistory ? 1 : 0}
        flexShrink={showStaticHistory ? 1 : 0}
        overflow="hidden"
      >
        {/* Keep a single historical Static stream in the shell so printed
            banners and scrolled-past transcript lines move upward cleanly
            without competing Static regions fighting for reconciliation. */}
        <Static items={staticItems}>
          {(item) => <ShellStaticItemView key={item.key} item={item as ShellStaticItem} />}
        </Static>

        {/* The "▸ <view> · <workspace> · <target>" sub-banner used to render
        here. Removed: ScreenFrame's chrome already shows the view label
        (breadcrumb) and the workspace + target (status row). The banner was
        triple-printing the same context across two adjacent rows. */}

        <MemoShellLiveHistory
          history={visibleLiveHistory}
          suppressRunningToolName={suppressRunningToolName}
          compactRunningToolCalls={shell.shellView === "task-story"}
        />
      </Box>

      <Box
        flexDirection="column"
        flexGrow={showStaticHistory ? 0 : 1}
        flexShrink={1}
        overflow="hidden"
      >
        <Box flexDirection="column" flexGrow={1} flexShrink={1} overflow="hidden">
          {!shell.processing ||
          shell.shellView === "context-build" ||
          shell.shellView === "task-story" ||
          shell.shellView === "module-run" ||
          shell.shellView === "actor-detail" ? (
            <InteractionErrorBoundary label={describeShellLocation(shell)}>
              <MemoShellViewPanel
                summary={shellState.summary}
                shell={shell}
                agentActivity={shellState.agentActivity}
              />
            </InteractionErrorBoundary>
          ) : null}
        </Box>
        {!shell.processing ||
        shell.shellView === "task-story" ||
        shell.shellView === "module-run" ||
        shell.shellView === "actor-detail" ? (
          <ShellWayfinding shell={shell} narrow={columns < 110} />
        ) : null}
        {shell.shellView !== "module-run" ? (
          <ShellTaskStatusLine shell={shell} columns={columns} />
        ) : null}

        <ShellAdvisoryStack store={store} />

        <Ratchet>
          <Box flexDirection="column" minHeight={1}>
            {shell.plannerBusy && !shell.pendingPlan && (
              <Box marginTop={theme.spacing.sm} paddingLeft={theme.spacing.md}>
                <Spinner />
                <Text>
                  {"  "}
                  {tokens.muted("planning\u2026")}
                </Text>
              </Box>
            )}

            {shell.pendingPlan && <PlanCard plan={shell.pendingPlan} />}

            {shell.processing && !hasSpecificBusySurface ? (
              <DelayedBusyIndicator
                label="Working"
                detail="Command accepted. Waiting for the first progress event."
              />
            ) : null}

            {shell.pendingAssistantText && (
              <HistoryEntry
                entry={{
                  type: "output",
                  text: shell.pendingAssistantText,
                  timestamp: pendingAssistantStartedAtRef.current || Date.now(),
                }}
              />
            )}

            {shellState.ctrlCArmedAt &&
            Date.now() - shellState.ctrlCArmedAt < CTRL_C_ARM_WINDOW_MS ? (
              <Box marginTop={theme.spacing.sm} paddingLeft={theme.spacing.md}>
                <Text>{tokens.warn("press Ctrl+C again to exit")}</Text>
              </Box>
            ) : null}
          </Box>
        </Ratchet>

        <ShellInputArea store={store} shell={shell} columns={columns} />
      </Box>
    </Box>
  );
}

const ShellInputArea = memo(
  function ShellInputArea({
    store,
    shell,
    columns,
  }: {
    store: UIStore;
    shell: ShellState;
    columns: number;
  }): React.ReactElement | null {
    const { theme } = useLayoutContext();
    const { exit } = useApp();
    const [input, setInput] = useState("");
    const [cursor, setCursor] = useState(0);
    const [historyIndex, setHistoryIndex] = useState<number | null>(null);
    const draftInputRef = useRef("");
    const inputRef = useRef("");
    const cursorRef = useRef(0);
    const pendingReturnTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
    const pendingReturnArmedRef = useRef(false);
    const pendingReturnExpiresAtRef = useRef(0);
    const lastTextInputAtRef = useRef(0);
    // Length of the most recent text-input event. Single-char events are
    // keystrokes (or `tmux send-keys`, which delivers char-at-a-time over PTY);
    // multi-char events are pastes. The Enter-guard only fires for pastes,
    // so scripted automation (`tmux send-keys "/cmd" Enter`) is not swallowed.
    const lastTextInputLenRef = useRef(0);
    const onInputRef = useRef(shell.onInput);
    onInputRef.current = shell.onInput;

    const clearPendingReturnTimer = (): void => {
      if (pendingReturnTimerRef.current) {
        clearTimeout(pendingReturnTimerRef.current);
        pendingReturnTimerRef.current = null;
      }
    };

    const disarmPendingReturn = (): void => {
      clearPendingReturnTimer();
      pendingReturnArmedRef.current = false;
      pendingReturnExpiresAtRef.current = 0;
    };

    const updateCursor = (next: number): void => {
      const clamped = Math.max(0, Math.min(next, inputRef.current.length));
      cursorRef.current = clamped;
      setCursor(clamped);
    };

    const replaceInput = (next: string, nextCursor = next.length): void => {
      inputRef.current = next;
      setInput(next);
      const clamped = Math.max(0, Math.min(nextCursor, next.length));
      cursorRef.current = clamped;
      setCursor(clamped);
    };

    const clearInput = (): void => {
      disarmPendingReturn();
      replaceInput("", 0);
      setHistoryIndex(null);
      draftInputRef.current = "";
    };

    const submitBufferedInput = (): void => {
      const value = inputRef.current;
      if (value.length === 0) return;
      disarmPendingReturn();
      onInputRef.current?.(value);
      clearInput();
    };

    const scheduleBufferedSubmit = (): void => {
      clearPendingReturnTimer();
      pendingReturnTimerRef.current = setTimeout(() => {
        pendingReturnTimerRef.current = null;
        if (!pendingReturnArmedRef.current) return;
        if (Date.now() > pendingReturnExpiresAtRef.current) {
          disarmPendingReturn();
          return;
        }
        if (inputRef.current.length > 0) submitBufferedInput();
      }, 35);
    };

    const armBufferedSubmit = (): void => {
      pendingReturnArmedRef.current = true;
      pendingReturnExpiresAtRef.current = Date.now() + 500;
      scheduleBufferedSubmit();
    };

    useEffect(
      () => () => {
        if (pendingReturnTimerRef.current) {
          clearTimeout(pendingReturnTimerRef.current);
          pendingReturnTimerRef.current = null;
        }
      },
      [],
    );

    // Register the *base* row at the input-area level so per-view
    // components mounted earlier in the tree (FindingsView, ModuleHome,
    // etc.) can still take LIFO precedence via their own
    // `useRegisterKeybindings`. The base row is what the catalog and
    // generic landing surfaces show. Per-view rows mount earlier in the
    // CopilotShell tree (MemoShellViewPanel renders before
    // ShellInputArea), so their effects run first and our registration
    // here ends up *latest* in the LIFO stack — which would shadow the
    // view's row. To avoid that for views that register their own row,
    // we only register the base row when the shell is in a "no-view-row"
    // state: catalog, processing, plan-pending, or sast-tasks (which has
    // its own dedicated row above).
    const viewRegistersOwnRow =
      shell.shellView === "module" ||
      shell.shellView === "findings" ||
      shell.shellView === "finding" ||
      shell.shellView === "tune" ||
      shell.shellView === "options" ||
      shell.shellView === "threats" ||
      shell.shellView === "module-run" ||
      shell.shellView === "actor-detail" ||
      shell.shellView === "prompts-editor" ||
      shell.shellView === "context-build";
    const idleBindings = buildIdleKeybindsForView(shell.shellView);
    const activeBindings = shell.processing
      ? shell.shellView === "module-run" &&
        shell.moduleRun?.status === "running" &&
        shell.moduleRun.liveControl === "pause-resume"
        ? MODULE_RUN_LIVE_KEYBINDS
        : PROCESSING_KEYBINDS
      : shell.pendingPlan && input.length === 0
        ? PLAN_KEYBINDS
        : shell.shellView === "sast-tasks" && input.length === 0
          ? SAST_TASK_KEYBINDS
          : viewRegistersOwnRow
            ? null
            : idleBindings;
    useRegisterKeybindings(activeBindings);

    useInput(
      (char, key) => {
        const liveState = store.getState();
        const liveShell = liveState.shell;
        if (!liveShell) return;
        const bufferedInput = inputRef.current;

        // High-order keybind dispatch — a single pure reducer decides
        // whether this keystroke maps to an abort, an exit, a slash-command
        // dispatch, a cursor move, or a buffer clear. The fall-through
        // `type: "none"` path drops back to the local-edit handler below
        // (typing, backspace, Enter submit, Tab, history recall). Keeping
        // this logic in a pure function gives us a single table of truth
        // for the shell's keymap — see tests/copilot/keybinds.test.ts.
        const action = resolveKeybind({
          stroke: { char, key },
          input: bufferedInput,
          state: liveState,
          looseFindingCount: countLooseFindings(
            liveState.summary?.actionableFindings ?? [],
            liveState.summary?.exploitChains ?? [],
          ),
          sastTaskCount: SAST_TASK_CAPABILITIES.length,
          now: Date.now(),
        });

        // Disarm the two-stage Ctrl+C counter on anything that isn't the
        // arm/exit continuation. Done once here so every branch below sees
        // a consistent store.
        if (
          liveState.ctrlCArmedAt &&
          action.type !== "arm-exit" &&
          action.type !== "exit" &&
          action.type !== "abort-inflight"
        ) {
          store.update({ ctrlCArmedAt: undefined });
        }

        switch (action.type) {
          case "abort-inflight":
            liveShell.onAbort?.();
            return;
          case "arm-exit":
            store.update({ ctrlCArmedAt: action.at });
            return;
          case "exit":
            liveShell.onExit?.();
            exit();
            return;
          case "dispatch":
            liveShell.onInput?.(action.command);
            return;
          case "set-finding-cursor":
            store.update({ shell: { ...liveShell, findingCursor: action.cursor } });
            return;
          case "set-sast-task-cursor":
            store.update({ shell: { ...liveShell, sastTaskCursor: action.cursor } });
            return;
          case "set-kb-cursor":
            if (liveShell.kb) {
              store.update({
                shell: {
                  ...liveShell,
                  kb: { ...liveShell.kb, cursor: action.cursor },
                },
              });
            }
            return;
          case "toggle-story":
            store.update({ shell: { ...liveShell, shellView: action.nextView } });
            return;
          case "toggle-context-tail":
            if (liveShell.contextBuild) {
              store.update({
                shell: {
                  ...liveShell,
                  contextBuild: {
                    ...liveShell.contextBuild,
                    tailExpanded: !liveShell.contextBuild.tailExpanded,
                  },
                },
              });
            }
            return;
          case "clear-input":
            clearInput();
            return;
          case "none":
            break;
        }

        if (liveShell.processing) {
          return;
        }

        const currentInput = inputRef.current;
        const currentCursor = cursorRef.current;

        const isReturn = key.return || char === "\r" || char === "\n";
        if (isReturn) {
          // Decision lives in shouldSubmitOnReturn() so tests can lock the
          // behavior without driving Ink. Pastes (multi-char events within
          // a few ms) buffer; keystrokes and `tmux send-keys` (single-char
          // events) submit immediately even when followed by Enter within
          // microseconds.
          const submit = shouldSubmitOnReturn({
            bufferedInputLength: currentInput.length,
            msSinceLastTextInput: Date.now() - lastTextInputAtRef.current,
            lastTextInputCharLength: lastTextInputLenRef.current,
          });
          if (submit) submitBufferedInput();
          else armBufferedSubmit();
          return;
        }

        if (key.leftArrow) {
          updateCursor(currentCursor - 1);
          return;
        }

        if (key.rightArrow) {
          updateCursor(currentCursor + 1);
          return;
        }

        if (isCtrlChord(char, "a", key.ctrl)) {
          updateCursor(0);
          return;
        }

        if (isCtrlChord(char, "e", key.ctrl)) {
          updateCursor(currentInput.length);
          return;
        }

        // Ink 5 surfaces the physical Backspace key (\x7f) as `key.delete`,
        // not `key.backspace` — see text-edit-actions.ts. Merge both into a
        // single delete-left so backspace works at end-of-line.
        if (key.backspace || key.delete) {
          const edit = applyBackspace(currentInput, currentCursor);
          if (!edit) return;
          replaceInput(edit.value, edit.cursor);
          setHistoryIndex(null);
          return;
        }

        if (key.upArrow) {
          if (liveShell.commandHistory.length === 0) return;
          if (historyIndex === null) {
            draftInputRef.current = currentInput;
            const nextIndex = liveShell.commandHistory.length - 1;
            setHistoryIndex(nextIndex);
            const next = liveShell.commandHistory[nextIndex] ?? "";
            replaceInput(next);
            return;
          }
          const nextIndex = Math.max(0, historyIndex - 1);
          setHistoryIndex(nextIndex);
          const next = liveShell.commandHistory[nextIndex] ?? "";
          replaceInput(next);
          return;
        }

        if (key.downArrow) {
          if (historyIndex === null) return;
          const nextIndex = historyIndex + 1;
          if (nextIndex >= liveShell.commandHistory.length) {
            setHistoryIndex(null);
            replaceInput(draftInputRef.current);
            return;
          }
          setHistoryIndex(nextIndex);
          const next = liveShell.commandHistory[nextIndex] ?? "";
          replaceInput(next);
          return;
        }

        // Esc handling lives in `resolveKeybind` above — it dispatches `/no`
        // for pending plans, `clear-input` for non-empty buffers, and `/back`
        // for backable views. The catalog-empty-buffer Esc falls through to
        // `none` and is intentionally a no-op (mirrors q-on-catalog).

        if (key.tab && currentInput.trim().startsWith("/")) {
          const suggestion = firstShellSuggestion(currentInput);
          if (suggestion) {
            replaceInput(suggestion);
            setHistoryIndex(null);
          }
          return;
        }

        if (char === "?" && currentInput.length === 0) {
          liveShell.onInput?.("/help");
          return;
        }

        if (isCtrlChord(char, "u", key.ctrl)) {
          clearInput();
          return;
        }

        if (char && !key.ctrl && !key.meta && !key.tab) {
          if (historyIndex === null) draftInputRef.current = "";
          lastTextInputAtRef.current = Date.now();
          lastTextInputLenRef.current = char.length;
          replaceInput(
            currentInput.slice(0, currentCursor) + char + currentInput.slice(currentCursor),
            currentCursor + char.length,
          );
          if (pendingReturnArmedRef.current) {
            if (Date.now() <= pendingReturnExpiresAtRef.current) scheduleBufferedSubmit();
            else disarmPendingReturn();
          }
          setHistoryIndex(null);
        }
      },
      { isActive: process.stdin.isTTY === true },
    );

    if (shell.processing) return null;

    const inputLine = renderShellInputSegments({
      prompt: buildShellPrompt(shell.focusedModule),
      input,
      cursor,
      columns,
      cursorGlyph: theme.glyphs.textCursor,
    });
    const slashSuggestions = input.trim().startsWith("/") ? listShellSuggestions(input) : [];
    const renderedInputLine = `${tokens.accent(inputLine.prompt)}${inputLine.beforeCursor}${tokens.tertiary(inputLine.cursorText)}${inputLine.afterCursor}`;

    return (
      <Box flexDirection="column" marginTop={SPACING.sm} minHeight={2}>
        <Box width={Math.max(1, columns)}>
          <Text wrap="truncate-end">{renderedInputLine}</Text>
        </Box>
        {slashSuggestions.length > 0 ? (
          <Box flexDirection="column" paddingLeft={theme.spacing.md}>
            <Text>
              {tokens.tertiary("Suggestions  ")}
              {tokens.muted("(Tab: accept · Enter: submit as-typed)")}
            </Text>
            <Text>{tokens.tertiary(slashSuggestions.join("  ·  "))}</Text>
          </Box>
        ) : (
          <Box minHeight={1} />
        )}
      </Box>
    );
  },
  (prev, next) =>
    prev.store === next.store &&
    prev.columns === next.columns &&
    prev.shell.processing === next.shell.processing &&
    prev.shell.pendingPlan === next.shell.pendingPlan &&
    prev.shell.focusedModule === next.shell.focusedModule &&
    prev.shell.commandHistory === next.shell.commandHistory,
);

/**
 * Shell-mode mirror of `RunningView`'s `AdvisoryStack`. Renders the
 * rate-limit and cost-cap halt surfaces above the input area whenever
 * `state.throttle` / `state.costCapHalted` are set, regardless of which
 * `mode` is active. Without this, a triage tool fired from the shell
 * would silently throttle (CLAUDE.md says the rate-limit banner should
 * "auto-render" when throttle is set) or hit the cost cap with no
 * visible card.
 *
 * Order is rate-limit (one line) above cost-cap halt (multi-line card),
 * which mirrors `RunningView` so muscle memory carries between modes.
 */
function ShellAdvisoryStack({ store }: { store: UIStore }): React.ReactElement | null {
  const advisory = useUISelector(
    store,
    (s) => ({
      throttle: s.throttle,
      costCapHalted: s.costCapHalted,
      runningCostUsd: s.runningCostUsd ?? 0,
      budgetUsd: s.costCapBudgetUsd ?? s.configBanner?.budget,
    }),
    shallowEqual,
  );
  if (!advisory.throttle && !advisory.costCapHalted) return null;
  return (
    <Box flexDirection="column">
      <RateLimitBanner throttle={advisory.throttle} />
      {advisory.costCapHalted ? (
        <CostCapHalt runningCostUsd={advisory.runningCostUsd} budgetUsd={advisory.budgetUsd} />
      ) : null}
    </Box>
  );
}

const SHELL_LIVE_HISTORY_COUNT = 8;
const LIVE_ACTIVITY_MIN_ROWS = 8;
const LIVE_ACTIVITY_MAX_ROWS = 24;
const LIVE_ACTIVITY_RESERVED_ROWS = 12;

function liveActivityDisplayLimit(rows: number | undefined): number {
  const terminalRows = rows ?? 30;
  const available = terminalRows - LIVE_ACTIVITY_RESERVED_ROWS;
  return Math.min(
    LIVE_ACTIVITY_MAX_ROWS,
    Math.max(LIVE_ACTIVITY_MIN_ROWS, Number.isFinite(available) ? available : 12),
  );
}

type ShellStaticItem =
  | { key: string; kind: "splash"; workspace?: string | null; target?: string | null }
  | { key: string; kind: "banner"; shell: ShellState }
  | { key: string; kind: "history"; entry: ShellHistoryEntry };

function splitShellHistory(history: ReadonlyArray<ShellHistoryEntry>): {
  staticHistory: ReadonlyArray<ShellHistoryEntry>;
  liveHistory: ReadonlyArray<ShellHistoryEntry>;
} {
  // Running tool-call entries mutate in place (status flip, resultOutput
  // injection, liveActivities tail). They can't go into `<Static>` until
  // they reach a terminal status, so everything at-or-after the oldest
  // running tool-call stays in the live zone regardless of entry age.
  const firstRunningIdx = history.findIndex(
    (e) => e.type === "tool-call" && e.status === "running",
  );
  const defaultCutoff = Math.max(0, history.length - SHELL_LIVE_HISTORY_COUNT);
  const staticCutoff =
    firstRunningIdx >= 0 ? Math.min(firstRunningIdx, defaultCutoff) : defaultCutoff;
  return {
    staticHistory: history.slice(0, staticCutoff),
    liveHistory: history.slice(staticCutoff),
  };
}

function isStructuredViewNoise(entry: ShellHistoryEntry): boolean {
  if (entry.type === "input") return true;
  return entry.type === "output" && /^Focused on .+\. \d+ tools available\.$/.test(entry.text);
}

function findLastHistoryInputIndex(history: ReadonlyArray<ShellHistoryEntry>): number {
  for (let i = history.length - 1; i >= 0; i -= 1) {
    if (history[i]?.type === "input") return i;
  }
  return -1;
}

function ShellStaticItemView({ item }: { item: ShellStaticItem }): React.ReactElement {
  switch (item.kind) {
    case "splash":
      return <BannerSplash workspace={item.workspace} target={item.target} />;
    case "banner":
      // The "banner" Static item is now a no-op — its content (location +
      // workspace + target) is rendered by the live ScreenFrame chrome. We
      // keep the kind in the union so prior session state still type-checks.
      return <Box />;
    case "history":
      return <HistoryEntry entry={item.entry} />;
  }
}

const MemoShellLiveHistory = memo(
  function ShellLiveHistory({
    history,
    suppressRunningToolName,
    compactRunningToolCalls = false,
  }: {
    history: ReadonlyArray<ShellHistoryEntry>;
    suppressRunningToolName?: string;
    compactRunningToolCalls?: boolean;
  }): React.ReactElement {
    const visibleHistory = suppressRunningToolName
      ? history.filter(
          (entry) =>
            !(
              entry.type === "tool-call" &&
              entry.status === "running" &&
              entry.tool === suppressRunningToolName
            ),
        )
      : history;
    return (
      <Box flexDirection="column">
        {visibleHistory.map((entry) => (
          <HistoryEntry
            key={historyEntryKey(entry)}
            entry={entry}
            compactToolCall={
              compactRunningToolCalls && entry.type === "tool-call" && entry.status === "running"
            }
          />
        ))}
      </Box>
    );
  },
  (prev, next) =>
    prev.history === next.history &&
    prev.suppressRunningToolName === next.suppressRunningToolName &&
    prev.compactRunningToolCalls === next.compactRunningToolCalls,
);

function ShellTaskStatusLine({
  shell,
  columns,
}: {
  shell: ShellState;
  columns: number;
}): React.ReactElement | null {
  const story = shell.taskStory;
  const current = shell.currentTool;
  const elapsedMs = useElapsed(
    story?.startedAt ?? current?.startedAt,
    shell.processing ? 1000 : 5000,
  );
  if (!story && !current) return null;
  const abortStatus = current?.abortStatus ?? story?.abortStatus;
  const backgroundJobs = story?.backgroundJobs ?? [];
  const runningBackground = backgroundJobs.filter((job) => job.status === "running");
  const idleTerminalStory = !shell.processing && !current && runningBackground.length === 0;
  if (idleTerminalStory && shell.shellView !== "task-story") return null;
  const stateLabel =
    abortStatus === "aborting"
      ? "interrupting"
      : abortStatus === "aborted"
        ? "aborted"
        : runningBackground.length > 0 && !shell.processing
          ? "background"
          : shell.processing
            ? "running"
            : "done";
  const controls = shell.processing && columns >= 78 ? "Ctrl+C interrupt · Ctrl+O details" : "";
  const displayElapsedMs =
    !shell.processing && story?.endedAt && story.startedAt
      ? Math.max(0, story.endedAt - story.startedAt)
      : elapsedMs;
  const elapsed =
    displayElapsedMs > 0
      ? `${Math.floor(displayElapsedMs / 60000)
          .toString()
          .padStart(2, "0")}:${Math.floor((displayElapsedMs % 60000) / 1000)
          .toString()
          .padStart(2, "0")}`
      : "";
  const label = truncateEnd(
    shell.focusedModule ?? current?.displayName ?? current?.name ?? "task",
    columns < 72 ? 18 : 28,
  );
  const backgroundLabel =
    runningBackground.length > 0
      ? `${runningBackground.length} background ${runningBackground.length === 1 ? "job" : "jobs"}`
      : "";
  const heartbeat = formatShellHeartbeat(shell.llmHeartbeat, columns < 72);
  const line = truncateEnd(
    [label, stateLabel, elapsed, backgroundLabel, heartbeat, controls].filter(Boolean).join(" · "),
    Math.max(24, columns - SPACING.md * 2),
  );
  const renderLine =
    abortStatus === "aborting" || abortStatus === "aborted"
      ? tokens.warn(line)
      : tokens.muted(line);
  return (
    <Box marginTop={SPACING.xs} paddingLeft={SPACING.md}>
      <Text>{renderLine}</Text>
    </Box>
  );
}

function formatShellHeartbeat(
  heartbeat: ShellState["llmHeartbeat"] | undefined,
  narrow: boolean,
): string {
  if (!heartbeat || (heartbeat.activeCalls === 0 && heartbeat.completedCalls === 0)) return "";
  const calls =
    heartbeat.activeCalls > 0
      ? `${heartbeat.activeCalls} LLM`
      : `${heartbeat.completedCalls} LLM done`;
  if (narrow) return calls;
  const parts = [];
  if (heartbeat.latestModel) parts.push(heartbeat.latestModel);
  parts.push(calls);
  if (heartbeat.totalCostUsd > 0) parts.push(`$${heartbeat.totalCostUsd.toFixed(2)}`);
  return parts.join(" · ");
}

function describeShellLocation(shell: ShellState): string {
  if (shell.shellView === "module") return `${shell.focusedModule ?? "module"} home`;
  if (shell.shellView === "finding") return `finding ${shell.openFindingId ?? "detail"}`;
  if (shell.shellView === "task-story") return "task story";
  if (shell.shellView === "threats") return `threat/${shell.threatTab ?? "summary"}`;
  if (shell.shellView === "module-run") return `${shell.focusedModule ?? "module"} run`;
  if (shell.shellView === "actor-detail")
    return `${shell.focusedModule ?? "module"} actor ${shell.focusedActor ?? ""}`.trim();
  if (shell.shellView === "prompts-editor") return `${shell.focusedModule ?? "module"} prompts`;
  return shell.shellView;
}

function historyEntryKey(entry: ShellHistoryEntry): string {
  // Prefer explicit IDs for mutable tool-call rows, then fall back to
  // immutable fields that stay stable across shell re-renders.
  if (entry.id) return `id:${entry.id}`;
  return `${entry.type}:${entry.timestamp}:${entry.toolUseId ?? ""}:${entry.text}`;
}

/**
 * Dynamic panel that replaces itself based on `shell.shellView`. The catalog
 * still lives in the <Static> banner up top (rendered once per session) — this
 * panel is for the sub-surfaces (module home, findings, finding detail, tune)
 * that need to re-render as the operator navigates.
 *
 * Returns an empty box when the view is the catalog (already drawn above) so
 * the component is free to add/remove itself without flicker.
 */
function ShellViewPanel({
  summary,
  shell,
  agentActivity,
}: {
  summary: SummaryData | null;
  shell: ShellState;
  agentActivity?: ReadonlyMap<string, ReadonlyArray<AgentActivityLine>>;
}): React.ReactElement | null {
  // Stable React keys per view stop React from re-mounting sibling sub-trees
  // when the shellView changes. The `shellView` value is the key — same view
  // string, same DOM identity, fresh view string, fresh mount. Without keys,
  // React reconciles by position and reparents (re-running mount effects in
  // children that should have been preserved) when the view changes shape.
  const view = shell.shellView ?? "catalog";
  switch (shell.shellView) {
    case "catalog":
      return shell.moduleCatalog && shell.moduleCatalog.length > 0 ? (
        <ModuleCatalog key={view} shell={shell} />
      ) : null;
    case "module":
      return shell.focusedModule ? <ModuleHome key={view} shell={shell} /> : null;
    case "tune":
      return shell.focusedModule ? <TuneView key={view} shell={shell} /> : null;
    case "options":
      return shell.focusedModule ? <OptionsView key={view} shell={shell} /> : null;
    case "sast-tasks":
      return <SastTasksView key={view} shell={shell} />;
    case "findings": {
      const findings = summary?.actionableFindings ?? [];
      const chains = (summary?.exploitChains ?? []).map((c) => ({
        id: c.id,
        name: c.name,
        severity: c.overallSeverity,
        findingFingerprints: c.steps.map((s) => s.findingFingerprint),
      }));
      return (
        <FindingsView
          key={view}
          mode="unified"
          findings={findings}
          chains={chains}
          findingCursor={shell.findingCursor}
          pageSize={shell.findingPageSize}
          focusedModule={shell.focusedModule}
        />
      );
    }
    case "since":
      return <DiffSinceView key={view} summary={summary} shell={shell} />;
    case "finding": {
      const openId = shell.openFindingId;
      if (!openId || !summary) return null;
      // Resolve through the deterministic B.3 alias map so F-NNNN always
      // maps to the same finding for a given summary snapshot, and fall
      // back to fingerprint / prefix matching for raw input.
      const aliases = computeFindingAliases(summary.actionableFindings ?? []);
      const target = resolveAlias(
        openId,
        aliases,
        (summary.actionableFindings ?? []).map((f) => f.fingerprint),
      );
      const match = target
        ? summary.actionableFindings?.find((f) => f.fingerprint === target)
        : undefined;
      if (!match) return null;
      return <FindingCard key={`finding:${target}`} mode="linear" finding={match} />;
    }
    case "threats": {
      const threatKey = `${view}:${shell.threatTab ?? "summary"}`;
      switch (shell.threatTab ?? "summary") {
        case "dfd":
          return <ThreatDfdView key={threatKey} shell={shell} />;
        case "stride":
          return <ThreatStrideMatrix key={threatKey} shell={shell} />;
        case "stories":
          return <AttackerStoriesView key={threatKey} shell={shell} />;
        case "scope":
          return <ScopeAndCriticalityView key={threatKey} shell={shell} />;
        case "summary":
          return <ThreatSummaryExport key={threatKey} shell={shell} />;
      }
      return <ThreatSummaryExport key={threatKey} shell={shell} />;
    }
    case "context-build":
      return <ContextBuildView key={view} shell={shell} />;
    case "task-story":
      return <TaskStoryView key={view} story={shell.taskStory} processing={shell.processing} />;
    case "module-run":
      // `summary.actionableFindings` carries `actorFingerprint` once the
      // run completes; ModuleRunView/ActorTranscriptView filter by it.
      return (
        <ModuleRunView
          key={view}
          shell={shell}
          findings={summary?.actionableFindings ?? []}
          agentActivity={agentActivity}
        />
      );
    case "actor-detail":
      return (
        <ActorTranscriptView
          key={view}
          shell={shell}
          findings={summary?.actionableFindings ?? []}
          agentActivity={agentActivity}
        />
      );
    case "prompts-editor":
      return <PromptsEditorView key={view} shell={shell} />;
    case "kb":
      return <KbView key={view} shell={shell} />;
    default:
      return null;
  }
}

/**
 * Memoized wrapper around the dynamic view panel — so a running tool-spinner
 * doesn't redraw the (unrelated) findings/finding/tune view tree on every
 * heartbeat update.
 */
const MemoShellViewPanel = memo(
  ShellViewPanel,
  (prev, next) =>
    prev.shell.shellView === next.shell.shellView &&
    prev.shell.focusedModule === next.shell.focusedModule &&
    prev.shell.openFindingId === next.shell.openFindingId &&
    prev.shell.threatModel === next.shell.threatModel &&
    prev.shell.contextSnapshot === next.shell.contextSnapshot &&
    prev.shell.threatDfdSelection === next.shell.threatDfdSelection &&
    prev.shell.contextRegenPaletteOpen === next.shell.contextRegenPaletteOpen &&
    prev.shell.pendingThreatPatch === next.shell.pendingThreatPatch &&
    prev.shell.findingCursor === next.shell.findingCursor &&
    prev.shell.sastTaskCursor === next.shell.sastTaskCursor &&
    prev.shell.findingPageSize === next.shell.findingPageSize &&
    prev.shell.diffSince === next.shell.diffSince &&
    prev.shell.moduleCatalog === next.shell.moduleCatalog &&
    prev.shell.moduleOptions === next.shell.moduleOptions &&
    prev.shell.tuneSnapshot === next.shell.tuneSnapshot &&
    prev.shell.contextBuild === next.shell.contextBuild &&
    prev.shell.taskStory === next.shell.taskStory &&
    prev.shell.moduleRun === next.shell.moduleRun &&
    prev.shell.focusedActor === next.shell.focusedActor &&
    prev.shell.promptsEditor === next.shell.promptsEditor &&
    prev.shell.optionsView === next.shell.optionsView &&
    prev.agentActivity === next.agentActivity &&
    prev.summary === next.summary,
);

/**
 * Render a single history entry. Tool-call entries are the richest: they
 * own a `PulseDot` for the `⏺` glyph (pulsing while running, solid green /
 * red / dim on resolution), a bold display name, an `(args)` hint, and —
 * when the tool completes — a `⎿  <resultOutput>` summary line underneath.
 * While running, the entry also renders a tail of recent `liveActivities`
 * so operators can see what the tool is doing at a glance.
 */
function HistoryEntry({
  entry,
  compactToolCall = false,
}: {
  entry: ShellHistoryEntry;
  compactToolCall?: boolean;
}): React.ReactElement {
  switch (entry.type) {
    case "input":
      return (
        <Box marginTop={SPACING.sm}>
          <Text>
            {tokens.accent(entry.prompt ?? buildShellPrompt(null))}
            {entry.text}
          </Text>
        </Box>
      );
    case "output":
      return (
        <Box marginTop={SPACING.sm}>
          <Markdown text={entry.text} />
        </Box>
      );
    case "error":
      return (
        <Box marginTop={SPACING.sm}>
          <ErrorCard message={entry.text} error={entry.text} />
        </Box>
      );
    case "tool-call":
      return <ToolCallEntry entry={entry} compact={compactToolCall} />;
    case "hunt-post-mortem":
      return <HuntPostMortemEntry entry={entry} />;
    case "story":
      return entry.storyEvent ? (
        <StoryEventLine event={entry.storyEvent} />
      ) : (
        <Box paddingLeft={SPACING.md}>
          <Text>{tokens.muted(entry.text)}</Text>
        </Box>
      );
    case "tool-progress": {
      if (entry.storyEvent) {
        return <StoryEventLine event={entry.storyEvent} />;
      }
      const kind = entry.progressKind ?? "info";
      const wrap = (s: string): string => {
        if (kind === "ok") return tokens.success(s);
        if (kind === "fail") return tokens.danger(s);
        // Nested sub-agent tool headers (Read/Write/Glob/…) inherit base
        // text color — muted is reserved for free-form body-text pulses,
        // matching opencode's `∟` / Claude Code's `⎿` convention.
        if (kind === "invocation") return tokens.value(s);
        return tokens.muted(s);
      };
      return (
        <Box paddingLeft={SPACING.xs}>
          <Gutter>
            <Text>{tokens.tertiary(LOWER_HOOK)}</Text>
          </Gutter>
          <Text> {wrap(entry.text)}</Text>
        </Box>
      );
    }
  }
}

function TaskStoryView({
  story,
  processing,
}: {
  story: ShellTaskStoryState | undefined;
  processing: boolean;
}): React.ReactElement {
  const events = story?.events ?? [];
  const artifacts = storyTabEvents(events, "artifacts");
  const errors = storyTabEvents(events, "errors");
  const debug = storyTabEvents(events, "debug");
  const visibleLive = storyTabEvents(events, "live").slice(-16);
  const status = story?.abortStatus === "aborting" ? "aborting" : processing ? "live" : "latest";
  const backgroundJobs = story?.backgroundJobs ?? [];
  const runningBackground = backgroundJobs.filter((job) => job.status === "running");

  // Build a compact, comma-joined section summary so the header conveys
  // counts without forcing the four pseudo-tabs that previously rendered
  // every section regardless of content.
  const summaryParts: string[] = [];
  if (visibleLive.length > 0) summaryParts.push(`${visibleLive.length} live`);
  if (artifacts.length > 0)
    summaryParts.push(`${artifacts.length} artifact${artifacts.length === 1 ? "" : "s"}`);
  if (errors.length > 0)
    summaryParts.push(`${errors.length} error${errors.length === 1 ? "" : "s"}`);
  if (debug.length > 0) summaryParts.push(`${debug.length} debug`);

  return (
    <Box flexDirection="column" marginTop={SPACING.sm} paddingLeft={SPACING.md}>
      <Text>
        {tokens.strong("Task story")}
        {tokens.muted(` · ${status}`)}
        {story?.activeRunIds.length
          ? tokens.muted(` · ${story.activeRunIds.length} run id(s)`)
          : null}
        {runningBackground.length > 0
          ? tokens.muted(` · ${runningBackground.length} background`)
          : null}
        {summaryParts.length > 0 ? tokens.muted(` · ${summaryParts.join(" · ")}`) : null}
      </Text>
      {backgroundJobs.length > 0 ? <BackgroundJobSection jobs={backgroundJobs} /> : null}
      {visibleLive.length > 0 ? <StorySection title="Live" events={visibleLive} empty="" /> : null}
      {errors.length > 0 ? <StorySection title="Errors" events={errors} empty="" /> : null}
      {artifacts.length > 0 ? <StorySection title="Artifacts" events={artifacts} empty="" /> : null}
      {debug.length > 0 ? (
        <Box marginTop={SPACING.xs}>
          <Text>
            {tokens.muted(
              `Debug · ${debug.length} entr${debug.length === 1 ? "y" : "ies"} (raw tool calls — see scrollback above)`,
            )}
          </Text>
        </Box>
      ) : null}
      {summaryParts.length === 0 && backgroundJobs.length === 0 ? (
        <Box marginTop={SPACING.xs}>
          <Text>{tokens.tertiary("No story beats yet.")}</Text>
        </Box>
      ) : null}
    </Box>
  );
}

function BackgroundJobSection({
  jobs,
}: {
  jobs: NonNullable<ShellTaskStoryState["backgroundJobs"]>;
}): React.ReactElement {
  return (
    <Box flexDirection="column" marginTop={SPACING.xs}>
      <Text>{tokens.muted("Background")}</Text>
      {jobs.slice(0, 6).map((job) => (
        <Text key={job.id}>
          {tokens.tertiary(LOWER_HOOK)} {tokens.value(`job ${job.id}`)}
          {tokens.muted(` · ${job.status} · ${job.label}`)}
        </Text>
      ))}
    </Box>
  );
}

function StorySection({
  title,
  events,
  empty,
}: {
  title: string;
  events: ShellStoryEvent[];
  empty: string;
}): React.ReactElement {
  return (
    <Box flexDirection="column" marginTop={SPACING.xs}>
      <Text>{tokens.muted(title)}</Text>
      {events.length === 0 ? (
        <Text>{tokens.tertiary(empty)}</Text>
      ) : (
        events.map((event) => <StoryEventLine key={event.id} event={event} compact />)
      )}
    </Box>
  );
}

function StoryEventLine({
  event,
  compact = false,
}: {
  event: ShellStoryEvent;
  compact?: boolean;
}): React.ReactElement {
  const status = storyStatusLabel(event.status);
  const prefix = `${storyKindLabel(event.kind)}:${status}`;
  const color = (value: string): string => {
    if (event.status === "fail") return tokens.danger(value);
    if (event.status === "aborted" || event.status === "aborting") return tokens.warn(value);
    if (event.status === "ok") return tokens.success(value);
    if (event.importance === "debug") return tokens.tertiary(value);
    return tokens.value(value);
  };
  const details = [
    event.detail,
    event.artifactPath,
    event.count != null ? `${event.count}` : undefined,
    event.costUsd != null && event.costUsd > 0 ? `$${event.costUsd.toFixed(2)}` : undefined,
  ].filter(Boolean);

  return (
    <Box paddingLeft={compact ? SPACING.sm : SPACING.xs}>
      <Text>
        {tokens.tertiary(LOWER_HOOK)} {color(prefix)}
        {tokens.muted(" · ")}
        {event.message}
        {details.length > 0 ? tokens.muted(` · ${details.join(" · ")}`) : null}
      </Text>
    </Box>
  );
}

/**
 * Header + optional result line for a tool-call entry. Ratchet wraps the
 * whole block so that when `resultOutput` arrives (and replaces shorter
 * `liveActivities`) the total height never shrinks — no flicker during
 * the transition.
 */
function ToolCallEntry({
  entry,
  compact = false,
}: {
  entry: ShellHistoryEntry;
  compact?: boolean;
}): React.ReactElement {
  const { stdout } = useStdout();
  const status = entry.status;
  const aborting = entry.abortStatus === "aborting";
  const dotStatus = aborting && status === "running" ? "warn" : status;
  const label = entry.displayName ?? entry.tool ?? entry.text.replace(/^[⏺●]\s*/, "");
  const elapsedSuffix =
    status && status !== "running" && entry.elapsedSeconds && entry.elapsedSeconds > 0
      ? tokens.muted(` · ${entry.elapsedSeconds}s`)
      : "";
  const ts = tokens.muted(` ${formatClock(entry.timestamp)}`);

  // Result line — per-tool renderResult output (or generic verb) shown
  // under the `⏺` when the tool resolves. Muted when ok, danger on
  // failure, dim-muted on abort.
  const hasResult = status && status !== "running" && entry.resultOutput;
  const resultColor = (text: string): string => {
    if (status === "ok") return tokens.success(text);
    if (status === "fail") return tokens.danger(text);
    return tokens.muted(text);
  };
  const outcomeGlyph =
    status === "ok"
      ? OUTCOME_GLYPH.ok
      : status === "fail"
        ? OUTCOME_GLYPH.fail
        : status === "abort"
          ? OUTCOME_GLYPH.abort
          : "";
  const liveLimit = liveActivityDisplayLimit(stdout?.rows);
  const liveActivities = entry.liveActivities ?? [];
  const visibleLiveActivities = liveActivities.slice(0, liveLimit).slice().reverse();
  const hiddenLiveActivityCount =
    (entry.liveActivitiesDropped ?? 0) +
    Math.max(0, liveActivities.length - visibleLiveActivities.length);

  // In task-story view, the panel below is the canonical activity surface;
  // collapse the per-tool tail to one pointer line so the same updates
  // don't render twice. Off task-story, the tail is the only progress
  // indicator and we render it in full.
  const showActivityTail = !compact && status === "running" && liveActivities.length > 0;
  const showCompactPointer = compact && status === "running" && liveActivities.length > 0;

  return (
    <Ratchet>
      <Box marginTop={SPACING.sm}>
        <Gutter>
          {dotStatus ? <PulseDot status={dotStatus} /> : <Text>{tokens.accent(BLACK_CIRCLE)}</Text>}
        </Gutter>
        <Text>
          {tokens.label(label)}
          {entry.inputHint ? tokens.muted(`(${entry.inputHint})`) : ""}
          {aborting ? tokens.warn(" · interrupting") : ""}
          {elapsedSuffix}
          {ts}
        </Text>
      </Box>
      {showCompactPointer ? (
        <Box>
          <Gutter />
          <Gutter>
            <Text>{tokens.tertiary(LOWER_HOOK)}</Text>
          </Gutter>
          <Text>
            {" "}
            {tokens.tertiary(
              `${liveActivities.length + (entry.liveActivitiesDropped ?? 0)} update${
                liveActivities.length + (entry.liveActivitiesDropped ?? 0) === 1 ? "" : "s"
              } · see Task story below`,
            )}
          </Text>
        </Box>
      ) : null}
      {showActivityTail ? (
        <Box flexDirection="column">
          {hiddenLiveActivityCount > 0 ? (
            <Box>
              <Gutter />
              <Gutter>
                <Text>{tokens.tertiary(LOWER_HOOK)}</Text>
              </Gutter>
              <Text>
                {" "}
                {tokens.tertiary(
                  `+${hiddenLiveActivityCount} earlier update${hiddenLiveActivityCount === 1 ? "" : "s"} · Ctrl+O details`,
                )}
              </Text>
            </Box>
          ) : null}
          {visibleLiveActivities.map((activity) => (
            <Box key={activity.id}>
              <Gutter />
              <Gutter>
                <Text>{tokens.tertiary(LOWER_HOOK)}</Text>
              </Gutter>
              <Text> {tokens.muted(truncateEnd(activity.text, 104))}</Text>
            </Box>
          ))}
        </Box>
      ) : null}
      {hasResult ? (
        <Box>
          <Gutter />
          <Gutter>
            <Text>{tokens.tertiary(LOWER_HOOK)}</Text>
          </Gutter>
          <Text>
            {" "}
            {outcomeGlyph ? `${resultColor(outcomeGlyph)} ` : ""}
            {resultColor(entry.resultOutput!)}
          </Text>
        </Box>
      ) : null}
    </Ratchet>
  );
}

/**
 * Collapsed scrollback block summarising a completed hunt run. Shows
 * `N actors · M findings · $X.XX` as the headline with per-actor
 * breakdown hidden behind `space to expand`. Replaces the ephemeral
 * HeartbeatStrip per-agent list which only renders during the `running`
 * phase — without this entry, operators lose the per-actor audit trail
 * the instant the tool returns.
 */
function HuntPostMortemEntry({ entry }: { entry: ShellHistoryEntry }): React.ReactElement {
  const summary = entry.huntSummary;
  if (!summary) {
    return (
      <Box marginTop={SPACING.sm} paddingLeft={SPACING.md}>
        <Text>{tokens.muted(entry.text)}</Text>
      </Box>
    );
  }

  const headline = (
    <Text>
      {tokens.strong(`${summary.actorCount} actor${summary.actorCount === 1 ? "" : "s"}`)}
      {tokens.muted(
        `  ·  ${summary.findingsCount} finding${summary.findingsCount === 1 ? "" : "s"}  ·  $${summary.costUsd.toFixed(2)}`,
      )}
    </Text>
  );

  return (
    <Box marginTop={SPACING.sm} paddingLeft={SPACING.md} flexDirection="column">
      <ExpandableSection summary={headline} hint="(press space for per-actor breakdown)">
        {summary.perActor.map((actor) => (
          <HuntActorRow key={actor.fingerprint} actor={actor} />
        ))}
      </ExpandableSection>
    </Box>
  );
}

function HuntActorRow({ actor }: { actor: HuntActorSnapshot }): React.ReactElement {
  const lastLine = actor.lines[actor.lines.length - 1];
  const label = extractActorLabel(actor.fingerprint);
  const detail = lastLine ? formatLastLine(lastLine) : "(no activity)";
  return (
    <Text>
      {tokens.muted("•")} {tokens.value(label)}
      {tokens.muted("  ·  ")}
      {tokens.muted(detail)}
    </Text>
  );
}

/**
 * Pull the human-readable actor slug out of a carlini-threat-hunt fingerprint.
 * `buildActorFingerprint` in `src/modules/carlini-threat-hunt/carlini-threat-hunt.ts`
 * builds `carlini-threat-hunt:<Actor_Name>:<runIndex>`; we show
 * `Actor Name` (runIndex 0 suppressed) or `Actor Name (run N)`.
 */
function extractActorLabel(fingerprint: string): string {
  const parts = fingerprint.split(":");
  if (parts.length < 3) return fingerprint;
  const actorSlug = parts[parts.length - 2]!.replace(/_/g, " ");
  const runIndex = parts[parts.length - 1]!;
  return runIndex === "0" ? actorSlug : `${actorSlug} (run ${runIndex})`;
}

function formatLastLine(line: AgentActivityLine): string {
  const prefix =
    line.kind === "tool-complete"
      ? "✓"
      : line.kind === "tool-start"
        ? "→"
        : line.kind === "tool-progress"
          ? "…"
          : line.kind === "reasoning"
            ? "•"
            : line.kind === "finding-preview"
              ? "!"
              : "·";
  const detail = line.detail ?? line.toolName ?? line.kind;
  return `${prefix} ${truncateEnd(detail, 80)}`;
}
