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
import type React from "react";
import { memo, useRef, useState } from "react";
import { computeFindingAliases, resolveAlias } from "../../copilot/finding-alias.js";
import {
  buildShellPrompt,
  firstShellSuggestion,
  listShellSuggestions,
} from "../../copilot/shell.js";
import { formatClock, truncateEnd } from "../format.js";
import { BLACK_CIRCLE, LOWER_HOOK, OUTCOME_GLYPH } from "../glyphs.js";
import { applyBackspace, isCtrlChord } from "../hooks/text-edit-actions.js";
import { useRegisterKeybindings } from "../hooks/useKeybindings.js";
import { shallowEqual, useUISelector } from "../hooks.js";
import { useLayoutContext } from "../layout-context.js";
import { Gutter } from "../primitives/Gutter.js";
import { Markdown } from "../primitives/Markdown.js";
import { Ratchet } from "../primitives/Ratchet.js";
import {
  CTRL_C_ARM_WINDOW_MS as CTRL_C_ARM_WINDOW_MS_IMPORTED,
  resolveKeybind,
} from "../shell-keybinds.js";
import type {
  ActionableFinding,
  ShellHistoryEntry,
  ShellState,
  SummaryData,
  UIStore,
} from "../state.js";
import { SPACING, tokens } from "../tokens.js";
import { AttackerStoriesView } from "./AttackerStoriesView.js";
import { BannerSplash } from "./BannerSplash.js";
import { DiffSinceView } from "./DiffSinceView.js";
import { ErrorMessage } from "./ErrorMessage.js";
import { FindingCard } from "./FindingCard.js";
import { FindingsView } from "./FindingsView.js";
import { ModuleCatalog } from "./ModuleCatalog.js";
import { ModuleHome } from "./ModuleHome.js";
import { PlanCard } from "./PlanCard.js";
import { PulseDot } from "./PulseDot.js";
import { ScopeAndCriticalityView } from "./ScopeAndCriticalityView.js";
import { Spinner } from "./Spinner.js";
import { ThreatDfdView } from "./ThreatDfdView.js";
import { ThreatStrideMatrix } from "./ThreatStrideMatrix.js";
import { ThreatSummaryExport } from "./ThreatSummaryExport.js";
import { ToolRunningStatus } from "./ToolRunningStatus.js";
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

const PROCESSING_KEYBINDS = [{ keys: "Ctrl+C", label: "Abort" }];
const PLAN_KEYBINDS = [
  { keys: "Y", label: "Apply plan" },
  { keys: "N/Esc", label: "Discard plan" },
  { keys: "Ctrl+C", label: "Exit", secondary: true },
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
      ctrlCArmedAt: s.ctrlCArmedAt,
    }),
    shallowEqual,
  );
  const shell = shellState.shell;
  const { exit } = useApp();
  const [input, setInput] = useState("");
  const [cursor, setCursor] = useState(0);
  const { stdout } = useStdout();
  const columns = stdout?.columns ?? 120;
  const [historyIndex, setHistoryIndex] = useState<number | null>(null);
  const draftInputRef = useRef("");
  const pendingAssistantStartedAtRef = useRef<number>(Date.now());

  const processing = shell?.processing === true;

  useRegisterKeybindings(
    processing
      ? PROCESSING_KEYBINDS
      : shell?.pendingPlan && input.length === 0
        ? PLAN_KEYBINDS
        : IDLE_KEYBINDS,
  );

  // Raw-mode watchdog now lives on `AppInner` via `useRawModeWatchdog` so it
  // survives `mode` flips ("shell" ↔ "running" ↔ "summary"). Previously the
  // watchdog was scoped here; when a tool dispatch caused the report-worker
  // to flip `mode` to "running", `CopilotShell` unmounted, the watchdog
  // unmounted with it, and the Claude Agent SDK subprocess could drop raw
  // mode for the rest of the run with nobody watching.

  useInput(
    (char, key) => {
      const liveState = store.getState();
      const liveShell = liveState.shell;
      if (!liveShell) return;

      // High-order keybind dispatch — a single pure reducer decides
      // whether this keystroke maps to an abort, an exit, a slash-command
      // dispatch, a cursor move, or a buffer clear. The fall-through
      // `type: "none"` path drops back to the local-edit handler below
      // (typing, backspace, Enter submit, Tab, history recall). Keeping
      // this logic in a pure function gives us a single table of truth
      // for the shell's keymap — see tests/copilot/keybinds.test.ts.
      const action = resolveKeybind({
        stroke: { char, key },
        input,
        state: liveState,
        looseFindingCount: countLooseFindings(
          liveState.summary?.actionableFindings ?? [],
          liveState.summary?.exploitChains ?? [],
        ),
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
        case "clear-input":
          setInput("");
          setCursor(0);
          setHistoryIndex(null);
          draftInputRef.current = "";
          return;
        case "none":
          break;
      }

      if (liveShell.processing) {
        return;
      }

      if (key.return && input.length > 0) {
        liveShell.onInput?.(input);
        setInput("");
        setCursor(0);
        setHistoryIndex(null);
        draftInputRef.current = "";
        return;
      }

      if (key.leftArrow) {
        setCursor((c) => Math.max(0, c - 1));
        return;
      }

      if (key.rightArrow) {
        setCursor((c) => Math.min(input.length, c + 1));
        return;
      }

      if (isCtrlChord(char, "a", key.ctrl)) {
        setCursor(0);
        return;
      }

      if (isCtrlChord(char, "e", key.ctrl)) {
        setCursor(input.length);
        return;
      }

      // Ink 5 surfaces the physical Backspace key (\x7f) as `key.delete`,
      // not `key.backspace` — see text-edit-actions.ts. Merge both into a
      // single delete-left so backspace works at end-of-line.
      if (key.backspace || key.delete) {
        const edit = applyBackspace(input, cursor);
        if (!edit) return;
        setInput(edit.value);
        setCursor(edit.cursor);
        setHistoryIndex(null);
        return;
      }

      if (key.upArrow) {
        if (liveShell.commandHistory.length === 0) return;
        if (historyIndex === null) {
          draftInputRef.current = input;
          const nextIndex = liveShell.commandHistory.length - 1;
          setHistoryIndex(nextIndex);
          const next = liveShell.commandHistory[nextIndex] ?? "";
          setInput(next);
          setCursor(next.length);
          return;
        }
        const nextIndex = Math.max(0, historyIndex - 1);
        setHistoryIndex(nextIndex);
        const next = liveShell.commandHistory[nextIndex] ?? "";
        setInput(next);
        setCursor(next.length);
        return;
      }

      if (key.downArrow) {
        if (historyIndex === null) return;
        const nextIndex = historyIndex + 1;
        if (nextIndex >= liveShell.commandHistory.length) {
          setHistoryIndex(null);
          setInput(draftInputRef.current);
          setCursor(draftInputRef.current.length);
          return;
        }
        setHistoryIndex(nextIndex);
        const next = liveShell.commandHistory[nextIndex] ?? "";
        setInput(next);
        setCursor(next.length);
        return;
      }

      // Esc handling lives in `resolveKeybind` above — it dispatches `/no`
      // for pending plans, `clear-input` for non-empty buffers, and `/back`
      // for backable views. The catalog-empty-buffer Esc falls through to
      // `none` and is intentionally a no-op (mirrors q-on-catalog).

      if (key.tab && input.trim().startsWith("/")) {
        const suggestion = firstShellSuggestion(input);
        if (suggestion) {
          setInput(suggestion);
          setCursor(suggestion.length);
          setHistoryIndex(null);
        }
        return;
      }

      if (char === "?" && input.length === 0) {
        liveShell.onInput?.("/help");
        return;
      }

      if (isCtrlChord(char, "u", key.ctrl)) {
        setInput("");
        setCursor(0);
        setHistoryIndex(null);
        draftInputRef.current = "";
        return;
      }

      if (char && !key.ctrl && !key.meta && !key.tab) {
        if (historyIndex === null) draftInputRef.current = "";
        setInput((v) => v.slice(0, cursor) + char + v.slice(cursor));
        setCursor((c) => c + char.length);
        setHistoryIndex(null);
      }
    },
    { isActive: process.stdin.isTTY === true && !!shell },
  );

  if (!shell) return <Text>Loading...</Text>;

  if (shell.pendingAssistantText) {
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
  const showCatalog = shell.moduleCatalog && shell.moduleCatalog.length > 0;

  const slashSuggestions = input.trim().startsWith("/") ? listShellSuggestions(input) : [];

  return (
    <Box flexDirection="column">
      {/* Phase D.2 banner splash — one-shot ASCII wordmark + tip. Inside
          a <Static> so it stays at the top and doesn't re-render during
          normal shell churn. */}
      <Static items={["kz-splash"]}>
        {() => <BannerSplash key="kz-splash" workspace={shell.workspace} target={shell.target} />}
      </Static>

      {showCatalog ? (
        <MemoShellBanner shell={shell} />
      ) : (
        <Static items={["shell-banner"]}>
          {() => <MemoShellBanner key="shell-banner" shell={shell} />}
        </Static>
      )}

      <MemoShellHistory history={shell.history} />

      {!shell.processing && shell.history.length > 0 ? (
        <Box marginTop={SPACING.sm} paddingLeft={SPACING.md}>
          <Text>{tokens.tertiary("interactive")}</Text>
        </Box>
      ) : null}

      <MemoShellViewPanel summary={shellState.summary} shell={shell} />
      <ShellWayfinding shell={shell} narrow={columns < 110} />

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

      {shell.pendingAssistantText && (
        <HistoryEntry
          entry={{
            type: "output",
            text: shell.pendingAssistantText,
            timestamp: pendingAssistantStartedAtRef.current || Date.now(),
          }}
        />
      )}

      {shell.processing && shell.currentTool && (
        <Box flexDirection="column">
          <ToolRunningStatus tool={shell.currentTool} />
          {shell.llmHeartbeat && <LlmHeartbeatLine heartbeat={shell.llmHeartbeat} />}
        </Box>
      )}

      {shell.processing && !shell.currentTool && (
        <Box flexDirection="column" marginTop={theme.spacing.sm} paddingLeft={theme.spacing.md}>
          <Box>
            <Spinner />
            <Text>
              {"  "}
              {tokens.muted("running...")}
            </Text>
          </Box>
          {shell.llmHeartbeat && <LlmHeartbeatLine heartbeat={shell.llmHeartbeat} />}
        </Box>
      )}

      {shellState.ctrlCArmedAt && Date.now() - shellState.ctrlCArmedAt < CTRL_C_ARM_WINDOW_MS ? (
        <Box marginTop={theme.spacing.sm} paddingLeft={theme.spacing.md}>
          <Text>{tokens.warn("press Ctrl+C again to exit")}</Text>
        </Box>
      ) : null}

      {!shell.processing && (
        <>
          <Box marginTop={SPACING.sm}>
            <Text>
              {tokens.accent(buildShellPrompt(shell.focusedModule))}
              {input.slice(0, cursor)}
              {tokens.tertiary(cursor < input.length ? input[cursor] : theme.glyphs.textCursor)}
              {cursor < input.length ? input.slice(cursor + 1) : ""}
            </Text>
          </Box>
          {slashSuggestions.length > 0 && (
            <Box flexDirection="column" paddingLeft={theme.spacing.md}>
              <Text>{tokens.tertiary("Suggestions")}</Text>
              <Text>{tokens.tertiary(slashSuggestions.join("  ·  "))}</Text>
            </Box>
          )}
        </>
      )}
    </Box>
  );
}

const MemoShellHistory = memo(
  function ShellHistory({
    history,
  }: {
    history: ReadonlyArray<ShellHistoryEntry>;
  }): React.ReactElement {
    const LIVE_COUNT = 8;
    // Running tool-call entries mutate in place (status flip, resultOutput
    // injection, liveActivities tail). They can't go into `<Static>` until
    // they reach a terminal status, so everything at-or-after the oldest
    // running tool-call stays in the live zone regardless of entry age.
    const firstRunningIdx = history.findIndex(
      (e) => e.type === "tool-call" && e.status === "running",
    );
    const defaultCutoff = Math.max(0, history.length - LIVE_COUNT);
    const staticCutoff =
      firstRunningIdx >= 0 ? Math.min(firstRunningIdx, defaultCutoff) : defaultCutoff;
    const staticHistory = history.slice(0, staticCutoff);
    const liveHistory = history.slice(staticCutoff);

    return (
      <>
        <Static items={staticHistory}>
          {(item) => (
            <HistoryEntry
              key={historyEntryKey(item as ShellHistoryEntry)}
              entry={item as ShellHistoryEntry}
            />
          )}
        </Static>
        <Box flexDirection="column">
          {liveHistory.map((entry) => (
            <HistoryEntry key={historyEntryKey(entry)} entry={entry} />
          ))}
        </Box>
      </>
    );
  },
  (prev, next) => prev.history === next.history,
);

function ShellWayfinding({
  shell,
  narrow,
}: {
  shell: ShellState;
  narrow: boolean;
}): React.ReactElement {
  const location = describeShellLocation(shell);
  const backHint =
    shell.shellView === "catalog"
      ? "top-level"
      : shell.shellView === "finding"
        ? "/back → findings"
        : shell.shellView === "module"
          ? "/back → catalog"
          : "/back → module";
  return (
    <Box marginTop={SPACING.sm} paddingLeft={SPACING.md}>
      <Text>
        {tokens.muted("you are in ")}
        {tokens.strong(location)}
        {tokens.muted(" · mode ")}
        {tokens.value(shell.processing ? "running" : "idle")}
        {!narrow ? tokens.muted(` · ${backHint}`) : null}
      </Text>
    </Box>
  );
}

function describeShellLocation(shell: ShellState): string {
  if (shell.shellView === "module") return `${shell.focusedModule ?? "module"} home`;
  if (shell.shellView === "finding") return `finding ${shell.openFindingId ?? "detail"}`;
  if (shell.shellView.startsWith("threat-")) return shell.shellView.replace("threat-", "threat/");
  return shell.shellView;
}

function historyEntryKey(entry: ShellHistoryEntry): string {
  // Prefer explicit IDs for mutable tool-call rows, then fall back to
  // immutable fields that stay stable across shell re-renders.
  if (entry.id) return `id:${entry.id}`;
  return `${entry.type}:${entry.timestamp}:${entry.toolUseId ?? ""}:${entry.text}`;
}

/**
 * One-line LLM heartbeat shown under the tool spinner. Reads the rolling
 * `shell.llmHeartbeat` state (populated via `llm:call-start/complete/error`
 * bus subscriptions in shell.ts) so operators can tell a slow LLM call from
 * a hang without dropping into `--verbose`.
 */
function LlmHeartbeatLine({
  heartbeat,
}: {
  heartbeat: NonNullable<ShellState["llmHeartbeat"]>;
}): React.ReactElement | null {
  const { activeCalls, completedCalls, latestModel, totalCostUsd } = heartbeat;
  if (activeCalls === 0 && completedCalls === 0) return null;
  const parts: string[] = [];
  if (latestModel) parts.push(latestModel);
  const calls =
    activeCalls > 0
      ? `${activeCalls} call${activeCalls === 1 ? "" : "s"} in flight`
      : `${completedCalls} call${completedCalls === 1 ? "" : "s"}`;
  parts.push(calls);
  if (totalCostUsd > 0) parts.push(`$${totalCostUsd.toFixed(2)}`);
  return (
    <Box paddingLeft={SPACING.lg}>
      <Text>{tokens.muted(`· ${parts.join(" · ")}`)}</Text>
    </Box>
  );
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
}: {
  summary: SummaryData | null;
  shell: ShellState;
}): React.ReactElement | null {
  // Stable React keys per view stop React from re-mounting sibling sub-trees
  // when the shellView changes. The `shellView` value is the key — same view
  // string, same DOM identity, fresh view string, fresh mount. Without keys,
  // React reconciles by position and reparents (re-running mount effects in
  // children that should have been preserved) when the view changes shape.
  const view = shell.shellView ?? "catalog";
  switch (shell.shellView) {
    case "module":
      return shell.focusedModule ? <ModuleHome key={view} shell={shell} /> : null;
    case "tune":
      return shell.focusedModule ? <TuneView key={view} shell={shell} /> : null;
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
        />
      );
    }
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
    // Phase C — threat model views. C.4–C.5 still route through the
    // placeholder until their real components land.
    case "threat-dfd":
      return <ThreatDfdView key={view} shell={shell} />;
    case "threat-stride":
      return <ThreatStrideMatrix key={view} shell={shell} />;
    case "threat-stories":
      return <AttackerStoriesView key={view} shell={shell} />;
    case "threat-scope":
      return <ScopeAndCriticalityView key={view} shell={shell} />;
    case "threat-summary":
      return <ThreatSummaryExport key={view} shell={shell} />;
    case "diff-since":
      return <DiffSinceView key={view} summary={summary} shell={shell} />;
    default:
      return null;
  }
}

/**
 * Memoized wrapper around ShellBanner — re-renders only when a field it
 * actually reads changes. Without this, every `store.update(...)` (LLM
 * heartbeat tick, phase-progress event, currentTool change) forces
 * ModuleCatalog to redraw its whole table, which caused visible flicker
 * on long-running tool runs.
 */
const MemoShellBanner = memo(
  ShellBannerImpl,
  (prev, next) =>
    prev.shell.moduleCatalog === next.shell.moduleCatalog &&
    prev.shell.modules === next.shell.modules &&
    prev.shell.tools === next.shell.tools &&
    prev.shell.target === next.shell.target &&
    prev.shell.workspace === next.shell.workspace,
);

/**
 * Same idea as `MemoShellBanner`, applied to the sub-view panel — so a
 * running tool-spinner doesn't redraw the (unrelated) findings/finding/tune
 * view tree on every heartbeat update.
 */
const MemoShellViewPanel = memo(
  ShellViewPanel,
  (prev, next) =>
    prev.shell.shellView === next.shell.shellView &&
    prev.shell.focusedModule === next.shell.focusedModule &&
    prev.shell.openFindingId === next.shell.openFindingId &&
    prev.shell.threatModel === next.shell.threatModel &&
    prev.shell.findingCursor === next.shell.findingCursor &&
    prev.shell.findingPageSize === next.shell.findingPageSize &&
    prev.summary === next.summary,
);

function ShellBannerImpl({ shell }: { shell: ShellState }): React.ReactElement {
  // Prefer the v2 catalog view whenever we have module data; fall back to the
  // legacy flat header only if `moduleCatalog` hasn't been populated yet
  // (e.g. during an early boot tick before `startInkShell` finishes init).
  if (shell.moduleCatalog && shell.moduleCatalog.length > 0) {
    return <ModuleCatalog shell={shell} />;
  }
  return (
    <Box flexDirection="column" marginBottom={SPACING.sm} paddingLeft={SPACING.md}>
      <Text>{""}</Text>
      <Text>{tokens.label("Kuzushi")}</Text>
      <Text>{tokens.muted("security-native AI operating environment")}</Text>
      <Text>{""}</Text>
      <Text>{`Modules:   ${shell.modules.join(", ") || "none"}`}</Text>
      <Text>{`Tools:     ${shell.tools.length} available`}</Text>
      {shell.target && <Text>{`Target:    ${shell.target}`}</Text>}
      {shell.workspace && <Text>{`Workspace: ${shell.workspace}`}</Text>}
      <Text>{""}</Text>
      <Text>{tokens.muted('Type "/help" for commands, or just describe what you need.')}</Text>
    </Box>
  );
}

/**
 * Render a single history entry. Tool-call entries are the richest: they
 * own a `PulseDot` for the `⏺` glyph (pulsing while running, solid green /
 * red / dim on resolution), a bold display name, an `(args)` hint, and —
 * when the tool completes — a `⎿  <resultOutput>` summary line underneath.
 * While running, the entry also renders a tail of recent `liveActivities`
 * so operators can see what the tool is doing at a glance.
 */
function HistoryEntry({ entry }: { entry: ShellHistoryEntry }): React.ReactElement {
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
          <ErrorMessage text={entry.text} />
        </Box>
      );
    case "tool-call":
      return <ToolCallEntry entry={entry} />;
    case "tool-progress": {
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

/**
 * Header + optional result line for a tool-call entry. Ratchet wraps the
 * whole block so that when `resultOutput` arrives (and replaces shorter
 * `liveActivities`) the total height never shrinks — no flicker during
 * the transition.
 */
function ToolCallEntry({ entry }: { entry: ShellHistoryEntry }): React.ReactElement {
  const status = entry.status;
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

  return (
    <Ratchet>
      <Box marginTop={SPACING.sm}>
        <Gutter>
          {status ? <PulseDot status={status} /> : <Text>{tokens.accent(BLACK_CIRCLE)}</Text>}
        </Gutter>
        <Text>
          {tokens.label(label)}
          {entry.inputHint ? tokens.muted(`(${entry.inputHint})`) : ""}
          {elapsedSuffix}
          {ts}
        </Text>
      </Box>
      {status === "running" && entry.liveActivities && entry.liveActivities.length > 0 ? (
        <Box flexDirection="column">
          {entry.liveActivities.slice(-4).map((activity) => (
            <Box key={activity.id}>
              <Gutter />
              <Gutter>
                <Text>{tokens.tertiary(LOWER_HOOK)}</Text>
              </Gutter>
              <Text> {tokens.muted(truncateEnd(activity.text, 104))}</Text>
            </Box>
          ))}
          {entry.liveActivities.length > 4 ? (
            <Box>
              <Gutter />
              <Gutter>
                <Text dimColor>{LOWER_HOOK}</Text>
              </Gutter>
              <Text> {tokens.muted(`… ${entry.liveActivities.length - 4} earlier updates`)}</Text>
            </Box>
          ) : null}
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
