/**
 * Ink component for the copilot shell.
 *
 * Clean conversation stream with proper spacing. User messages, agent
 * responses, inline tool activity. The Ink App handles mode transitions —
 * when a scan runs, the app switches to "running" mode and renders
 * PipelineIndicator/StatusFooter, then switches back here.
 *
 * Uses <MultilineText> for multi-line entries, tokens for all styling, and
 * registers its active keybindings with the shared footer.
 */

import { Box, Static, Text, useApp, useInput } from "ink";
import type React from "react";
import { memo, useEffect, useRef, useState } from "react";
import { computeFindingAliases, resolveAlias } from "../../copilot/finding-alias.js";
import { buildShellPrompt } from "../../copilot/shell.js";
import { useRegisterKeybindings } from "../hooks/useKeybindings.js";
import { useUIState } from "../hooks.js";
import { MultilineText } from "../primitives/MultilineText.js";
import type { ShellHistoryEntry, ShellState, UIState, UIStore } from "../state.js";
import { tokens } from "../tokens.js";
import { AttackerStoriesView } from "./AttackerStoriesView.js";
import { FindingCard } from "./FindingCard.js";
import { FindingsView } from "./FindingsView.js";
import { ModuleCatalog } from "./ModuleCatalog.js";
import { ModuleHome } from "./ModuleHome.js";
import { PlanCard } from "./PlanCard.js";
import { ScopeAndCriticalityView } from "./ScopeAndCriticalityView.js";
import { Spinner } from "./Spinner.js";
import { ThreatDfdView } from "./ThreatDfdView.js";
import { ThreatPlaceholder } from "./ThreatPlaceholder.js";
import { ThreatStrideMatrix } from "./ThreatStrideMatrix.js";
import { TuneView } from "./TuneView.js";

interface CopilotShellProps {
  store: UIStore;
}

const IDLE_KEYBINDS = [
  { keys: "Enter", label: "Send" },
  { keys: "\u2191/\u2193", label: "History" },
  { keys: "Esc", label: "Clear input", secondary: true },
  { keys: "Ctrl+C", label: "Exit", secondary: true },
];

const PROCESSING_KEYBINDS = [{ keys: "Ctrl+C", label: "Abort" }];

/** Window during which a second Ctrl+C at the idle prompt commits the exit. */
const CTRL_C_ARM_WINDOW_MS = 2000;

/** True for any of the Phase C threat-model sub-views. */
function isThreatShellView(view: ShellState["shellView"] | undefined): boolean {
  return (
    view === "threat-dfd" ||
    view === "threat-stride" ||
    view === "threat-stories" ||
    view === "threat-scope" ||
    view === "threat-summary"
  );
}

export function CopilotShell({ store }: CopilotShellProps): React.ReactElement {
  const state = useUIState(store);
  const shell = state.shell;
  const { exit } = useApp();
  const [input, setInput] = useState("");
  const [historyIndex, setHistoryIndex] = useState<number | null>(null);
  const draftInputRef = useRef("");

  const processing = shell?.processing === true;
  useRegisterKeybindings(processing ? PROCESSING_KEYBINDS : IDLE_KEYBINDS);

  useInput(
    (char, key) => {
      if (!shell) return;

      if ((key.ctrl && char === "c") || (key.ctrl && char === "d")) {
        // In-flight work always gets an immediate abort — no point arming
        // when there's something to interrupt. `onAbort` is idempotent;
        // a second Ctrl+C after abort falls through to the exit path.
        if (shell.processing) {
          shell.onAbort?.();
          return;
        }
        // B.4 two-stage Ctrl+C at the idle prompt: first press arms,
        // second press within CTRL_C_ARM_WINDOW_MS exits. Anything else
        // pressed within the window disarms silently.
        const now = Date.now();
        const armedAt = state.ctrlCArmedAt ?? 0;
        if (now - armedAt <= CTRL_C_ARM_WINDOW_MS) {
          shell.onExit?.();
          exit();
          return;
        }
        store.update({ ctrlCArmedAt: now });
        return;
      }

      // Any other key disarms the Ctrl+C stage counter if one is in flight.
      if (state.ctrlCArmedAt) {
        store.update({ ctrlCArmedAt: undefined });
      }

      if (shell.processing) {
        return;
      }

      // When a NL-planner proposal is waiting for confirmation, route y / n /
      // Esc through the shell's onInput so the same /yes, /no handlers in
      // shell.ts apply or discard. Single-key shortcut — operator doesn't
      // need to type a slash command.
      if (shell.pendingPlan && input.length === 0) {
        if (char === "y" || char === "Y") {
          shell.onInput?.("/yes");
          return;
        }
        if (char === "n" || char === "N" || key.escape) {
          shell.onInput?.("/no");
          return;
        }
      }

      // Phase C — while on a threat view, 1..5 cycle through the five
      // sub-views without having to retype `/threats <name>`. Only active
      // when the input buffer is empty so the digits don't interfere
      // with natural-language input.
      if (isThreatShellView(shell.shellView) && input.length === 0) {
        if (char === "1") {
          shell.onInput?.("/threats dfd");
          return;
        }
        if (char === "2") {
          shell.onInput?.("/threats stride");
          return;
        }
        if (char === "3") {
          shell.onInput?.("/threats stories");
          return;
        }
        if (char === "4") {
          shell.onInput?.("/threats scope");
          return;
        }
        if (char === "5") {
          shell.onInput?.("/threats summary");
          return;
        }
      }

      if (key.return && input.length > 0) {
        shell.onInput?.(input);
        setInput("");
        setHistoryIndex(null);
        draftInputRef.current = "";
        return;
      }

      if (key.backspace || key.delete) {
        setInput((v) => v.slice(0, -1));
        setHistoryIndex(null);
        return;
      }

      if (key.upArrow) {
        if (shell.commandHistory.length === 0) return;
        if (historyIndex === null) {
          draftInputRef.current = input;
          const nextIndex = shell.commandHistory.length - 1;
          setHistoryIndex(nextIndex);
          setInput(shell.commandHistory[nextIndex] ?? "");
          return;
        }
        const nextIndex = Math.max(0, historyIndex - 1);
        setHistoryIndex(nextIndex);
        setInput(shell.commandHistory[nextIndex] ?? "");
        return;
      }

      if (key.downArrow) {
        if (historyIndex === null) return;
        const nextIndex = historyIndex + 1;
        if (nextIndex >= shell.commandHistory.length) {
          setHistoryIndex(null);
          setInput(draftInputRef.current);
          return;
        }
        setHistoryIndex(nextIndex);
        setInput(shell.commandHistory[nextIndex] ?? "");
        return;
      }

      if (key.escape) {
        setInput("");
        setHistoryIndex(null);
        draftInputRef.current = "";
        return;
      }

      if (char && !key.ctrl && !key.meta && !key.tab) {
        if (historyIndex === null) draftInputRef.current = "";
        setInput((v) => v + char);
        setHistoryIndex(null);
      }
    },
    { isActive: process.stdin.isTTY === true && !!shell },
  );

  if (!shell) return <Text>Loading...</Text>;

  const LIVE_COUNT = 8;
  const staticHistory =
    shell.history.length > LIVE_COUNT ? shell.history.slice(0, -LIVE_COUNT) : [];
  const liveHistory =
    shell.history.length > LIVE_COUNT ? shell.history.slice(-LIVE_COUNT) : shell.history;

  // ModuleCatalog re-reads shell.moduleCatalog on every render; wrapping it in
  // <Static> would freeze the first snapshot and hide module/last-run updates,
  // so we render it plainly. To stop it from re-rendering on every shell state
  // update (heartbeat ticks, phase events, etc. — which previously caused
  // visible flicker), the banner is memoized on just the fields it reads.
  const showCatalog = shell.moduleCatalog && shell.moduleCatalog.length > 0;

  return (
    <Box flexDirection="column">
      {showCatalog ? (
        <MemoShellBanner shell={shell} />
      ) : (
        <Static items={["shell-banner"]}>
          {() => <MemoShellBanner key="shell-banner" shell={shell} />}
        </Static>
      )}

      <Static items={staticHistory.map((entry, i) => ({ ...entry, _key: `h-${i}` }))}>
        {(item) => (
          <HistoryEntry key={(item as { _key: string })._key} entry={item as ShellHistoryEntry} />
        )}
      </Static>

      <Box flexDirection="column">
        {liveHistory.map((entry, i) => (
          <HistoryEntry key={`live-${i}`} entry={entry} />
        ))}
      </Box>

      <MemoShellViewPanel state={state} shell={shell} />

      {shell.plannerBusy && !shell.pendingPlan && (
        <Box marginTop={1} paddingLeft={2}>
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
            timestamp: Date.now(),
          }}
        />
      )}

      {shell.processing && shell.currentTool && (
        <Box flexDirection="column" marginTop={1} paddingLeft={2}>
          <Box>
            <Spinner />
            <Text>
              {"  "}
              {tokens.muted(shell.currentTool.name)}
              {shell.currentTool.subLabel ? tokens.muted(` · ${shell.currentTool.subLabel}`) : ""}
            </Text>
            {shell.currentTool.startedAt ? (
              <LiveElapsed startedAt={shell.currentTool.startedAt} />
            ) : shell.currentTool.elapsedSeconds && shell.currentTool.elapsedSeconds > 0 ? (
              <Text>{tokens.muted(` ${shell.currentTool.elapsedSeconds.toFixed(0)}s`)}</Text>
            ) : null}
          </Box>
          {shell.llmHeartbeat && <LlmHeartbeatLine heartbeat={shell.llmHeartbeat} />}
        </Box>
      )}

      {shell.processing && !shell.currentTool && (
        <Box flexDirection="column" marginTop={1} paddingLeft={2}>
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

      {state.ctrlCArmedAt && Date.now() - state.ctrlCArmedAt < CTRL_C_ARM_WINDOW_MS ? (
        <Box marginTop={1} paddingLeft={2}>
          <Text>{tokens.warn("press Ctrl+C again to exit")}</Text>
        </Box>
      ) : null}

      {!shell.processing && (
        <Box marginTop={1}>
          <Text>
            {tokens.accent(buildShellPrompt(shell.focusedModule))}
            {input}
            {tokens.muted("\u2588")}
          </Text>
        </Box>
      )}
    </Box>
  );
}

/**
 * Self-ticking elapsed-time display. Owns its own 1s timer so the shell
 * subtree doesn't re-render every second when only the seconds digit
 * changed — fixes the visible flicker that happened when the tracker in
 * shared.ts was writing elapsed into shell state on an interval.
 */
function LiveElapsed({ startedAt }: { startedAt: number }): React.ReactElement {
  const [elapsed, setElapsed] = useState(() => Math.floor((Date.now() - startedAt) / 1000));
  useEffect(() => {
    const timer = setInterval(() => {
      setElapsed(Math.floor((Date.now() - startedAt) / 1000));
    }, 1000);
    return () => clearInterval(timer);
  }, [startedAt]);
  if (elapsed <= 0) return <Text>{""}</Text>;
  return <Text>{tokens.muted(` ${elapsed}s`)}</Text>;
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
    <Box paddingLeft={4}>
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
  state,
  shell,
}: {
  state: UIState;
  shell: ShellState;
}): React.ReactElement | null {
  switch (shell.shellView) {
    case "module":
      return shell.focusedModule ? <ModuleHome shell={shell} /> : null;
    case "tune":
      return shell.focusedModule ? <TuneView shell={shell} /> : null;
    case "findings": {
      const summary = state.summary;
      const findings = summary?.actionableFindings ?? [];
      const chains = (summary?.exploitChains ?? []).map((c) => ({
        id: c.id,
        name: c.name,
        severity: c.overallSeverity,
        findingFingerprints: c.steps.map((s) => s.findingFingerprint),
      }));
      return <FindingsView mode="unified" findings={findings} chains={chains} />;
    }
    case "finding": {
      const summary = state.summary;
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
      return <FindingCard mode="linear" finding={match} />;
    }
    // Phase C — threat model views. C.4–C.5 still route through the
    // placeholder until their real components land.
    case "threat-dfd":
      return <ThreatDfdView shell={shell} />;
    case "threat-stride":
      return <ThreatStrideMatrix shell={shell} />;
    case "threat-stories":
      return <AttackerStoriesView shell={shell} />;
    case "threat-scope":
      return <ScopeAndCriticalityView shell={shell} />;
    case "threat-summary":
      return <ThreatPlaceholder shell={shell} />;
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
    prev.state.summary === next.state.summary,
);

function ShellBannerImpl({ shell }: { shell: ShellState }): React.ReactElement {
  // Prefer the v2 catalog view whenever we have module data; fall back to the
  // legacy flat header only if `moduleCatalog` hasn't been populated yet
  // (e.g. during an early boot tick before `startInkShell` finishes init).
  if (shell.moduleCatalog && shell.moduleCatalog.length > 0) {
    return <ModuleCatalog shell={shell} />;
  }
  return (
    <Box flexDirection="column" marginBottom={1} paddingLeft={2}>
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

function HistoryEntry({ entry }: { entry: ShellHistoryEntry }): React.ReactElement {
  switch (entry.type) {
    case "input":
      return (
        <Box marginTop={1}>
          <Text>
            {tokens.accent(entry.prompt ?? buildShellPrompt(null))}
            {entry.text}
          </Text>
        </Box>
      );
    case "output":
      return (
        <Box marginTop={1}>
          <MultilineText text={entry.text} />
        </Box>
      );
    case "error":
      return (
        <Box marginTop={1}>
          <Text>{tokens.danger(entry.text)}</Text>
        </Box>
      );
  }
}
