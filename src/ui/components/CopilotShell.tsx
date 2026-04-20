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
import { useRef, useState } from "react";
import { computeFindingAliases, resolveAlias } from "../../copilot/finding-alias.js";
import { buildShellPrompt } from "../../copilot/shell.js";
import { useRegisterKeybindings } from "../hooks/useKeybindings.js";
import { useUIState } from "../hooks.js";
import { MultilineText } from "../primitives/MultilineText.js";
import type { ShellHistoryEntry, ShellState, UIState, UIStore } from "../state.js";
import { tokens } from "../tokens.js";
import { FindingCard } from "./FindingCard.js";
import { FindingsView } from "./FindingsView.js";
import { ModuleCatalog } from "./ModuleCatalog.js";
import { ModuleHome } from "./ModuleHome.js";
import { PlanCard } from "./PlanCard.js";
import { Spinner } from "./Spinner.js";
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
        if (shell.processing) {
          shell.onAbort?.();
          return;
        }
        shell.onExit?.();
        exit();
        return;
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
  // <Static> would freeze the first snapshot and hide module/last-run updates.
  // Render it as a plain child at the top — there's exactly one catalog per
  // session, so the cost is negligible.
  const showCatalog = shell.moduleCatalog && shell.moduleCatalog.length > 0;

  return (
    <Box flexDirection="column">
      {showCatalog ? (
        <ShellBanner shell={shell} />
      ) : (
        <Static items={["shell-banner"]}>
          {() => <ShellBanner key="shell-banner" shell={shell} />}
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

      <ShellViewPanel state={state} shell={shell} />

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
        <Box marginTop={1} paddingLeft={2}>
          <Spinner />
          <Text>
            {"  "}
            {tokens.muted(shell.currentTool.name)}
            {shell.currentTool.elapsedSeconds > 0 &&
              tokens.muted(` ${shell.currentTool.elapsedSeconds.toFixed(0)}s`)}
          </Text>
        </Box>
      )}

      {shell.processing && !shell.currentTool && (
        <Box marginTop={1} paddingLeft={2}>
          <Spinner />
          <Text>
            {"  "}
            {tokens.muted("running...")}
          </Text>
        </Box>
      )}

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
    default:
      return null;
  }
}

function ShellBanner({ shell }: { shell: ShellState }): React.ReactElement {
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
