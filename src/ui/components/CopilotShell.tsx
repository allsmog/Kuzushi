/**
 * Ink component for the copilot shell.
 *
 * Clean conversation stream with proper spacing. User messages,
 * agent responses, inline tool activity. The Ink App handles mode
 * transitions — when a scan runs, the app switches to "running" mode
 * and renders PipelineIndicator/StatusFooter, then switches back here.
 */

import chalk from "chalk";
import { Box, Static, Text, useApp, useInput } from "ink";
import type React from "react";
import { useRef, useState } from "react";
import { buildShellPrompt } from "../../copilot/shell.js";
import { useUIState } from "../hooks.js";
import type { ShellHistoryEntry, ShellState, UIStore } from "../state.js";
import { Spinner } from "./Spinner.js";

interface CopilotShellProps {
  store: UIStore;
}

export function CopilotShell({ store }: CopilotShellProps): React.ReactElement {
  const state = useUIState(store);
  const shell = state.shell;
  const { exit } = useApp();
  const [input, setInput] = useState("");
  const [historyIndex, setHistoryIndex] = useState<number | null>(null);
  const draftInputRef = useRef("");

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
        if (shell.commandHistory.length === 0) {
          return;
        }
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
        if (historyIndex === null) {
          return;
        }
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
        if (historyIndex === null) {
          draftInputRef.current = "";
        }
        setInput((v) => v + char);
        setHistoryIndex(null);
      }
    },
    { isActive: process.stdin.isTTY === true && !!shell },
  );

  if (!shell) return <Text>Loading...</Text>;

  // Split history: older entries go to Static (never re-rendered)
  const LIVE_COUNT = 8;
  const staticHistory =
    shell.history.length > LIVE_COUNT ? shell.history.slice(0, -LIVE_COUNT) : [];
  const liveHistory =
    shell.history.length > LIVE_COUNT ? shell.history.slice(-LIVE_COUNT) : shell.history;

  return (
    <Box flexDirection="column">
      <Static items={["shell-banner"]}>
        {() => <ShellBanner key="shell-banner" shell={shell} />}
      </Static>

      {/* Static region — rendered once */}
      <Static items={staticHistory.map((entry, i) => ({ ...entry, _key: `h-${i}` }))}>
        {(item) => (
          <HistoryEntry key={(item as { _key: string })._key} entry={item as ShellHistoryEntry} />
        )}
      </Static>

      {/* Live region */}
      <Box flexDirection="column">
        {liveHistory.map((entry, i) => (
          <HistoryEntry key={`live-${i}`} entry={entry} />
        ))}
      </Box>

      {shell.pendingAssistantText && (
        <HistoryEntry
          entry={{
            type: "output",
            text: shell.pendingAssistantText,
            timestamp: Date.now(),
          }}
        />
      )}

      {/* Tool activity */}
      {shell.processing && shell.currentTool && (
        <Box marginTop={1} paddingLeft={2}>
          <Spinner />
          <Text>
            {"  "}
            {chalk.dim(shell.currentTool.name)}
            {shell.currentTool.elapsedSeconds > 0 &&
              chalk.dim(` ${shell.currentTool.elapsedSeconds.toFixed(0)}s`)}
          </Text>
        </Box>
      )}

      {/* Processing indicator */}
      {shell.processing && !shell.currentTool && (
        <Box marginTop={1} paddingLeft={2}>
          <Spinner />
          <Text>
            {"  "}
            {chalk.dim("running...")}
          </Text>
        </Box>
      )}

      {/* Input prompt */}
      {!shell.processing && (
        <Box marginTop={1}>
          <Text>
            {chalk.bold.cyan(buildShellPrompt(shell.focusedModule))}
            {input}
            {chalk.dim("█")}
          </Text>
        </Box>
      )}
    </Box>
  );
}

function ShellBanner({ shell }: { shell: ShellState }): React.ReactElement {
  return (
    <Box flexDirection="column" marginBottom={1}>
      <Text>{""}</Text>
      <Text>{chalk.bold("  Kuzushi")}</Text>
      <Text>{chalk.dim("  security-native AI operating environment")}</Text>
      <Text>{""}</Text>
      <Text>{`  Modules:   ${shell.modules.join(", ") || "none"}`}</Text>
      <Text>{`  Tools:     ${shell.tools.length} available`}</Text>
      {shell.target && <Text>{`  Target:    ${shell.target}`}</Text>}
      {shell.workspace && <Text>{`  Workspace: ${shell.workspace}`}</Text>}
      <Text>{""}</Text>
      <Text>{chalk.dim('  Type "/help" for commands, or just describe what you need.')}</Text>
    </Box>
  );
}

function HistoryEntry({ entry }: { entry: ShellHistoryEntry }): React.ReactElement {
  switch (entry.type) {
    case "input":
      return (
        <Box marginTop={1}>
          <Text>
            {chalk.bold.cyan(entry.prompt ?? buildShellPrompt(null))}
            {entry.text}
          </Text>
        </Box>
      );
    case "output":
      return (
        <Box flexDirection="column" marginTop={1}>
          {entry.text.split("\n").map((line, i) => (
            <Text key={i}>{line}</Text>
          ))}
        </Box>
      );
    case "error":
      return (
        <Box marginTop={1}>
          <Text>{chalk.red(entry.text)}</Text>
        </Box>
      );
  }
}
