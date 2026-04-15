/**
 * Ink component for the copilot shell — renders like Claude Code.
 *
 * Clean conversation stream: user messages, agent responses, inline
 * tool activity. No REPL chrome, no command menus. Just a conversation.
 */
import React, { useState, useEffect } from "react";
import { Box, Text, useInput, useApp, Static } from "ink";
import chalk from "chalk";
import { useUIState } from "../hooks.js";
import { Spinner } from "./Spinner.js";
import type { UIStore, ShellHistoryEntry } from "../state.js";

interface CopilotShellProps {
  store: UIStore;
}

export function CopilotShell({ store }: CopilotShellProps): React.ReactElement {
  const state = useUIState(store);
  const shell = state.shell;
  const { exit } = useApp();
  const [input, setInput] = useState("");

  useInput((char, key) => {
    if (!shell || shell.processing) return;

    if (key.return && input.length > 0) {
      // Append user input to history and mark processing
      const currentShell = store.getState().shell;
      if (currentShell) {
        store.update({
          shell: {
            ...currentShell,
            history: [
              ...currentShell.history,
              { type: "input", text: input, timestamp: Date.now() },
            ],
            processing: true,
          },
        });
      }
      shell.onInput?.(input);
      setInput("");
      return;
    }

    if (key.backspace || key.delete) {
      setInput((v) => v.slice(0, -1));
      return;
    }

    if ((key.ctrl && char === "c") || (key.ctrl && char === "d")) {
      shell.onExit?.();
      exit();
      return;
    }

    if (key.escape) {
      setInput("");
      return;
    }

    if (char && !key.ctrl && !key.meta && !key.tab) {
      setInput((v) => v + char);
    }
  }, { isActive: process.stdin.isTTY === true && !!shell && !shell.processing });

  if (!shell) return <Text>Loading...</Text>;

  // Split history into static (already rendered) and live (recent)
  const staticHistory = shell.history.slice(0, -6);
  const liveHistory = shell.history.length > 6
    ? shell.history.slice(-6)
    : shell.history;

  return (
    <Box flexDirection="column">
      {/* Static region — rendered once, never re-rendered */}
      <Static items={staticHistory.map((entry, i) => ({ ...entry, _key: `h-${i}` }))}>
        {(item) => (
          <HistoryEntry key={(item as { _key: string })._key} entry={item as ShellHistoryEntry} />
        )}
      </Static>

      {/* Live region — recent entries + current activity */}
      <Box flexDirection="column">
        {liveHistory.map((entry, i) => (
          <HistoryEntry key={`live-${i}`} entry={entry} />
        ))}
      </Box>

      {/* Tool activity indicator */}
      {shell.processing && shell.currentTool && (
        <Box paddingLeft={2}>
          <Spinner />
          <Text>
            {" "}{chalk.dim(shell.currentTool.name)}
            {shell.currentTool.elapsedSeconds > 0 &&
              chalk.dim(` ${shell.currentTool.elapsedSeconds.toFixed(0)}s`)}
          </Text>
        </Box>
      )}

      {/* Thinking indicator (no specific tool) */}
      {shell.processing && !shell.currentTool && (
        <Box paddingLeft={2}>
          <Spinner />
          <Text>{" "}{chalk.dim("thinking...")}</Text>
        </Box>
      )}

      {/* Input prompt */}
      {!shell.processing && (
        <Box>
          <Text>
            {chalk.bold.white("> ")}{input}{chalk.dim("█")}
          </Text>
        </Box>
      )}
    </Box>
  );
}

function HistoryEntry({ entry }: { entry: ShellHistoryEntry }): React.ReactElement {
  switch (entry.type) {
    case "input":
      return (
        <Box>
          <Text>{chalk.bold.white("> ")}{entry.text}</Text>
        </Box>
      );
    case "output":
      return (
        <Box flexDirection="column" paddingLeft={0}>
          {entry.text.split("\n").map((line, i) => (
            <Text key={i}>{line}</Text>
          ))}
        </Box>
      );
    case "error":
      return (
        <Box>
          <Text>{chalk.red(entry.text)}</Text>
        </Box>
      );
  }
}
