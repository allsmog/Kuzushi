/**
 * Ink component for the copilot shell.
 *
 * Clean conversation stream with proper spacing. User messages,
 * agent responses, inline tool activity. The Ink App handles mode
 * transitions — when a scan runs, the app switches to "running" mode
 * and renders PipelineIndicator/StatusFooter, then switches back here.
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

  // Split history: older entries go to Static (never re-rendered)
  const LIVE_COUNT = 8;
  const staticHistory = shell.history.length > LIVE_COUNT
    ? shell.history.slice(0, -LIVE_COUNT)
    : [];
  const liveHistory = shell.history.length > LIVE_COUNT
    ? shell.history.slice(-LIVE_COUNT)
    : shell.history;

  return (
    <Box flexDirection="column">
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

      {/* Tool activity */}
      {shell.processing && shell.currentTool && (
        <Box marginTop={1} paddingLeft={2}>
          <Spinner />
          <Text>
            {"  "}{chalk.dim(shell.currentTool.name)}
            {shell.currentTool.elapsedSeconds > 0 &&
              chalk.dim(` ${shell.currentTool.elapsedSeconds.toFixed(0)}s`)}
          </Text>
        </Box>
      )}

      {/* Processing indicator */}
      {shell.processing && !shell.currentTool && (
        <Box marginTop={1} paddingLeft={2}>
          <Spinner />
          <Text>{"  "}{chalk.dim("running...")}</Text>
        </Box>
      )}

      {/* Input prompt */}
      {!shell.processing && (
        <Box marginTop={1}>
          <Text>
            {chalk.bold.cyan("> ")}{input}{chalk.dim("█")}
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
        <Box marginTop={1}>
          <Text>{chalk.bold.cyan("> ")}{entry.text}</Text>
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
