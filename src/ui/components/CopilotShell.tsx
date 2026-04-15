/**
 * Ink component for the interactive copilot shell.
 *
 * Renders:
 * - Shell header (modules, tools, target)
 * - Scrollable conversation history
 * - Text input prompt with module-aware prefix
 * - Processing indicator when a command is running
 */
import React, { useState, useEffect } from "react";
import { Box, Text, useInput, useApp } from "ink";
import chalk from "chalk";
import { useUIState } from "../hooks.js";
import type { UIStore, ShellState, ShellHistoryEntry } from "../state.js";

interface CopilotShellProps {
  store: UIStore;
}

const CATEGORY_COLORS: Record<string, (s: string) => string> = {
  offense: chalk.red,
  defense: chalk.blue,
  governance: chalk.yellow,
  intel: chalk.green,
};

export function CopilotShell({ store }: CopilotShellProps): React.ReactElement {
  const state = useUIState(store);
  const shell = state.shell;
  const { exit } = useApp();
  const [input, setInput] = useState("");
  const [cursorVisible, setCursorVisible] = useState(true);

  // Cursor blink
  useEffect(() => {
    const id = setInterval(() => setCursorVisible((v) => !v), 530);
    return () => clearInterval(id);
  }, []);

  useInput((char, key) => {
    if (!shell || shell.processing) return;

    if (key.return && input.length > 0) {
      // Append input to history
      store.update({
        shell: {
          ...shell,
          history: [
            ...shell.history,
            { type: "input", text: input, timestamp: Date.now() },
          ],
          processing: true,
        },
      });
      shell.onInput?.(input);
      setInput("");
      return;
    }

    if (key.backspace || key.delete) {
      setInput((v) => v.slice(0, -1));
      return;
    }

    // Ctrl+C or Ctrl+D
    if ((key.ctrl && char === "c") || (key.ctrl && char === "d")) {
      shell.onExit?.();
      exit();
      return;
    }

    // Escape clears input
    if (key.escape) {
      setInput("");
      return;
    }

    // Regular character
    if (char && !key.ctrl && !key.meta) {
      setInput((v) => v + char);
    }
  }, { isActive: process.stdin.isTTY === true && !!shell && !shell.processing });

  if (!shell) return <Text>Loading shell...</Text>;

  const prompt = shell.focusedModule
    ? `${chalk.white("kuzushi")}${chalk.dim("/")}${chalk.cyan(shell.focusedModule)}${chalk.white("> ")}`
    : `${chalk.white("kuzushi> ")}`;

  // Show last N history entries
  const visibleHistory = shell.history.slice(-20);

  return (
    <Box flexDirection="column" paddingLeft={1}>
      {/* Header */}
      <Box flexDirection="column" marginBottom={1}>
        <Text>
          {chalk.white.bold("kuzushi shell")}
          {chalk.dim("  security-native AI operating environment")}
        </Text>
        <Text>
          {chalk.dim("modules: ")}
          {shell.modules.map((id, i) => {
            // Try to color by category — default to white
            const colorFn = CATEGORY_COLORS.offense; // Will be refined when we have category info
            return (i > 0 ? chalk.dim(", ") : "") + colorFn(id);
          }).join("")}
          {chalk.dim("  tools: ")}
          {chalk.white(`${shell.tools.length}`)}
          {shell.target ? `${chalk.dim("  target: ")}${chalk.white(shell.target)}` : ""}
          {shell.workspace ? `${chalk.dim("  workspace: ")}${chalk.white(shell.workspace)}` : ""}
        </Text>
        <Text>{chalk.dim('Type "help" for commands, or describe what you need.')}</Text>
      </Box>

      {/* History */}
      {visibleHistory.map((entry, i) => (
        <HistoryLine key={i} entry={entry} />
      ))}

      {/* Processing indicator */}
      {shell.processing && (
        <Box>
          <Text>{chalk.cyan("  thinking...")}</Text>
        </Box>
      )}

      {/* Input prompt */}
      {!shell.processing && (
        <Box>
          <Text>
            {prompt}{input}{cursorVisible ? chalk.white("█") : " "}
          </Text>
        </Box>
      )}
    </Box>
  );
}

function HistoryLine({ entry }: { entry: ShellHistoryEntry }): React.ReactElement {
  switch (entry.type) {
    case "input":
      return (
        <Text>{chalk.dim("you> ")}{chalk.white(entry.text)}</Text>
      );
    case "output":
      return (
        <Box flexDirection="column" paddingLeft={2}>
          {entry.text.split("\n").map((line, i) => (
            <Text key={i}>{line}</Text>
          ))}
        </Box>
      );
    case "error":
      return (
        <Text>{chalk.red(`  Error: ${entry.text}`)}</Text>
      );
  }
}
