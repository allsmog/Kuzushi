/**
 * Interactive command input for live scan control.
 *
 * Sits at the bottom of the Ink app, accepting slash commands:
 *   /skip <fingerprint>   — skip a finding during triage
 *   /skip-rule <ruleId>   — suppress all findings matching a rule
 *   /focus <path>         — prioritize findings in a path
 *   /pause                — pause triage after current finding
 *   /resume               — resume triage
 *   /status               — show current scan stats
 *   /cost                 — show cost breakdown
 *   /export               — open export menu
 *   /help or ?            — show available commands
 *
 * Typing is delegated to the <TextInput> primitive once the user types
 * `/` or `?` to enter command mode.
 */

import { Box, Text, useInput } from "ink";
import type React from "react";
import { useState } from "react";
import { useRegisterKeybindings } from "../hooks/useKeybindings.js";
import { icons } from "../icons.js";
import { TextInput } from "../primitives/TextInput.js";
import { SPACING, tokens } from "../tokens.js";

export interface ReplCommand {
  name: string;
  args: string[];
  raw: string;
}

export interface CommandResult {
  message: string;
  type: "success" | "error" | "info";
}

interface CommandInputProps {
  active: boolean;
  onCommand: (cmd: ReplCommand) => CommandResult | undefined;
}

const COMMANDS: Array<{ name: string; args: string; desc: string }> = [
  { name: "/skip", args: "<fingerprint>", desc: "Skip a finding" },
  { name: "/skip-rule", args: "<ruleId>", desc: "Suppress findings by rule" },
  { name: "/focus", args: "<path>", desc: "Prioritize findings in path" },
  { name: "/pause", args: "", desc: "Pause after current finding" },
  { name: "/resume", args: "", desc: "Resume triage" },
  { name: "/status", args: "", desc: "Show current stats" },
  { name: "/cost", args: "", desc: "Show cost breakdown" },
  { name: "/help", args: "", desc: "Show this help" },
];

const IDLE_KEYBINDS = [
  { keys: "1/2/3", label: "Switch view" },
  { keys: "m", label: "Agents", secondary: true },
  { keys: "n", label: "Notices", secondary: true },
  { keys: "/", label: "Command" },
  { keys: "?", label: "Help", secondary: true },
  { keys: "Ctrl+C", label: "Interrupt", secondary: true },
];

const COMMAND_KEYBINDS = [
  { keys: "Enter", label: "Run" },
  { keys: "Esc", label: "Cancel" },
];

export function CommandInput({ active, onCommand }: CommandInputProps): React.ReactElement | null {
  const [input, setInput] = useState("");
  const [lastResult, setLastResult] = useState<CommandResult | null>(null);
  const [showHelp, setShowHelp] = useState(false);
  const [expanded, setExpanded] = useState(false);

  const canUseInput = active && process.stdin.isTTY === true;

  useRegisterKeybindings(expanded ? COMMAND_KEYBINDS : IDLE_KEYBINDS);

  // Idle-state watcher: waits for "/" or "?" to flip into command mode.
  // Typing itself is handled by <TextInput> once expanded.
  useInput(
    (char) => {
      if (expanded) return;
      if (char === "/") {
        setExpanded(true);
        setInput("/");
      } else if (char === "?") {
        setExpanded(true);
        setShowHelp(true);
        setLastResult({ message: "", type: "info" });
      }
    },
    { isActive: canUseInput && !expanded },
  );

  const runCommand = (value: string) => {
    if (value.length === 0) return;
    const cmd = parseCommand(value);
    if (cmd) {
      if (cmd.name === "help") {
        setShowHelp((v) => !v);
        setLastResult({ message: "", type: "info" });
      } else {
        const result = onCommand(cmd);
        setLastResult(result ?? { message: `${cmd.name}: ok`, type: "success" });
        setShowHelp(false);
      }
    } else {
      setLastResult({ message: `Unknown command: ${value}`, type: "error" });
    }
    setInput("");
    setExpanded(false);
  };

  const cancel = () => {
    setInput("");
    setLastResult(null);
    setShowHelp(false);
    setExpanded(false);
  };

  if (!active || !process.stdin.isTTY) return null;

  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      {showHelp && (
        <Box flexDirection="column" marginBottom={SPACING.sm} paddingLeft={SPACING.md}>
          <Text>{tokens.muted("Available commands:")}</Text>
          <Box flexDirection="column" paddingLeft={SPACING.md}>
            {COMMANDS.map((cmd) => (
              <Text key={cmd.name}>
                {tokens.accent(cmd.name)} {tokens.muted(cmd.args)}
                {"  "}
                {tokens.muted(cmd.desc)}
              </Text>
            ))}
          </Box>
        </Box>
      )}

      {lastResult?.message && (
        <Box paddingLeft={SPACING.md}>
          <Text>
            {lastResult.type === "success"
              ? tokens.success(icons.success)
              : lastResult.type === "error"
                ? tokens.danger(icons.error)
                : tokens.muted(icons.dot)}{" "}
            {lastResult.type === "error"
              ? tokens.danger(lastResult.message)
              : tokens.muted(lastResult.message)}
          </Text>
        </Box>
      )}

      {expanded && (
        <Box paddingLeft={SPACING.md}>
          <TextInput
            value={input}
            onChange={setInput}
            onSubmit={runCommand}
            onCancel={cancel}
            isActive={canUseInput}
            prefix={`${icons.arrow} `}
            placeholder="type / for commands, ? for help"
          />
        </Box>
      )}
    </Box>
  );
}

function parseCommand(raw: string): ReplCommand | null {
  const trimmed = raw.trim();

  if (trimmed === "?") {
    return { name: "help", args: [], raw: trimmed };
  }

  if (!trimmed.startsWith("/")) {
    return null;
  }

  const parts = trimmed.slice(1).split(/\s+/);
  const name = parts[0]!;
  const args = parts.slice(1);

  const validNames = COMMANDS.map((c) => c.name.slice(1));
  if (!validNames.includes(name)) {
    return null;
  }

  return { name, args, raw: trimmed };
}
